/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![allow(unexpected_cfgs)]

use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str;
use std::time::Duration;
use std::{fs, io};

use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use himmelblau::graph::Graph;
use himmelblau_policies::policies::apply_intune_policy;
use himmelblau_unix_common::config::{split_username, HimmelblauConfig};
use himmelblau_unix_common::constants::{
    DEFAULT_CONFIG_PATH, DEFAULT_KERBEROS_CONF_DIR, LOCAL_TASK_NAMES_CACHE,
};
use himmelblau_unix_common::unix_proto::{
    HomeDirectoryInfo, LocalTaskOwner, TaskRequest, TaskResponse,
};
use himmelblau_unix_common::user_map::UserMap;
use kanidm_utils_users::{get_effective_gid, get_effective_uid};
use libc::uid_t;
use libc::{lchown, umask};
use libkrimes::proto::KerberosCredentials;
use sd_notify::NotifyState;
use serde::{Deserialize, Serialize};
use sketching::tracing_forest::traits::*;
use sketching::tracing_forest::util::*;
use sketching::tracing_forest::{self};
use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;
use tokio::net::UnixStream;
use tokio::sync::broadcast;
use tokio::time;
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::span;
use walkdir::WalkDir;
use zbus::{proxy, Connection, OwnedObjectPath};

#[cfg(all(target_family = "unix", feature = "selinux"))]
use himmelblau_unix_common::selinux_util;

struct TaskCodec;

#[proxy(
    interface = "org.freedesktop.Accounts",
    default_service = "org.freedesktop.Accounts",
    default_path = "/org/freedesktop/Accounts"
)]
trait AccountsService {
    fn find_user_by_name(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn cache_user(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    interface = "org.freedesktop.Accounts.User",
    default_service = "org.freedesktop.Accounts"
)]
trait AccountsServiceUser {
    fn set_icon_file(&self, filename: &str) -> zbus::Result<()>;
}

impl Decoder for TaskCodec {
    type Error = io::Error;
    type Item = TaskRequest;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match serde_json::from_slice::<TaskRequest>(src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<TaskResponse> for TaskCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: TaskResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("Attempting to send request -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::other("JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

impl TaskCodec {
    fn new() -> Self {
        TaskCodec
    }
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let path_os = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "Unable to create c-string".to_string())?;

    // Change the owner to the gid - remember, himmelblau ONLY has gid's, the uid is implied.
    if unsafe { lchown(path_os.as_ptr(), uid, gid) } != 0 {
        return Err("Unable to set ownership".to_string());
    }
    Ok(())
}

fn create_home_directory(
    info: &HomeDirectoryInfo,
    home_prefix: &str,
    use_etc_skel: bool,
    use_selinux: bool,
) -> Result<(), String> {
    // Final sanity check to prevent certain classes of attacks.
    let name = info.name.trim_start_matches('.').replace(['/', '\\'], "");

    let home_prefix_path = Path::new(home_prefix);

    // Does our home_prefix actually exist?
    if !home_prefix_path.exists() || !home_prefix_path.is_dir() {
        return Err("Invalid home_prefix from configuration".to_string());
    }

    // Actually process the request here.
    let hd_path_raw = format!("{}{}", home_prefix, name);
    let hd_path = Path::new(&hd_path_raw);

    // Assert the resulting named home path is consistent and correct.
    if let Some(pp) = hd_path.parent() {
        if pp != home_prefix_path {
            return Err("Invalid home directory name - not within home_prefix".to_string());
        }
    } else {
        return Err("Invalid/Corrupt home directory path - no prefix found".to_string());
    }

    // Get a handle to the SELinux labeling interface
    debug!(?use_selinux, "selinux for home dir labeling");
    #[cfg(all(target_family = "unix", feature = "selinux"))]
    let labeler = if use_selinux {
        selinux_util::SelinuxLabeler::new(info.uid, home_prefix)?
    } else {
        selinux_util::SelinuxLabeler::new_noop()
    };

    // An alias link still pointing at the old home of a renamed account.
    for alias in info.aliases.iter() {
        let alias = alias.trim_start_matches('.').replace(['/', '\\'], "");
        if let Ok(old) = fs::read_link(format!("{}{}", home_prefix, alias)) {
            let old_path = home_prefix_path.join(old);
            let owned = fs::symlink_metadata(&old_path)
                .map(|m| m.is_dir() && m.uid() == info.uid)
                .unwrap_or(false);
            if owned && old_path.parent() == Some(home_prefix_path) && !hd_path.exists() {
                fs::rename(&old_path, hd_path).map_err(|e| format!("{:?}", e))?;
            }
        }
    }

    if let Ok(m) = fs::symlink_metadata(hd_path) {
        if m.uid() != info.uid {
            return Err("Home directory belongs to another user".to_string());
        }
    }

    // Does the home directory exist?
    if !hd_path.exists() {
        // Set the SELinux security context for file creation
        #[cfg(all(target_family = "unix", feature = "selinux"))]
        labeler.do_setfscreatecon_for_path()?;

        // Set a umask
        let before = unsafe { umask(0o0027) };

        // Create the dir
        if let Err(e) = fs::create_dir_all(hd_path) {
            let _ = unsafe { umask(before) };
            return Err(format!("{:?}", e));
        }
        let _ = unsafe { umask(before) };

        chown(hd_path, info.uid, info.gid)?;

        // Copy in structure from /etc/skel/ if present
        let skel_dir = Path::new("/etc/skel/");
        if use_etc_skel && skel_dir.exists() {
            info!("preparing homedir using /etc/skel");
            for entry in WalkDir::new(skel_dir).into_iter().filter_map(|e| e.ok()) {
                let dest = &hd_path.join(
                    entry
                        .path()
                        .strip_prefix(skel_dir)
                        .map_err(|e| e.to_string())?,
                );

                #[cfg(all(target_family = "unix", feature = "selinux"))]
                {
                    let p = entry
                        .path()
                        .strip_prefix(skel_dir)
                        .map_err(|e| e.to_string())?;
                    labeler.label_path(p)?;
                }

                if entry.path().is_dir() {
                    fs::create_dir_all(dest).map_err(|e| e.to_string())?;
                } else {
                    fs::copy(entry.path(), dest).map_err(|e| e.to_string())?;
                }
                chown(dest, info.uid, info.gid)?;

                // Create equivalence rule in the SELinux policy
                #[cfg(all(target_family = "unix", feature = "selinux"))]
                labeler.setup_equivalence_rule(&hd_path_raw)?;
            }
        }
    }

    // Reset object creation SELinux context to default
    #[cfg(all(target_family = "unix", feature = "selinux"))]
    labeler.set_default_context_for_fs_objects()?;

    let name_rel_path = Path::new(&name);
    // Does the aliases exist
    for alias in info.aliases.iter() {
        // Sanity check the alias.
        // let alias = alias.replace(".", "").replace("/", "").replace("\\", "");
        let alias = alias.trim_start_matches('.').replace(['/', '\\'], "");
        let alias_path_raw = format!("{}{}", home_prefix, alias);
        let alias_path = Path::new(&alias_path_raw);

        // Assert the resulting alias path is consistent and correct.
        if let Some(pp) = alias_path.parent() {
            if pp != home_prefix_path {
                return Err("Invalid home directory alias - not within home_prefix".to_string());
            }
        } else {
            return Err("Invalid/Corrupt alias directory path - no prefix found".to_string());
        }

        if alias_path.symlink_metadata().is_ok() {
            let attr = match fs::symlink_metadata(alias_path) {
                Ok(a) => a,
                Err(e) => {
                    return Err(format!("{:?}", e));
                }
            };

            if attr.file_type().is_symlink() {
                // Probably need to update it.
                if let Err(e) = fs::remove_file(alias_path) {
                    return Err(format!("{:?}", e));
                }
                if let Err(e) = symlink(name_rel_path, alias_path) {
                    return Err(format!("{:?}", e));
                }
            }
        } else {
            // Does not exist. Create.
            if let Err(e) = symlink(name_rel_path, alias_path) {
                return Err(format!("{:?}", e));
            }
        }
    }
    Ok(())
}

fn add_user_to_group(account_id: &str, local_group: &str) {
    match Command::new("gpasswd")
        .arg("-a")
        .arg(account_id)
        .arg(local_group)
        .output()
    {
        Ok(res) => {
            if !res.status.success() {
                error!("Failed adding user to local group {}", local_group);
            }
        }
        Err(e) => {
            error!("Failed adding user to local group {}: {:?}", local_group, e);
        }
    }
}

fn group_members_include(users: &str, account_id: &str) -> bool {
    users.split(',').any(|user| user.trim() == account_id)
}

fn user_in_group(account_id: &str, local_group: &str) -> Result<bool, String> {
    let out = Command::new("getent")
        .arg("group")
        .arg(local_group)
        .output()
        .map_err(|e| format!("Failed to inspect local group {}: {:?}", local_group, e))?;

    match out.status.code() {
        Some(0) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let users = stdout.split(':').nth(3).unwrap_or_default();
            Ok(group_members_include(users, account_id))
        }
        // No such group.
        Some(2) => Ok(false),
        _ => Err(format!("Failed to inspect local group {}", local_group)),
    }
}

fn remove_user_from_group(account_id: &str, local_group: &str) -> Result<(), String> {
    if !user_in_group(account_id, local_group)? {
        trace!(
            "User {} is not a member of {}, nothing to remove",
            account_id,
            local_group
        );
        return Ok(());
    }

    match Command::new("gpasswd")
        .arg("-d")
        .arg(account_id)
        .arg(local_group)
        .output()
    {
        Ok(res) if res.status.success() => Ok(()),
        Ok(_) => Err(format!(
            "Failed removing user from local group {}",
            local_group
        )),
        Err(e) => Err(format!(
            "Failed removing user from local group {}: {:?}",
            local_group, e
        )),
    }
}

fn execute_user_script(account_id: &str, script: &str, access_token: &str) -> i32 {
    match Command::new("sh")
        .arg("-c")
        .arg(script)
        .env("USERNAME", account_id)
        .env("ACCESS_TOKEN", access_token)
        .output()
    {
        Ok(res) => {
            if !res.status.success() {
                let stdout = str::from_utf8(&res.stdout).unwrap_or("Invalid UTF-8 in stdout");
                let stderr = str::from_utf8(&res.stderr).unwrap_or("Invalid UTF-8 in stderr");
                error!(
                    "Failed to execute script '{}':\nstdout: {}\nstderr: {}",
                    script, stdout, stderr
                );
            }

            // If we don't get a status code, make assumptions
            if res.status.success() {
                res.status.code().unwrap_or(0)
            } else {
                res.status.code().unwrap_or(2)
            }
        }
        Err(e) => {
            error!("Failed to execute script '{}': {:?}", script, e);
            // If the script fails to execute at all, we assume this is a hard
            // failure and terminate the authentication attempt.
            2
        }
    }
}

/// Check if a user already has an entry in the given subid file
fn user_has_subid_entry(username: &str, subid_file: &Path) -> bool {
    if let Ok(contents) = fs::read_to_string(subid_file) {
        let prefix = format!("{}:", username);
        contents.lines().any(|line| line.starts_with(&prefix))
    } else {
        false
    }
}

/// Reject account names that could forge additional records in a subid file.
///
/// /etc/subuid and /etc/subgid are newline separated `name:start:count`
/// records. An account name containing the field separator (`:`) or a record
/// separator (any control character, which covers `\n`, `\r` and NUL) would
/// let a single delegation request write arbitrary *additional* delegations,
/// e.g. `padding:1:2\nattacker:0:65536\npad` grants host UID 0 to `attacker`.
/// See GHSA-x259-23ph-65m5.
fn validate_subid_username(username: &str) -> Result<(), String> {
    if username.is_empty() {
        return Err("Refusing subordinate ID entry for an empty account name".to_string());
    }

    if let Some(c) = username.chars().find(|c| *c == ':' || c.is_control()) {
        return Err(format!(
            "Refusing subordinate ID entry for account name {:?}: illegal character {:?}",
            username, c
        ));
    }

    Ok(())
}

fn subid_range_taken(contents: &str, start: u32, count: u32) -> bool {
    contents.lines().any(|line| {
        let mut fields = line.rsplitn(3, ':');
        match (
            fields.next().and_then(|c| c.parse::<u64>().ok()),
            fields.next().and_then(|s| s.parse::<u64>().ok()),
        ) {
            (Some(c), Some(s)) => s < start as u64 + count as u64 && (start as u64) < s + c,
            _ => false,
        }
    })
}

/// Add a subordinate ID entry to /etc/subuid or /etc/subgid
/// Format: username:start:count
fn add_subid_entry(
    username: &str,
    start: u32,
    count: u32,
    (min, max): (u32, u32),
    subid_file: &Path,
) -> Result<(), String> {
    // Never interpolate an unvalidated name into a subid record.
    validate_subid_username(username)?;
    let _lock = lock_subid_file(subid_file)?;

    // Check if user already has an entry
    if user_has_subid_entry(username, subid_file) {
        debug!(
            "User {} already has an entry in {}, skipping",
            username,
            subid_file.display()
        );
        return Ok(());
    }

    // Never overlap a range which another name, e.g. a migrated one, holds.
    let contents = fs::read_to_string(subid_file).unwrap_or_default();
    let step = count.max(1);
    let slots = (max.saturating_sub(min) / step).max(1);
    let mut start = start;
    let mut probes = 0;
    while subid_range_taken(&contents, start, count) {
        probes += 1;
        if probes >= slots {
            return Err("No free subordinate ID range".to_string());
        }
        start = min + (start.saturating_sub(min) / step + 1) % slots * step;
    }

    // Append the new entry
    let entry = format!("{}:{}:{}\n", username, start, count);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(subid_file)
        .map_err(|e| format!("Failed to open {}: {:?}", subid_file.display(), e))?;

    file.write_all(entry.as_bytes())
        .map_err(|e| format!("Failed to write to {}: {:?}", subid_file.display(), e))?;

    info!(
        "Added subordinate ID entry for {} in {}: start={}, count={}",
        username,
        subid_file.display(),
        start,
        count
    );

    Ok(())
}

/// Set up subordinate UID/GID mappings for a user
fn setup_subordinate_ids(
    username: &str,
    start: u32,
    count: u32,
    subid_range: (u32, u32),
) -> Result<(), String> {
    let subuid_path = Path::new("/etc/subuid");
    let subgid_path = Path::new("/etc/subgid");

    // Add entry to /etc/subuid
    add_subid_entry(username, start, count, subid_range, subuid_path)?;

    // Add entry to /etc/subgid (same range)
    add_subid_entry(username, start, count, subid_range, subgid_path)?;

    Ok(())
}

/// Lock a subid file the way shadow does: `<file>.lock` holds the pid of its owner.
struct SubidLock(PathBuf);

impl Drop for SubidLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn lock_subid_file(subid_file: &Path) -> Result<SubidLock, String> {
    let mut path = subid_file.as_os_str().to_owned();
    path.push(".lock");
    let path = PathBuf::from(path);
    for _ in 0..20 {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut lock) => {
                let _ = write!(lock, "{}", std::process::id());
                return Ok(SubidLock(path));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let stale = fs::read_to_string(&path)
                    .ok()
                    .and_then(|pid| pid.trim().parse::<u32>().ok())
                    .is_some_and(|pid| !Path::new(&format!("/proc/{}", pid)).exists());
                if stale {
                    let _ = fs::remove_file(&path);
                } else {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            Err(e) => return Err(format!("Failed to lock {}: {:?}", subid_file.display(), e)),
        }
    }
    Err(format!("Timed out locking {}", subid_file.display()))
}

/// Create the replacement with the SELinux context of the file it replaces (a random file in
/// `/etc` would be `etc_t`, not `shadow_t`). Without a context there is nothing to preserve.
fn new_labeled_temp_file(file: &Path, dir: &Path) -> io::Result<NamedTempFile> {
    use std::os::fd::AsRawFd;
    let fscreate = |label: &[u8]| -> io::Result<()> {
        let attr = OpenOptions::new()
            .write(true)
            .open("/proc/thread-self/attr/fscreate")?;
        match unsafe { libc::write(attr.as_raw_fd(), label.as_ptr().cast(), label.len()) } {
            -1 => Err(io::Error::last_os_error()),
            n if n as usize == label.len() => Ok(()),
            _ => Err(io::Error::other("short fscreate write")),
        }
    };
    let path = CString::new(file.as_os_str().as_bytes())?;
    let mut label = [0u8; 1024];
    let len = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"security.selinux".as_ptr(),
            label.as_mut_ptr().cast(),
            label.len(),
        )
    };
    if len < 0 {
        let e = io::Error::last_os_error();
        // Only an unlabeled or not yet created file establishes that there is no label to keep.
        return match e.raw_os_error() {
            Some(libc::ENODATA | libc::ENOTSUP | libc::ENOENT) => NamedTempFile::new_in(dir),
            _ => Err(e),
        };
    }
    if len == 0 {
        return NamedTempFile::new_in(dir);
    }
    let selinux = Path::new("/sys/fs/selinux/enforce").try_exists();
    new_temp_file_with_context(dir, &label[..len as usize], selinux, fscreate)
}

/// fscreate is thread-local kernel state: set, create and reset it on a thread that ends before
/// the caller resumes, so even a failed reset cannot leak into the daemon's runtime thread.
fn new_temp_file_with_context(
    dir: &Path,
    label: &[u8],
    selinux: io::Result<bool>,
    mut fscreate: impl FnMut(&[u8]) -> io::Result<()> + Send,
) -> io::Result<NamedTempFile> {
    // Without an active SELinux a label is neither enforced nor settable; a failed probe is not
    // evidence of that.
    if !selinux? {
        return NamedTempFile::new_in(dir);
    }
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .spawn_scoped(scope, move || {
                fscreate(label)?;
                let tmp = NamedTempFile::new_in(dir);
                // Reset even if creation failed; a failed reset drops the temporary file.
                fscreate(&[])?;
                tmp
            })?
            .join()
            .map_err(|_| io::Error::other("file context thread panicked"))?
    })
}

/// Replace a file with a fully synced temporary file.
fn replace_file(path: &Path, contents: &[u8], permissions: fs::Permissions) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = dir.unwrap_or(Path::new("."));
    let mut tmp = new_labeled_temp_file(path, dir)?;
    tmp.as_file().set_permissions(permissions)?;
    tmp.write_all(contents)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    // The rename is only durable once the directory entry is synced as well.
    fs::File::open(dir)?.sync_all()
}

/// Move a retired name's subid range to the owner's new name (unless that name already has one).
fn migrate_subid_entry(previous: &str, name: &str, subid_file: &Path) -> Result<(), String> {
    validate_subid_username(name)?;
    let _lock = lock_subid_file(subid_file)?;
    let contents = match fs::read_to_string(subid_file) {
        Ok(contents) => contents,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("Failed to read {}: {:?}", subid_file.display(), e)),
    };
    let previous_prefix = format!("{}:", previous);
    if !contents
        .lines()
        .any(|line| line.starts_with(&previous_prefix))
    {
        return Ok(());
    }

    let name_prefix = format!("{}:", name);
    let mut has_range = contents.lines().any(|line| line.starts_with(&name_prefix));
    let mut migrated = String::with_capacity(contents.len());
    for line in contents.lines() {
        match line.strip_prefix(&previous_prefix) {
            Some(range) if !has_range => {
                migrated.push_str(&name_prefix);
                migrated.push_str(range);
                has_range = true;
            }
            Some(_) => continue,
            None => migrated.push_str(line),
        }
        migrated.push('\n');
    }

    fs::metadata(subid_file)
        .and_then(|meta| replace_file(subid_file, migrated.as_bytes(), meta.permissions()))
        .map_err(|e| format!("Failed to write to {}: {:?}", subid_file.display(), e))?;
    info!(
        "Moved subordinate ID entry of {} to {} in {}",
        previous,
        name,
        subid_file.display()
    );
    Ok(())
}

/// Give `name` the range reserved for its owner and park a stale holder's range under that
/// holder's reservation. The owner's reservation stays as the marker, so repeating it is a no-op.
fn reclaim_subid_range(
    owner_keys: &[String],
    name: &str,
    evicted: &[String],
    subid_file: &Path,
) -> Result<(), String> {
    validate_subid_username(name)?;
    let _lock = lock_subid_file(subid_file)?;
    let contents = match fs::read_to_string(subid_file) {
        Ok(contents) => contents,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("Failed to read {}: {:?}", subid_file.display(), e)),
    };
    let current = format!("{}:", name);
    let holder = evicted
        .first()
        .map(|old| format!("{}:", reserved_subid_name(old)));
    let restored = owner_keys.iter().find_map(|key| {
        let own = format!("{}:", reserved_subid_name(key));
        contents.lines().find_map(|line| line.strip_prefix(&own))
    });
    let mut can_park = holder
        .as_ref()
        .is_some_and(|h| !contents.lines().any(|line| line.starts_with(h)));
    let (mut out, mut changed, mut has_name) = (String::new(), false, false);
    for line in contents.lines() {
        match (line.strip_prefix(&current), &holder) {
            (Some(range), Some(h)) if Some(range) != restored => {
                changed = true;
                if can_park {
                    out.push_str(&format!("{}{}\n", h, range));
                    can_park = false;
                }
            }
            (name_row, _) => {
                has_name |= name_row.is_some();
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    if let (Some(range), false) = (restored, has_name) {
        out.push_str(&format!("{}{}\n", current, range));
        changed = true;
    }
    if changed {
        fs::metadata(subid_file)
            .and_then(|meta| replace_file(subid_file, out.as_bytes(), meta.permissions()))
            .map_err(|e| format!("Failed to write to {}: {:?}", subid_file.display(), e))?;
    }
    Ok(())
}

fn is_local_passwd_user(name: &str) -> bool {
    let prefix = format!("{}:", name);
    fs::read_to_string("/etc/passwd")
        .map(|passwd| passwd.lines().any(|line| line.starts_with(&prefix)))
        .unwrap_or(false)
}

/// `Local` names were /etc/passwd accounts when claimed, so their subid rows are not Himmelblau's.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum TaskName {
    Himmelblau(String),
    Local { local: String },
}

impl TaskName {
    fn name(&self) -> &str {
        match self {
            TaskName::Himmelblau(name) | TaskName::Local { local: name } => name,
        }
    }

    fn is_local(&self) -> bool {
        matches!(self, TaskName::Local { .. })
    }
}

/// Remember the owner's last local name (`local`: an /etc/passwd account). `retire` gets the
/// previous name and its `local` flag (if it changed and nobody else took it) and the stale holders
/// of `name` with Himmelblau-owned rows; the name is only recorded if it succeeds.
fn claim_local_task_name(
    state: &Path,
    owner: &LocalTaskOwner,
    name: &str,
    local: bool,
    retire: impl FnOnce(Option<(&str, bool)>, &[String]) -> Result<(), String>,
) -> Result<(), String> {
    let mut names: HashMap<String, TaskName> = match fs::read(state) {
        Ok(data) => serde_json::from_slice(&data)
            .map_err(|e| format!("Invalid local task state in {}: {}", state.display(), e))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => HashMap::new(),
        Err(e) => return Err(format!("Failed to read {}: {}", state.display(), e)),
    };
    let mut nil_tenant = owner.clone();
    nil_tenant.tenant_id = None;
    let legacy = owner
        .tenant_id
        .and_then(|_| names.remove(&nil_tenant.key()));
    let migrated = legacy.is_some();
    let owner = owner.key();
    let previous = names.remove(&owner).or(legacy);
    // An unchanged name keeps the provenance it was first claimed with.
    let local = match &previous {
        Some(previous) if previous.name() == name => previous.is_local(),
        _ => local,
    };
    let record = name.to_string();
    let record = if local {
        TaskName::Local { local: record }
    } else {
        TaskName::Himmelblau(record)
    };
    names.insert(owner.clone(), record);
    // Rows of a name that was and still is a local account stay with that account.
    let evicted: Vec<String> = names
        .iter()
        .filter(|(holder, held)| **holder != owner && held.name() == name)
        .filter(|(_, held)| !(local && held.is_local()))
        .map(|(holder, _)| holder.clone())
        .collect();
    let count = names.len();
    names.retain(|holder, held| *holder == owner || held.name() != name);
    if previous.as_ref().map(TaskName::name) == Some(name) && names.len() == count && !migrated {
        return Ok(());
    }
    let previous =
        previous.filter(|p| p.name() != name && !names.values().any(|h| h.name() == p.name()));
    retire(
        previous.as_ref().map(|p| (p.name(), p.is_local())),
        &evicted,
    )?;

    serde_json::to_vec(&names)
        .map_err(io::Error::other)
        .and_then(|data| replace_file(state, &data, fs::Permissions::from_mode(0o600)))
        .map_err(|e| {
            format!(
                "Failed to record local task name in {}: {}",
                state.display(),
                e
            )
        })
}

// This cannot be a portable SAM name or a UPN, so another login cannot claim the reservation.
fn reserved_subid_name(owner_key: &str) -> String {
    format!("himmelblau-retired/{}", owner_key)
}

/// Retire the previous name's grants when an owner's local name changes.
fn retire_previous_local_name(
    owner: &LocalTaskOwner,
    name: &str,
    local_groups: &[String],
    local_sudo_group: &str,
    mapped_local: Option<&str>,
) -> Result<(), String> {
    let state = Path::new(LOCAL_TASK_NAMES_CACHE);
    let local = is_local_passwd_user(name);
    // The owner's range may still be parked under its key from before its tenant was known.
    let nil_tenant = LocalTaskOwner {
        tenant_id: None,
        ..owner.clone()
    };
    let owner_keys = [owner.key(), nil_tenant.key()];
    claim_local_task_name(state, owner, name, local, |previous, evicted| {
        let subid_files = [Path::new("/etc/subuid"), Path::new("/etc/subgid")];
        if !local || !evicted.is_empty() {
            // A stale holder keeps its range under its own key, so the new owner gets a fresh one,
            // and an evicted owner returning under another name gets its reserved range back.
            for subid_file in subid_files {
                reclaim_subid_range(&owner_keys, name, evicted, subid_file)?;
            }
        }
        let Some((previous, previous_local)) = previous else {
            return Ok(());
        };

        debug!("Retiring local name {} in favor of {}", previous, name);
        for group in local_groups
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(local_sudo_group))
        {
            remove_user_from_group(previous, group)?;
        }

        // Rows tracked for this owner move on even if a local account took the name since; only a
        // still existing account claimed as local, or the owner's user-map account, keeps them.
        if !(previous_local && is_local_passwd_user(previous)) && mapped_local != Some(previous) {
            for subid_file in subid_files {
                migrate_subid_entry(previous, name, subid_file)?;
            }
        }
        Ok(())
    })
}

async fn set_accountsservice_icon(account_id: &str, icon_path: &Path) -> zbus::Result<()> {
    let connection = Connection::system().await?;
    let accounts = AccountsServiceProxy::new(&connection).await?;
    let user_path = match accounts.find_user_by_name(account_id).await {
        Ok(path) => path,
        Err(err) => {
            debug!(
                ?err,
                account_id, "AccountsService FindUserByName failed; falling back to CacheUser"
            );
            accounts.cache_user(account_id).await?
        }
    };
    let user = AccountsServiceUserProxy::builder(&connection)
        .path(user_path)
        .build()
        .await?;

    user.set_icon_file(icon_path.to_string_lossy().as_ref())
        .await
}

fn create_profile_photo_temp_file(icons_dir: &Path) -> io::Result<NamedTempFile> {
    let file = NamedTempFile::new_in(icons_dir)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

fn resolve_profile_photo_account_id(cfg: &HimmelblauConfig, upn: &str) -> String {
    let user_map = UserMap::new(&cfg.get_user_map_file());
    user_map
        .get_local_from_upn(&upn.to_lowercase())
        .unwrap_or_else(|| cfg.map_upn_to_name(upn))
}

#[cfg(test)]
fn profile_photo_task_response(outcome: Result<(), String>) -> TaskResponse {
    match outcome {
        Ok(()) => TaskResponse::Success(0),
        Err(e) => TaskResponse::Error(e),
    }
}

async fn load_profile_photo(
    cfg: &HimmelblauConfig,
    upn: &str,
    access_token: &str,
) -> Result<(), String> {
    let icons_dir = Path::new("/var/lib/AccountsService/icons/");
    if !icons_dir.exists() {
        return Err(format!(
            "Profile photo directory '{}' doesn't exist",
            icons_dir.display()
        ));
    }

    let domain = split_username(upn)
        .map(|(_, domain)| domain)
        .ok_or_else(|| format!("Couldn't parse domain from UPN '{upn}'"))?;

    // Resolve mapped UPNs back to the local account that owns the avatar.
    let account_id = resolve_profile_photo_account_id(cfg, upn);

    // Reject invalid account identifiers before resolving them through
    // AccountsService. Stripping characters could select a different user.
    if account_id.is_empty()
        || !account_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-'))
    {
        return Err(format!(
            "Invalid account_id '{account_id}' for profile photo - disallowed characters"
        ));
    }

    let profile_photo = create_profile_photo_temp_file(icons_dir)
        .map_err(|e| format!("Failed creating profile photo: {e:?}"))?;
    let file = profile_photo
        .reopen()
        .map_err(|e| format!("Failed opening profile photo: {e:?}"))?;
    let authority_host = cfg.get_authority_host(domain);
    let tenant_id = cfg.get_tenant_id(domain);
    let graph_url = cfg.get_graph_url(domain);
    let ip_versions = cfg.get_ip_versions();
    let request_timeout = cfg.get_request_timeout();
    let graph = Graph::new(
        &cfg.get_odc_provider(domain),
        domain,
        Some(&authority_host),
        tenant_id.as_deref(),
        graph_url.as_deref(),
        Duration::from_secs(request_timeout),
        &ip_versions,
    )
    .await
    .map_err(|e| format!("Failed creating Graph client: {e:?}"))?;
    graph
        .fetch_user_profile_photo(access_token, file)
        .await
        .map_err(|e| format!("Failed fetching profile photo: {e:?}"))?;
    set_accountsservice_icon(&account_id, profile_photo.path())
        .await
        .map_err(|e| format!("Failed updating AccountsService profile photo: {e:?}"))?;
    Ok(())
}

fn store_tgt(tgt: &KerberosCredentials, uid: uid_t, gid: uid_t) -> Result<(), String> {
    // Usually default_ccache_name in /etc/krb5.conf contains a %{uid} substitution,
    // which will be '0' (root) for the tasks daemon because it runs as root. Force
    // the ccache name.
    // TODO: Add a new himmelblau.conf option to define the ccache name
    let ccname = Some(format!("KEYRING:persistent:{}", uid));

    debug!(?ccname, "Storing kerberos ticket in credential cache");

    let guard = uzers::switch::switch_user_group(uid, gid)
        .map_err(|e| format!("Failed to switch user/group: {}", e))?;

    let mut ccache = match libkrimes::ccache::resolve(ccname.as_deref()) {
        Ok(ccache) => ccache,
        Err(e) => {
            drop(guard);
            let msg = format!("Failed to resolve credential cache {:?}: {:?}", ccname, e);
            return Err(msg);
        }
    };

    match ccache.init(tgt.name(), None) {
        Ok(_) => (),
        Err(e) => {
            drop(guard);
            let msg = format!("Failed to init credential cache {:?}: {:?}", ccname, e);
            return Err(msg);
        }
    }

    match ccache.store(tgt) {
        Ok(_) => (),
        Err(e) => {
            drop(guard);
            let msg = format!("Failed to store TGT in credential cache: {:?}", e);
            return Err(msg);
        }
    }

    drop(guard);

    Ok(())
}

fn write_kerberos_config_snippet(
    top_level_names: Option<String>,
    tenant_id: &str,
    authority_host: &str,
) -> Result<(), String> {
    write_kerberos_config_snippet_to(
        top_level_names,
        tenant_id,
        authority_host,
        Path::new(DEFAULT_KERBEROS_CONF_DIR),
    )
}

fn write_kerberos_config_snippet_to(
    top_level_names: Option<String>,
    tenant_id: &str,
    authority_host: &str,
    krb_conf_dir: &Path,
) -> Result<(), String> {
    if tenant_id.is_empty() {
        return Err("Failed to write Kerberos config snippet, empty tenant_id".to_string());
    }

    // The tenant_id will be used in a file path. Validate it is really an UUID.
    uuid::Uuid::try_parse(tenant_id).map_err(|x| format!("Failed to validate tenant ID: {x}"))?;

    trace!(?krb_conf_dir, "Check kerberos config dir exists");
    match krb_conf_dir.try_exists() {
        Ok(true) if krb_conf_dir.is_dir() => Ok(()),
        Ok(true) => Err(format!("Path {krb_conf_dir:?} is not a directory")),
        Ok(false) => fs::create_dir_all(krb_conf_dir)
            .map_err(|e| format!("Failed to create {krb_conf_dir:?}: {e}")),
        Err(e) => Err(format!("Failed to check if {krb_conf_dir:?} exists: {e}")),
    }?;

    let krb_snippet = krb_conf_dir.join(format!("himmelblau_{tenant_id}.conf"));
    let mut file = match OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o644)
        .open(&krb_snippet)
    {
        Ok(file) => file,
        Err(e) => return Err(format!("Failed to open {krb_snippet:?}: {e}")),
    };

    let libdefs = "[libdefaults]\n\tdns_canonicalize_hostname = false\n";
    file.write_all(libdefs.as_bytes())
        .map_err(|e| format!("Failed to write to {krb_snippet:?}: {e}"))?;

    let realms = format!(
        "[realms]\n\tKERBEROS.MICROSOFTONLINE.COM = {{\n\t\tkdc = https://{authority_host}/{tenant_id}/kerberos\n\t}}\n"
    );
    file.write_all(realms.as_bytes())
        .map_err(|e| format!("Failed to write to {krb_snippet:?}: {e}"))?;

    let domain_realms: Vec<String> = match top_level_names {
        Some(s) => s
            .split(",")
            .map(|e| e.trim())
            .filter(|e| !e.contains(":"))
            .map(|x| format!("\t{x} = KERBEROS.MICROSOFTONLINE.COM"))
            .collect(),
        None => vec![],
    };
    let domain_realms = format!("[domain_realm]\n{}\n", domain_realms.join("\n"));
    file.write_all(domain_realms.as_bytes())
        .map_err(|e| format!("Failed to write to {krb_snippet:?}: {e}"))?;

    Ok(())
}

async fn handle_tasks(stream: UnixStream, cfg: &HimmelblauConfig) {
    let mut reqs = Framed::new(stream, TaskCodec::new());

    loop {
        let next_req = reqs.next().await;
        let span = span!(Level::INFO, "TaskRequest");
        let _ = span.enter();
        match next_req {
            Some(Ok(TaskRequest::HomeDirectory(info))) => {
                debug!("Received task -> HomeDirectory(...)");
                let domain = split_username(&info.name).map(|(_, domain)| domain);

                let resp = match create_home_directory(
                    &info,
                    &cfg.get_home_prefix(domain),
                    cfg.get_use_etc_skel(),
                    cfg.get_selinux(),
                ) {
                    Ok(()) => TaskResponse::Success(0),
                    Err(msg) => TaskResponse::Error(msg),
                };

                // Now send a result.
                if let Err(e) = reqs.send(resp).await {
                    error!("Error -> {:?}", e);
                    return;
                }
                // All good, loop.
            }
            Some(Ok(TaskRequest::LocalGroups(mut account_id, is_sudoer, owner))) => {
                debug!("Received task -> LocalGroups(...)",);
                account_id = cfg.map_upn_to_name(&account_id);

                let local_groups = cfg.get_local_groups();
                let local_sudo_group = cfg.get_local_sudo_group();
                let mapped_local = UserMap::new(&cfg.get_user_map_file())
                    .get_local_from_upn(&owner.upn.to_lowercase());
                if let Err(msg) = retire_previous_local_name(
                    &owner,
                    &account_id,
                    &local_groups,
                    &local_sudo_group,
                    mapped_local.as_deref(),
                ) {
                    error!("Failed to retire the previous local name: {}", msg);
                    if let Err(e) = reqs.send(TaskResponse::Error(msg)).await {
                        error!("Error -> {:?}", e);
                        return;
                    }
                    continue;
                }

                for local_group in &local_groups {
                    add_user_to_group(&account_id, local_group);
                }

                // Only run sudo groups if local_groups does not contain local_sudo_group (default = sudo)
                if !local_groups.contains(&local_sudo_group) {
                    if is_sudoer {
                        add_user_to_group(&account_id, &local_sudo_group);
                    } else {
                        if let Err(e) = remove_user_from_group(&account_id, &local_sudo_group) {
                            error!("{}", e);
                        }
                    }
                }

                // Always indicate success here
                if let Err(e) = reqs.send(TaskResponse::Success(0)).await {
                    error!("Error -> {:?}", e);
                    return;
                }
            }
            Some(Ok(TaskRequest::LogonScript(account_id, access_token))) => {
                debug!("Received task -> LogonScript(...)");
                let mut status = 0;
                if let Some(script) = cfg.get_logon_script() {
                    status = execute_user_script(&account_id, &script, &access_token);
                }

                // Indicate the status response
                if let Err(e) = reqs.send(TaskResponse::Success(status)).await {
                    error!("Error -> {:?}", e);
                    return;
                }
            }
            Some(Ok(TaskRequest::KerberosConfig(top_level_names, tenant_id, authority_host))) => {
                debug!("Received task -> KerberosConfig(...)");

                let response = match (tenant_id, authority_host) {
                    (Some(t), Some(host)) => match write_kerberos_config_snippet(top_level_names, &t, &host) {
                        Ok(_) => TaskResponse::Success(0),
                        Err(msg) => TaskResponse::Error(msg),
                    },
                    _ => TaskResponse::Error(
                        "Failed to write Kerberos config snippet, missing tenant_id or authority_host".to_string(),
                    ),
                };

                if let Err(e) = reqs.send(response).await {
                    error!("Error -> {:?}", e);
                    return;
                }
            }
            Some(Ok(TaskRequest::KerberosTGTs(uid, gid, tgt_cloud, tgt_ad))) => {
                debug!("Received task -> KerberosTGTs({}, {}, ...)", uid, gid);

                let cloud_ret = if let Some(tgt_cloud) = tgt_cloud {
                    store_tgt(tgt_cloud.as_ref(), uid, gid)
                } else {
                    Ok(())
                };

                let ad_ret = if let Some(tgt_ad) = tgt_ad {
                    store_tgt(tgt_ad.as_ref(), uid, gid)
                } else {
                    Ok(())
                };

                let response = match cloud_ret.and(ad_ret) {
                    Ok(_) => TaskResponse::Success(0),
                    Err(msg) => TaskResponse::Error(msg),
                };
                if let Err(e) = reqs.send(response).await {
                    error!("Error -> {:?}", e);
                    return;
                }
            }
            Some(Ok(TaskRequest::LoadProfilePhoto(account_id, access_token))) => {
                debug!("Received task -> LoadProfilePhoto(...)");
                // Reply before Graph runs. This socket also serves HomeDirectory,
                // and that request gives up after one second.
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    match load_profile_photo(&cfg, &account_id, &access_token).await {
                        Ok(()) => info!("Fetching user profile picture succeeded"),
                        Err(e) => error!("{e}"),
                    }
                });
                if let Err(e) = reqs.send(TaskResponse::Success(0)).await {
                    error!("Error -> {:?}", e);
                    return;
                }
            }
            Some(Ok(TaskRequest::ApplyPolicy(
                intune_device_id,
                account_id,
                graph_token,
                intune_token,
                iwservice_token,
            ))) => {
                debug!("Received task -> ApplyPolicy(...)");
                let intune_device_id = match intune_device_id {
                    Some(id) => id,
                    None => {
                        debug!("Device not enrolled in Intune, skipping");
                        if let Err(e) = reqs.send(TaskResponse::Success(0)).await {
                            error!("Error -> {:?}", e);
                            return;
                        }
                        continue;
                    }
                };
                let noncompliant_rules = match apply_intune_policy(
                    &intune_device_id,
                    cfg,
                    &account_id,
                    &graph_token,
                    &intune_token,
                    &iwservice_token,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Failed to apply Intune policies: {:?}", e);
                        if let Err(e) = reqs
                            .send(TaskResponse::Error(format!(
                                "Failed to apply Intune policies: {:?}",
                                e
                            )))
                            .await
                        {
                            error!("Error -> {:?}", e);
                            return;
                        }
                        continue;
                    }
                };

                let response = if noncompliant_rules.is_empty() {
                    debug!("tasks: policy applied, device is compliant");
                    TaskResponse::Success(0)
                } else {
                    debug!(
                        count = noncompliant_rules.len(),
                        "tasks: policy applied, device is non-compliant"
                    );
                    TaskResponse::NonCompliant(noncompliant_rules)
                };

                if let Err(e) = reqs.send(response).await {
                    error!("Error -> {:?}", e);
                    return;
                }
            }
            Some(Ok(TaskRequest::SubordinateIds(username, start, count))) => {
                debug!(
                    "Received task -> SubordinateIds({:?}, {}, {})",
                    username, start, count
                );

                let range = cfg.get_subid_range();
                let resp = match setup_subordinate_ids(&username, start, count, range) {
                    Ok(()) => TaskResponse::Success(0),
                    Err(msg) => {
                        error!(
                            "Failed to setup subordinate IDs for {:?}: {}",
                            username, msg
                        );
                        TaskResponse::Error(msg)
                    }
                };

                if let Err(e) = reqs.send(resp).await {
                    error!("Error -> {:?}", e);
                    return;
                }
            }
            Some(Err(e)) => {
                error!("Error -> {:?}", e);
                return;
            }
            None => {
                debug!("Task connection closed");
                return;
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // let cuid = get_current_uid();
    // let cgid = get_current_gid();
    // We only need to check effective id
    let ceuid = get_effective_uid();
    let cegid = get_effective_gid();
    let systemd_booted = sd_notify::booted().unwrap_or(false);

    let config_path = Path::new(DEFAULT_CONFIG_PATH);
    let config_path_str = match config_path.to_str() {
        Some(cps) => cps,
        None => {
            error!("Unable to turn config_path to str");
            return ExitCode::FAILURE;
        }
    };

    let cfg = match HimmelblauConfig::new(Some(config_path_str)) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse {}: {}", config_path_str, e);
            return ExitCode::FAILURE;
        }
    };

    if cfg.get_debug() {
        std::env::set_var("RUST_LOG", "debug");
    }

    #[allow(clippy::expect_used)]
    tracing_forest::worker_task()
        .set_global(true)
        // Fall back to stderr
        .map_sender(|sender| sender.or_stderr())
        .build_on(|subscriber| {
            subscriber.with(
                EnvFilter::try_from_default_env()
                    .or_else(|_| EnvFilter::try_new("info"))
                    .expect("Failed to init envfilter"),
            )
        })
        .on(async {
            let span = span!(Level::INFO, "Task daemon initialization");
            let _enter = span.enter();

            if ceuid != 0 || cegid != 0 {
                error!("Refusing to run - this process *MUST* operate as root.");
                return ExitCode::FAILURE;
            }

            let task_sock_path = cfg.get_task_socket_path();
            debug!("Attempting to use {} ...", task_sock_path);

            let (broadcast_tx, mut broadcast_rx) = broadcast::channel(4);
            let mut d_broadcast_rx = broadcast_tx.subscribe();

            let server = tokio::spawn(async move {
                loop {
                    info!("Attempting to connect to himmelblaud ...");

                    tokio::select! {
                        _ = broadcast_rx.recv() => {
                            break;
                        }
                        connect_res = UnixStream::connect(&task_sock_path) => {
                            match connect_res {
                                Ok(stream) => {
                                    info!("Found himmelblaud, waiting for tasks ...");
                                    // Yep! Now let the main handler do it's job.
                                    // If it returns (dc, etc, then we loop and try again).
                                    tokio::select! {
                                        _ = d_broadcast_rx.recv() => {
                                            break;
                                        }
                                        _ = handle_tasks(stream, &cfg) => {
                                            continue;
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!("\\---> {:?}", e);
                                    error!("Unable to find himmelblaud, sleeping ...");
                                    // Back off.
                                    time::sleep(Duration::from_millis(5000)).await;
                                }
                            }
                        }
                    }
                }
            });

            info!("Server started ...");

            drop(_enter);

            if systemd_booted {
                if let Ok(monotonic_usec) = sd_notify::NotifyState::monotonic_usec_now() {
                    let _ = sd_notify::notify(&[NotifyState::Ready, monotonic_usec]);
                }
            }

            // Ping the systemd watchdog at half the configured WatchdogSec interval.
            let mut watchdog_interval = if systemd_booted {
                std::env::var("WATCHDOG_USEC")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|usec| time::interval(Duration::from_micros(usec / 2)))
            } else {
                None
            };

            loop {
                tokio::select! {
                    Ok(()) = tokio::signal::ctrl_c() => {
                        break
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::terminate();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        break
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::alarm();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::hangup();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::user_defined1();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }

                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::user_defined2();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    _ = async {
                        match watchdog_interval.as_mut() {
                            Some(interval) => interval.tick().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        let _ = sd_notify::notify(&[NotifyState::Watchdog]);
                    }
                }
            }

            info!("Signal received, shutting down");
            if systemd_booted {
                if let Ok(monotonic_usec) = sd_notify::NotifyState::monotonic_usec_now() {
                    let _ = sd_notify::notify(&[NotifyState::Stopping, monotonic_usec]);
                }
            }

            // Send a broadcast that we are done.
            if let Err(e) = broadcast_tx.send(true) {
                error!("Unable to shutdown workers {:?}", e);
            }

            let _ = server.await;
            ExitCode::SUCCESS
        })
        .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// The exact payload from GHSA-x259-23ph-65m5.
    const ADVISORY_PAYLOAD: &str = "padding:100000:65536\nattacker:0:65536\npadding";
    const TENANT_ID: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn validate_subid_username_accepts_legitimate_names() {
        for username in [
            "user",
            "user@example.com",
            "first.last-1_2@contoso.com",
            "user+alias@example.com",
            "jos\u{e9}@example.com",
        ] {
            assert!(
                validate_subid_username(username).is_ok(),
                "expected {:?} to be accepted",
                username
            );
        }
    }

    fn task_owner(upn: &str) -> LocalTaskOwner {
        LocalTaskOwner {
            object_id: uuid::Uuid::new_v5(
                &uuid::Uuid::NAMESPACE_DNS,
                upn.to_lowercase().as_bytes(),
            ),
            tenant_id: Some(uuid::Uuid::parse_str(TENANT_ID).unwrap()),
            upn: upn.to_string(),
        }
    }

    fn record_local_task_name(state: &Path, owner: &str, name: &str) -> Option<String> {
        let mut retired = None;
        claim_local_task_name(state, &task_owner(owner), name, false, |previous, _| {
            retired = previous.map(|(previous, _)| previous.to_string());
            Ok(())
        })
        .unwrap();
        retired
    }

    #[test]
    fn group_membership_matches_newline_terminated_last_member() {
        let users = "alice,bob\n";

        assert!(group_members_include(users, "bob"));
    }

    #[test]
    fn changed_local_task_name_is_retired_unless_taken_over() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let state = tmpdir.path().join("local-task-names.json");

        assert_eq!(record_local_task_name(&state, "A@example.com", "bob"), None);
        assert_eq!(record_local_task_name(&state, "a@example.com", "bob"), None);
        assert_eq!(
            record_local_task_name(&state, "a@example.com", "robert"),
            Some("bob".to_string())
        );

        assert_eq!(
            record_local_task_name(&state, "b@example.com", "robert"),
            None
        );
        assert_eq!(record_local_task_name(&state, "a@example.com", "bob"), None);
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn claiming_a_name_transfers_it_from_a_stale_holder() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let state = tmpdir.path().join("local-task-names.json");

        assert_eq!(record_local_task_name(&state, "a@example.com", "bob"), None);
        assert_eq!(record_local_task_name(&state, "b@example.com", "bob"), None);
        assert_eq!(
            record_local_task_name(&state, "b@example.com", "robert"),
            Some("bob".to_string())
        );
    }

    #[test]
    fn stale_holders_are_reported_and_failed_retirements_are_retried() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let state = tmpdir.path().join("local-task-names.json");

        assert_eq!(record_local_task_name(&state, "a@example.com", "bob"), None);
        let mut evicted = vec![];
        claim_local_task_name(
            &state,
            &task_owner("b@example.com"),
            "bob",
            false,
            |_, stale| {
                evicted = stale.to_vec();
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(evicted, [task_owner("a@example.com").key()]);

        let failed = claim_local_task_name(
            &state,
            &task_owner("b@example.com"),
            "robert",
            false,
            |_, _| Err("x".into()),
        );
        assert!(failed.is_err());
        assert_eq!(
            record_local_task_name(&state, "b@example.com", "robert"),
            Some("bob".to_string())
        );
    }

    #[test]
    fn upn_rename_keeps_the_same_local_task_owner_and_subid_range() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = tmpdir.path().join("local-task-names.json");
        let subuid = tmpdir.path().join("subuid");
        let owner = task_owner("a@example.com");
        claim_local_task_name(&state, &owner, "bob", false, |_, _| Ok(())).unwrap();
        fs::write(&subuid, "bob:100000:65536\n").unwrap();
        let before = fs::read(&state).unwrap();
        let renamed = LocalTaskOwner {
            upn: "renamed@example.com".into(),
            ..owner.clone()
        };

        claim_local_task_name(&state, &renamed, "bob", false, |_, _| {
            panic!("an unchanged local account must not be retired after a UPN rename")
        })
        .unwrap();
        add_subid_entry("bob", 200000, 65536, (100000, 1000000), &subuid).unwrap();
        assert_eq!(fs::read(&state).unwrap(), before);
        assert_eq!(fs::read_to_string(&subuid).unwrap(), "bob:100000:65536\n");

        for replacement in [
            LocalTaskOwner {
                object_id: uuid::Uuid::new_v4(),
                ..renamed.clone()
            },
            LocalTaskOwner {
                tenant_id: Some(uuid::Uuid::new_v4()),
                ..renamed.clone()
            },
        ] {
            let other_state = tmpdir.path().join(replacement.key());
            fs::write(&other_state, &before).unwrap();
            claim_local_task_name(
                &other_state,
                &replacement,
                "bob",
                false,
                |previous, evicted| {
                    assert_eq!(previous, None);
                    assert_eq!(evicted, [owner.key()]);
                    Ok(())
                },
            )
            .unwrap();
        }
    }

    #[test]
    fn legacy_upn_owner_is_parked_instead_of_claimed() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = tmpdir.path().join("local-task-names.json");
        fs::write(&state, br#"{"a@example.com":"bob"}"#).unwrap();
        let owner = task_owner("A@Example.com");
        claim_local_task_name(&state, &owner, "bob", false, |previous, evicted| {
            assert_eq!(previous, None);
            assert_eq!(evicted, ["a@example.com"]);
            Ok(())
        })
        .unwrap();
        let names: HashMap<String, String> =
            serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        assert_eq!(names, HashMap::from([(owner.key(), "bob".into())]));
    }

    #[test]
    fn nil_tenant_owner_is_upgraded_when_the_tenant_becomes_known() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = tmpdir.path().join("local-task-names.json");
        let owner = task_owner("a@example.com");
        let nil_tenant = LocalTaskOwner {
            tenant_id: None,
            ..owner.clone()
        };
        let names = HashMap::from([(nil_tenant.key(), "bob".to_string())]);
        fs::write(&state, serde_json::to_vec(&names).unwrap()).unwrap();

        claim_local_task_name(&state, &owner, "bob", false, |previous, evicted| {
            assert_eq!(previous, None);
            assert!(evicted.is_empty());
            Ok(())
        })
        .unwrap();
        let names: HashMap<String, String> =
            serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        assert_eq!(names, HashMap::from([(owner.key(), "bob".into())]));
    }

    #[test]
    fn unchanged_local_name_keeps_local_provenance() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = tmpdir.path().join("local-task-names.json");
        let owner = task_owner("a@example.com");
        claim_local_task_name(&state, &owner, "bob", true, |_, _| Ok(())).unwrap();

        claim_local_task_name(&state, &owner, "bob", false, |_, _| {
            panic!("an unchanged local account must not be retired")
        })
        .unwrap();

        let names: HashMap<String, TaskName> =
            serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        assert!(matches!(
            names.get(&owner.key()),
            Some(TaskName::Local { local }) if local == "bob"
        ));
    }

    #[test]
    fn nil_tenant_local_owner_upgrade_keeps_local_provenance() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = tmpdir.path().join("local-task-names.json");
        let owner = task_owner("a@example.com");
        let nil_tenant = LocalTaskOwner {
            tenant_id: None,
            ..owner.clone()
        };
        let names = HashMap::from([(
            nil_tenant.key(),
            TaskName::Local {
                local: "bob".to_string(),
            },
        )]);
        fs::write(&state, serde_json::to_vec(&names).unwrap()).unwrap();

        claim_local_task_name(&state, &owner, "bob", false, |previous, evicted| {
            assert_eq!(previous, None);
            assert!(evicted.is_empty());
            Ok(())
        })
        .unwrap();

        let names: HashMap<String, TaskName> =
            serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        assert!(matches!(
            names.get(&owner.key()),
            Some(TaskName::Local { local }) if local == "bob"
        ));
    }

    #[test]
    fn unreadable_or_malformed_local_task_state_aborts_before_retirement() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = tmpdir.path().join("local-task-names.json");
        for contents in [b"{".as_slice(), b"[]", b"null", br#"{"a":42}"#] {
            fs::write(&state, contents).unwrap();
            assert!(claim_local_task_name(
                &state,
                &task_owner("a@example.com"),
                "bob",
                false,
                |_, _| { panic!("invalid state must abort before retirement") }
            )
            .is_err());
            assert_eq!(fs::read(&state).unwrap(), contents);
        }
        // A directory gives a deterministic read error even when tests run as root.
        assert!(claim_local_task_name(
            tmpdir.path(),
            &task_owner("a@example.com"),
            "bob",
            false,
            |_, _| { panic!("unreadable state must abort before retirement") }
        )
        .is_err());
    }

    #[test]
    fn local_task_state_is_replaced_atomically() {
        use std::io::Read;
        let tmpdir = tempfile::tempdir().unwrap();
        let state = tmpdir.path().join("local-task-names.json");
        record_local_task_name(&state, "a@example.com", "bob");
        let before = fs::read(&state).unwrap();
        let mut old_file = fs::File::open(&state).unwrap();
        record_local_task_name(&state, "a@example.com", "robert");
        let mut old_contents = Vec::new();
        old_file.read_to_end(&mut old_contents).unwrap();
        assert_eq!(old_contents, before);
        let names: HashMap<String, String> =
            serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        assert_eq!(names[&task_owner("a@example.com").key()], "robert");
        assert_eq!(fs::read_dir(tmpdir.path()).unwrap().count(), 1);
    }

    #[test]
    fn file_context_failures_leave_neither_a_file_nor_the_context_behind() {
        thread_local! {
            static CONTEXT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        }
        let tmpdir = tempfile::tempdir().unwrap();
        let missing = tmpdir.path().join("missing");
        let caller = std::thread::current().id();
        for (dir, fail_set, fail_reset) in [
            (tmpdir.path(), true, false),
            (missing.as_path(), false, false),
            (tmpdir.path(), false, true),
        ] {
            let mut calls = Vec::new();
            let result = new_temp_file_with_context(dir, b"shadow_t", Ok(true), |label| {
                assert_ne!(std::thread::current().id(), caller);
                calls.push(label.to_vec());
                if (fail_set && !label.is_empty()) || (fail_reset && label.is_empty()) {
                    return Err(io::Error::from_raw_os_error(libc::EACCES));
                }
                CONTEXT.set(!label.is_empty());
                Ok(())
            });
            assert!(result.is_err());
            // A context that was set is always reset, and never on the calling thread.
            assert_eq!(calls.len(), if fail_set { 1 } else { 2 });
            assert!(!CONTEXT.get());
            assert_eq!(fs::read_dir(tmpdir.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn selinux_probe_error_is_not_taken_for_disabled_selinux() {
        let tmpdir = tempfile::tempdir().unwrap();
        // Present: labeled; absent: SELinux disabled, so a plain file; probe error: no file.
        for (selinux, created, labeled) in [
            (Ok(true), true, true),
            (Ok(false), true, false),
            (Err(io::ErrorKind::PermissionDenied.into()), false, false),
        ] {
            let mut calls = 0;
            let result = new_temp_file_with_context(tmpdir.path(), b"shadow_t", selinux, |_| {
                calls += 1;
                Ok(())
            });
            assert_eq!(result.is_ok(), created);
            assert_eq!(calls > 0, labeled);
        }
    }

    #[test]
    fn unreadable_file_label_does_not_create_a_replacement() {
        let tmpdir = tempfile::tempdir().unwrap();
        let file = tmpdir.path().join("file");
        fs::write(&file, "").unwrap();
        // A path below a regular file fails with ENOTDIR, not with a missing label.
        assert!(new_labeled_temp_file(&file.join("x"), tmpdir.path()).is_err());
        assert_eq!(fs::read_dir(tmpdir.path()).unwrap().count(), 1);
    }

    #[test]
    fn add_subid_entry_wraps_inside_the_range() {
        let subid_file = tempfile::NamedTempFile::new().expect("failed to create temp subid file");
        let path = subid_file.path();
        fs::write(path, "robert:165536:65536\n").unwrap();

        assert!(add_subid_entry("bob", 165536, 65536, (100000, 231072), path).is_ok());
        assert!(fs::read_to_string(path)
            .unwrap()
            .ends_with("bob:100000:65536\n"));
    }

    #[test]
    fn evicted_subid_owner_can_reclaim_its_reserved_range() {
        let tmpdir = tempfile::tempdir().unwrap();
        let subuid = tmpdir.path().join("subuid");
        let reserved = reserved_subid_name(&task_owner("a@example.com").key());
        fs::write(&subuid, "bob:100000:65536\n").unwrap();
        migrate_subid_entry("bob", &reserved, &subuid).unwrap();
        add_subid_entry("bob", 100000, 65536, (100000, 1000000), &subuid).unwrap();
        migrate_subid_entry(&reserved, "robert", &subuid).unwrap();
        let contents = fs::read_to_string(&subuid).unwrap();
        assert_eq!(contents, "robert:100000:65536\nbob:165536:65536\n");
    }

    #[test]
    fn reclaiming_a_reserved_range_is_repeatable() {
        let tmpdir = tempfile::tempdir().unwrap();
        let subuid = tmpdir.path().join("subuid");
        let (a, b) = (
            task_owner("a@example.com").key(),
            task_owner("b@example.com").key(),
        );
        let (ra, rb) = (reserved_subid_name(&a), reserved_subid_name(&b));
        fs::write(&subuid, format!("bob:200000:65536\n{}:100000:65536\n", rb)).unwrap();

        for _ in 0..2 {
            reclaim_subid_range(&[b.clone()], "bob", &[a.clone()], &subuid).unwrap();
            assert_eq!(
                fs::read_to_string(&subuid).unwrap(),
                format!("{ra}:200000:65536\n{rb}:100000:65536\nbob:100000:65536\n")
            );
        }
    }

    #[test]
    fn retired_subid_range_moves_to_the_new_name() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let subuid = tmpdir.path().join("subuid");

        fs::write(&subuid, "root:1:2\nbob:100000:65536\n").unwrap();
        migrate_subid_entry("bob", "robert", &subuid).unwrap();
        assert_eq!(
            fs::read_to_string(&subuid).unwrap(),
            "root:1:2\nrobert:100000:65536\n"
        );

        fs::write(&subuid, "bob:100000:65536\nrobert:200000:65536\n").unwrap();
        migrate_subid_entry("bob", "robert", &subuid).unwrap();
        assert_eq!(
            fs::read_to_string(&subuid).unwrap(),
            "robert:200000:65536\n"
        );

        fs::write(&subuid, "bobby:1:2\n").unwrap();
        migrate_subid_entry("bob", "robert", &subuid).unwrap();
        assert_eq!(fs::read_to_string(&subuid).unwrap(), "bobby:1:2\n");

        assert!(migrate_subid_entry("bob", "x:0:1", &subuid).is_err());
        migrate_subid_entry("bob", "robert", &tmpdir.path().join("missing")).unwrap();
    }

    #[test]
    fn validate_subid_username_rejects_record_forging_names() {
        for username in [
            "",
            "attacker:0:65536",
            ADVISORY_PAYLOAD,
            "victim\nroot",
            "victim\r\nroot",
            "victim\0root",
        ] {
            assert!(
                validate_subid_username(username).is_err(),
                "expected {:?} to be rejected",
                username
            );
        }
    }

    #[test]
    fn add_subid_entry_rejects_payload_and_leaves_file_untouched() {
        let subid_file = tempfile::NamedTempFile::new().expect("failed to create temp subid file");
        let path = subid_file.path();

        let before = fs::read(path).unwrap_or_default();

        assert!(add_subid_entry(ADVISORY_PAYLOAD, 100000, 65536, (0, u32::MAX), path).is_err());

        let after = fs::read(path).unwrap_or_default();
        assert_eq!(before, after, "subid file must not be modified");
    }

    #[test]
    fn add_subid_entry_appends_a_single_record_for_a_valid_name() {
        let subid_file = tempfile::NamedTempFile::new().expect("failed to create temp subid file");
        let path = subid_file.path();

        assert!(
            add_subid_entry("user@example.com", 2100000000, 65536, (0, u32::MAX), path).is_ok()
        );

        let contents = fs::read_to_string(path).unwrap_or_default();
        assert_eq!(contents, "user@example.com:2100000000:65536\n");

        // A second call for the same user must not duplicate the record.
        assert!(
            add_subid_entry("user@example.com", 2100000000, 65536, (0, u32::MAX), path).is_ok()
        );

        let contents = fs::read_to_string(path).unwrap_or_default();
        assert_eq!(contents, "user@example.com:2100000000:65536\n");
    }

    #[test]
    fn add_subid_entry_skips_a_range_held_by_a_migrated_name() {
        let subid_file = tempfile::NamedTempFile::new().expect("failed to create temp subid file");
        let path = subid_file.path();
        fs::write(path, "robert:100000:65536\n").unwrap();

        assert!(add_subid_entry("bob", 100000, 65536, (100000, 150000), path).is_err());
        assert!(add_subid_entry("bob", 100000, 65536, (100000, u32::MAX), path).is_ok());

        let contents = fs::read_to_string(path).unwrap();
        assert_eq!(contents, "robert:100000:65536\nbob:165536:65536\n");
    }

    #[test]
    fn renamed_home_is_moved_and_foreign_home_is_refused() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let prefix = format!("{}/", tmpdir.path().display());
        let uid = fs::metadata(tmpdir.path()).unwrap().uid();
        let gid = fs::metadata(tmpdir.path()).unwrap().gid();
        let info = |name: &str, uid| HomeDirectoryInfo {
            uid,
            gid,
            name: name.to_string(),
            aliases: vec!["alice@contoso.com".to_string()],
        };

        fs::create_dir(tmpdir.path().join("bob")).unwrap();
        symlink("bob", tmpdir.path().join("alice@contoso.com")).unwrap();
        assert!(create_home_directory(&info("robert", uid), &prefix, false, false).is_ok());
        assert!(!tmpdir.path().join("bob").exists());
        assert!(tmpdir.path().join("robert").is_dir());

        assert!(create_home_directory(&info("robert", uid + 1), &prefix, false, false).is_err());
    }

    #[test]
    fn profile_photo_temp_file_is_private() {
        let icons_dir = tempfile::tempdir().expect("failed to create temp icon directory");
        let profile_photo = create_profile_photo_temp_file(icons_dir.path())
            .expect("failed to create profile photo");

        let mode = profile_photo
            .as_file()
            .metadata()
            .expect("failed to read profile photo metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn profile_photo_account_resolution_reloads_user_map() {
        let tempdir = tempfile::tempdir().expect("failed to create temp directory");
        let user_map_path = tempdir.path().join("user-map");
        let config_path = tempdir.path().join("himmelblau.conf");
        fs::write(&user_map_path, "alice:user@example.com\n").expect("failed to write user map");
        fs::write(
            &config_path,
            format!("[global]\nuser_map_file = {}\n", user_map_path.display()),
        )
        .expect("failed to write config");
        let cfg = HimmelblauConfig::new(Some(
            config_path.to_str().expect("config path is not UTF-8"),
        ))
        .expect("failed to parse config");

        assert_eq!(
            resolve_profile_photo_account_id(&cfg, "User@Example.com"),
            "alice"
        );

        fs::write(&user_map_path, "bob:user@example.com\n").expect("failed to update user map");
        assert_eq!(
            resolve_profile_photo_account_id(&cfg, "user@example.com"),
            "bob"
        );
    }

    #[test]
    fn profile_photo_failure_returns_task_error() {
        match profile_photo_task_response(Err("profile photo failed".to_string())) {
            TaskResponse::Error(message) => assert_eq!(message, "profile photo failed"),
            response => panic!("expected task error, got {response:?}"),
        }
    }

    #[test]
    fn write_kerberos_config_snippet_creates_missing_config_dir() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let krb_conf_dir = tmpdir.path().join("krb5.conf.d");

        write_kerberos_config_snippet_to(
            Some(".example.com, example.com, invalid:realm".to_string()),
            TENANT_ID,
            "login.microsoftonline.us",
            &krb_conf_dir,
        )
        .expect("expected kerberos config snippet to be written");

        assert!(krb_conf_dir.is_dir());
        let snippet_path = krb_conf_dir.join(format!("himmelblau_{TENANT_ID}.conf"));
        let contents =
            fs::read_to_string(snippet_path).expect("expected kerberos config snippet to exist");
        assert!(contents.contains("[libdefaults]\n\tdns_canonicalize_hostname = false\n"));
        assert!(contents.contains(&format!(
            "\t\tkdc = https://login.microsoftonline.us/{TENANT_ID}/kerberos"
        )));
        assert!(contents.contains("\t.example.com = KERBEROS.MICROSOFTONLINE.COM"));
        assert!(contents.contains("\texample.com = KERBEROS.MICROSOFTONLINE.COM"));
        assert!(!contents.contains("invalid:realm = KERBEROS.MICROSOFTONLINE.COM"));
    }

    #[test]
    fn write_kerberos_config_snippet_rejects_non_directory_path() {
        let krb_conf_dir =
            tempfile::NamedTempFile::new().expect("failed to create temp config path");

        let err = write_kerberos_config_snippet_to(
            None,
            TENANT_ID,
            "login.microsoftonline.com",
            krb_conf_dir.path(),
        )
        .expect_err("expected non-directory config path to be rejected");

        assert!(err.contains("is not a directory"));
    }

    #[test]
    fn write_kerberos_config_snippet_rejects_invalid_tenant_without_creating_dir() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let krb_conf_dir = tmpdir.path().join("krb5.conf.d");

        let err = write_kerberos_config_snippet_to(
            None,
            "not-a-tenant-id",
            "login.microsoftonline.com",
            &krb_conf_dir,
        )
        .expect_err("expected invalid tenant ID to be rejected");

        assert!(err.contains("Failed to validate tenant ID"));
        assert!(!krb_conf_dir.exists());
    }
}
