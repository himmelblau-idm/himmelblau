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

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::process::ExitCode;
use std::str;
use std::time::Duration;
use std::{fs, io};

use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use himmelblau::graph::Graph;
use himmelblau_policies::policies::apply_intune_policy;
use himmelblau_unix_common::config::{split_username, HimmelblauConfig};
use himmelblau_unix_common::constants::{DEFAULT_CCACHE_DIR, DEFAULT_CONFIG_PATH};
use himmelblau_unix_common::unix_proto::{HomeDirectoryInfo, TaskRequest, TaskResponse};
use kanidm_utils_users::{get_effective_gid, get_effective_uid};
use libc::{lchown, umask};
use libc::{mode_t, uid_t};
use sd_notify::NotifyState;
use sketching::tracing_forest::traits::*;
use sketching::tracing_forest::util::*;
use sketching::tracing_forest::{self};
use std::fs::OpenOptions;
use std::fs::{DirBuilder, File};
use std::io::Write;
use std::process::Command;
use tokio::net::UnixStream;
use tokio::sync::broadcast;
use tokio::time;
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::span;
use walkdir::WalkDir;

#[cfg(all(target_family = "unix", feature = "selinux"))]
use himmelblau_unix_common::selinux_util;

struct TaskCodec;

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
            io::Error::new(io::ErrorKind::Other, "JSON encode error")
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

        if alias_path.exists() {
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

fn remove_user_from_group(account_id: &str, local_group: &str) {
    match Command::new("gpasswd")
        .arg("-d")
        .arg(account_id)
        .arg(local_group)
        .output()
    {
        Ok(res) => {
            if !res.status.success() {
                error!("Failed removing user from local group {}", local_group);
            }
        }
        Err(e) => {
            error!(
                "Failed removing user from local group {}: {:?}",
                local_group, e
            );
        }
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

fn write_bytes_to_file(bytes: &[u8], filename: &Path, uid: uid_t, gid: uid_t, mode: mode_t) -> i32 {
    let mut file = match OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(filename)
    {
        Ok(file) => file,
        Err(_) => return 1,
    };

    if chown(filename, uid, gid).is_err() {
        return 3;
    }

    if file.write_all(bytes).is_err() {
        return 2;
    }

    0
}

fn create_ccache_dir(ccache_dir: &Path, uid: uid_t, gid: uid_t) -> io::Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(ccache_dir)
        .map_err(|e| {
            error!(
                "Failed to create the krb5 ccache directory '{}': {:?}",
                ccache_dir.display(),
                e
            );
            e
        })?;

    std::os::unix::fs::chown(ccache_dir, Some(uid), Some(gid)).map_err(|e| {
        error!(
            "Failed to set the krb5 ccache directory '{}' owner and group: {:?}",
            ccache_dir.display(),
            e
        );
        e
    })
}

async fn handle_tasks(stream: UnixStream, cfg: &HimmelblauConfig) {
    let mut reqs = Framed::new(stream, TaskCodec::new());

    loop {
        let next_req = reqs.next().await;
        let span = span!(Level::INFO, "TaskRequest");
        let _ = span.enter();
        match next_req {
            Some(Ok(TaskRequest::HomeDirectory(info))) => {
                debug!("Received task -> HomeDirectory({:?})", info);
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
            Some(Ok(TaskRequest::LocalGroups(mut account_id, is_sudoer))) => {
                debug!("Received task -> LocalGroups(...)",);
                account_id = cfg.map_upn_to_name(&account_id);

                let local_groups = cfg.get_local_groups();
                for local_group in &local_groups {
                    add_user_to_group(&account_id, &local_group);
                }

                let local_sudo_group = cfg.get_local_sudo_group();

                // Only run sudo groups if local_groups does not contain local_sudo_group (default = sudo)
                if !local_groups.contains(&local_sudo_group) {
                    if is_sudoer {
                        add_user_to_group(&account_id, &local_sudo_group);
                    } else {
                        remove_user_from_group(&account_id, &local_sudo_group);
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
            Some(Ok(TaskRequest::KerberosCCache(uid, gid, cloud_ccache, ad_ccache))) => {
                debug!("Received task -> KerberosCCache({}, ...)", uid);
                let ccache_dir_str = format!("{}{}", DEFAULT_CCACHE_DIR, uid);
                let ccache_dir = Path::new(&ccache_dir_str);

                let response = match create_ccache_dir(ccache_dir, uid, gid) {
                    Ok(()) => {
                        let primary_name = ccache_dir.join("primary");
                        write_bytes_to_file(b"tkt\n", &primary_name, uid, gid, 0o600);

                        let cloud_ret = if !cloud_ccache.is_empty() {
                            // The cloud_tkt is the primary only if the on-prem isn't
                            // present.
                            let name = if !ad_ccache.is_empty() {
                                "cloud_tkt"
                            } else {
                                "tkt"
                            };
                            let cloud_ccache_name = ccache_dir.join(name);
                            write_bytes_to_file(&cloud_ccache, &cloud_ccache_name, uid, gid, 0o600)
                                * 10
                        } else {
                            0
                        };

                        let ad_ret = if !ad_ccache.is_empty() {
                            // If the on-prem ad_tkt exists, it overrides the primary
                            let name = "tkt";
                            let ad_ccache_name = ccache_dir.join(name);
                            write_bytes_to_file(&ad_ccache, &ad_ccache_name, uid, gid, 0o600) * 100
                        } else {
                            0
                        };
                        TaskResponse::Success(cloud_ret + ad_ret)
                    }
                    Err(_) => TaskResponse::Error(
                        "Failed to create credential cache directory".to_string(),
                    ),
                };

                // Indicate the status response
                if let Err(e) = reqs.send(response).await {
                    error!("Error -> {:?}", e);
                    return;
                }
            }
            Some(Ok(TaskRequest::LoadProfilePhoto(mut account_id, access_token))) => {
                debug!("Received task -> LoadProfilePhoto(...)");
                let icons_dir = "/var/lib/AccountsService/icons/";
                if !Path::new(icons_dir).exists() {
                    info!("Profile photo directory '{}' doesn't exist.", icons_dir);
                } else {
                    let upn = account_id.clone();
                    let domain = split_username(&upn).map(|(_, domain)| domain);
                    account_id = cfg.map_upn_to_name(&account_id);
                    // Set the profile picture
                    if let Some(domain) = domain {
                        let filename = format!("/var/lib/AccountsService/icons/{}", account_id);
                        match File::create(&filename) {
                            Ok(file) => {
                                let authority_host = cfg.get_authority_host(domain);
                                let tenant_id = cfg.get_tenant_id(domain);
                                let graph_url = cfg.get_graph_url(domain);
                                if let Ok(graph) = Graph::new(
                                    &cfg.get_odc_provider(domain),
                                    domain,
                                    Some(&authority_host),
                                    tenant_id.as_deref(),
                                    graph_url.as_deref(),
                                )
                                .await
                                {
                                    if let Err(e) =
                                        graph.fetch_user_profile_photo(&access_token, file).await
                                    {
                                        error!("Failed fetching user profile photo: {:?}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed creating file for user profile photo: {:?}", e)
                            }
                        }
                        let user_file = format!("/var/lib/AccountsService/users/{}", account_id);
                        match File::create(&user_file) {
                            Ok(mut file) => {
                                let contents =
                                    format!("[User]\nIcon={}\nSystemAccount=false\n", filename);

                                if let Err(e) = file.write_all(contents.as_bytes()) {
                                    error!("Failed writing to user profile settings: {:?}", e);
                                }
                            }
                            Err(e) => {
                                error!("Failed creating file for user profile settings: {:?}", e)
                            }
                        }
                    } else {
                        error!("Couldn't parse domain from name");
                    }
                }

                // Always indicate success here
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
                let res = match apply_intune_policy(
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
                debug!("tasks: Got response code `{}` while applying policy", res);

                // Indicate the status response
                if let Err(e) = reqs
                    .send(TaskResponse::Success(if res { 0 } else { 1 }))
                    .await
                {
                    error!("Error -> {:?}", e);
                    return;
                }
            }
            Some(Err(e)) => {
                error!("Error -> {:?}", e);
                return;
            }
            _ => {
                error!("Error -> Unexpected response");
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
                    let _ = sd_notify::notify(true, &[NotifyState::Ready, monotonic_usec]);
                }
            }

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
                }
            }

            info!("Signal received, shutting down");
            if systemd_booted {
                if let Ok(monotonic_usec) = sd_notify::NotifyState::monotonic_usec_now() {
                    let _ = sd_notify::notify(true, &[NotifyState::Stopping, monotonic_usec]);
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
