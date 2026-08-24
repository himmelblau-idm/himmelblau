/*
 * Transparent OpenSSH credential preparation for Himmelblau.
 *
 * This process owns the private key.  himmelblaud receives only the public
 * half and identifies the user from SO_PEERCRED.
 */

use himmelblau_unix_common::client_sync::DaemonClientBlocking;
use himmelblau_unix_common::constants::DEFAULT_SOCK_PATH;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const RENEW_BEFORE_SECONDS: u64 = 300;

#[derive(Debug, Serialize, Deserialize)]
struct CertificateState {
    valid_before: u64,
    signing_ca_fingerprint_sha256: String,
}

fn check_directory(path: &Path, uid: u32, required_mode: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o700 != required_mode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unsafe runtime directory {}", path.display()),
        ));
    }
    Ok(())
}

fn ensure_private_directory(path: &Path, uid: u32) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err),
    }
    check_directory(path, uid, 0o700)
}

fn lock(file: &File) -> io::Result<()> {
    // SAFETY: flock only observes the valid descriptor owned by `file`.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

fn ensure_key(key_path: &Path) -> io::Result<()> {
    let public_path = PathBuf::from(format!("{}.pub", key_path.display()));
    if key_path.is_file() && public_path.is_file() {
        return Ok(());
    }

    let temporary = key_path.with_extension(format!("new.{}", std::process::id()));
    let status = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "rsa", "-b", "3072", "-N", "", "-f"])
        .arg(&temporary)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other("ssh-keygen failed"));
    }

    let temporary_public = PathBuf::from(format!("{}.pub", temporary.display()));
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(&temporary_public, fs::Permissions::from_mode(0o600))?;
    fs::rename(&temporary, key_path)?;
    fs::rename(&temporary_public, public_path)?;
    Ok(())
}

fn cached_certificate_is_fresh(cert: &Path, state: &Path, now: u64) -> bool {
    if !cert.is_file() {
        return false;
    }
    fs::read(state)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<CertificateState>(&bytes).ok())
        .is_some_and(|state| state.valid_before > now.saturating_add(RENEW_BEFORE_SECONDS))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    check_directory(&runtime, uid, 0o700)?;
    let himmelblau_dir = runtime.join("himmelblau");
    ensure_private_directory(&himmelblau_dir, uid)?;
    let ssh_dir = himmelblau_dir.join("ssh");
    ensure_private_directory(&ssh_dir, uid)?;

    let lock_path = ssh_dir.join("lock");
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock_path)?;
    lock(&lock_file)?;

    let key_path = ssh_dir.join("id_rsa");
    let cert_path = ssh_dir.join("id_rsa-cert.pub");
    let state_path = ssh_dir.join("certificate.json");
    ensure_key(&key_path)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if cached_certificate_is_fresh(&cert_path, &state_path, now) {
        return Ok(());
    }

    let public_key = fs::read_to_string(format!("{}.pub", key_path.display()))?;
    let mut client = DaemonClientBlocking::new(DEFAULT_SOCK_PATH)?;
    let response = client.call_and_wait(
        &ClientRequest::AcquireSshCertificate {
            openssh_public_key: public_key.trim().to_string(),
        },
        30,
    )?;

    let ClientResponse::SshCertificate(certificate) = response else {
        return Err("interactive Himmelblau sign-in is required for Entra SSH SSO".into());
    };
    if certificate.valid_before <= now.saturating_add(RENEW_BEFORE_SECONDS) {
        return Err("Microsoft returned an SSH certificate with insufficient lifetime".into());
    }

    atomic_write(
        &cert_path,
        format!("{}\n", certificate.openssh_certificate).as_bytes(),
        0o600,
    )?;
    atomic_write(
        &state_path,
        &serde_json::to_vec(&CertificateState {
            valid_before: certificate.valid_before,
            signing_ca_fingerprint_sha256: certificate.signing_ca_fingerprint_sha256,
        })?,
        0o600,
    )?;
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Himmelblau Entra SSH certificate unavailable: {err}");
        std::process::exit(1);
    }
}
