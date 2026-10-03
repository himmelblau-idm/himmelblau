/*
 * Transparent OpenSSH credential preparation for Himmelblau.
 *
 * This process owns the private key.  himmelblaud receives only the public
 * half and identifies the user from SO_PEERCRED.
 */

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use himmelblau_unix_common::client_sync::DaemonClientBlocking;
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use himmelblau_unix_common::ssh_cert::parse_ssh_certificate;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const RENEW_BEFORE_SECONDS: u64 = 300;
const TRUST_FILE: &str = "/var/lib/himmelblau/ssh-ca/trusted_user_ca_keys";

#[derive(Debug, Serialize, Deserialize)]
struct CertificateState {
    valid_after: u64,
    valid_before: u64,
    signing_ca_fingerprint_sha256: String,
    certificate_sha256: String,
    public_key_sha256: String,
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

fn ensure_key(key_path: &Path) -> io::Result<bool> {
    let public_path = PathBuf::from(format!("{}.pub", key_path.display()));
    if key_path.is_file() {
        let derived = Command::new("/usr/bin/ssh-keygen")
            .args(["-y", "-P", "", "-f"])
            .arg(key_path)
            .stdin(Stdio::null())
            .output()?;
        if !derived.status.success() {
            return Err(io::Error::other("cannot derive existing SSH public key"));
        }
        let derived = String::from_utf8(derived.stdout).map_err(io::Error::other)?;
        let matches = fs::read_to_string(&public_path).ok().is_some_and(|public| {
            public
                .split_whitespace()
                .take(2)
                .eq(derived.split_whitespace().take(2))
        });
        if matches {
            return Ok(false);
        }
        atomic_write(&public_path, derived.as_bytes(), 0o600)?;
        return Ok(true);
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
    Ok(true)
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn trust_contains_fingerprint(trust: &Path, expected: &str) -> bool {
    fs::read_to_string(trust).ok().is_some_and(|contents| {
        contents.lines().any(|line| {
            let mut fields = line.split_whitespace();
            let Some(_key_type) = fields.next() else {
                return false;
            };
            let Some(body) = fields.next() else {
                return false;
            };
            STANDARD.decode(body).ok().is_some_and(|blob| {
                format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob))) == expected
            })
        })
    })
}

fn cached_certificate_is_fresh(
    cert: &Path,
    state: &Path,
    public_key: &Path,
    trust: &Path,
    now: u64,
) -> bool {
    let Some(cert_bytes) = fs::read(cert).ok() else {
        return false;
    };
    let Some(public_key_bytes) = fs::read(public_key).ok() else {
        return false;
    };
    let Some(state) = fs::read(state)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<CertificateState>(&bytes).ok())
    else {
        return false;
    };
    let Some(body) = std::str::from_utf8(&cert_bytes)
        .ok()
        .and_then(|line| line.split_whitespace().nth(1))
    else {
        return false;
    };
    let Some(parsed) = parse_ssh_certificate(body).ok() else {
        return false;
    };

    state.certificate_sha256 == sha256_hex(&cert_bytes)
        && state.public_key_sha256 == sha256_hex(&public_key_bytes)
        && state.valid_after == parsed.valid_after
        && state.valid_before == parsed.valid_before
        && state.signing_ca_fingerprint_sha256 == parsed.signing_ca_fingerprint_sha256
        && certificate_window_is_usable(state.valid_after, state.valid_before, now)
        && trust_contains_fingerprint(trust, &state.signing_ca_fingerprint_sha256)
}

fn certificate_window_is_usable(valid_after: u64, valid_before: u64, now: u64) -> bool {
    valid_after <= now && valid_before > now.saturating_add(RENEW_BEFORE_SECONDS)
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
    if ensure_key(&key_path)? {
        // A repaired/generated pair invalidates any certificate for the old key.
        for path in [&cert_path, &state_path] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let public_path = PathBuf::from(format!("{}.pub", key_path.display()));
    if cached_certificate_is_fresh(
        &cert_path,
        &state_path,
        &public_path,
        Path::new(TRUST_FILE),
        now,
    ) {
        return Ok(());
    }

    let public_key_bytes = fs::read(&public_path)?;
    let public_key = std::str::from_utf8(&public_key_bytes)?;
    let config =
        HimmelblauConfig::new_unprivileged(Some(DEFAULT_CONFIG_PATH)).map_err(io::Error::other)?;
    let mut client = DaemonClientBlocking::new(&config.get_socket_path())?;
    let response = client.call_and_wait(
        &ClientRequest::AcquireSshCertificate {
            openssh_public_key: public_key.trim().to_string(),
        },
        30,
    )?;

    let ClientResponse::SshCertificate(certificate) = response else {
        return Err("interactive Himmelblau sign-in is required for Entra SSH SSO".into());
    };
    if certificate.valid_after > now {
        return Err("Microsoft returned an SSH certificate that is not yet valid".into());
    }
    if certificate.valid_before <= now.saturating_add(RENEW_BEFORE_SECONDS) {
        return Err("Microsoft returned an SSH certificate with insufficient lifetime".into());
    }

    let certificate_bytes = format!("{}\n", certificate.openssh_certificate).into_bytes();
    atomic_write(&cert_path, &certificate_bytes, 0o600)?;
    atomic_write(
        &state_path,
        &serde_json::to_vec(&CertificateState {
            valid_after: certificate.valid_after,
            valid_before: certificate.valid_before,
            signing_ca_fingerprint_sha256: certificate.signing_ca_fingerprint_sha256,
            certificate_sha256: sha256_hex(&certificate_bytes),
            public_key_sha256: sha256_hex(&public_key_bytes),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_window_must_be_current_and_have_renewal_margin() {
        let now = 10_000;
        assert!(certificate_window_is_usable(
            now,
            now + RENEW_BEFORE_SECONDS + 1,
            now
        ));
        assert!(!certificate_window_is_usable(
            now + 1,
            now + RENEW_BEFORE_SECONDS + 2,
            now
        ));
        assert!(!certificate_window_is_usable(
            now,
            now + RENEW_BEFORE_SECONDS,
            now
        ));
    }

    #[test]
    fn trust_fingerprint_must_match_an_installed_key() {
        let root = std::env::temp_dir().join(format!(
            "himmelblau-trust-fingerprint-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("test directory");
        let trust = root.join("trusted-ca");
        let blob = b"test OpenSSH CA blob";
        fs::write(
            &trust,
            format!("ssh-rsa {} test-ca\n", STANDARD.encode(blob)),
        )
        .expect("trust file");
        let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)));
        assert!(trust_contains_fingerprint(&trust, &fingerprint));
        assert!(!trust_contains_fingerprint(&trust, "SHA256:not-the-key"));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn mismatched_public_key_is_repaired_without_replacing_private_key() {
        let root = std::env::temp_dir().join(format!(
            "himmelblau-key-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("test directory");
        let key = root.join("id_rsa");
        let status = Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .expect("key generation");
        assert!(status.success());
        let private = fs::read(&key).expect("private key");
        let public = fs::read(key.with_extension("pub")).expect("public key");
        fs::write(key.with_extension("pub"), "ssh-ed25519 stale-key").expect("stale public key");
        assert!(ensure_key(&key).expect("repair key"));
        assert_eq!(fs::read(&key).expect("unchanged private key"), private);
        let repaired = fs::read_to_string(key.with_extension("pub")).expect("derived public key");
        let original = String::from_utf8(public).expect("public text");
        assert!(repaired
            .split_whitespace()
            .take(2)
            .eq(original.split_whitespace().take(2)));
        assert!(!ensure_key(&key).expect("matching key"));
        fs::remove_dir_all(root).expect("remove test directory");
    }
}
