use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use openssl::bn::BigNum;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use reqwest::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, DATE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_RESPONSE_SIZE: usize = 256 * 1024;
const TRUST_DIR: &str = "/var/lib/himmelblau/ssh-ca";
const TRUST_FILE: &str = "/var/lib/himmelblau/ssh-ca/trusted_user_ca_keys";
const PROVENANCE_FILE: &str = "/var/lib/himmelblau/ssh-ca/provenance.json";
const REFRESH_LOCK_FILE: &str = "/var/lib/himmelblau/ssh-ca/refresh.lock";

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    keys: Vec<DiscoveryKey>,
}

#[derive(Debug, Deserialize)]
struct DiscoveryKey {
    kty: String,
    #[serde(rename = "use")]
    usage: String,
    kid: String,
    n: String,
    e: String,
    x5c: Vec<String>,
    cloud_instance_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct KeyProvenance {
    kid: String,
    openssh_fingerprint_sha256: String,
    x509_subject: String,
    x509_not_before: String,
    x509_not_after: String,
}

#[derive(Debug, Serialize)]
struct Provenance {
    source_url: String,
    authority_host: String,
    retrieved_at_unix: u64,
    response_date: String,
    cache_control: String,
    max_age_seconds: u64,
    request_id: Option<String>,
    response_sha256: String,
    response_size: usize,
    trust_sha256: String,
    keys: Vec<KeyProvenance>,
}

#[derive(Debug, Deserialize, Serialize)]
struct FreshnessProvenance {
    source_url: String,
    authority_host: String,
    retrieved_at_unix: u64,
    max_age_seconds: u64,
    trust_sha256: String,
}

fn endpoint(authority: &str) -> Result<(&'static str, Option<&'static str>), String> {
    match authority
        .trim_end_matches('/')
        .to_ascii_lowercase()
        .as_str()
    {
        "login.microsoftonline.com" | "https://login.microsoftonline.com" => Ok((
            "https://login.microsoftonline.com/common/discovery/keys",
            Some("microsoftonline.com"),
        )),
        "login.microsoftonline.us" | "https://login.microsoftonline.us" => Ok((
            "https://login.microsoftonline.us/common/discovery/keys",
            Some("microsoftonline.us"),
        )),
        "login.chinacloudapi.cn" | "https://login.chinacloudapi.cn" => {
            Ok(("https://login.chinacloudapi.cn/common/discovery/keys", None))
        }
        _ => Err(format!("unsupported Microsoft authority host: {authority}")),
    }
}

fn canonical_base64url(value: &str, field: &str) -> Result<Vec<u8>, String> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("invalid {field} base64url"))?;
    if decoded.is_empty() || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(format!("non-canonical {field}"));
    }
    Ok(decoded)
}

fn ssh_string(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "SSH key field too large")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn positive_mpint(mut value: Vec<u8>) -> Vec<u8> {
    while value.len() > 1 && value.first() == Some(&0) && value[1] & 0x80 == 0 {
        value.remove(0);
    }
    if value.first().is_some_and(|byte| byte & 0x80 != 0) {
        value.insert(0, 0);
    }
    value
}

fn openssh_rsa_blob(exponent: Vec<u8>, modulus: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut blob = Vec::with_capacity(modulus.len() + 64);
    ssh_string(&mut blob, b"ssh-rsa")?;
    ssh_string(&mut blob, &positive_mpint(exponent))?;
    ssh_string(&mut blob, &positive_mpint(modulus))?;
    Ok(blob)
}

fn max_age(cache_control: &str) -> Result<u64, String> {
    cache_control
        .split(',')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("max-age="))
        .ok_or_else(|| "Microsoft response omitted max-age".to_string())?
        .parse::<u64>()
        .map(|age| age.min(86_400))
        .map_err(|_| "invalid Microsoft max-age".to_string())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn atomic_write(path: &Path, value: &[u8], mode: u32) -> Result<(), String> {
    let temporary = PathBuf::from(format!("{}.tmp.{}", path.display(), std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)
        .map_err(|err| format!("create {}: {err}", temporary.display()))?;
    if let Err(err) = file.write_all(value).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("write {}: {err}", temporary.display()));
    }
    fs::rename(&temporary, path).map_err(|err| {
        let _ = fs::remove_file(&temporary);
        format!("activate {}: {err}", path.display())
    })
}

fn open_secure_regular_file(
    path: &Path,
    required_uid: u32,
    required_gid: u32,
) -> Result<fs::File, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|err| format!("open {} securely: {err}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("inspect {}: {err}", path.display()))?;
    if !metadata.is_file()
        || metadata.uid() != required_uid
        || metadata.gid() != required_gid
        || metadata.mode() & 0o022 != 0
    {
        return Err(format!(
            "{} must be a root-owned, non-writable regular file",
            path.display()
        ));
    }
    Ok(file)
}

fn read_secure_regular_file(
    path: &Path,
    limit: usize,
    required_uid: u32,
    required_gid: u32,
) -> Result<Vec<u8>, String> {
    let file = open_secure_regular_file(path, required_uid, required_gid)?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| format!("read {}: {err}", path.display()))?;
    if bytes.len() > limit {
        return Err(format!("{} exceeds size limit", path.display()));
    }
    Ok(bytes)
}

// The allowlisted HTTPS discovery response authenticates the signing key.
// x5c may carry a CA-issued leaf, and therefore need not be self-signed.
fn validate_certificate(
    key: &DiscoveryKey,
    modulus: &[u8],
    exponent: &[u8],
    now: &openssl::asn1::Asn1TimeRef,
) -> Result<X509, String> {
    let x509_der = STANDARD
        .decode(&key.x5c[0])
        .map_err(|_| format!("invalid x5c for {}", key.kid))?;
    let certificate =
        X509::from_der(&x509_der).map_err(|err| format!("parse x5c for {}: {err}", key.kid))?;
    let certificate_key = certificate
        .public_key()
        .map_err(|err| format!("parse x5c public key for {}: {err}", key.kid))?;
    let certificate_rsa = certificate_key
        .rsa()
        .map_err(|_| format!("x5c key is not RSA for {}", key.kid))?;
    if certificate_rsa.n().to_vec() != modulus || certificate_rsa.e().to_vec() != exponent {
        return Err(format!("JWK/x5c public key mismatch for {}", key.kid));
    }
    if certificate
        .not_before()
        .compare(&now)
        .map_err(|err| err.to_string())?
        == Ordering::Greater
        || certificate
            .not_after()
            .compare(&now)
            .map_err(|err| err.to_string())?
            != Ordering::Greater
    {
        return Err(format!("x5c is not currently valid for {}", key.kid));
    }
    Ok(certificate)
}

fn secure_trust_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => match fs::create_dir(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(format!("create trust directory: {err}")),
        },
        Err(err) => return Err(format!("inspect trust directory: {err}")),
    }
    let metadata = fs::symlink_metadata(path).map_err(|err| err.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.gid() != 0 {
        return Err(format!(
            "trust directory must be a root-owned real directory: {}",
            path.display()
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|err| format!("secure trust directory: {err}"))?;
    let metadata = fs::symlink_metadata(path).map_err(|err| err.to_string())?;
    if metadata.mode() & 0o7777 != 0o755 || metadata.uid() != 0 || metadata.gid() != 0 {
        return Err("unsafe trust directory ownership/mode".into());
    }
    Ok(())
}

fn check_trust_parent(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|err| format!("read trust parent: {err}"))?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err("unsafe trust parent ownership/mode".into());
    }
    Ok(())
}

fn ensure_trust_parent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => return check_trust_parent(path),
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
            return Err(format!("read trust parent: {err}"));
        }
        Err(_) => {}
    }
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("secure new trust parent: {err}"))?,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(format!("create trust parent: {err}")),
    }
    check_trust_parent(path)
}

struct RefreshLock(fs::File);

impl Drop for RefreshLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains valid for the lifetime of the guard.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn open_refresh_lock_file(
    path: &Path,
    required_uid: u32,
    required_gid: u32,
) -> Result<fs::File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|err| format!("open refresh lock securely: {err}"))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("inspect refresh lock: {err}"))?;
    if !metadata.is_file()
        || metadata.uid() != required_uid
        || metadata.gid() != required_gid
        || metadata.mode() & 0o077 != 0
    {
        return Err("refresh lock must be an owner-only regular file".into());
    }
    Ok(file)
}

fn acquire_refresh_lock(
    path: &Path,
    required_uid: u32,
    required_gid: u32,
) -> Result<RefreshLock, String> {
    let file = open_refresh_lock_file(path, required_uid, required_gid)?;
    loop {
        // SAFETY: flock only observes the valid descriptor owned by `file`.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(RefreshLock(file));
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!("lock SSH CA refresh state: {err}"));
        }
    }
}

fn prepare_trust_storage(parent: &Path, trust_dir: &Path) -> Result<(), String> {
    // Validate the non-writable parent before creating or changing anything
    // beneath it, then harden the only directory the refresh unit may mutate.
    check_trust_parent(parent)?;
    secure_trust_directory(trust_dir)
}

fn validate_key_id(kid: &str) -> Result<(), String> {
    if kid.is_empty() || kid.chars().any(char::is_control) {
        return Err("invalid Microsoft signing key identifier".into());
    }
    Ok(())
}

fn fresh_provenance(
    bytes: Option<&[u8]>,
    trust: Option<&[u8]>,
    now: u64,
    expected_source_url: &str,
    expected_authority_host: &str,
) -> Option<FreshnessProvenance> {
    let bytes = bytes.filter(|bytes| bytes.len() <= MAX_RESPONSE_SIZE)?;
    let trust = trust.filter(|trust| trust.len() <= MAX_RESPONSE_SIZE)?;
    let provenance: FreshnessProvenance = serde_json::from_slice(bytes).ok()?;
    if provenance.source_url != expected_source_url
        || provenance.authority_host != expected_authority_host
        || provenance.trust_sha256 != hex_lower(&Sha256::digest(trust))
        || provenance.max_age_seconds > 86_400
        || provenance.retrieved_at_unix > now
    {
        return None;
    }
    let deadline = provenance
        .retrieved_at_unix
        .checked_add(provenance.max_age_seconds)?;
    (now <= deadline).then_some(provenance)
}

fn disable_stale_trust(
    trust: &Path,
    provenance: &Path,
    now: u64,
    expected_authority: Option<(&str, &str)>,
) -> Result<bool, String> {
    disable_stale_trust_owned(trust, provenance, now, 0, 0, expected_authority)
}

fn disable_stale_trust_owned(
    trust: &Path,
    provenance: &Path,
    now: u64,
    required_uid: u32,
    required_gid: u32,
    expected_authority: Option<(&str, &str)>,
) -> Result<bool, String> {
    let trust_bytes =
        read_secure_regular_file(trust, MAX_RESPONSE_SIZE, required_uid, required_gid).ok();
    let provenance_bytes =
        read_secure_regular_file(provenance, MAX_RESPONSE_SIZE, required_uid, required_gid).ok();
    if trust_bytes.is_some() {
        if let Some(provenance) = expected_authority.and_then(|(source_url, authority_host)| {
            fresh_provenance(
                provenance_bytes.as_deref(),
                trust_bytes.as_deref(),
                now,
                source_url,
                authority_host,
            )
        }) {
            eprintln!(
                "last-known-good CA set from {} remains fresh until Unix time {}",
                provenance.source_url,
                provenance.retrieved_at_unix + provenance.max_age_seconds
            );
            return Ok(false);
        }
    }
    atomic_write(
        trust,
        b"# Microsoft SSH CA trust disabled: freshness record missing, invalid, or expired\n",
        0o644,
    )?;
    eprintln!("Disabled Microsoft SSH CA trust: freshness record missing, invalid, or expired");
    Ok(true)
}

fn append_response_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), String> {
    if chunk.len() > MAX_RESPONSE_SIZE.saturating_sub(body.len()) {
        return Err("Microsoft response exceeds size limit".into());
    }
    body.extend_from_slice(chunk);
    Ok(())
}

fn configured_authority(config: &HimmelblauConfig) -> Result<String, String> {
    let authorities: BTreeSet<_> = config
        .get_configured_domains()
        .iter()
        .map(|domain| config.get_authority_host(domain))
        .collect();
    if authorities.len() != 1 {
        return Err("SSH CA activation requires exactly one configured Microsoft cloud".into());
    }
    authorities
        .into_iter()
        .next()
        .ok_or_else(|| "Himmelblau is not joined/configured".to_string())
}

#[tokio::main]
async fn main() {
    let mode = std::env::args().nth(1);
    let result = match mode.as_deref() {
        None => run(false).await,
        Some("--allow-unconfigured") => run(true).await,
        Some("--disable-if-stale") => match disable_if_stale() {
            Ok(true) => Ok(()),
            // Distinguish retained fresh trust from an inspection/write error.
            // The timer wrapper treats both nonzero statuses as a failed refresh;
            // installation can safely proceed only for this specific outcome.
            Ok(false) => std::process::exit(2),
            Err(err) => Err(err),
        },
        Some(_) => Err(
            "usage: himmelblau-ssh-ca-refresh [--disable-if-stale | --allow-unconfigured]"
                .to_string(),
        ),
    };
    if let Err(err) = result {
        if mode.as_deref() == Some("--disable-if-stale") {
            eprintln!("Himmelblau Microsoft SSH CA staleness check: {err}");
        } else {
            eprintln!("Himmelblau Microsoft SSH CA refresh failed: {err}");
        }
        std::process::exit(1);
    }
}

fn disable_if_stale() -> Result<bool, String> {
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } != 0 {
        return Err("CA refresh must run as root".into());
    }
    prepare_trust_storage(Path::new("/var/lib/himmelblau"), Path::new(TRUST_DIR))?;
    let _lock = acquire_refresh_lock(Path::new(REFRESH_LOCK_FILE), 0, 0)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_secs();
    let current_authority = HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH))
        .ok()
        .and_then(|config| configured_authority(&config).ok())
        .and_then(|authority| {
            endpoint(&authority)
                .ok()
                .map(|(source_url, _)| (source_url.to_string(), authority))
        });
    disable_stale_trust(
        Path::new(TRUST_FILE),
        Path::new(PROVENANCE_FILE),
        now,
        current_authority
            .as_ref()
            .map(|(source_url, authority)| (source_url.as_str(), authority.as_str())),
    )
}

async fn run(allow_unconfigured: bool) -> Result<(), String> {
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } != 0 {
        return Err("CA refresh must run as root".into());
    }
    if allow_unconfigured {
        ensure_trust_parent(Path::new("/var/lib/himmelblau"))?;
    } else {
        // The timer may only mutate ReadWritePaths=/var/lib/himmelblau/ssh-ca.
        check_trust_parent(Path::new("/var/lib/himmelblau"))?;
    }
    secure_trust_directory(Path::new(TRUST_DIR))?;
    let _lock = acquire_refresh_lock(Path::new(REFRESH_LOCK_FILE), 0, 0)?;
    let config = HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH))
        .map_err(|err| format!("read Himmelblau configuration: {err}"))?;
    if allow_unconfigured && config.get_configured_domains().is_empty() {
        atomic_write(
            Path::new(TRUST_FILE),
            b"# Entra SSH CA activation awaits domain configuration\n",
            0o644,
        )?;
        eprintln!("Entra SSH CA activation deferred until a domain is configured");
        return Ok(());
    }
    let authority = configured_authority(&config)?;
    let (source_url, expected_cloud) = endpoint(&authority)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| format!("build HTTPS client: {err}"))?;
    let mut response = client
        .get(source_url)
        .send()
        .await
        .map_err(|err| format!("Microsoft HTTPS request: {err}"))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("Microsoft returned HTTP {}", response.status()));
    }
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_RESPONSE_SIZE)
    {
        return Err("Microsoft response exceeds size limit".into());
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "Microsoft response omitted Content-Type".to_string())?;
    if !content_type
        .to_ascii_lowercase()
        .starts_with("application/json")
    {
        return Err(format!("unexpected Content-Type: {content_type}"));
    }
    let response_date = response
        .headers()
        .get(DATE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "Microsoft response omitted Date".to_string())?
        .to_string();
    let server_time = httpdate::parse_http_date(&response_date)
        .map_err(|_| "invalid Microsoft response Date".to_string())?;
    let clock_delta = SystemTime::now()
        .duration_since(server_time)
        .or_else(|_| server_time.duration_since(SystemTime::now()))
        .map_err(|_| "invalid response clock delta".to_string())?;
    if clock_delta > Duration::from_secs(15 * 60) {
        return Err("Microsoft response Date is stale or local clock is incorrect".into());
    }
    let cache_control = response
        .headers()
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "Microsoft response omitted Cache-Control".to_string())?
        .to_string();
    let max_age_seconds = max_age(&cache_control)?;
    let request_id = response
        .headers()
        .get("x-ms-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| format!("read Microsoft response: {err}"))?
    {
        append_response_chunk(&mut body, &chunk)?;
    }
    let document: DiscoveryDocument =
        serde_json::from_slice(&body).map_err(|err| format!("parse Microsoft keys: {err}"))?;
    if document.keys.is_empty() || document.keys.len() > 64 {
        return Err("Microsoft response contains an invalid key count".into());
    }

    let now = openssl::asn1::Asn1Time::days_from_now(0)
        .map_err(|err| format!("create X.509 comparison time: {err}"))?;
    let mut seen = HashMap::<String, Vec<u8>>::new();
    let mut key_lines = Vec::new();
    let mut provenance_keys = Vec::new();
    for key in document.keys {
        let cloud_matches = match expected_cloud {
            Some(expected) => key.cloud_instance_name.as_deref() == Some(expected),
            None => key.cloud_instance_name.is_none(),
        };
        if !cloud_matches {
            continue;
        }
        validate_key_id(&key.kid)?;
        if key.kty != "RSA" || key.usage != "sig" || key.x5c.is_empty() {
            return Err(format!("invalid Microsoft signing key {}", key.kid));
        }
        let modulus = canonical_base64url(&key.n, "RSA modulus")?;
        let exponent = canonical_base64url(&key.e, "RSA exponent")?;
        if exponent.as_slice() != [1, 0, 1] {
            return Err(format!("unexpected RSA exponent for {}", key.kid));
        }
        let modulus_bits = modulus.len() * 8 - modulus[0].leading_zeros() as usize;
        if !(2048..=8192).contains(&modulus_bits) {
            return Err(format!("unsupported RSA modulus size for {}", key.kid));
        }

        let certificate = validate_certificate(&key, &modulus, &exponent, &now)?;
        // Constructing the PKey independently catches malformed integer edge
        // cases before OpenSSH sees the generated line.
        let rsa = Rsa::from_public_components(
            BigNum::from_slice(&modulus).map_err(|err| err.to_string())?,
            BigNum::from_slice(&exponent).map_err(|err| err.to_string())?,
        )
        .map_err(|err| format!("construct RSA key {}: {err}", key.kid))?;
        PKey::from_rsa(rsa).map_err(|err| format!("construct PKey {}: {err}", key.kid))?;

        let blob = openssh_rsa_blob(exponent, modulus)?;
        if let Some(previous) = seen.insert(key.kid.clone(), blob.clone()) {
            if previous != blob {
                return Err(format!("conflicting duplicate Microsoft kid {}", key.kid));
            }
            continue;
        }
        let fingerprint = format!(
            "SHA256:{}",
            STANDARD.encode(Sha256::digest(&blob)).trim_end_matches('=')
        );
        key_lines.push(format!(
            "ssh-rsa {} microsoft-entra-kid={}",
            STANDARD.encode(&blob),
            key.kid
        ));
        provenance_keys.push(KeyProvenance {
            kid: key.kid.clone(),
            openssh_fingerprint_sha256: fingerprint,
            x509_subject: certificate
                .subject_name()
                .entries()
                .next()
                .map(|entry| entry.data().to_string())
                .transpose()
                .map_err(|err| format!("read x5c subject for {}: {err}", key.kid))?
                .unwrap_or_else(|| "<unavailable>".to_string()),
            x509_not_before: certificate.not_before().to_string(),
            x509_not_after: certificate.not_after().to_string(),
        });
    }
    if key_lines.is_empty() {
        return Err("Microsoft response contained no keys for the configured cloud".into());
    }

    secure_trust_directory(Path::new(TRUST_DIR))?;
    let trust = format!("{}\n", key_lines.join("\n"));
    // Validate the complete OpenSSH file with the system implementation before
    // it can become active.
    let validation = PathBuf::from(format!("{TRUST_DIR}/validate.{}", std::process::id()));
    atomic_write(&validation, trust.as_bytes(), 0o644)?;
    let status = Command::new("/usr/bin/ssh-keygen")
        .args(["-l", "-f"])
        .arg(&validation)
        .status()
        .map_err(|err| format!("run ssh-keygen: {err}"))?;
    let _ = fs::remove_file(&validation);
    if !status.success() {
        return Err("OpenSSH rejected the generated Microsoft CA set".into());
    }

    let retrieved_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_secs();
    let provenance = Provenance {
        source_url: source_url.to_string(),
        authority_host: authority,
        retrieved_at_unix,
        response_date,
        cache_control,
        max_age_seconds,
        request_id,
        response_sha256: hex_lower(&Sha256::digest(&body)),
        response_size: body.len(),
        trust_sha256: hex_lower(&Sha256::digest(trust.as_bytes())),
        keys: provenance_keys,
    };
    let provenance_json = serde_json::to_vec_pretty(&provenance).map_err(|err| err.to_string())?;
    // Never follow or preserve an unsafe pre-existing trust-file symlink during
    // rollback. A failed provenance install removes the newly written trust
    // file unless the previous value was itself a secure regular file.
    let old_trust = read_secure_regular_file(Path::new(TRUST_FILE), MAX_RESPONSE_SIZE, 0, 0).ok();
    atomic_write(Path::new(TRUST_FILE), trust.as_bytes(), 0o644)?;
    if let Err(err) = atomic_write(Path::new(PROVENANCE_FILE), &provenance_json, 0o644) {
        let rollback = match old_trust {
            Some(value) => atomic_write(Path::new(TRUST_FILE), &value, 0o644),
            None => fs::remove_file(TRUST_FILE)
                .or_else(|remove_err| {
                    if remove_err.kind() == std::io::ErrorKind::NotFound {
                        Ok(())
                    } else {
                        Err(remove_err)
                    }
                })
                .map_err(|remove_err| format!("remove new trust file: {remove_err}")),
        };
        return match rollback {
            Ok(()) => Err(format!("install CA provenance: {err}; trust rolled back")),
            Err(rollback_err) => Err(format!(
                "install CA provenance: {err}; CRITICAL trust rollback failed: {rollback_err}"
            )),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SOURCE: &str = "https://login.microsoftonline.com/common/discovery/keys";
    const TEST_AUTHORITY: &str = "login.microsoftonline.com";

    fn freshness_record(
        trust: &[u8],
        source_url: &str,
        authority_host: &str,
        retrieved_at_unix: u64,
        max_age_seconds: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&FreshnessProvenance {
            source_url: source_url.into(),
            authority_host: authority_host.into(),
            retrieved_at_unix,
            max_age_seconds,
            trust_sha256: hex_lower(&Sha256::digest(trust)),
        })
        .expect("freshness JSON")
    }

    #[test]
    fn ca_issued_leaf_is_accepted_when_its_public_key_matches() {
        use openssl::asn1::{Asn1Integer, Asn1Time};
        use openssl::hash::MessageDigest;
        use openssl::x509::X509NameBuilder;
        let rsa = Rsa::generate(2048).expect("leaf key");
        let modulus = rsa.n().to_vec();
        let exponent = rsa.e().to_vec();
        let leaf_key = PKey::from_rsa(rsa).expect("leaf PKey");
        let issuer_key =
            PKey::from_rsa(Rsa::generate(2048).expect("issuer key")).expect("issuer PKey");
        let mut subject = X509NameBuilder::new().expect("subject");
        subject
            .append_entry_by_text("CN", "signing-key")
            .expect("subject CN");
        let subject = subject.build();
        let mut issuer = X509NameBuilder::new().expect("issuer");
        issuer
            .append_entry_by_text("CN", "issuing-CA")
            .expect("issuer CN");
        let issuer = issuer.build();
        let mut certificate = X509::builder().expect("certificate");
        certificate.set_version(2).expect("version");
        let serial =
            Asn1Integer::from_bn(&BigNum::from_u32(1).expect("serial BN")).expect("serial");
        certificate.set_serial_number(&serial).expect("set serial");
        certificate.set_subject_name(&subject).expect("set subject");
        certificate.set_issuer_name(&issuer).expect("set issuer");
        certificate.set_pubkey(&leaf_key).expect("set key");
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).expect("start"))
            .expect("set start");
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).expect("end"))
            .expect("set end");
        certificate
            .sign(&issuer_key, MessageDigest::sha256())
            .expect("CA signature");
        let certificate = certificate.build();
        assert!(!certificate.verify(&leaf_key).unwrap_or(false));
        let key = DiscoveryKey {
            kty: "RSA".into(),
            usage: "sig".into(),
            kid: "test-leaf".into(),
            n: URL_SAFE_NO_PAD.encode(&modulus),
            e: URL_SAFE_NO_PAD.encode(&exponent),
            x5c: vec![STANDARD.encode(certificate.to_der().expect("DER"))],
            cloud_instance_name: Some("microsoftonline.com".into()),
        };
        let now = Asn1Time::days_from_now(0).expect("now");
        assert!(validate_certificate(&key, &modulus, &exponent, &now).is_ok());
        assert!(validate_certificate(&key, &[1, 2, 3], &exponent, &now).is_err());
    }

    #[test]
    fn malformed_key_id_cannot_inject_ca_lines() {
        for kid in ["", "key\nssh-rsa injected", "key\r", "key\0"] {
            let error = validate_key_id(kid).expect_err("invalid identifier");
            assert!(!error.contains(kid) || kid.is_empty());
            assert!(!error.contains('\n'));
        }
        assert!(validate_key_id("normal_key-id").is_ok());
    }

    #[test]
    fn absent_corrupt_or_expired_provenance_clears_trust() {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        // SAFETY: getgid has no preconditions.
        let gid = unsafe { libc::getgid() };
        let root = std::env::temp_dir().join(format!(
            "himmelblau-freshness-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("test directory");
        let trust = root.join("trust");
        let provenance = root.join("provenance");
        let old_trust = b"old CA keys";
        for record in [
            None,
            Some(b"corrupt".to_vec()),
            Some(freshness_record(
                old_trust,
                TEST_SOURCE,
                TEST_AUTHORITY,
                1,
                1,
            )),
            Some(freshness_record(
                old_trust,
                "https://login.microsoftonline.us/common/discovery/keys",
                "login.microsoftonline.us",
                99,
                100,
            )),
        ] {
            fs::write(&trust, old_trust).expect("trust");
            match record {
                Some(bytes) => fs::write(&provenance, &bytes).expect("record"),
                None => {}
            }
            assert!(disable_stale_trust_owned(
                &trust,
                &provenance,
                100,
                uid,
                gid,
                Some((TEST_SOURCE, TEST_AUTHORITY)),
            )
            .expect("disable trust"));
            assert!(fs::read_to_string(&trust)
                .expect("trust contents")
                .starts_with("# Microsoft SSH CA trust disabled"));
        }
        let fresh_trust = b"fresh CA keys";
        fs::write(&trust, fresh_trust).expect("fresh trust");
        fs::write(
            &provenance,
            freshness_record(fresh_trust, TEST_SOURCE, TEST_AUTHORITY, 99, 100),
        )
        .expect("fresh record");
        assert!(!disable_stale_trust_owned(
            &trust,
            &provenance,
            100,
            uid,
            gid,
            Some((TEST_SOURCE, TEST_AUTHORITY)),
        )
        .expect("fresh trust retained"));
        assert_eq!(fs::read(&trust).expect("fresh keys"), fresh_trust);

        // Emulate a crash after replacing the trust file but before installing
        // its matching provenance record. The old fresh record must not retain
        // the newly installed trust set during an outage.
        fs::write(&trust, b"different cloud CA keys").expect("replace trust only");
        assert!(disable_stale_trust_owned(
            &trust,
            &provenance,
            100,
            uid,
            gid,
            Some((TEST_SOURCE, TEST_AUTHORITY)),
        )
        .expect("mismatched trust disabled"));
        assert!(fs::read_to_string(&trust)
            .expect("disabled mismatched trust")
            .starts_with("# Microsoft SSH CA trust disabled"));

        fs::remove_file(&provenance).expect("remove provenance");
        assert!(disable_stale_trust_owned(
            &root.join("missing").join("trust"),
            &provenance,
            100,
            uid,
            gid,
            Some((TEST_SOURCE, TEST_AUTHORITY)),
        )
        .is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn fresh_provenance_cannot_retain_an_unsafe_trust_file() {
        use std::os::unix::fs::symlink;

        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        // SAFETY: getgid has no preconditions.
        let gid = unsafe { libc::getgid() };
        let root = std::env::temp_dir().join(format!(
            "himmelblau-trust-file-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("test directory");
        let trust = root.join("trust");
        let provenance = root.join("provenance");
        let attacker_trust = b"attacker-controlled trust";
        let record = freshness_record(attacker_trust, TEST_SOURCE, TEST_AUTHORITY, 99, 100);

        fs::write(&trust, attacker_trust).expect("trust");
        fs::set_permissions(&trust, fs::Permissions::from_mode(0o666)).expect("writable trust");
        fs::write(&provenance, &record).expect("fresh provenance");
        assert!(disable_stale_trust_owned(
            &trust,
            &provenance,
            100,
            uid,
            gid,
            Some((TEST_SOURCE, TEST_AUTHORITY)),
        )
        .expect("disable writable trust"));
        assert!(fs::read_to_string(&trust)
            .expect("disabled trust")
            .starts_with("# Microsoft SSH CA trust disabled"));

        fs::write(&trust, b"otherwise secure trust").expect("reset trust");
        fs::remove_file(&provenance).expect("remove provenance");
        let target = root.join("provenance-target");
        fs::write(
            &target,
            freshness_record(
                b"otherwise secure trust",
                TEST_SOURCE,
                TEST_AUTHORITY,
                99,
                100,
            ),
        )
        .expect("target");
        symlink(&target, &provenance).expect("provenance symlink");
        assert!(disable_stale_trust_owned(
            &trust,
            &provenance,
            100,
            uid,
            gid,
            Some((TEST_SOURCE, TEST_AUTHORITY)),
        )
        .expect("disable symlinked provenance"));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn recurring_refresh_checks_parent_without_changing_mode() {
        let root = std::env::temp_dir().join(format!(
            "himmelblau-parent-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("test directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).expect("read-only mode");
        if unsafe { libc::getuid() } == 0 {
            check_trust_parent(&root).expect("read-only parent accepted");
        }
        assert_eq!(
            fs::metadata(&root).expect("metadata").mode() & 0o7777,
            0o555
        );
        fs::remove_dir(root).expect("cleanup");
    }

    #[test]
    fn install_parent_creation_preserves_existing_private_mode() {
        if unsafe { libc::getuid() } != 0 {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "himmelblau-install-parent-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("test root");
        let parent = root.join("himmelblau");
        ensure_trust_parent(&parent).expect("create parent");
        assert_eq!(
            fs::metadata(&parent).expect("metadata").mode() & 0o7777,
            0o755
        );
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).expect("private mode");
        ensure_trust_parent(&parent).expect("validate existing parent");
        assert_eq!(
            fs::metadata(&parent).expect("metadata").mode() & 0o7777,
            0o700
        );
        fs::remove_dir(&parent).expect("remove parent");
        fs::remove_dir(root).expect("remove root");
    }

    #[test]
    fn refresh_lock_serializes_state_mutations() {
        let root = std::env::temp_dir().join(format!(
            "himmelblau-refresh-lock-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("test directory");
        let path = root.join("refresh.lock");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let first = acquire_refresh_lock(&path, uid, gid).expect("first lock");
        let second = open_refresh_lock_file(&path, uid, gid).expect("second descriptor");
        let status = unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(status, -1);
        drop(first);
        let status = unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(status, 0);
        drop(second);
        fs::remove_file(path).expect("remove lock");
        fs::remove_dir(root).expect("remove directory");
    }

    #[test]
    fn staleness_storage_rejects_unsafe_parent_before_creating_child() {
        if unsafe { libc::getuid() } != 0 {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "himmelblau-stale-storage-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("test parent");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).expect("unsafe mode");
        let trust = root.join("ssh-ca");
        assert!(prepare_trust_storage(&root, &trust).is_err());
        assert!(!trust.exists());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("safe mode");
        prepare_trust_storage(&root, &trust).expect("secure storage");
        assert_eq!(
            fs::metadata(&trust).expect("trust metadata").mode() & 0o7777,
            0o755
        );
        fs::remove_dir(&trust).expect("remove trust");
        fs::remove_dir(root).expect("remove parent");
    }

    #[test]
    fn response_limit_applies_before_appending_chunk() {
        let mut body = vec![0; MAX_RESPONSE_SIZE - 1];
        assert!(append_response_chunk(&mut body, &[1]).is_ok());
        assert!(append_response_chunk(&mut body, &[2]).is_err());
        assert_eq!(body.len(), MAX_RESPONSE_SIZE);
        assert_eq!(body.last(), Some(&1));
    }

    #[test]
    fn trust_directory_repairs_writable_modes_and_rejects_symlinks() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!(
            "himmelblau-ca-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("test directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).expect("writable mode");
        // This helper runs as root in production; unprivileged tests must verify rejection.
        if unsafe { libc::getuid() } == 0 {
            secure_trust_directory(&root).expect("secure directory");
            assert_eq!(
                fs::metadata(&root).expect("metadata").mode() & 0o7777,
                0o755
            );
        } else {
            assert!(secure_trust_directory(&root).is_err());
        }
        let link = root.with_extension("symlink");
        symlink(&root, &link).expect("test symlink");
        assert!(secure_trust_directory(&link).is_err());
        fs::remove_file(link).expect("remove link");
        let dangling_target = root.with_extension("missing-target");
        let dangling_link = root.with_extension("dangling-symlink");
        symlink(&dangling_target, &dangling_link).expect("test dangling symlink");
        assert!(secure_trust_directory(&dangling_link).is_err());
        assert!(!dangling_target.exists());
        fs::remove_file(dangling_link).expect("remove dangling link");
        fs::remove_dir(root).expect("remove test directory");
    }
}
