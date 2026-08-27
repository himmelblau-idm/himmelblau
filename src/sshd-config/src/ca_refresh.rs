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
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_RESPONSE_SIZE: usize = 256 * 1024;
const TRUST_DIR: &str = "/var/lib/himmelblau/ssh-ca";
const TRUST_FILE: &str = "/var/lib/himmelblau/ssh-ca/trusted_user_ca_keys";
const PROVENANCE_FILE: &str = "/var/lib/himmelblau/ssh-ca/provenance.json";

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
    keys: Vec<KeyProvenance>,
}

#[derive(Debug, Deserialize)]
struct FreshnessProvenance {
    source_url: String,
    retrieved_at_unix: u64,
    max_age_seconds: u64,
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

fn configured_authority() -> Result<String, String> {
    let config = HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH))
        .map_err(|err| format!("read Himmelblau configuration: {err}"))?;
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
    let result = match std::env::args().nth(1).as_deref() {
        None => run().await,
        Some("--disable-if-stale") => disable_if_stale(),
        Some(_) => Err("usage: himmelblau-ssh-ca-refresh [--disable-if-stale]".to_string()),
    };
    if let Err(err) = result {
        eprintln!("Himmelblau Microsoft SSH CA refresh failed: {err}");
        std::process::exit(1);
    }
}

fn disable_if_stale() -> Result<(), String> {
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } != 0 {
        return Err("CA refresh must run as root".into());
    }
    let bytes = fs::read(PROVENANCE_FILE)
        .map_err(|err| format!("read last-known-good CA provenance: {err}"))?;
    if bytes.len() > MAX_RESPONSE_SIZE {
        return Err("CA provenance exceeds size limit".into());
    }
    let provenance: FreshnessProvenance = serde_json::from_slice(&bytes)
        .map_err(|err| format!("parse last-known-good CA provenance: {err}"))?;
    let deadline = provenance
        .retrieved_at_unix
        .checked_add(provenance.max_age_seconds)
        .ok_or_else(|| "invalid CA freshness deadline".to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_secs();
    if now <= deadline {
        return Err(format!(
            "last-known-good Microsoft CA set remains fresh until Unix time {deadline}"
        ));
    }

    // Keep the configured path present, but remove all trust anchors. The
    // caller validates and reloads sshd before this takes effect.
    atomic_write(
        Path::new(TRUST_FILE),
        b"# Microsoft SSH CA trust disabled: last-known-good set is stale\n",
        0o644,
    )?;
    eprintln!(
        "Disabled stale Microsoft SSH CA trust from {} (retrieved at Unix time {})",
        provenance.source_url, provenance.retrieved_at_unix
    );
    Ok(())
}

async fn run() -> Result<(), String> {
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } != 0 {
        return Err("CA refresh must run as root".into());
    }
    let authority = configured_authority()?;
    let (source_url, expected_cloud) = endpoint(&authority)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| format!("build HTTPS client: {err}"))?;
    let response = client
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
    let body = response
        .bytes()
        .await
        .map_err(|err| format!("read Microsoft response: {err}"))?;
    if body.len() > MAX_RESPONSE_SIZE {
        return Err("Microsoft response exceeds size limit".into());
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
        if key.kty != "RSA" || key.usage != "sig" || key.x5c.len() != 1 || key.kid.is_empty() {
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
        if !certificate
            .verify(&certificate_key)
            .map_err(|err| format!("verify x5c for {}: {err}", key.kid))?
        {
            return Err(format!("invalid x5c self-signature for {}", key.kid));
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

    fs::create_dir_all(TRUST_DIR).map_err(|err| format!("create trust directory: {err}"))?;
    fs::set_permissions(TRUST_DIR, fs::Permissions::from_mode(0o755))
        .map_err(|err| format!("secure trust directory: {err}"))?;
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
        keys: provenance_keys,
    };
    let provenance_json = serde_json::to_vec_pretty(&provenance).map_err(|err| err.to_string())?;
    let old_trust = fs::read(TRUST_FILE).ok();
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
