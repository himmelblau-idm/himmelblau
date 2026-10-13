//! Collabora's current Qt build stores cloud providers in the starter page's
//! Chromium localStorage. Keep this isolated so a future native config bridge
//! can replace it without changing the Graph service.
use anyhow::{bail, Context, Result};
use rusty_leveldb::{LdbIterator, Options, DB};
use serde_json::{json, Value};
use std::{
    env,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
};

const PROVIDERS: &str = "coda.cloudProviders";
const ORIGIN: &str = "file://";
const PROVIDER_ID: &str = "himmelblau-microsoft365";

fn profiles() -> Result<Vec<PathBuf>> {
    let home = PathBuf::from(env::var("HOME").context("HOME is unset")?);
    let native = env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".config"));
    Ok(vec![
        home.join(".var/app/com.collaboraoffice.Office/config/Collabora Office"),
        native.join("Collabora Office"),
    ])
}

fn key() -> Vec<u8> {
    let mut key = format!("_{ORIGIN}\0").into_bytes();
    key.push(1); // Chromium Latin-1 string marker.
    key.extend_from_slice(PROVIDERS.as_bytes());
    key
}

fn decode(bytes: &[u8]) -> Result<String> {
    match bytes.first() {
        Some(1) => Ok(bytes[1..].iter().map(|b| char::from(*b)).collect()),
        Some(0) => {
            let rest = &bytes[1..];
            if rest.len() % 2 != 0 {
                bail!("Invalid UTF-16 localStorage value");
            }
            let chars = rest
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]));
            Ok(String::from_utf16(&chars.collect::<Vec<_>>())?)
        }
        _ => bail!("Unknown localStorage encoding"),
    }
}

fn encode(value: &str) -> Vec<u8> {
    if value.chars().all(|c| (c as u32) <= 255) {
        let mut bytes = vec![1];
        bytes.extend(value.chars().map(|c| c as u8));
        bytes
    } else {
        let mut bytes = vec![0];
        for unit in value.encode_utf16() {
            bytes.extend(unit.to_le_bytes());
        }
        bytes
    }
}

fn private_directory(path: &Path) -> Result<()> {
    // Refuse symlinks: chmod must not affect a target outside this profile.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_dir() => bail!("Profile storage is not a directory"),
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(path)?;
        }
        Err(err) => return Err(err.into()),
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn secure_storage(root: &Path) -> Result<PathBuf> {
    private_directory(root)?;
    private_directory(&root.join("Local Storage"))?;
    let path = root.join("Local Storage/leveldb");
    private_directory(&path)?;
    for entry in std::fs::read_dir(&path)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        if !metadata.is_file() {
            bail!("Unexpected non-file in Collabora localStorage");
        }
        std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

fn provision_one(root: &PathBuf, url: &str) -> Result<()> {
    if !root.exists() {
        bail!("Collabora profile does not exist yet");
    }
    let path = secure_storage(root)?;
    let mut db = DB::open(&path, Options::default())
        .map_err(|e| anyhow::anyhow!("Cannot open {}: {e}", path.display()))?;
    let key = key();
    let existing = db.get(&key).map(|v| decode(&v)).transpose()?;
    let mut providers: Vec<Value> = match existing {
        Some(text) => serde_json::from_str(&text).context("Invalid Collabora provider list")?,
        None => Vec::new(),
    };
    let registered: Vec<_> = providers
        .iter()
        .filter(|p| p.get("id").and_then(Value::as_str) == Some(PROVIDER_ID))
        .collect();
    if registered.len() == 1 && registered[0].get("url").and_then(Value::as_str) == Some(url) {
        db.close().map_err(|e| anyhow::anyhow!("DB close: {e}"))?;
        secure_storage(root)?;
        return Ok(());
    }
    providers.retain(|p| p.get("id").and_then(Value::as_str) != Some(PROVIDER_ID));
    providers.push(json!({"id":PROVIDER_ID,"kind":"other","name":"Microsoft 365","url":url}));
    let encoded = encode(&serde_json::to_string(&providers)?);
    // Chromium's schema marker and origin metadata are required for new stores.
    db.put(b"VERSION", b"1")
        .map_err(|e| anyhow::anyhow!("DB version: {e}"))?;
    db.put(&key, &encoded)
        .map_err(|e| anyhow::anyhow!("DB provider: {e}"))?;
    update_metadata(&mut db)?;
    db.flush().map_err(|e| anyhow::anyhow!("DB flush: {e}"))?;
    db.close().map_err(|e| anyhow::anyhow!("DB close: {e}"))?;
    secure_storage(root)?;
    Ok(())
}

fn update_metadata(db: &mut DB) -> Result<()> {
    let mut size = 0;
    let prefix = format!("_{ORIGIN}\0");
    let mut iter = db
        .new_iter()
        .map_err(|e| anyhow::anyhow!("DB iterator: {e}"))?;
    iter.seek(prefix.as_bytes());
    while let Some((stored_key, stored_value)) = iter.current() {
        if !stored_key.starts_with(prefix.as_bytes()) {
            break;
        }
        size += stored_key.len() - prefix.len() + stored_value.len();
        if !iter.advance() {
            break;
        }
    }
    let meta = metadata(size);
    db.put(format!("META:{ORIGIN}").as_bytes(), &meta)
        .map_err(|e| anyhow::anyhow!("DB metadata: {e}"))?;
    Ok(())
}

// LocalStorageOriginMetaData protobuf: field 1 is WebKit microseconds since
// 1601-01-01; field 2 is the storage byte count.
fn metadata(size: usize) -> Vec<u8> {
    let unix_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;
    let mut out = vec![8];
    varint(unix_us + 11_644_473_600_000_000, &mut out);
    out.push(16);
    varint(size as u64, &mut out);
    out
}

fn varint(mut number: u64, output: &mut Vec<u8>) {
    while number >= 128 {
        output.push((number as u8) | 128);
        number >>= 7;
    }
    output.push(number as u8);
}

pub fn provision(url: &str) -> Result<()> {
    let mut success = false;
    for root in profiles()? {
        match provision_one(&root, url) {
            Ok(()) => success = true,
            Err(err) => {
                tracing::warn!(path=%root.display(), "Cannot register Collabora provider: {err}")
            }
        }
    }
    if !success {
        bail!("No Collabora profile could be updated");
    }
    Ok(())
}

/// Run as the profile owner, after stopping the bridge and closing Collabora.
pub fn remove() -> Result<()> {
    for root in profiles()? {
        remove_one(&root)?;
    }
    Ok(())
}

fn remove_one(root: &PathBuf) -> Result<()> {
    let path = root.join("Local Storage/leveldb");
    if !path.exists() {
        return Ok(());
    }
    secure_storage(&root)?;
    let mut db = DB::open(&path, Options::default())
        .map_err(|e| anyhow::anyhow!("Cannot open {}: {e}", path.display()))?;
    if let Some(bytes) = db.get(&key()) {
        let mut providers: Vec<Value> = serde_json::from_str(&decode(&bytes)?)?;
        providers.retain(|p| p.get("id").and_then(Value::as_str) != Some(PROVIDER_ID));
        db.put(&key(), &encode(&serde_json::to_string(&providers)?))
            .map_err(|e| anyhow::anyhow!("DB provider cleanup: {e}"))?;
        update_metadata(&mut db)?;
        db.flush().map_err(|e| anyhow::anyhow!("DB flush: {e}"))?
    }
    db.close().map_err(|e| anyhow::anyhow!("DB close: {e}"))?;
    secure_storage(&root)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_storage_round_trip_preserves_other_clouds() {
        let root = env::temp_dir().join(format!("collabora-profile-{}", uuid::Uuid::new_v4()));
        let path = root.join("Local Storage/leveldb");
        std::fs::create_dir_all(&path).unwrap();
        {
            let mut db = DB::open(&path, Options::default()).unwrap();
            db.put(&key(), &encode(r#"[{"id":"other-1","kind":"other","name":"My cloud","url":"https://example.invalid"}]"#)).unwrap();
            db.close().unwrap();
        }
        provision_one(&root, "http://127.0.0.1:42310/?k=first").unwrap();
        provision_one(&root, "http://127.0.0.1:42310/?k=second").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for entry in std::fs::read_dir(&path).unwrap() {
            assert_eq!(
                entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let mut db = DB::open(&path, Options::default()).unwrap();
        let text = decode(&db.get(&key()).unwrap()).unwrap();
        let providers: Vec<Value> = serde_json::from_str(&text).unwrap();
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0]["name"], "My cloud");
        assert_eq!(providers[1]["url"], "http://127.0.0.1:42310/?k=second");
        db.close().unwrap();
        remove_one(&root).unwrap();
        let mut db = DB::open(&path, Options::default()).unwrap();
        let providers: Vec<Value> =
            serde_json::from_str(&decode(&db.get(&key()).unwrap()).unwrap()).unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0]["id"], "other-1");
        db.close().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_profiles_are_not_created() {
        let root = env::temp_dir().join(format!("collabora-missing-{}", uuid::Uuid::new_v4()));
        assert!(provision_one(&root, "http://127.0.0.1:1234/?k=secret").is_err());
        assert!(!root.exists());
    }

    #[test]
    fn chromium_string_encodings() {
        assert_eq!(decode(&encode("München 🌍")).unwrap(), "München 🌍");
        assert_eq!(decode(&encode("Microsoft 365")).unwrap(), "Microsoft 365");
    }
}
