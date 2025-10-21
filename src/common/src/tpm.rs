/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use kanidm_hsm_crypto::provider::BoxedDynTpm;
use kanidm_hsm_crypto::AuthValue;
use std::error::Error;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use zeroize::{Zeroize, Zeroizing};

pub fn decrypt_hsm_pin(hsm_pin_path: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    let mut child = Command::new("systemd-creds")
        .arg("decrypt")
        .arg("--name=hsm-pin")
        .arg(hsm_pin_path)
        .arg("-")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let mut stdout = child.stdout.take().ok_or({
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed decrypting HSM PIN from {}", hsm_pin_path),
        )
    })?;
    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf)?;

    // Wait for child exit
    let status = child.wait()?;
    if !status.success() {
        let code = status.code().unwrap_or(-1);
        buf.zeroize();
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed decrypting HSM PIN from {}: {}", hsm_pin_path, code),
        )
        .into());
    }

    while buf.last().copied() == Some(b'\n') {
        buf.pop();
    }

    Ok(buf.into())
}

pub async fn read_hsm_pin(hsm_pin_path: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    if !PathBuf::from_str(hsm_pin_path)?.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("HSM PIN file '{}' not found", hsm_pin_path),
        )
        .into());
    }

    let mut file = File::open(hsm_pin_path).await?;
    let mut contents = vec![];
    file.read_to_end(&mut contents).await?;
    Ok(contents.into())
}

pub async fn write_hsm_pin(hsm_pin_path: &str) -> Result<(), Box<dyn Error>> {
    if !PathBuf::from_str(hsm_pin_path)?.exists() {
        let new_pin = AuthValue::generate().map_err(|hsm_err| {
            error!(?hsm_err, "Unable to generate new pin");
            std::io::Error::new(std::io::ErrorKind::Other, "Unable to generate new pin")
        })?;

        std::fs::write(hsm_pin_path, new_pin)?;

        info!("Generated new HSM pin");
    }

    Ok(())
}

#[cfg(feature = "tpm")]
pub fn open_tpm(tcti_name: &str) -> Option<BoxedDynTpm> {
    use kanidm_hsm_crypto::provider::{BoxedDynTpm, TssTpm};
    match TssTpm::new(tcti_name) {
        Ok(tpm) => {
            debug!("opened hw tpm");
            Some(BoxedDynTpm::new(tpm))
        }
        Err(tpm_err) => {
            error!(?tpm_err, "Unable to open requested tpm device");
            None
        }
    }
}

#[cfg(not(feature = "tpm"))]
pub fn open_tpm(_tcti_name: &str) -> Option<BoxedDynTpm> {
    error!("Hardware TPM supported was not enabled in this build. Unable to proceed");
    None
}

#[cfg(feature = "tpm")]
pub fn open_tpm_if_possible(tcti_name: &str) -> BoxedDynTpm {
    use kanidm_hsm_crypto::provider::{BoxedDynTpm, SoftTpm, TssTpm};
    match TssTpm::new(tcti_name) {
        Ok(tpm) => {
            debug!("opened hw tpm");
            BoxedDynTpm::new(tpm)
        }
        Err(tpm_err) => {
            warn!(
                ?tpm_err,
                "Unable to open requested tpm device, falling back to soft tpm"
            );
            BoxedDynTpm::new(SoftTpm::new())
        }
    }
}

#[cfg(not(feature = "tpm"))]
pub fn open_tpm_if_possible(_tcti_name: &str) -> BoxedDynTpm {
    use kanidm_hsm_crypto::provider::SoftTpm;
    debug!("opened soft tpm");
    BoxedDynTpm::new(SoftTpm::new())
}

#[macro_export]
macro_rules! tpm_init {
    ($cfg:ident, $on_error:expr) => {{
        use himmelblau_unix_common::constants::DEFAULT_HSM_PIN_PATH_ENC;
        use himmelblau_unix_common::tpm::{
            decrypt_hsm_pin, open_tpm, open_tpm_if_possible, read_hsm_pin, write_hsm_pin,
        };
        use himmelblau_unix_common::unix_config::HsmType;
        use kanidm_hsm_crypto::AuthValue;

        // Check for an existing encrypted hsm pin. If present, we MUST be root
        // to decrypt it (aad-tool will use this, or himmelblaud started with
        // `skip-root-check`).
        let hsm_pin = match decrypt_hsm_pin(DEFAULT_HSM_PIN_PATH_ENC) {
            Ok(hsm_pin) => hsm_pin,
            Err(e) => {
                // Himmelblaud might still read the decrypted PIN from systemd
                // later, so we don't want this message explicitly printed to debug.
                trace!("Failed reading encrypted HSM PIN: {}", e);

                // Check for and create the hsm pin if required.
                if let Err(err) = write_hsm_pin(&$cfg.get_hsm_pin_path()).await {
                    error!(
                        ?err,
                        "Failed to create HSM PIN into {}",
                        &$cfg.get_hsm_pin_path()
                    );
                    $on_error
                };
                // read the hsm pin
                match read_hsm_pin(&$cfg.get_hsm_pin_path()).await {
                    Ok(hp) => hp,
                    Err(err) => {
                        error!(
                            ?err,
                            "Failed to read HSM PIN from {}",
                            &$cfg.get_hsm_pin_path()
                        );
                        $on_error
                    }
                }
            }
        };

        let auth_value = match AuthValue::try_from(hsm_pin.as_slice()) {
            Ok(av) => av,
            Err(err) => {
                error!(?err, "invalid hsm pin");
                $on_error
            }
        };

        let mut hsm: BoxedDynTpm = match $cfg.get_hsm_type() {
            HsmType::Soft => BoxedDynTpm::new(SoftTpm::new()),
            HsmType::TpmIfPossible => open_tpm_if_possible(&$cfg.get_tpm_tcti_name()),
            HsmType::Tpm => match open_tpm(&$cfg.get_tpm_tcti_name()) {
                Some(hsm) => hsm,
                None => $on_error,
            },
        };

        (auth_value, hsm)
    }};
}

#[macro_export]
macro_rules! tpm_loadable_machine_key {
    ($db:ident, $hsm:ident, $auth_value:ident, $create:ident, $on_error:expr) => {{
        let mut db_txn = $db.write().await;
        let loadable_machine_key = match db_txn.get_hsm_machine_key() {
            Ok(Some(lmk)) => lmk,
            Ok(None) => {
                if $create {
                    // No machine key found - create one, and store it.
                    let loadable_machine_key = match $hsm.root_storage_key_create(&$auth_value) {
                        Ok(lmk) => lmk,
                        Err(err) => {
                            error!(?err, "Unable to create hsm loadable machine key");
                            $on_error
                        }
                    };

                    if let Err(err) = db_txn.insert_hsm_machine_key(&loadable_machine_key) {
                        error!(?err, "Unable to persist hsm loadable machine key");
                        $on_error
                    }

                    loadable_machine_key
                } else {
                    error!("Unable to access hsm loadable machine key");
                    $on_error
                }
            }
            Err(err) => {
                error!(?err, "Unable to access hsm loadable machine key");
                $on_error
            }
        };

        if $create {
            if let Err(err) = db_txn.commit() {
                error!(
                    ?err,
                    "Failed to commit database transaction, unable to proceed"
                );
                $on_error
            }
        }

        loadable_machine_key
    }};
}

#[macro_export]
macro_rules! tpm_machine_key {
    ($hsm:ident, $auth_value:ident, $loadable_machine_key:ident, $cfg:ident, $on_error:expr) => {
        match $hsm.root_storage_key_load(&$auth_value, &$loadable_machine_key) {
            Ok(mk) => mk,
            Err(err) => {
                error!(?err, "Unable to load machine root key - This can occur if you have changed your HSM pin");
                error!("To proceed you must remove the content of the cache db ({}) to reset all keys", &$cfg.get_db_path());
                $on_error
            }
        }
    };
}

pub fn confidential_client_creds<D: crate::db::KeyStoreTxn + Send>(
    hsm: &mut kanidm_hsm_crypto::provider::BoxedDynTpm,
    keystore: &mut D,
    machine_key: &kanidm_hsm_crypto::structures::StorageKey,
    domain: &str,
) -> Result<Option<(String, himmelblau::ClientCredential)>, crate::idprovider::interface::IdpError>
{
    use crate::constants::{
        CONFIDENTIAL_CLIENT_CERT_KEY_TAG, CONFIDENTIAL_CLIENT_CERT_TAG,
        CONFIDENTIAL_CLIENT_SECRET_TAG,
    };
    use crate::idprovider::interface::IdpError;
    use der::asn1::Utf8StringRef;
    use der::Decode;
    use serde_json::Value;

    let secret_tag = format!("{}/{}", domain, CONFIDENTIAL_CLIENT_SECRET_TAG);
    if let Ok(Some(sealed_secret)) = keystore.get_tagged_hsm_key(&secret_tag) {
        if let Ok(secret_info) = hsm.unseal_data(machine_key, &sealed_secret) {
            let value: Value =
                serde_json::from_str(&String::from_utf8(secret_info.to_vec()).map_err(|e| {
                    error!(?e, "Failed extracting secret from cache");
                    IdpError::KeyStore
                })?)
                .map_err(|e| {
                    error!(?e, "Failed extracting secret from cache");
                    IdpError::KeyStore
                })?;

            let secret = value["secret"].as_str().ok_or_else(|| {
                error!("Failed extracting secret from cache");
                IdpError::KeyStore
            })?;
            let client_id = value["client_id"].as_str().ok_or_else(|| {
                error!("Failed extracting secret client_id from cache");
                IdpError::KeyStore
            })?;

            return Ok(Some((
                client_id.to_string(),
                himmelblau::ClientCredential::from_secret(secret.to_string()),
            )));
        }
    }

    let key_tag = format!("{}/{}", domain, CONFIDENTIAL_CLIENT_CERT_KEY_TAG);
    if let Ok(Some(loadable_cert_key)) = keystore.get_tagged_hsm_key(&key_tag) {
        let key = hsm
            .msoapxbc_rsa_key_load(machine_key, &loadable_cert_key)
            .map_err(|e| {
                error!("Failed to load IdentityKey: {:?}", e);
                IdpError::KeyStore
            })?;

        let cert_tag = format!("{}/{}", domain, CONFIDENTIAL_CLIENT_CERT_TAG);
        if let Ok(Some(sealed_cert)) = keystore.get_tagged_hsm_key(&cert_tag) {
            let cert = kanidm_lib_crypto::x509_cert::Certificate::from_der(
                &hsm.unseal_data(machine_key, &sealed_cert).map_err(|e| {
                    error!("Failed to unseal certificate: {:?}", e);
                    IdpError::KeyStore
                })?,
            )
            .map_err(|e| {
                error!("Failed to load certificate: {:?}", e);
                IdpError::KeyStore
            })?;

            let client_id = cert
                .tbs_certificate
                .subject
                .as_ref()
                .iter()
                .flat_map(|rdn| rdn.0.iter())
                .find_map(|attr| {
                    (attr.oid.to_string() == "2.5.4.3")
                        .then(|| attr.value.decode_as::<Utf8StringRef>().ok())
                        .flatten()
                })
                .ok_or_else(|| {
                    error!("Failed extracting client_id from certificate");
                    IdpError::KeyStore
                })?
                .to_string();

            return Ok(Some((
                client_id,
                himmelblau::ClientCredential::from_certificate(&cert, key),
            )));
        }
    }

    Ok(None)
}
