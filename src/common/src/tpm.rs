/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use kanidm_hsm_crypto::AuthValue;
use std::error::Error;
use std::path::PathBuf;
use std::str::FromStr;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

pub async fn read_hsm_pin(hsm_pin_path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
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
    Ok(contents)
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

#[macro_export]
macro_rules! tpm_init {
    ($cfg:ident) => {{
        use himmelblau_unix_common::tpm::{read_hsm_pin, write_hsm_pin};
        use himmelblau_unix_common::unix_config::HsmType;
        use kanidm_hsm_crypto::AuthValue;

        // Check for and create the hsm pin if required.
        if let Err(err) = write_hsm_pin(&$cfg.get_hsm_pin_path()).await {
            error!(
                ?err,
                "Failed to create HSM PIN into {}",
                &$cfg.get_hsm_pin_path()
            );
            return ExitCode::FAILURE;
        };
        // read the hsm pin
        let hsm_pin = match read_hsm_pin(&$cfg.get_hsm_pin_path()).await {
            Ok(hp) => hp,
            Err(err) => {
                error!(
                    ?err,
                    "Failed to read HSM PIN from {}",
                    &$cfg.get_hsm_pin_path()
                );
                return ExitCode::FAILURE;
            }
        };

        let auth_value = match AuthValue::try_from(hsm_pin.as_slice()) {
            Ok(av) => av,
            Err(err) => {
                error!(?err, "invalid hsm pin");
                return ExitCode::FAILURE;
            }
        };

        let mut hsm: BoxedDynTpm = match $cfg.get_hsm_type() {
            HsmType::Soft => BoxedDynTpm::new(SoftTpm::new()),
            HsmType::Tpm => {
                error!("TPM not supported ... yet");
                return ExitCode::FAILURE;
            }
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
                    let loadable_machine_key = match $hsm.machine_key_create(&$auth_value) {
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
        match $hsm.machine_key_load(&$auth_value, &$loadable_machine_key) {
            Ok(mk) => mk,
            Err(err) => {
                error!(?err, "Unable to load machine root key - This can occur if you have changed your HSM pin");
                error!("To proceed you must remove the content of the cache db ({}) to reset all keys", &$cfg.get_db_path());
                $on_error
            }
        }
    };
}
