/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2025

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
use crate::idprovider::interface::IdpError;
use kanidm_hsm_crypto::structures::SealedData;
use serde::{Deserialize, Serialize};
use std::thread::sleep;
use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};
use tokio::sync::RwLock;

pub fn flip_displayname_comma(name: &str) -> String {
    if let Some((left, right)) = name.split_once(',') {
        format!("{} {}", right.trim(), left.trim())
    } else {
        name.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpEnrollmentRecord {
    pub secret_b32: String,
    pub digits: usize,
    pub skew: u8,
    pub step: u64,
    pub issuer: String,
    pub account_name: String,
}

#[macro_export]
macro_rules! extract_base_url {
    ($msg:expr) => {{
        if let Ok(regex) = Regex::new(r#"https?://[^\s"'<>]+"#) {
            if let Some(mat) = regex.find(&$msg) {
                if let Ok(mut parsed) = Url::parse(mat.as_str()) {
                    parsed.set_query(None);
                    parsed.set_fragment(None);
                    Some(parsed.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }};
}

pub(crate) struct RefreshCache {
    refresh_cache: RwLock<HashMap<String, (SealedData, SystemTime)>>,
    refresh_token_cache: RwLock<HashMap<String, (String, SystemTime)>>,
}

pub(crate) enum RefreshCacheEntry {
    Prt(SealedData),
    RefreshToken(String),
}

impl RefreshCache {
    pub(crate) fn new() -> Self {
        RefreshCache {
            refresh_cache: RwLock::new(HashMap::new()),
            refresh_token_cache: RwLock::new(HashMap::new()),
        }
    }

    pub(crate) async fn refresh_token(
        &self,
        account_id: &str,
    ) -> Result<RefreshCacheEntry, IdpError> {
        self.purge().await;
        let refresh_cache = self.refresh_cache.read().await;
        match refresh_cache.get(account_id.to_lowercase().as_str()) {
            Some((refresh_token, _)) => Ok(RefreshCacheEntry::Prt(refresh_token.clone())),
            None => {
                let refresh_token_cache = self.refresh_token_cache.read().await;
                match refresh_token_cache.get(account_id.to_lowercase().as_str()) {
                    Some((refresh_token, _)) => {
                        Ok(RefreshCacheEntry::RefreshToken(refresh_token.clone()))
                    }
                    None => Err(IdpError::NotFound {
                        what: "account_id".to_string(),
                        where_: "refresh_cache".to_string(),
                    }),
                }
            }
        }
    }

    pub(crate) async fn purge(&self) {
        let mut refresh_cache = self.refresh_cache.write().await;
        let mut remove_list = vec![];
        for (k, (_, iat)) in refresh_cache.iter() {
            if *iat > SystemTime::now() + Duration::from_secs(86400) {
                remove_list.push(k.clone());
            }
        }
        for k in remove_list.iter() {
            refresh_cache.remove_entry(k);
        }
        let mut refresh_token_cache = self.refresh_token_cache.write().await;
        let mut remove_list = vec![];
        for (k, (_, iat)) in refresh_token_cache.iter() {
            if *iat > SystemTime::now() + Duration::from_secs(86400) {
                remove_list.push(k.clone());
            }
        }
        for k in remove_list.iter() {
            refresh_token_cache.remove_entry(k);
        }
    }

    pub(crate) async fn add(&self, account_id: &str, refresh_token: &RefreshCacheEntry) {
        match refresh_token {
            RefreshCacheEntry::Prt(prt) => {
                let mut refresh_cache = self.refresh_cache.write().await;
                refresh_cache.insert(
                    account_id.to_string().to_lowercase(),
                    (prt.clone(), SystemTime::now()),
                );
            }
            RefreshCacheEntry::RefreshToken(refresh_token) => {
                let mut refresh_token_cache = self.refresh_token_cache.write().await;
                refresh_token_cache.insert(
                    account_id.to_string().to_lowercase(),
                    (refresh_token.clone(), SystemTime::now()),
                );
            }
        }
    }
}

pub struct BadPinCounter {
    counter: RwLock<HashMap<String, u32>>,
}

impl Default for BadPinCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl BadPinCounter {
    pub(crate) fn new() -> Self {
        BadPinCounter {
            counter: RwLock::new(HashMap::new()),
        }
    }

    pub(crate) async fn bad_pin_count(&self, account_id: &str) -> u32 {
        let map = self.counter.read().await;
        *map.get(account_id).unwrap_or(&0)
    }

    pub(crate) async fn increment_bad_pin_count(&self, account_id: &str) {
        let mut map = self.counter.write().await;
        let counter = map.entry(account_id.to_string()).or_insert(0);
        *counter += 1;

        // Discourage attackers by waiting for an ever increasing wait time for each bad pin
        sleep(Duration::from_secs((*counter as u64) * 2));
    }

    pub(crate) async fn reset_bad_pin_count(&self, account_id: &str) {
        let mut map = self.counter.write().await;
        map.insert(account_id.to_string(), 0);
    }
}

#[macro_export]
macro_rules! handle_hello_bad_pin_count {
    ($self:expr, $account_id:expr, $keystore:expr, $ret_fn:expr) => {{
        $self.bad_pin_counter
            .increment_bad_pin_count($account_id)
            .await;

        let hello_pin_retry_count = $self.config.read().await.get_hello_pin_retry_count();
        let bad_pin_count = $self.bad_pin_counter.bad_pin_count($account_id).await;

        if bad_pin_count == hello_pin_retry_count {
            return $ret_fn(
                "Failed to authenticate with Hello PIN. One more failed attempt will require multi-factor authentication and resetting your Linux Hello PIN."
            );
        }

        // If we've exceeded the bad pin count, delete the Hello key
        if bad_pin_count > hello_pin_retry_count {
            let hello_key_tag = $self.fetch_hello_key_tag($account_id, true);
            $keystore
                .delete_tagged_hsm_key(&hello_key_tag)
                .map_err(|e| {
                    error!("Failed to delete hello key: {:?}", e);
                    IdpError::Tpm
                })?;
            let hello_key_tag = $self.fetch_hello_key_tag($account_id, false);
            $keystore
                .delete_tagged_hsm_key(&hello_key_tag)
                .map_err(|e| {
                    error!("Failed to delete hello key: {:?}", e);
                    IdpError::Tpm
                })?;
            let hello_prt_tag = $self.fetch_hello_prt_key_tag($account_id);
            $keystore
                .delete_tagged_hsm_key(&hello_prt_tag)
                .map_err(|e| {
                    error!("Failed to delete hello PRT: {:?}", e);
                    IdpError::Tpm
                })?;
            let hello_refresh_token_tag = $self.fetch_hello_refresh_token_key_tag($account_id);
            $keystore
                .delete_tagged_hsm_key(&hello_refresh_token_tag)
                .map_err(|e| {
                    error!("Failed to delete hello refresh token: {:?}", e);
                    IdpError::Tpm
                })?;
            return $ret_fn(
                "Too many incorrect PIN attempts. You will need to enroll a new Linux Hello PIN."
            );
        }
    }};
}

#[derive(PartialEq)]
pub(crate) enum KeyType {
    Hello,
    Decoupled,
}

#[macro_export]
macro_rules! impl_offline_break_glass {
    ($self:ident, $ttl:ident) => {{
        let mut state = $self.state.lock().await;
        let (ttl, enabled) = {
            let cfg = $self.config.read().await;
            (
                match $ttl {
                    Some(ttl) => ttl,
                    None => cfg.get_offline_breakglass_ttl(),
                },
                cfg.get_offline_breakglass_enabled(),
            )
        };
        if enabled {
            let offline_next_check = Duration::from_secs(ttl);
            *state = CacheState::OfflineNextCheck(SystemTime::now() + offline_next_check);
        }
        Ok(())
    }};
}

#[macro_export]
macro_rules! impl_himmelblau_hello_key_helpers {
    () => {
        fn fetch_hello_key_tag(&self, account_id: &str, amr_ngcmfa: bool) -> String {
            if amr_ngcmfa {
                format!("{}/hello", account_id.to_lowercase())
            } else {
                format!("{}/hello_decoupled", account_id.to_lowercase())
            }
        }

        #[instrument(level = "debug", skip_all)]
        fn fetch_hello_key<D: KeyStoreTxn + Send>(
            &self,
            account_id: &str,
            keystore: &mut D,
        ) -> Result<(LoadableMsHelloKey, KeyType), IdpError> {
            match keystore.get_tagged_hsm_key(&format!("{}/hello", account_id.to_lowercase())) {
                Ok(Some(hello_key)) => Ok((hello_key, KeyType::Hello)),
                Err(_) | Ok(None) => {
                    let hello_key = keystore
                        .get_tagged_hsm_key(&format!(
                            "{}/hello_decoupled",
                            account_id.to_lowercase()
                        ))
                        .map_err(|_| IdpError::BadRequest)?
                        .ok_or(IdpError::BadRequest)?;
                    Ok((hello_key, KeyType::Decoupled))
                }
            }
        }

        fn fetch_hello_prt_key_tag(&self, account_id: &str) -> String {
            format!("{}/hello_prt", account_id.to_lowercase())
        }

        fn fetch_hello_refresh_token_key_tag(&self, account_id: &str) -> String {
            format!("{}/hello_refresh_token", account_id.to_lowercase())
        }

        fn fetch_hello_totp_key_tag(&self, account_id: &str) -> String {
            format!("{}/hello_totp", account_id.to_lowercase())
        }
    };
}

#[macro_export]
macro_rules! load_cached_prt {
    ($hello_key:ident, $cred:ident, $self:ident, $account_id:expr, $keystore:expr, $tpm:expr, $machine_key:expr) => {
        // Check for and decrypt any cached PRT
        let hello_prt_tag = $self.fetch_hello_prt_key_tag($account_id);
        if let Ok(Some(hello_prt)) = $keystore.get_tagged_hsm_key(&hello_prt_tag) {
            let prt = $self
                .client
                .read()
                .await
                .unseal_user_prt_with_hello_key(&hello_prt, &$hello_key, &$cred, $tpm, $machine_key)
                .map_err(|e| {
                    error!("Failed to load hello prt: {:?}", e);
                    IdpError::Tpm
                })?;
            // Check if the cached PRT has expired.
            // This happens after 14 days of no online contact.
            if $self
                .client
                .read()
                .await
                .is_prt_expired(&prt, $tpm, $machine_key)
                .map_err(|e| {
                    error!("Failed to check prt expiration: {:?}", e);
                    IdpError::Tpm
                })?
            {
                return Ok(AuthResult::Denied(
                    "Offline auth has expired. Please connect to the network to continue."
                        .to_string(),
                ));
            }
            $self
                .refresh_cache
                .add($account_id, &RefreshCacheEntry::Prt(prt.clone()))
                .await;
        }
    };
}

#[macro_export]
macro_rules! load_cached_prt_no_op {
    ($hello_key:ident, $cred:ident, $self:ident, $account_id:expr, $keystore:expr, $tpm:expr, $machine_key:expr) => {
        // No-op, since openidconnect does not have PRTs
    };
}

#[macro_export]
macro_rules! impl_himmelblau_offline_auth_init {
    ($self:ident, $account_id:expr, $no_hello_pin:ident, $keystore:expr, $password_auth:expr) => {{
        let hello_key = $self.fetch_hello_key($account_id, $keystore).ok();
        let (sfa_enabled, hello_pin_retry_count, breakglass_enabled) = {
            let cfg = $self.config.read().await;
            (
                cfg.get_enable_sfa_fallback(),
                cfg.get_hello_pin_retry_count(),
                cfg.get_offline_breakglass_enabled(),
            )
        };
        // We only have 2 options when performing an offline auth; Hello PIN,
        // or cached password for SFA users. If neither option is available,
        // we should respond with a resonable error indicating how to proceed.
        if hello_key.is_some()
            && $self.bad_pin_counter.bad_pin_count($account_id).await <= hello_pin_retry_count
            && !$no_hello_pin
        {
            Ok((AuthRequest::Pin, AuthCredHandler::None))
        } else if $password_auth && (sfa_enabled || breakglass_enabled) {
            Ok((AuthRequest::Password, AuthCredHandler::None))
        } else {
            Ok((
                AuthRequest::InitDenied {
                    msg: "Network outage detected.".to_string(),
                },
                AuthCredHandler::None,
            ))
        }
    }};
}

#[macro_export]
macro_rules! impl_handle_hello_pin_totp_auth {
    ($self:ident, $account_id:expr, $keystore:expr, $token:expr, $cred:ident, $hello_pin:ident, $tpm:expr, $machine_key:expr, $pending_sealed_totp:expr, $auth_cache_action:expr) => {{
        let hello_totp_tag = $self.fetch_hello_totp_key_tag($account_id);
        // Track if this is a pending setup (need to save to HSM on success)
        let is_pending_setup = $pending_sealed_totp.is_some();
        // If we have a pending sealed TOTP (from setup), use it. Otherwise fetch from HSM.
        let sealed_totp_secret: SealedData = if let Some(ref pending) = $pending_sealed_totp {
            pending.clone()
        } else if let Ok(Some(stored)) = $keystore.get_tagged_hsm_key(&hello_totp_tag) {
            stored
        } else {
            error!("Failed to get hello totp key");
            return Err(IdpError::BadRequest);
        };

        let (hello_key, _keytype) = $self.fetch_hello_key($account_id, $keystore).map_err(|e| {
            error!("Offline authentication failed. Hello key missing.");
            e
        })?;

        let pin = PinValue::new(&$hello_pin).map_err(|e| {
            error!("Failed setting pin value: {:?}", e);
            IdpError::Tpm
        })?;
        match $tpm.ms_hello_key_load($machine_key, &hello_key, &pin) {
            Ok((_, win_hello_storage_key)) => {
                let totp_secret = String::from_utf8(
                    $tpm.unseal_data(&win_hello_storage_key, &sealed_totp_secret)
                        .map_err(|e| {
                            error!("Failed to unseal totp secrets: {:?}", e);
                            IdpError::Tpm
                        })?
                        .to_vec(),
                )
                .map_err(|e| {
                    error!("Failed to decode totp secrets: {:?}", e);
                    IdpError::Tpm
                })?;
                let record: TotpEnrollmentRecord =
                    serde_json::from_str(&totp_secret).map_err(|e| {
                        error!("Failed to parse totp record: {:?}", e);
                        IdpError::Tpm
                    })?;
                let totp = TOTP::new(
                    Algorithm::SHA1,
                    record.digits,
                    record.skew,
                    record.step,
                    Secret::Encoded(record.secret_b32.clone())
                        .to_bytes()
                        .map_err(|e| {
                            error!("Failed to decode totp secret: {:?}", e);
                            IdpError::Tpm
                        })?,
                    Some(record.issuer.clone()),
                    record.account_name.clone(),
                )
                .map_err(|e| {
                    error!("Failed to create TOTP instance: {:?}", e);
                    IdpError::Tpm
                })?;
                if totp.check_current(&$cred).map_err(|e| {
                    error!("Failed to verify TOTP code: {:?}", e);
                    IdpError::Tpm
                })? {
                    // TOTP validation succeeded - save to HSM if this was a pending setup
                    if is_pending_setup {
                        $keystore
                            .insert_tagged_hsm_key(&hello_totp_tag, &sealed_totp_secret)
                            .map_err(|e| {
                                error!("Failed to store hello totp key: {:?}", e);
                                IdpError::Tpm
                            })?;
                    }
                    $self.bad_pin_counter.reset_bad_pin_count($account_id).await;
                    Ok(($auth_cache_action)(AuthResult::Success {
                        token: $token.clone(),
                    }))
                } else {
                    handle_hello_bad_pin_count!($self, $account_id, $keystore, |msg: &str| {
                        Ok(($auth_cache_action)(AuthResult::Denied(msg.to_string())))
                    });
                    Ok(($auth_cache_action)(AuthResult::Denied(
                        "Failed to authenticate with Hello TOTP code.".to_string(),
                    )))
                }
            }
            Err(e) => {
                error!("{:?}", e);
                handle_hello_bad_pin_count!($self, $account_id, $keystore, |msg: &str| {
                    Ok(($auth_cache_action)(AuthResult::Denied(msg.to_string())))
                });
                Ok(($auth_cache_action)(AuthResult::Denied(
                    "Failed to authenticate with Hello TOTP code.".to_string(),
                )))
            }
        }
    }};
}

#[macro_export]
macro_rules! check_hello_totp_setup {
    ($self:ident, $account_id:expr, $keystore:expr) => {{
        let hello_totp_tag = $self.fetch_hello_totp_key_tag($account_id);
        let totp_key: Option<SealedData> = $keystore
            .get_tagged_hsm_key(&hello_totp_tag)
            .map_err(|e| {
                error!("Failed to get hello totp key: {:?}", e);
                IdpError::Tpm
            })
            .ok()
            .flatten();
        totp_key.is_some()
    }};
}

#[macro_export]
macro_rules! check_hello_totp_enabled {
    ($self:ident) => {{
        let cfg = $self.config.read().await;
        cfg.get_enable_hello_totp()
    }};
}

#[macro_export]
macro_rules! impl_himmelblau_offline_auth_step {
    ($cred_handler:expr, $pam_next_req:expr, $self:ident, $account_id:expr, $keystore:expr, $tpm:expr, $machine_key:expr, $token:expr, $load_cached_prt:ident) => {{
        match (&$cred_handler, $pam_next_req) {
            (_, PamAuthRequest::Pin { cred }) => {
                let (hello_key, _keytype) =
                    $self.fetch_hello_key($account_id, $keystore).map_err(|e| {
                        error!("Offline authentication failed. Hello key missing.");
                        e
                    })?;

                let pin = PinValue::new(&cred).map_err(|e| {
                    error!("Failed setting pin value: {:?}", e);
                    IdpError::Tpm
                })?;
                match $tpm.ms_hello_key_load($machine_key, &hello_key, &pin) {
                    Ok((_, win_hello_storage_key)) => {
                        $load_cached_prt!(
                            hello_key,
                            cred,
                            $self,
                            $account_id,
                            $keystore,
                            $tpm,
                            $machine_key
                        );

                        let hello_refresh_token_tag =
                            $self.fetch_hello_refresh_token_key_tag($account_id);
                        if let Ok(Some(sealed_refresh_token)) =
                            $keystore.get_tagged_hsm_key(&hello_refresh_token_tag)
                        {
                            let refresh_token = String::from_utf8(
                                $tpm.unseal_data(&win_hello_storage_key, &sealed_refresh_token)
                                    .map_err(|e| {
                                        error!("Failed to unseal refresh token: {:?}", e);
                                        IdpError::Tpm
                                    })?
                                    .to_vec(),
                            )
                            .map_err(|e| {
                                error!("Failed to decode refresh token: {:?}", e);
                                IdpError::Tpm
                            })?;
                            $self
                                .refresh_cache
                                .add($account_id, &RefreshCacheEntry::RefreshToken(refresh_token))
                                .await;
                        }
                        if check_hello_totp_setup!($self, $account_id, $keystore)
                            && check_hello_totp_enabled!($self)
                        {
                            Ok(AuthResult::Next(AuthRequest::HelloTOTP {
                                msg: "Please enter your Hello TOTP code from your Authenticator: "
                                    .to_string(),
                            }))
                        } else {
                            $self.bad_pin_counter.reset_bad_pin_count($account_id).await;
                            Ok(AuthResult::Success {
                                token: $token.clone(),
                            })
                        }
                    }
                    Err(e) => {
                        error!("{:?}", e);
                        handle_hello_bad_pin_count!($self, $account_id, $keystore, |msg: &str| {
                            Ok(AuthResult::Denied(msg.to_string()))
                        });
                        Ok(AuthResult::Denied(
                            "Failed to authenticate with Hello PIN.".to_string(),
                        ))
                    }
                }
            }
            (
                AuthCredHandler::HelloTOTP {
                    cred: hello_pin,
                    pending_sealed_totp,
                },
                PamAuthRequest::HelloTOTP { cred },
            ) => {
                impl_handle_hello_pin_totp_auth!(
                    $self,
                    $account_id,
                    $keystore,
                    $token,
                    cred,
                    hello_pin,
                    $tpm,
                    $machine_key,
                    pending_sealed_totp,
                    |auth_result| { auth_result }
                )
            }
            _ => Err(IdpError::BadRequest),
        }
    }};
}

#[macro_export]
macro_rules! entra_id_prt_token_fetch {
    ($self:ident, $prt:ident, $scopes:ident, $client_id:ident, $tpm:ident, $machine_key:ident) => {{
        $self
            .client
            .read()
            .await
            .exchange_prt_for_access_token(
                &$prt,
                $scopes.iter().map(|s| s.as_ref()).collect(),
                None,
                $client_id.as_deref(),
                $tpm,
                $machine_key,
            )
            .await
            .map_err(|e| {
                error!("{:?}", e);
                IdpError::BadRequest
            })
    }};
}

#[macro_export]
macro_rules! no_op_prt_token_fetch {
    ($self:ident, $prt:ident, $scopes:ident, $client_id:ident, $tpm:ident, $machine_key:ident) => {
        // openidconnect does not have PRTs
        return Err(IdpError::BadRequest)
    };
}

#[macro_export]
macro_rules! entra_id_refresh_token_token_fetch {
    ($self:ident, $refresh_token:ident, $scopes:ident) => {{
        let client = PublicClientApplication::new(BROKER_APP_ID, None).map_err(|e| {
            error!("Failed to create public client application: {:?}", e);
            IdpError::BadRequest
        })?;
        let scopes = if $self.is_consumer_tenant().await {
            // Remove "https://graph.microsoft.com/.default" from the
            // scopes for consumer tenants. This is the default scope
            // requested by the SSO extension, but it is not valid for
            // consumer tenants.
            $scopes
                .into_iter()
                .filter(|s| s != "https://graph.microsoft.com/.default")
                .collect()
        } else {
            $scopes
        };
        client
            .acquire_token_by_refresh_token(
                &$refresh_token,
                scopes.iter().map(|s| s.as_ref()).collect(),
            )
            .await
            .map_err(|e| {
                error!("Failed to refresh token: {:?}", e);
                IdpError::BadRequest
            })
    }};
}

#[macro_export]
macro_rules! oidc_refresh_token_token_fetch {
    ($self:ident, $refresh_token:ident, $scopes:ident) => {
        match $self
            .client
            .acquire_token_by_refresh_token(
                &$refresh_token,
                $scopes.iter().map(|s| s.as_ref()).collect(),
            )
            .await
        {
            Ok(token) => token.into_unix_user_token().map_err(|e| {
                error!("Failed to convert token to user token: {:?}", e);
                IdpError::BadRequest
            }),
            Err(e) => {
                error!("Failed to refresh token: {:?}", e);
                return Err(IdpError::BadRequest);
            }
        }
    };
}

#[macro_export]
macro_rules! impl_unix_user_access {
    ($self:ident, $old_token:ident, $scopes:ident, $client_id:ident, $id:ident, $tpm:ident, $machine_key:ident, $prt_token_refresh:ident, $refresh_token_token_refresh:ident) => {{
        if ($self.delayed_init().await).is_err() {
            // We can't fetch an access_token when initialization hasn't
            // completed. This only happens when we're offline during first
            // startup. This should never happen!
            return Err(IdpError::BadRequest);
        }

        if !$self.check_online($tpm, SystemTime::now()).await {
            // We can't fetch an access_token when offline
            return Err(IdpError::BadRequest);
        }

        /* Use the prt mem cache to refresh the user token */
        let account_id = match $old_token {
            Some(token) => token.spn.clone(),
            None => $id.to_string().clone(),
        };
        let refresh_cache_entry = $self.refresh_cache.refresh_token(&account_id).await?;
        match refresh_cache_entry {
            #![allow(unused_variables)]
            RefreshCacheEntry::Prt(prt) => {
                $prt_token_refresh!($self, prt, $scopes, $client_id, $tpm, $machine_key)
            }
            RefreshCacheEntry::RefreshToken(refresh_token) => {
                $refresh_token_token_refresh!($self, refresh_token, $scopes)
            }
        }
    }};
}

#[macro_export]
macro_rules! impl_provision_hello_key {
    ($self:ident, $token:ident, $cred:ident, $tpm:ident, $machine_key:ident) => {
        $self
            .client
            .read()
            .await
            .provision_hello_for_business_key(&$token, $tpm, $machine_key, &$cred)
            .await
    };
}

#[macro_export]
macro_rules! impl_create_decoupled_hello_key {
    ($self:ident, $token:ident, $amr_ngcmfa:expr, $tpm:ident, $machine_key:ident, $cred:ident, $error:expr) => {{
        let pin = PinValue::new(&$cred).map_err(|e| {
            error!("Failed setting pin value: {:?}", e);
            $error
        })?;
        $tpm.ms_hello_key_create($machine_key, &pin).map_err(|e| {
            error!("Failed to create hello key: {:?}", e);
            $error
        })?
    }};
}

#[macro_export]
macro_rules! impl_provision_or_create_hello_key {
    ($self:ident, $token:ident, $amr_ngcmfa:expr, $tpm:ident, $machine_key:ident, $cred:ident, $error:expr) => {
        if $amr_ngcmfa {
            impl_provision_hello_key!($self, $token, $cred, $tpm, $machine_key).map_err(|e| {
                error!("Failed to provision hello key: {:?}", e);
                $error
            })?
        } else {
            impl_create_decoupled_hello_key!(
                $self,
                $token,
                $amr_ngcmfa,
                $tpm,
                $machine_key,
                $cred,
                $error
            )
        }
    };
}

#[macro_export]
macro_rules! impl_change_auth_token {
    ($self:ident, $account_id:ident, $token:ident, $cred:ident, $keystore:ident, $tpm:ident, $machine_key:ident, $amr_ngcmfa:expr, $create_hello_key:ident) => {{
        if ($self.delayed_init().await).is_err() {
            // We can't change the Hello PIN when initialization hasn't
            // completed. This only happens when we're offline during first
            // startup.
            return Err(IdpError::BadRequest);
        }

        if !$self.check_online($tpm, SystemTime::now()).await {
            // We can't change the Hello PIN when offline
            return Err(IdpError::BadRequest);
        }

        #[allow(unused_variables)]
        let amr_ngcmfa = $amr_ngcmfa;

        let hello_tag = $self.fetch_hello_key_tag($account_id, $amr_ngcmfa);

        // Ensure the user is setting the token for the account it has authenticated to
        if $account_id.to_string().to_lowercase()
            != $token
                .spn()
                .map_err(|e| {
                    error!("Failed checking the spn on the user token: {:?}", e);
                    IdpError::BadRequest
                })?
                .to_lowercase()
        {
            error!("A hello key may only be set by the authenticated user!");
            return Err(IdpError::BadRequest);
        }

        // Set the hello pin
        let hello_key = $create_hello_key!(
            $self,
            $token,
            amr_ngcmfa,
            $tpm,
            $machine_key,
            $cred,
            IdpError::Tpm
        );
        $keystore
            .insert_tagged_hsm_key(&hello_tag, &hello_key)
            .map_err(|e| {
                error!("Failed to provision hello key: {:?}", e);
                IdpError::Tpm
            })?;
        Ok(true)
    }};
}

#[macro_export]
macro_rules! impl_check_online {
    ($self:ident, $tpm:ident, $now:expr) => {{
        let state = $self.state.lock().await.clone();
        match state {
            // Proceed
            CacheState::Online => true,
            CacheState::OfflineNextCheck(at_time) if $now >= at_time => {
                // Attempt online. If fails, return token.
                $self.attempt_online($tpm, $now).await
            }
            CacheState::OfflineNextCheck(_) | CacheState::Offline => false,
        }
    }};
}

#[macro_export]
macro_rules! impl_setup_hello_totp {
    ($self:ident, $account_id:ident, $keystore:ident, $old_token:ident, $hello_pin:ident, $tpm:ident, $machine_key:ident, $cred_handler:ident) => {{
        let hostname = hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let issuer = format!("Himmelblau {}", hostname);
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::generate_secret().to_bytes().map_err(|e| {
                error!("Failed to generate totp secret: {:?}", e);
                IdpError::Tpm
            })?,
            Some(issuer.clone()),
            $account_id.to_string(),
        )
        .map_err(|e| {
            error!("Failed to create TOTP instance: {:?}", e);
            IdpError::Tpm
        })?;
        let secret_b32 = totp.get_secret_base32();
        let record = TotpEnrollmentRecord {
            secret_b32: secret_b32.clone(),
            digits: 6,
            skew: 1,
            step: 30,
            issuer: issuer.clone(),
            account_name: $account_id.to_string(),
        };
        let record_json = serde_json::to_string(&record).map_err(|e| {
            error!("Failed to serialize TOTP record: {:?}", e);
            IdpError::Tpm
        })?;
        // DANGER ZONE ---->
        // WARNING: This message is **parsed** by the QR Greeter plugin. Modifying
        // the message format may break the plugin!
        // The exact regex used by the QR Greeter plugin is:
        // const TOTP_SETUP_RE = /Enter the setup key '([^']+)'.*Use '([^']+)'.*'([^']+)' as the label\/name\./s;
        let msg = format!(
            "Enter the setup key '{}' to enroll a TOTP Authenticator app. Use '{}' for the code name and '{}' as the label/name.",
            secret_b32, issuer, $account_id
        );
        // <---- DANGER ZONE
        let pin = PinValue::new(&$hello_pin).map_err(|e| {
            error!("Failed setting pin value: {:?}", e);
            IdpError::Tpm
        })?;
        let (hello_key, _) =
                    $self.fetch_hello_key($account_id, $keystore).map_err(|e| {
                        error!("Online authentication failed. Hello key missing.");
                        e
                    })?;
        let (_, win_hello_storage_key) = $tpm.ms_hello_key_load($machine_key, &hello_key, &pin).map_err(|e| {
            error!("Failed to load hello key: {:?}", e);
            IdpError::Tpm
        })?;
        let record_json_zeroizing = Zeroizing::new(record_json.as_bytes().to_vec());
        let sealed_totp_secret = $tpm
            .seal_data(&win_hello_storage_key, record_json_zeroizing)
            .map_err(|e| {
                error!("Failed to seal totp secret: {:?}", e);
                IdpError::Tpm
            })?;
        // Store the sealed secret in the cred_handler - it will be saved to HSM
        // only after successful TOTP validation
        *$cred_handler = AuthCredHandler::HelloTOTP {
            cred: $hello_pin.clone(),
            pending_sealed_totp: Some(sealed_totp_secret),
        };
        Ok((
            AuthResult::Next(AuthRequest::HelloTOTP {
                msg,
            }),
            AuthCacheAction::None,
        ))
    }};
}
