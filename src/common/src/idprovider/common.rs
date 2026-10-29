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
use crate::constants::ID_MAP_CACHE;
use crate::db::KeyStoreTxn;
use crate::idmap_cache::StaticIdCache;
use crate::idprovider::interface::{GroupToken, IdpError, UserToken};
use idmap::Idmap;
use kanidm_hsm_crypto::provider::{BoxedDynTpm, Tpm};
use kanidm_hsm_crypto::structures::{SealedData, StorageKey};
use lazy_static::lazy_static;
use openidconnect::core::CoreGenderClaim;
use openidconnect::{AdditionalClaims, UserInfoClaims};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};
use tokio::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroizing;

/// When a cached PRT is older than 4h, opportunistically issue an
/// `exchange_prt_for_prt` before using it for access-token acquisition.
pub const PRT_REFRESH_AGE: Duration = Duration::from_secs(4 * 3600);

/// Tolerate trailing slashes without normalizing other issuer differences.
pub(crate) fn oidc_issuer_matches(configured: &str, reported: Option<&str>) -> bool {
    reported.is_some_and(|issuer| issuer.trim_end_matches('/') == configured.trim_end_matches('/'))
}

/// Build a `reqwest::Client` for `attempt_online()` probes.
///
/// Uses `request_timeout` for the total request budget and a derived
/// connect timeout of `min(request_timeout / 2, 3s)` so we fail fast
/// when the network is unreachable. Mirrors the pattern in libhimmelblau
/// `auth.rs`.
pub(crate) fn build_online_probe_client(
    request_timeout_secs: u64,
    redirect_policy: reqwest::redirect::Policy,
) -> Result<reqwest::Client, reqwest::Error> {
    let request_timeout = Duration::from_secs(request_timeout_secs);
    let connect_timeout = std::cmp::min(request_timeout / 2, Duration::from_secs(3));
    reqwest::Client::builder()
        .redirect(redirect_policy)
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .build()
}

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

lazy_static! {
    pub(crate) static ref URL_REGEX: Option<Regex> = Regex::new(r#"https?://[^\s"'<>]+"#).ok();
}

#[macro_export]
macro_rules! extract_base_url {
    ($msg:expr) => {{
        if let Some(regex) = $crate::idprovider::common::URL_REGEX.as_ref() {
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

    /// Returns how long ago the PRT for `account_id` was cached (or None if
    /// there is no PRT entry for that account).
    pub(crate) async fn prt_age(&self, account_id: &str) -> Option<Duration> {
        let refresh_cache = self.refresh_cache.read().await;
        refresh_cache
            .get(account_id.to_lowercase().as_str())
            .and_then(|(_, iat)| iat.elapsed().ok())
    }

    pub(crate) async fn purge(&self) {
        let mut refresh_cache = self.refresh_cache.write().await;
        let mut remove_list = vec![];
        for (k, (_, iat)) in refresh_cache.iter() {
            if *iat + Duration::from_secs(86400) < SystemTime::now() {
                remove_list.push(k.clone());
            }
        }
        for k in remove_list.iter() {
            refresh_cache.remove_entry(k);
        }
        let mut refresh_token_cache = self.refresh_token_cache.write().await;
        let mut remove_list = vec![];
        for (k, (_, iat)) in refresh_token_cache.iter() {
            if *iat + Duration::from_secs(86400) < SystemTime::now() {
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

    pub(crate) async fn remove_prt(&self, account_id: &str) {
        let mut refresh_cache = self.refresh_cache.write().await;
        refresh_cache.remove(account_id.to_lowercase().as_str());
    }

    pub(crate) async fn remove_refresh_token(&self, account_id: &str) {
        self.refresh_token_cache
            .write()
            .await
            .remove(&account_id.to_lowercase());
    }

    /// Restoring a PIN-sealed credential must not overwrite a rotated token
    /// already held in memory. Preserve its insertion time as well.
    pub(crate) async fn add_reused_refresh_token(&self, account_id: &str, token: String) {
        self.refresh_token_cache
            .write()
            .await
            .entry(account_id.to_lowercase())
            .or_insert_with(|| (token, SystemTime::now()));
    }

    /// Cache a PRT that was reused for an access-token exchange without
    /// treating that exchange as a PRT renewal. If a PRT is already cached,
    /// keep both its value and original insertion time; it may be newer than a
    /// Hello-sealed copy loaded from disk.
    pub(crate) async fn add_reused_prt(&self, account_id: &str, prt: &SealedData) {
        let mut refresh_cache = self.refresh_cache.write().await;
        refresh_cache
            .entry(account_id.to_lowercase())
            .or_insert_with(|| (prt.clone(), SystemTime::now()));
    }

    /// Export all PRT entries from the in-memory cache as a JSON blob.
    /// This is used to persist them to a sealed memfd for systemd's
    /// FileDescriptorStore so they survive daemon restarts.
    /// Each entry includes the original insertion timestamp (seconds
    /// since UNIX epoch) so that cache retention is not extended by
    /// daemon restarts.
    pub async fn export_broker_prts(&self) -> Result<Vec<u8>, serde_json::Error> {
        let refresh_cache = self.refresh_cache.read().await;
        let entries: HashMap<String, (SealedData, u64)> = refresh_cache
            .iter()
            .map(|(k, (v, iat))| {
                let epoch_secs = iat
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                (k.clone(), (v.clone(), epoch_secs))
            })
            .collect();
        serde_json::to_vec(&entries)
    }

    /// Import PRT entries from a JSON blob (previously exported via
    /// `export_broker_prts`). Entries are added to the in-memory cache
    /// without touching the keystore. The original insertion timestamp
    /// is preserved so that the 24 h purge window is not reset.
    pub async fn import_broker_prts(&self, data: &[u8]) -> Result<(), serde_json::Error> {
        let mut refresh_cache = self.refresh_cache.write().await;
        let entries: HashMap<String, (SealedData, u64)> = serde_json::from_slice(data)?;
        for (account_id, (prt, epoch_secs)) in entries {
            let iat = SystemTime::UNIX_EPOCH + Duration::from_secs(epoch_secs);
            refresh_cache.insert(account_id.to_lowercase(), (prt, iat));
        }
        Ok(())
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
        tokio::time::sleep(Duration::from_secs((*counter as u64) * 2)).await;
    }

    pub(crate) async fn reset_bad_pin_count(&self, account_id: &str) {
        let mut map = self.counter.write().await;
        map.insert(account_id.to_string(), 0);
    }
}

pub(crate) fn should_warn_last_hello_pin_attempt(bad_pin_count: u32, retry_count: u32) -> bool {
    retry_count > 1 && bad_pin_count == retry_count - 1
}

pub(crate) fn should_block_hello_pin_attempts(bad_pin_count: u32, retry_count: u32) -> bool {
    bad_pin_count >= retry_count
}

pub(crate) fn should_offer_offline_hello_pin(
    is_remote_service: bool,
    hello_totp_enabled: bool,
    allow_remote_hello: bool,
) -> bool {
    !is_remote_service || hello_totp_enabled || allow_remote_hello
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TryUnsealPolicyDenial {
    HelloDisabled,
    HelloTotpEnabled,
    RetryLimitReached,
}

pub(crate) fn try_unseal_policy_denial(
    hello_enabled: bool,
    hello_totp_enabled: bool,
    bad_pin_count: u32,
    hello_pin_retry_count: u32,
) -> Option<TryUnsealPolicyDenial> {
    if !hello_enabled {
        Some(TryUnsealPolicyDenial::HelloDisabled)
    } else if hello_totp_enabled {
        Some(TryUnsealPolicyDenial::HelloTotpEnabled)
    } else if should_block_hello_pin_attempts(bad_pin_count, hello_pin_retry_count) {
        Some(TryUnsealPolicyDenial::RetryLimitReached)
    } else {
        None
    }
}

#[macro_export]
macro_rules! handle_hello_bad_pin_count {
    ($self:expr, $account_id:expr, $keystore:expr, $ret_fn:expr) => {{
        $self.bad_pin_counter
            .increment_bad_pin_count($account_id)
            .await;

        let hello_pin_retry_count = $self.config.lock().await.get_hello_pin_retry_count();
        let bad_pin_count = $self.bad_pin_counter.bad_pin_count($account_id).await;

        // If we've reached the bad pin count, delete the Hello key
        if $crate::idprovider::common::should_block_hello_pin_attempts(
            bad_pin_count,
            hello_pin_retry_count,
        ) {
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
                &tr("Too many incorrect PIN attempts. You will need to enroll a new Linux Hello PIN.")
            );
        }

        if $crate::idprovider::common::should_warn_last_hello_pin_attempt(
            bad_pin_count,
            hello_pin_retry_count,
        ) {
            return $ret_fn(
                &tr("Failed to authenticate with Hello PIN. One more failed attempt will require multi-factor authentication and will reset your Linux Hello PIN.")
            );
        }
    }};
}

#[derive(PartialEq)]
pub(crate) enum KeyType {
    Hello,
    Decoupled,
}

pub(crate) fn should_renew_expired_try_unseal_prt(keytype: &KeyType, online: bool) -> bool {
    online && matches!(keytype, KeyType::Hello)
}

/// Best effort: failures are logged, not returned.
pub(crate) fn cache_refresh_token_with_loaded_hello_key<K: KeyStoreTxn>(
    keystore: &mut K,
    tpm: &mut BoxedDynTpm,
    hello_storage_key: &StorageKey,
    refresh_token: &str,
    account_id: &str,
    refresh_token_tag: &str,
) {
    let sealed_refresh_token = match tpm.seal_data(
        hello_storage_key,
        Zeroizing::new(refresh_token.as_bytes().to_vec()),
    ) {
        Ok(sealed_refresh_token) => sealed_refresh_token,
        Err(e) => {
            error!(?e, account_id, "Failed to seal Hello refresh token");
            return;
        }
    };
    if let Err(e) = keystore.insert_tagged_hsm_key(refresh_token_tag, &sealed_refresh_token) {
        error!(
            ?e,
            account_id, refresh_token_tag, "Failed to cache Hello refresh token"
        );
    }
}

pub(crate) fn unseal_refresh_token_with_loaded_hello_key(
    tpm: &mut BoxedDynTpm,
    hello_storage_key: &StorageKey,
    sealed_refresh_token: &SealedData,
) -> Result<String, IdpError> {
    let refresh_token = tpm
        .unseal_data(hello_storage_key, sealed_refresh_token)
        .map_err(|e| {
            error!(?e, "Failed to unseal Hello refresh token");
            IdpError::Tpm
        })?;
    String::from_utf8(refresh_token.to_vec()).map_err(|e| {
        error!(?e, "Failed to decode Hello refresh token");
        IdpError::Tpm
    })
}

/// Return the refresh token sealed under `refresh_token_tag`, or `fallback`
/// when it is absent or cannot be unsealed.
pub(crate) fn sealed_refresh_token_or<K: KeyStoreTxn>(
    keystore: &mut K,
    tpm: &mut BoxedDynTpm,
    hello_storage_key: &StorageKey,
    refresh_token_tag: &str,
    fallback: Option<RefreshCacheEntry>,
) -> Option<RefreshCacheEntry> {
    match keystore.get_tagged_hsm_key(refresh_token_tag) {
        Ok(Some(sealed_refresh_token)) => unseal_refresh_token_with_loaded_hello_key(
            tpm,
            hello_storage_key,
            &sealed_refresh_token,
        )
        .ok()
        .map(RefreshCacheEntry::RefreshToken)
        .or(fallback),
        Err(_) | Ok(None) => fallback,
    }
}

/// Persist the token's PRT, or its refresh token when it has no PRT, sealed
/// with the loaded Hello key. Best effort: failures are logged, not returned.
#[macro_export]
macro_rules! cache_token_with_loaded_hello_key {
    ($self:expr, $account_id:expr, $token:expr, $loaded_hello_key:expr, $keystore:expr, $tpm:expr, $machine_key:expr) => {{
        if let Some(prt) = &$token.prt {
            let sealed_prt = $self
                .client
                .lock()
                .await
                .seal_user_prt_with_loaded_ms_hello_key(prt, $loaded_hello_key, $tpm, $machine_key);
            match sealed_prt {
                Ok(hello_prt) => {
                    let hello_prt_tag = $self.fetch_hello_prt_key_tag($account_id);
                    if let Err(e) = $keystore.insert_tagged_hsm_key(&hello_prt_tag, &hello_prt) {
                        error!(?e, account_id = $account_id, "Failed to cache Hello PRT");
                    }
                }
                Err(e) => {
                    error!(?e, account_id = $account_id, "Failed to seal Hello PRT");
                }
            }
        } else {
            let hello_refresh_token_tag = $self.fetch_hello_refresh_token_key_tag($account_id);
            $crate::idprovider::common::cache_refresh_token_with_loaded_hello_key(
                $keystore,
                $tpm,
                $loaded_hello_key.storage_key(),
                &$token.refresh_token,
                $account_id,
                &hello_refresh_token_tag,
            );
        }
    }};
}

#[macro_export]
macro_rules! impl_offline_break_glass {
    ($self:ident, $ttl:ident) => {{
        let mut state = $self.state.lock().await;
        let (ttl, enabled) = {
            let cfg = $self.config.lock().await;
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
    ($loaded_hello_key:ident, $self:ident, $account_id:expr, $keystore:expr, $tpm:expr, $machine_key:expr) => {
        // Check for and decrypt any cached PRT
        let hello_prt_tag = $self.fetch_hello_prt_key_tag($account_id);
        if let Ok(Some(hello_prt)) = $keystore.get_tagged_hsm_key(&hello_prt_tag) {
            let (prt, prt_expired) = $self
                .client
                .lock()
                .await
                .unseal_user_prt_with_loaded_ms_hello_key(
                    &hello_prt,
                    &$loaded_hello_key,
                    $tpm,
                    $machine_key,
                )
                .map_err(|e| {
                    error!("Failed to load hello prt: {:?}", e);
                    IdpError::Tpm
                })?;
            // Check if the cached PRT has expired.
            // This happens after 14 days of no online contact.
            if prt_expired {
                return Ok(AuthResult::Denied(tr(
                    "Offline auth has expired. Please connect to the network to continue.",
                )));
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
    ($loaded_hello_key:ident, $self:ident, $account_id:expr, $keystore:expr, $tpm:expr, $machine_key:expr) => {
        // No-op, since openidconnect does not have PRTs
    };
}

#[macro_export]
macro_rules! load_cached_prt_for_try_unseal {
    ($loaded_hello_key:ident, $keytype:ident, $online:ident, $self:ident, $account_id:expr, $keystore:expr, $tpm:expr, $machine_key:expr) => {
        let hello_prt_tag = $self.fetch_hello_prt_key_tag($account_id);
        if let Ok(Some(hello_prt)) = $keystore.get_tagged_hsm_key(&hello_prt_tag) {
            let (mut prt, prt_expired) = $self
                .client
                .lock()
                .await
                .unseal_user_prt_with_loaded_ms_hello_key(
                    &hello_prt,
                    &$loaded_hello_key,
                    $tpm,
                    $machine_key,
                )
                .map_err(|e| {
                    error!("Failed to load hello prt: {:?}", e);
                    IdpError::Tpm
                })?;
            if prt_expired {
                if !$crate::idprovider::common::should_renew_expired_try_unseal_prt(
                    &$keytype, $online,
                ) {
                    error!("Offline auth has expired. Please connect to the network to continue.");
                    return Ok(false);
                }

                let renewed_token = match $self
                    .client
                    .lock()
                    .await
                    .acquire_token_by_loaded_ms_hello_key(
                        $account_id,
                        &$loaded_hello_key,
                        vec![],
                        None,
                        None,
                        $tpm,
                        $machine_key,
                    )
                    .await
                {
                    Ok(token) => token,
                    Err(himmelblau::error::MsalError::RequestFailed(msg)) => {
                        error!(?msg, "Network down while renewing expired Hello PRT");
                        let mut state = $self.state.lock().await;
                        *state = $crate::idprovider::interface::CacheState::OfflineNextCheck(
                            std::time::SystemTime::now() + OFFLINE_NEXT_CHECK,
                        );
                        return Ok(false);
                    }
                    Err(e) => {
                        error!(?e, "Failed to renew expired Hello PRT");
                        return Ok(false);
                    }
                };
                let Some(renewed_prt) = renewed_token.prt.as_ref().cloned() else {
                    error!("Online Hello authentication did not return a replacement PRT");
                    return Ok(false);
                };
                $crate::cache_token_with_loaded_hello_key!(
                    $self,
                    $account_id,
                    renewed_token,
                    &$loaded_hello_key,
                    $keystore,
                    $tpm,
                    $machine_key
                );
                prt = renewed_prt;
            }
            $self
                .refresh_cache
                .add($account_id, &RefreshCacheEntry::Prt(prt))
                .await;
        }
    };
}

#[macro_export]
macro_rules! load_cached_prt_for_try_unseal_no_op {
    ($loaded_hello_key:ident, $keytype:ident, $online:ident, $self:ident, $account_id:expr, $keystore:expr, $tpm:expr, $machine_key:expr) => {
        // No-op, since openidconnect does not have PRTs
        let _ = (&$keytype, $online);
    };
}

#[macro_export]
macro_rules! impl_himmelblau_offline_auth_init {
    ($self:ident, $account_id:expr, $service:expr, $no_hello_pin:ident, $keystore:expr, $password_auth:expr) => {{
        let hello_key = $self.fetch_hello_key($account_id, $keystore).ok();
        let (
            sfa_enabled,
            hello_pin_retry_count,
            breakglass_enabled,
            remote_services,
            hello_totp_enabled,
            allow_remote_hello,
        ) = {
            let cfg = $self.config.lock().await;
            (
                cfg.get_enable_sfa_fallback(),
                cfg.get_hello_pin_retry_count(),
                cfg.get_offline_breakglass_enabled(),
                cfg.get_password_only_remote_services_deny_list(),
                cfg.get_enable_hello_totp(),
                cfg.get_allow_remote_hello(),
            )
        };
        let is_remote_service = $service.starts_with("remote:")
            || remote_services
                .iter()
                .any(|s| !s.is_empty() && $service.contains(s));
        // We only have 2 options when performing an offline auth; Hello PIN,
        // or cached password for SFA users. If neither option is available,
        // we should respond with a reasonable error indicating how to proceed.
        if hello_key.is_some()
            && !$crate::idprovider::common::should_block_hello_pin_attempts(
                $self.bad_pin_counter.bad_pin_count($account_id).await,
                hello_pin_retry_count,
            )
            && !$no_hello_pin
            && $crate::idprovider::common::should_offer_offline_hello_pin(
                is_remote_service,
                hello_totp_enabled,
                allow_remote_hello,
            )
        {
            Ok((AuthRequest::Pin, AuthCredHandler::None))
        } else if $password_auth && (sfa_enabled || breakglass_enabled) {
            Ok((
                AuthRequest::Password {
                    prompt: None,
                    long_prompt: None,
                },
                AuthCredHandler::None,
            ))
        } else {
            Ok((
                AuthRequest::InitDenied {
                    msg: tr("Network outage detected."),
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
                    Ok(($auth_cache_action)(AuthResult::Denied(tr(
                        "Failed to authenticate with Hello TOTP code.",
                    ))))
                }
            }
            Err(e) => {
                error!("{:?}", e);
                handle_hello_bad_pin_count!($self, $account_id, $keystore, |msg: &str| {
                    Ok(($auth_cache_action)(AuthResult::Denied(msg.to_string())))
                });
                Ok(($auth_cache_action)(AuthResult::Denied(tr(
                    "Failed to authenticate with Hello TOTP code.",
                ))))
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
        let cfg = $self.config.lock().await;
        cfg.get_enable_hello_totp()
    }};
}

#[macro_export]
macro_rules! impl_himmelblau_offline_auth_step {
    ($cred_handler:ident, $pam_next_req:expr, $self:ident, $account_id:ident, $keystore:ident, $tpm:ident, $machine_key:ident, $token:ident, $load_cached_prt:ident) => {{
        match (&$cred_handler, $pam_next_req) {
            (_, PamAuthRequest::Pin { cred }) => {
                let (hello_key, _keytype) =
                    $self.fetch_hello_key($account_id, $keystore).map_err(|e| {
                        error!("Offline authentication failed. Hello key missing.");
                        e
                    })?;

                match himmelblau::auth::LoadedMsHelloKey::load(
                    &hello_key,
                    &cred,
                    $tpm,
                    $machine_key,
                ) {
                    Ok(loaded_hello_key) => {
                        $load_cached_prt!(
                            loaded_hello_key,
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
                            let refresh_token =
                                $crate::idprovider::common::unseal_refresh_token_with_loaded_hello_key(
                                    $tpm,
                                    loaded_hello_key.storage_key(),
                                    &sealed_refresh_token,
                                )?;
                            $self
                                .refresh_cache
                                .add_reused_refresh_token($account_id, refresh_token)
                                .await;
                        }
                        if check_hello_totp_enabled!($self) {
                            if !check_hello_totp_setup!($self, $account_id, $keystore) {
                                let (auth_result, _auth_cache_action) =
                                    $crate::impl_setup_hello_totp_with_storage_key!(
                                        $account_id,
                                        loaded_hello_key.storage_key(),
                                        cred,
                                        $tpm,
                                        $cred_handler
                                    )?;
                                Ok(auth_result)
                            } else {
                                *$cred_handler = AuthCredHandler::HelloTOTP {
                                    cred,
                                    pending_sealed_totp: None,
                                };
                                Ok(AuthResult::Next(AuthRequest::HelloTOTP {
                                    msg: tr(
                                        "Please enter your Hello TOTP code from your Authenticator:",
                                    ) + " ",
                                }))
                            }
                        } else {
                            $self.bad_pin_counter.reset_bad_pin_count($account_id).await;
                            Ok(AuthResult::Success {
                                token: $token.clone(),
                            })
                        }
                    }
                    Err(e) => {
                        error!(?e, "Failed to load Hello key with PIN");
                        handle_hello_bad_pin_count!($self, $account_id, $keystore, |msg: &str| {
                            Ok(AuthResult::Denied(msg.to_string()))
                        });
                        Ok(AuthResult::Denied(tr(
                            "Failed to authenticate with Hello PIN.",
                        )))
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
macro_rules! impl_himmelblau_try_unseal {
    ($self:ident, $account_id:ident, $cred:ident, $keystore:ident, $tpm:ident, $machine_key:ident, $online:ident, $load_cached_prt:ident) => {{
        let (hello_enabled, hello_totp_enabled, hello_pin_retry_count) = {
            let cfg = $self.config.lock().await;
            (
                cfg.get_enable_hello(),
                cfg.get_enable_hello_totp(),
                cfg.get_hello_pin_retry_count(),
            )
        };
        let policy_denial = $crate::idprovider::common::try_unseal_policy_denial(
            hello_enabled,
            hello_totp_enabled,
            $self.bad_pin_counter.bad_pin_count($account_id).await,
            hello_pin_retry_count,
        );
        if let Some(denial) = policy_denial {
            match denial {
                $crate::idprovider::common::TryUnsealPolicyDenial::HelloDisabled => {
                    error!(
                        "Refusing try_unseal because Hello authentication is disabled; cached SSO material was not unsealed"
                    );
                }
                $crate::idprovider::common::TryUnsealPolicyDenial::HelloTotpEnabled => {
                    error!(
                        "Refusing try_unseal because enable_hello_totp requires an interactive second factor; cached SSO material was not unsealed"
                    );
                }
                $crate::idprovider::common::TryUnsealPolicyDenial::RetryLimitReached => {
                    error!(
                        "Refusing try_unseal because the Hello PIN retry limit has been reached; cached SSO material was not unsealed"
                    );
                }
            }
            return Ok(false);
        }

        let (hello_key, keytype) =
            $self.fetch_hello_key($account_id, $keystore).map_err(|e| {
                error!("try_unseal failed. Hello key missing.");
                e
            })?;

        match himmelblau::auth::LoadedMsHelloKey::load(&hello_key, $cred, $tpm, $machine_key) {
            Ok(loaded_hello_key) => {
                // The PIN has been validated. Clear stale failures before any
                // fallible PRT renewal or refresh-token restoration can return.
                $self.bad_pin_counter.reset_bad_pin_count($account_id).await;

                $load_cached_prt!(
                    loaded_hello_key,
                    keytype,
                    $online,
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
                    let refresh_token =
                        $crate::idprovider::common::unseal_refresh_token_with_loaded_hello_key(
                            $tpm,
                            loaded_hello_key.storage_key(),
                            &sealed_refresh_token,
                        )?;
                    $self
                        .refresh_cache
                        .add_reused_refresh_token($account_id, refresh_token)
                        .await;
                }
                Ok(true)
            }
            Err(e) => {
                error!(?e, "Failed to load Hello key with PIN");
                handle_hello_bad_pin_count!($self, $account_id, $keystore, |_msg: &str| {
                    Ok(false)
                });
                Ok(false)
            }
        }
    }};
}

#[macro_export]
macro_rules! entra_id_prt_token_fetch {
    ($self:ident, $prt:ident, $scopes:ident, $client_id:ident, $redirect_uri:ident, $req_cnf:ident, $tpm:ident, $machine_key:ident) => {{
        $self
            .client
            .lock()
            .await
            .exchange_prt_for_access_token(
                &$prt,
                $scopes.iter().map(|s| s.as_ref()).collect(),
                None,
                $client_id.as_deref(),
                $tpm,
                $machine_key,
                $redirect_uri.as_deref(),
                $req_cnf.as_deref(),
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
    ($self:ident, $prt:ident, $scopes:ident, $client_id:ident, $redirect_uri:ident, $req_cnf:ident, $tpm:ident, $machine_key:ident) => {
        // openidconnect does not have PRTs
        return Err(IdpError::BadRequest)
    };
}

#[macro_export]
macro_rules! entra_id_refresh_token_token_fetch {
    ($self:ident, $refresh_token:ident, $scopes:ident) => {{
        let (ip_versions, request_timeout) = {
            let cfg = $self.config.lock().await;
            (cfg.get_ip_versions(), cfg.get_request_timeout())
        };
        let client = PublicClientApplication::new(
            BROKER_APP_ID,
            None,
            std::time::Duration::from_secs(request_timeout),
            &ip_versions,
        )
        .map_err(|e| {
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
    ($self:ident, $refresh_token:ident, $scopes:ident) => {{
        let scopes: Vec<String> = $scopes
            .into_iter()
            .filter(|s| s != "https://graph.microsoft.com/.default")
            .collect();
        match $self
            .client
            .acquire_token_by_refresh_token(
                &$refresh_token,
                scopes.iter().map(|s| s.as_ref()).collect(),
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
    }};
}

#[macro_export]
macro_rules! impl_unix_user_access {
    ($self:ident, $old_token:ident, $scopes:ident, $client_id:ident, $redirect_uri:ident, $req_cnf:ident, $id:ident, $tpm:ident, $machine_key:ident, $prt_token_refresh:ident, $refresh_token_token_refresh:ident) => {{
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
                $prt_token_refresh!(
                    $self,
                    prt,
                    $scopes,
                    $client_id,
                    $redirect_uri,
                    $req_cnf,
                    $tpm,
                    $machine_key
                )
            }
            RefreshCacheEntry::RefreshToken(refresh_token) => {
                $refresh_token_token_refresh!($self, refresh_token, $scopes)
            }
        }
    }};
}

/// Issue #1051: Seal a PRT (or refresh token) with an existing Hello key
/// after successful online re-authentication. This is used when the cached
/// PRT/refresh token expired but the Hello key and PIN are still valid.
#[macro_export]
macro_rules! seal_prt_with_existing_hello_key {
    ($self:expr, $account_id:expr, $token:expr, $hello_key:expr, $pin:expr, $keystore:expr, $tpm:expr, $machine_key:expr) => {{
        match himmelblau::auth::LoadedMsHelloKey::load($hello_key, $pin, $tpm, $machine_key) {
            Ok(loaded_hello_key) => {
                $crate::cache_token_with_loaded_hello_key!(
                    $self,
                    $account_id,
                    $token,
                    &loaded_hello_key,
                    $keystore,
                    $tpm,
                    $machine_key
                );
            }
            Err(e) => {
                error!(
                    ?e,
                    account_id = $account_id,
                    "Failed to load Hello key for reauth sealing"
                );
            }
        }
    }};
}

#[macro_export]
macro_rules! impl_provision_hello_key {
    ($self:ident, $token:ident, $cred:ident, $tpm:ident, $machine_key:ident) => {
        $self
            .client
            .lock()
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

        let hello_totp_tag = $self.fetch_hello_totp_key_tag($account_id);
        $keystore
            .delete_tagged_hsm_key(&hello_totp_tag)
            .map_err(|e| {
                error!("Failed to delete hello TOTP: {:?}", e);
                IdpError::Tpm
            })?;

        Ok(true)
    }};
}

#[macro_export]
macro_rules! impl_check_online {
    ($self:ident, $now:expr) => {{
        let state = $self.state.lock().await.clone();
        match state {
            // Proceed
            CacheState::Online => true,
            CacheState::OfflineNextCheck(at_time) if $now >= at_time => {
                // Attempt online. If fails, return token.
                $self.attempt_online($now).await
            }
            CacheState::OfflineNextCheck(_) | CacheState::Offline => false,
        }
    }};
}

#[macro_export]
macro_rules! impl_probe_online {
    ($self:ident, $now:expr) => {{
        let state = $self.state.lock().await.clone();
        match state {
            CacheState::OfflineNextCheck(at_time) if $now < at_time => false,
            CacheState::Offline => false,
            // An Online state can be stale after a suspend or network change.
            CacheState::Online | CacheState::OfflineNextCheck(_) => {
                $self.attempt_online($now).await
            }
        }
    }};
}

#[macro_export]
macro_rules! impl_setup_hello_totp {
    ($self:ident, $account_id:ident, $keystore:ident, $old_token:ident, $hello_pin:ident, $tpm:ident, $machine_key:ident, $cred_handler:ident) => {{
        let pin = PinValue::new(&$hello_pin).map_err(|e| {
            error!("Failed setting pin value: {:?}", e);
            IdpError::Tpm
        })?;
        let (hello_key, _) = $self.fetch_hello_key($account_id, $keystore).map_err(|e| {
            error!("Online authentication failed. Hello key missing.");
            e
        })?;
        let (_, win_hello_storage_key) = $tpm
            .ms_hello_key_load($machine_key, &hello_key, &pin)
            .map_err(|e| {
                error!("Failed to load hello key: {:?}", e);
                IdpError::Tpm
            })?;
        $crate::impl_setup_hello_totp_with_storage_key!(
            $account_id,
            &win_hello_storage_key,
            $hello_pin,
            $tpm,
            $cred_handler
        )
    }};
}

/// Seal a new TOTP enrollment with the storage key of an already loaded
/// Hello key.
#[macro_export]
macro_rules! impl_setup_hello_totp_with_storage_key {
    ($account_id:ident, $hello_storage_key:expr, $hello_pin:ident, $tpm:ident, $cred_handler:ident) => {{
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
        let record_json_zeroizing = Zeroizing::new(record_json.as_bytes().to_vec());
        let sealed_totp_secret = $tpm
            .seal_data($hello_storage_key, record_json_zeroizing)
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
        let msg = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
            urlencoding::encode(&issuer),
            urlencoding::encode($account_id),
            secret_b32,
            urlencoding::encode(&issuer)
        );
        Ok((
            AuthResult::Next(AuthRequest::HelloTOTP { msg }),
            AuthCacheAction::None,
        ))
    }};
}

#[cfg(test)]
mod tests {
    use super::{
        cache_refresh_token_with_loaded_hello_key, oidc_issuer_matches, sealed_refresh_token_or,
        should_block_hello_pin_attempts, should_offer_offline_hello_pin,
        should_renew_expired_try_unseal_prt, should_warn_last_hello_pin_attempt,
        try_unseal_policy_denial, unseal_refresh_token_with_loaded_hello_key, BadPinCounter,
        IdpError, KeyType, RefreshCache, RefreshCacheEntry, TotpEnrollmentRecord,
        TryUnsealPolicyDenial,
    };
    use crate::db::{CacheError, KeyStoreTxn};
    use crate::idprovider::interface::{
        AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, CacheState,
    };
    use himmelblau::auth::{BrokerClientApplication, LoadedMsHelloKey, UserToken as MsalUserToken};
    use kanidm_hsm_crypto::{
        provider::{BoxedDynTpm, SoftTpm, Tpm},
        structures::{LoadableMsHelloKey, SealedData, StorageKey},
        AuthValue, PinValue,
    };
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime};
    use totp_rs::{Algorithm, Secret, TOTP};
    use zeroize::Zeroizing;

    struct ConnectivityFixture {
        state: tokio::sync::Mutex<CacheState>,
        reachable: bool,
        attempts: AtomicUsize,
    }

    impl ConnectivityFixture {
        fn new(state: CacheState, reachable: bool) -> Self {
            Self {
                state: tokio::sync::Mutex::new(state),
                reachable,
                attempts: AtomicUsize::new(0),
            }
        }

        async fn attempt_online(&self, now: SystemTime) -> bool {
            self.attempts.fetch_add(1, Ordering::AcqRel);
            *self.state.lock().await = if self.reachable {
                CacheState::Online
            } else {
                CacheState::OfflineNextCheck(now + Duration::from_secs(15))
            };
            self.reachable
        }

        async fn check_online(&self, now: SystemTime) -> bool {
            impl_check_online!(self, now)
        }

        async fn probe_online(&self, now: SystemTime) -> bool {
            impl_probe_online!(self, now)
        }

        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::Acquire)
        }
    }

    #[tokio::test]
    async fn probe_online_verifies_a_cached_online_state() {
        let now = SystemTime::now();
        let provider = ConnectivityFixture::new(CacheState::Online, false);
        assert!(provider.check_online(now).await);
        assert_eq!(provider.attempts(), 0);
        assert!(!provider.probe_online(now).await);
        assert_eq!(provider.attempts(), 1);
        assert!(matches!(
            *provider.state.lock().await,
            CacheState::OfflineNextCheck(_)
        ));

        let provider = ConnectivityFixture::new(CacheState::OfflineNextCheck(now), true);
        assert!(provider.probe_online(now).await);
        assert_eq!(provider.attempts(), 1);
    }

    #[tokio::test]
    async fn probe_online_respects_offline_and_retry_states() {
        let now = SystemTime::now();
        for state in [
            CacheState::Offline,
            CacheState::OfflineNextCheck(now + Duration::from_secs(60)),
        ] {
            let provider = ConnectivityFixture::new(state, true);
            assert!(!provider.probe_online(now).await);
            assert_eq!(provider.attempts(), 0);
        }
    }

    #[test]
    fn oidc_issuers_tolerate_only_trailing_slash_differences() {
        for base in [
            "https://login.example.com",
            "https://login.example.com/oauth2/default",
        ] {
            for configured_suffix in ["", "/", "///"] {
                for reported_suffix in ["", "/", "///"] {
                    assert!(oidc_issuer_matches(
                        &format!("{base}{configured_suffix}"),
                        Some(&format!("{base}{reported_suffix}")),
                    ));
                }
            }
        }
        let configured = "https://login.example.com/oauth2/default/";
        for reported in [
            None,
            Some(""),
            Some("https://other.example.com/oauth2/default"),
            Some("http://login.example.com/oauth2/default"),
            Some("https://login.example.com:8443/oauth2/default"),
            Some("https://login.example.com/oauth2/other"),
            Some("https://login.example.com/oauth2//default"),
            Some("https://login.example.com/oauth2/default?query=value"),
        ] {
            assert!(!oidc_issuer_matches(configured, reported));
        }
        for malformed in [serde_json::json!({}), serde_json::json!({"issuer": 42})] {
            assert!(!oidc_issuer_matches(
                configured,
                malformed["issuer"].as_str()
            ));
        }
    }

    fn test_prt(byte: u8) -> SealedData {
        SealedData::SoftV1 {
            data: Zeroizing::new(vec![byte]),
            tag: [byte; 16],
            iv: [byte; 16],
        }
    }

    fn serialized_prt(prt: &SealedData) -> Vec<u8> {
        serde_json::to_vec(prt).expect("test PRT should serialize")
    }

    #[tokio::test]
    async fn sealed_refresh_restoration_preserves_rotated_memory_token() {
        let cache = RefreshCache::new();
        let when = SystemTime::now() - Duration::from_secs(60);
        cache
            .refresh_token_cache
            .write()
            .await
            .insert("user@example.com".into(), ("rotated".into(), when));
        cache
            .add_reused_refresh_token("User@Example.com", "spent-disk-copy".into())
            .await;
        let entries = cache.refresh_token_cache.read().await;
        assert_eq!(
            entries.get("user@example.com"),
            Some(&("rotated".into(), when))
        );
        drop(entries);
        cache.remove_refresh_token("USER@example.com").await;
        assert!(cache.refresh_token("user@example.com").await.is_err());
        cache
            .add_reused_refresh_token("User@Example.com", "restored".into())
            .await;
        assert!(matches!(cache.refresh_token("user@example.com").await,
            Ok(RefreshCacheEntry::RefreshToken(value)) if value == "restored"));
    }

    #[tokio::test]
    async fn reused_prt_preserves_existing_value_and_timestamp() {
        let cache = RefreshCache::new();
        let account_id = "User@Example.com";
        let original_prt = test_prt(1);
        let original_timestamp = SystemTime::now() - Duration::from_secs(60);
        cache.refresh_cache.write().await.insert(
            account_id.to_lowercase(),
            (original_prt.clone(), original_timestamp),
        );

        cache.add_reused_prt(account_id, &test_prt(2)).await;

        let entries = cache.refresh_cache.read().await;
        let (cached_prt, cached_timestamp) = entries
            .get(&account_id.to_lowercase())
            .expect("existing PRT should remain cached");
        assert_eq!(serialized_prt(cached_prt), serialized_prt(&original_prt));
        assert_eq!(*cached_timestamp, original_timestamp);
    }

    #[tokio::test]
    async fn reused_prt_is_inserted_when_cache_is_empty() {
        let cache = RefreshCache::new();
        let account_id = "User@Example.com";
        let prt = test_prt(3);

        cache.add_reused_prt(account_id, &prt).await;

        let cached = cache
            .refresh_token(account_id)
            .await
            .expect("reused PRT should be cached when no entry exists");
        match cached {
            RefreshCacheEntry::Prt(cached_prt) => {
                assert_eq!(serialized_prt(&cached_prt), serialized_prt(&prt));
            }
            RefreshCacheEntry::RefreshToken(_) => panic!("expected a cached PRT"),
        }
    }

    #[tokio::test]
    async fn fresh_prt_replaces_existing_value_and_timestamp() {
        let cache = RefreshCache::new();
        let account_id = "User@Example.com";
        let original_timestamp = SystemTime::now() - Duration::from_secs(60);
        cache
            .refresh_cache
            .write()
            .await
            .insert(account_id.to_lowercase(), (test_prt(4), original_timestamp));
        let fresh_prt = test_prt(5);

        cache
            .add(account_id, &RefreshCacheEntry::Prt(fresh_prt.clone()))
            .await;

        let entries = cache.refresh_cache.read().await;
        let (cached_prt, cached_timestamp) = entries
            .get(&account_id.to_lowercase())
            .expect("fresh PRT should be cached");
        assert_eq!(serialized_prt(cached_prt), serialized_prt(&fresh_prt));
        assert!(*cached_timestamp > original_timestamp);
    }

    #[tokio::test]
    async fn remove_prt_deletes_cached_prt() {
        let cache = RefreshCache::new();
        let account_id = "User@Example.com";
        cache
            .add(account_id, &RefreshCacheEntry::Prt(test_prt(6)))
            .await;

        cache.remove_prt(account_id).await;

        assert!(cache.refresh_token(account_id).await.is_err());
    }

    #[tokio::test]
    async fn remove_prt_exposes_existing_refresh_token() {
        let cache = RefreshCache::new();
        let account_id = "User@Example.com";
        cache
            .add(
                account_id,
                &RefreshCacheEntry::RefreshToken("refresh-token".to_string()),
            )
            .await;
        cache
            .add(account_id, &RefreshCacheEntry::Prt(test_prt(7)))
            .await;

        cache.remove_prt(account_id).await;

        match cache
            .refresh_token(account_id)
            .await
            .expect("refresh token should remain cached")
        {
            RefreshCacheEntry::RefreshToken(refresh_token) => {
                assert_eq!(refresh_token, "refresh-token");
            }
            RefreshCacheEntry::Prt(_) => panic!("cached PRT should have been removed"),
        }
    }

    #[test]
    fn hello_pin_retry_count_allows_exactly_configured_failures() {
        let retry_count = 3;

        assert!(!should_warn_last_hello_pin_attempt(1, retry_count));
        assert!(!should_block_hello_pin_attempts(1, retry_count));

        assert!(should_warn_last_hello_pin_attempt(2, retry_count));
        assert!(!should_block_hello_pin_attempts(2, retry_count));

        assert!(!should_warn_last_hello_pin_attempt(3, retry_count));
        assert!(should_block_hello_pin_attempts(3, retry_count));
    }

    #[test]
    fn hello_pin_retry_count_zero_blocks_immediately() {
        assert!(!should_warn_last_hello_pin_attempt(0, 0));
        assert!(should_block_hello_pin_attempts(0, 0));
        assert!(should_block_hello_pin_attempts(1, 0));
    }

    #[tokio::test]
    async fn bad_pin_delay_does_not_block_runtime() {
        let counter = BadPinCounter::new();

        let delay = tokio::time::timeout(
            Duration::from_millis(10),
            counter.increment_bad_pin_count("user@example.com"),
        )
        .await;

        assert!(delay.is_err());
        assert_eq!(counter.bad_pin_count("user@example.com").await, 1);
    }

    #[test]
    fn offline_hello_pin_policy_blocks_unprotected_remote_auth() {
        assert!(!should_offer_offline_hello_pin(true, false, false));
        assert!(should_offer_offline_hello_pin(false, false, false));
        assert!(should_offer_offline_hello_pin(true, false, true));
        assert!(should_offer_offline_hello_pin(true, true, false));
    }

    #[test]
    fn expired_prt_is_renewed_only_for_online_try_unseal_with_hello_key() {
        assert!(should_renew_expired_try_unseal_prt(&KeyType::Hello, true));
        assert!(!should_renew_expired_try_unseal_prt(&KeyType::Hello, false));
        assert!(!should_renew_expired_try_unseal_prt(
            &KeyType::Decoupled,
            true
        ));
    }

    #[test]
    fn try_unseal_policy_enforces_all_hello_gates() {
        assert_eq!(
            try_unseal_policy_denial(false, false, 0, 3),
            Some(TryUnsealPolicyDenial::HelloDisabled)
        );
        assert_eq!(
            try_unseal_policy_denial(true, true, 0, 3),
            Some(TryUnsealPolicyDenial::HelloTotpEnabled)
        );
        assert_eq!(
            try_unseal_policy_denial(true, false, 2, 2),
            Some(TryUnsealPolicyDenial::RetryLimitReached)
        );
        assert_eq!(
            try_unseal_policy_denial(true, false, 0, 0),
            Some(TryUnsealPolicyDenial::RetryLimitReached)
        );
        assert_eq!(try_unseal_policy_denial(true, false, 1, 2), None);
    }

    const TEST_HELLO_PIN: &str = "123456";
    const TEST_ACCOUNT_ID: &str = "testuser@example.com";

    #[derive(Default)]
    struct RecordingKeyStore {
        entries: HashMap<String, Vec<u8>>,
        inserted_tags: Vec<String>,
        fail_insert: bool,
    }

    impl KeyStoreTxn for RecordingKeyStore {
        fn get_tagged_hsm_key<K: serde::de::DeserializeOwned>(
            &mut self,
            tag: &str,
        ) -> Result<Option<K>, CacheError> {
            self.entries
                .get(tag)
                .map(|entry| serde_cbor::from_slice(entry).map_err(|_| CacheError::SerdeJson))
                .transpose()
        }

        fn insert_tagged_hsm_key<K: serde::Serialize>(
            &mut self,
            tag: &str,
            key: &K,
        ) -> Result<(), CacheError> {
            if self.fail_insert {
                return Err(CacheError::Sqlite);
            }
            let entry = serde_cbor::to_vec(key).map_err(|_| CacheError::SerdeJson)?;
            self.entries.insert(tag.to_string(), entry);
            self.inserted_tags.push(tag.to_string());
            Ok(())
        }

        fn delete_tagged_hsm_key(&mut self, tag: &str) -> Result<(), CacheError> {
            self.entries.remove(tag);
            Ok(())
        }
    }

    struct ResealHarness {
        client: tokio::sync::Mutex<BrokerClientApplication>,
    }

    #[allow(dead_code)]
    impl ResealHarness {
        crate::impl_himmelblau_hello_key_helpers!();
    }

    fn reseal_harness() -> anyhow::Result<ResealHarness> {
        let client =
            BrokerClientApplication::new(None, None, None, None, Duration::from_secs(30), &[])
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        Ok(ResealHarness {
            client: tokio::sync::Mutex::new(client),
        })
    }

    fn user_token(prt: Option<SealedData>) -> anyhow::Result<MsalUserToken> {
        let mut token: MsalUserToken = serde_json::from_value(serde_json::json!({
            "token_type": "Bearer",
            "expires_in": 3600,
            "ext_expires_in": 3600,
            "refresh_token": "refresh-token",
        }))?;
        token.prt = prt;
        Ok(token)
    }

    fn soft_tpm_with_hello_key() -> anyhow::Result<(BoxedDynTpm, StorageKey, LoadableMsHelloKey)> {
        let mut tpm = BoxedDynTpm::new(SoftTpm::new());
        let auth = AuthValue::ephemeral().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let loadable_machine_key = tpm
            .root_storage_key_create(&auth)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let machine_key = tpm
            .root_storage_key_load(&auth, &loadable_machine_key)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let pin = PinValue::new(TEST_HELLO_PIN).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let hello_key = tpm
            .ms_hello_key_create(&machine_key, &pin)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        Ok((tpm, machine_key, hello_key))
    }

    fn load_hello_key(
        hello_key: &LoadableMsHelloKey,
        pin: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &StorageKey,
    ) -> anyhow::Result<LoadedMsHelloKey> {
        LoadedMsHelloKey::load(hello_key, pin, tpm, machine_key)
            .map_err(|e| anyhow::anyhow!("{e:?}"))
    }

    fn other_loaded_hello_key(
        tpm: &mut BoxedDynTpm,
        machine_key: &StorageKey,
    ) -> anyhow::Result<LoadedMsHelloKey> {
        let pin = PinValue::new(TEST_HELLO_PIN).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let hello_key = tpm
            .ms_hello_key_create(machine_key, &pin)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        load_hello_key(&hello_key, TEST_HELLO_PIN, tpm, machine_key)
    }

    const TEST_PRT_REFRESH_TOKEN: &str = "prt-refresh-token";

    /// A harness whose client holds a transport key, and a PRT sealed with it.
    fn harness_with_host_sealed_prt(
        tpm: &mut BoxedDynTpm,
        machine_key: &StorageKey,
    ) -> anyhow::Result<(ResealHarness, SealedData)> {
        let loadable_transport_key = tpm
            .msoapxbc_rsa_key_create(machine_key)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let transport_key = tpm
            .msoapxbc_rsa_key_load(machine_key, &loadable_transport_key)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let prt_storage_key = tpm.rs256_yield_cek(&transport_key);
        let prt = serde_json::to_vec(&serde_json::json!({
            "token_type": "Bearer",
            "expires_in": "3600",
            "ext_expires_in": "3600",
            "expires_on": "9999999999",
            "refresh_token": TEST_PRT_REFRESH_TOKEN,
            "refresh_token_expires_in": 3600,
            "id_token": { "name": "", "oid": "", "tid": "" },
        }))?;
        let host_sealed_prt = tpm
            .seal_data(
                prt_storage_key.as_ref().unwrap_or(machine_key),
                Zeroizing::new(prt),
            )
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let mut harness = reseal_harness()?;
        harness
            .client
            .get_mut()
            .set_transport_key(Some(loadable_transport_key));
        Ok((harness, host_sealed_prt))
    }

    fn unseal_cached_refresh_token(
        keystore: &mut RecordingKeyStore,
        tpm: &mut BoxedDynTpm,
        hello_storage_key: &StorageKey,
        refresh_token_tag: &str,
    ) -> anyhow::Result<String> {
        let sealed_refresh_token: SealedData = keystore
            .get_tagged_hsm_key(refresh_token_tag)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?
            .ok_or_else(|| anyhow::anyhow!("refresh token was not persisted"))?;
        unseal_refresh_token_with_loaded_hello_key(tpm, hello_storage_key, &sealed_refresh_token)
            .map_err(|e| anyhow::anyhow!("{e:?}"))
    }

    #[test]
    fn refresh_token_storage_uses_loaded_hello_key() -> anyhow::Result<()> {
        let (mut tpm, machine_key, hello_key) = soft_tpm_with_hello_key()?;
        let loaded_hello_key = load_hello_key(&hello_key, TEST_HELLO_PIN, &mut tpm, &machine_key)?;
        let hello_storage_key = loaded_hello_key.storage_key();
        let refresh_token_tag = format!("{TEST_ACCOUNT_ID}/hello_refresh_token");

        let mut keystore = RecordingKeyStore::default();
        cache_refresh_token_with_loaded_hello_key(
            &mut keystore,
            &mut tpm,
            hello_storage_key,
            "refresh-token",
            TEST_ACCOUNT_ID,
            &refresh_token_tag,
        );
        assert_eq!(keystore.inserted_tags, vec![refresh_token_tag.clone()]);
        assert_eq!(
            unseal_cached_refresh_token(
                &mut keystore,
                &mut tpm,
                hello_storage_key,
                &refresh_token_tag
            )?,
            "refresh-token"
        );

        let mut failing_keystore = RecordingKeyStore {
            fail_insert: true,
            ..Default::default()
        };
        cache_refresh_token_with_loaded_hello_key(
            &mut failing_keystore,
            &mut tpm,
            hello_storage_key,
            "refresh-token",
            TEST_ACCOUNT_ID,
            &refresh_token_tag,
        );
        assert!(failing_keystore.inserted_tags.is_empty());

        let invalid_utf8 = tpm
            .seal_data(hello_storage_key, Zeroizing::new(vec![0xff]))
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        assert!(matches!(
            unseal_refresh_token_with_loaded_hello_key(&mut tpm, hello_storage_key, &invalid_utf8),
            Err(IdpError::Tpm)
        ));

        let other_loaded_hello_key = other_loaded_hello_key(&mut tpm, &machine_key)?;
        assert!(unseal_cached_refresh_token(
            &mut keystore,
            &mut tpm,
            other_loaded_hello_key.storage_key(),
            &refresh_token_tag
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn unreadable_sealed_refresh_token_falls_back() -> anyhow::Result<()> {
        let (mut tpm, machine_key, hello_key) = soft_tpm_with_hello_key()?;
        let loaded_hello_key = load_hello_key(&hello_key, TEST_HELLO_PIN, &mut tpm, &machine_key)?;
        let hello_storage_key = loaded_hello_key.storage_key();
        let refresh_token_tag = format!("{TEST_ACCOUNT_ID}/hello_refresh_token");
        let fallback = || Some(RefreshCacheEntry::RefreshToken("in-memory".to_string()));
        let is_refresh_token = |entry: Option<RefreshCacheEntry>, expected: &str| matches!(entry, Some(RefreshCacheEntry::RefreshToken(value)) if value == expected);

        let mut keystore = RecordingKeyStore::default();
        assert!(is_refresh_token(
            sealed_refresh_token_or(
                &mut keystore,
                &mut tpm,
                hello_storage_key,
                &refresh_token_tag,
                fallback()
            ),
            "in-memory"
        ));

        cache_refresh_token_with_loaded_hello_key(
            &mut keystore,
            &mut tpm,
            hello_storage_key,
            "sealed",
            TEST_ACCOUNT_ID,
            &refresh_token_tag,
        );
        assert!(is_refresh_token(
            sealed_refresh_token_or(
                &mut keystore,
                &mut tpm,
                hello_storage_key,
                &refresh_token_tag,
                fallback()
            ),
            "sealed"
        ));

        let other_loaded_hello_key = other_loaded_hello_key(&mut tpm, &machine_key)?;
        assert!(is_refresh_token(
            sealed_refresh_token_or(
                &mut keystore,
                &mut tpm,
                other_loaded_hello_key.storage_key(),
                &refresh_token_tag,
                fallback()
            ),
            "in-memory"
        ));
        assert!(sealed_refresh_token_or(
            &mut keystore,
            &mut tpm,
            other_loaded_hello_key.storage_key(),
            &refresh_token_tag,
            None
        )
        .is_none());

        let invalid_utf8 = tpm
            .seal_data(hello_storage_key, Zeroizing::new(vec![0xff]))
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        keystore
            .insert_tagged_hsm_key(&refresh_token_tag, &invalid_utf8)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        assert!(is_refresh_token(
            sealed_refresh_token_or(
                &mut keystore,
                &mut tpm,
                hello_storage_key,
                &refresh_token_tag,
                fallback()
            ),
            "in-memory"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn reseal_without_prt_caches_refresh_token_with_existing_hello_key() -> anyhow::Result<()>
    {
        let harness = reseal_harness()?;
        let (mut tpm, machine_key, hello_key) = soft_tpm_with_hello_key()?;
        let token = user_token(None)?;
        let pin = Zeroizing::new(TEST_HELLO_PIN.to_string());
        let mut keystore = RecordingKeyStore::default();

        crate::seal_prt_with_existing_hello_key!(
            harness,
            TEST_ACCOUNT_ID,
            token,
            &hello_key,
            &pin,
            &mut keystore,
            &mut tpm,
            &machine_key
        );

        let refresh_token_tag = harness.fetch_hello_refresh_token_key_tag(TEST_ACCOUNT_ID);
        assert_eq!(keystore.inserted_tags, vec![refresh_token_tag.clone()]);
        let loaded_hello_key = load_hello_key(&hello_key, TEST_HELLO_PIN, &mut tpm, &machine_key)?;
        assert_eq!(
            unseal_cached_refresh_token(
                &mut keystore,
                &mut tpm,
                loaded_hello_key.storage_key(),
                &refresh_token_tag
            )?,
            "refresh-token"
        );
        Ok(())
    }

    #[tokio::test]
    async fn reseal_with_wrong_pin_caches_nothing() -> anyhow::Result<()> {
        let harness = reseal_harness()?;
        let (mut tpm, machine_key, hello_key) = soft_tpm_with_hello_key()?;
        let wrong_pin = Zeroizing::new("654321".to_string());

        for token in [user_token(None)?, user_token(Some(test_prt(1)))?] {
            let mut keystore = RecordingKeyStore::default();
            crate::seal_prt_with_existing_hello_key!(
                harness,
                TEST_ACCOUNT_ID,
                token,
                &hello_key,
                &wrong_pin,
                &mut keystore,
                &mut tpm,
                &machine_key
            );
            assert!(keystore.inserted_tags.is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    async fn reseal_prt_seal_failure_caches_nothing() -> anyhow::Result<()> {
        let harness = reseal_harness()?;
        let (mut tpm, machine_key, hello_key) = soft_tpm_with_hello_key()?;
        // Without a transport key the PRT cannot be re-sealed.
        let token = user_token(Some(test_prt(1)))?;
        let pin = Zeroizing::new(TEST_HELLO_PIN.to_string());
        let mut keystore = RecordingKeyStore::default();

        crate::seal_prt_with_existing_hello_key!(
            harness,
            TEST_ACCOUNT_ID,
            token,
            &hello_key,
            &pin,
            &mut keystore,
            &mut tpm,
            &machine_key
        );

        assert!(keystore.inserted_tags.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn token_cache_seals_prt_with_loaded_hello_key() -> anyhow::Result<()> {
        let (mut tpm, machine_key, hello_key) = soft_tpm_with_hello_key()?;
        let (harness, host_sealed_prt) = harness_with_host_sealed_prt(&mut tpm, &machine_key)?;
        let loaded_hello_key = load_hello_key(&hello_key, TEST_HELLO_PIN, &mut tpm, &machine_key)?;
        let token = user_token(Some(host_sealed_prt))?;
        let mut keystore = RecordingKeyStore::default();

        crate::cache_token_with_loaded_hello_key!(
            harness,
            TEST_ACCOUNT_ID,
            token,
            &loaded_hello_key,
            &mut keystore,
            &mut tpm,
            &machine_key
        );

        let prt_tag = harness.fetch_hello_prt_key_tag(TEST_ACCOUNT_ID);
        assert_eq!(keystore.inserted_tags, vec![prt_tag.clone()]);
        let hello_prt: SealedData = keystore
            .get_tagged_hsm_key(&prt_tag)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?
            .ok_or_else(|| anyhow::anyhow!("PRT was not persisted"))?;
        let prt = tpm
            .unseal_data(loaded_hello_key.storage_key(), &hello_prt)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let prt: serde_json::Value = serde_json::from_slice(&prt)?;
        assert_eq!(prt["refresh_token"], TEST_PRT_REFRESH_TOKEN);

        let other_loaded_hello_key = other_loaded_hello_key(&mut tpm, &machine_key)?;
        assert!(tpm
            .unseal_data(other_loaded_hello_key.storage_key(), &hello_prt)
            .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn token_cache_insert_failure_stores_nothing() -> anyhow::Result<()> {
        let (mut tpm, machine_key, hello_key) = soft_tpm_with_hello_key()?;
        let (harness, host_sealed_prt) = harness_with_host_sealed_prt(&mut tpm, &machine_key)?;
        let loaded_hello_key = load_hello_key(&hello_key, TEST_HELLO_PIN, &mut tpm, &machine_key)?;

        for token in [user_token(Some(host_sealed_prt))?, user_token(None)?] {
            let mut keystore = RecordingKeyStore {
                fail_insert: true,
                ..Default::default()
            };
            crate::cache_token_with_loaded_hello_key!(
                harness,
                TEST_ACCOUNT_ID,
                token,
                &loaded_hello_key,
                &mut keystore,
                &mut tpm,
                &machine_key
            );
            assert!(keystore.entries.is_empty());
        }
        Ok(())
    }

    fn setup_totp_with_storage_key(
        hello_storage_key: &StorageKey,
        tpm: &mut BoxedDynTpm,
        cred_handler: &mut AuthCredHandler,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        let account_id = TEST_ACCOUNT_ID;
        let pin = TEST_HELLO_PIN.to_string();
        crate::impl_setup_hello_totp_with_storage_key!(
            account_id,
            hello_storage_key,
            pin,
            tpm,
            cred_handler
        )
    }

    fn setup_totp_with_pin(
        harness: &ResealHarness,
        keystore: &mut RecordingKeyStore,
        pin: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &StorageKey,
        cred_handler: &mut AuthCredHandler,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        let account_id = TEST_ACCOUNT_ID;
        let pin = pin.to_string();
        crate::impl_setup_hello_totp!(
            harness,
            account_id,
            keystore,
            _old_token,
            pin,
            tpm,
            machine_key,
            cred_handler
        )
    }

    #[test]
    fn totp_setup_seals_enrollment_with_loaded_hello_key() -> anyhow::Result<()> {
        let (mut tpm, machine_key, hello_key) = soft_tpm_with_hello_key()?;
        let loaded_hello_key = load_hello_key(&hello_key, TEST_HELLO_PIN, &mut tpm, &machine_key)?;
        let mut cred_handler = AuthCredHandler::None;

        let msg = match setup_totp_with_storage_key(
            loaded_hello_key.storage_key(),
            &mut tpm,
            &mut cred_handler,
        ) {
            Ok((AuthResult::Next(AuthRequest::HelloTOTP { msg }), AuthCacheAction::None)) => msg,
            Ok(_) => anyhow::bail!("expected a TOTP enrollment request"),
            Err(e) => anyhow::bail!("TOTP setup failed: {e:?}"),
        };
        let sealed_totp = match cred_handler {
            AuthCredHandler::HelloTOTP {
                cred,
                pending_sealed_totp: Some(sealed_totp),
            } if cred == TEST_HELLO_PIN => sealed_totp,
            other => anyhow::bail!("unexpected credential handler: {other:?}"),
        };
        let record = tpm
            .unseal_data(loaded_hello_key.storage_key(), &sealed_totp)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let record: TotpEnrollmentRecord = serde_json::from_slice(&record)?;
        assert_eq!(record.account_name, TEST_ACCOUNT_ID);
        assert!(msg.starts_with("otpauth://totp/"));
        assert!(msg.contains(&format!("secret={}", record.secret_b32)));

        let other_loaded_hello_key = other_loaded_hello_key(&mut tpm, &machine_key)?;
        assert!(tpm
            .unseal_data(other_loaded_hello_key.storage_key(), &sealed_totp)
            .is_err());
        Ok(())
    }

    #[test]
    fn totp_setup_requires_stored_hello_key_and_correct_pin() -> anyhow::Result<()> {
        let harness = reseal_harness()?;
        let (mut tpm, machine_key, hello_key) = soft_tpm_with_hello_key()?;
        let mut cred_handler = AuthCredHandler::None;

        let mut empty_keystore = RecordingKeyStore::default();
        assert!(matches!(
            setup_totp_with_pin(
                &harness,
                &mut empty_keystore,
                TEST_HELLO_PIN,
                &mut tpm,
                &machine_key,
                &mut cred_handler
            ),
            Err(IdpError::BadRequest)
        ));
        assert!(matches!(cred_handler, AuthCredHandler::None));

        let mut keystore = RecordingKeyStore::default();
        keystore
            .insert_tagged_hsm_key(
                &harness.fetch_hello_key_tag(TEST_ACCOUNT_ID, true),
                &hello_key,
            )
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        assert!(matches!(
            setup_totp_with_pin(
                &harness,
                &mut keystore,
                "654321",
                &mut tpm,
                &machine_key,
                &mut cred_handler
            ),
            Err(IdpError::Tpm)
        ));
        assert!(matches!(cred_handler, AuthCredHandler::None));

        assert!(matches!(
            setup_totp_with_pin(
                &harness,
                &mut keystore,
                TEST_HELLO_PIN,
                &mut tpm,
                &machine_key,
                &mut cred_handler
            ),
            Ok((
                AuthResult::Next(AuthRequest::HelloTOTP { .. }),
                AuthCacheAction::None
            ))
        ));
        assert!(matches!(
            cred_handler,
            AuthCredHandler::HelloTOTP {
                pending_sealed_totp: Some(_),
                ..
            }
        ));
        Ok(())
    }
}

// Shared identity mapping for standard OIDC and Interaction Code providers.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OidcAdditionalUserInfoClaims(HashMap<String, Value>);
impl AdditionalClaims for OidcAdditionalUserInfoClaims {}

pub(crate) type OidcUserInfoClaims = UserInfoClaims<OidcAdditionalUserInfoClaims, CoreGenderClaim>;

fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn oidc_claim_string(userinfo_json: &Value, claim: &str) -> Option<String> {
    match userinfo_json.get(claim) {
        Some(Value::String(value)) if !value.is_empty() => Some(value.to_string()),
        Some(value) => {
            if matches!(value, Value::String(_)) {
                warn!(
                    claim,
                    "OIDC account ID claim is present but is an empty string"
                );
            } else {
                warn!(
                    claim,
                    value_type = value_type_name(value),
                    "OIDC account ID claim is present but is not a string"
                );
            }
            None
        }
        None => None,
    }
}

fn oidc_fallback_account_id(userinfo: &OidcUserInfoClaims) -> Option<String> {
    userinfo
        .preferred_username()
        .map(|username| username.to_string())
        .filter(|username| !username.is_empty())
        .or_else(|| {
            userinfo
                .email()
                .map(|email| email.to_string())
                .filter(|email| !email.is_empty())
        })
}

pub(crate) fn oidc_account_id_from_userinfo(
    userinfo: &OidcUserInfoClaims,
    configured_claims: &[String],
    strip_at_suffix: bool,
) -> Result<String, IdpError> {
    let account_id = if configured_claims.is_empty() {
        oidc_fallback_account_id(userinfo).ok_or_else(|| {
            error!("Missing non-empty preferred_username and email claims in userinfo");
            IdpError::BadRequest
        })?
    } else {
        let userinfo_json = serde_json::to_value(userinfo).map_err(|e| {
            error!(?e, "Failed to serialize OIDC userinfo claims");
            IdpError::BadRequest
        })?;

        let mut configured_account_id = None;
        for claim in configured_claims {
            if let Some(account_id) = oidc_claim_string(&userinfo_json, claim) {
                configured_account_id = Some(account_id);
                break;
            }
        }

        if let Some(account_id) = configured_account_id {
            account_id
        } else {
            warn!(
                claims = ?configured_claims,
                "Configured OIDC account ID claims did not match any non-empty string userinfo claim; falling back to preferred_username, then email"
            );

            oidc_fallback_account_id(userinfo).ok_or_else(|| {
                error!(
                    claims = ?configured_claims,
                    "Configured OIDC account ID claims did not match and fallback preferred_username/email claims are missing or empty"
                );
                IdpError::BadRequest
            })?
        }
    };

    if strip_at_suffix {
        let account_id = account_id
            .split_once('@')
            .map(|(local, _)| local.to_string())
            .unwrap_or(account_id);
        if account_id.is_empty() {
            error!("OIDC account ID is empty after stripping @suffix");
            Err(IdpError::BadRequest)
        } else {
            Ok(account_id)
        }
    } else {
        Ok(account_id)
    }
}

fn oidc_extract_claim_string(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.contains(':') || value.chars().any(char::is_control) {
        None
    } else {
        Some(value.to_string())
    }
}

fn oidc_claim_strings(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(group)) => oidc_extract_claim_string(group).into_iter().collect(),
        Some(Value::Array(groups)) => groups
            .iter()
            .filter_map(|group| group.as_str().and_then(oidc_extract_claim_string))
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn oidc_group_claims_from_value(claims: &Value) -> Vec<String> {
    let mut groups = oidc_claim_strings(claims.get("groups"));

    if let Some(Value::Object(realm_access)) = claims.get("realm_access") {
        groups.extend(oidc_claim_strings(realm_access.get("roles")));
    }

    if let Some(Value::Object(resource_access)) = claims.get("resource_access") {
        for resource in resource_access.values() {
            if let Value::Object(resource_claims) = resource {
                groups.extend(oidc_claim_strings(resource_claims.get("roles")));
            }
        }
    }

    groups.sort();
    groups.dedup();
    groups
}

pub(crate) fn oidc_group_tokens_from_claims(
    group_claims: Vec<String>,
    idmap: &Idmap,
    tenant_id: &Uuid,
) -> Vec<GroupToken> {
    group_claims
        .into_iter()
        .filter_map(|group| {
            let uuid = Uuid::new_v5(tenant_id, group.as_bytes());
            let gidnumber = match idmap.gen_to_unix(&tenant_id.to_string(), &group) {
                Ok(gidnumber) => gidnumber,
                Err(e) => {
                    error!(?e, group = %group, "Failed mapping OIDC group claim");
                    return None;
                }
            };

            Some(GroupToken {
                name: group.clone(),
                spn: group,
                uuid,
                gidnumber,
            })
        })
        .collect()
}

pub(crate) async fn oidc_user_token_from_claims(
    claims: &serde_json::Value,
    shell: String,
    idmap: &tokio::sync::Mutex<Idmap>,
    tenant_id: &uuid::Uuid,
    account_id_claims: &[String],
    strip_at_suffix: bool,
) -> Result<UserToken, IdpError> {
    let bytes = serde_json::to_vec(claims).map_err(|_| IdpError::BadRequest)?;
    let userinfo = OidcUserInfoClaims::from_json::<reqwest::Error>(&bytes, None)
        .map_err(|_| IdpError::BadRequest)?;
    let group_claims = oidc_group_claims_from_value(claims);
    let account_id = oidc_account_id_from_userinfo(&userinfo, account_id_claims, strip_at_suffix)?;

    let subject = userinfo.subject().to_string();
    let object_id = uuid::Uuid::new_v5(tenant_id, subject.as_bytes());

    let idmap_cache = StaticIdCache::new(ID_MAP_CACHE, false).map_err(|e| {
        error!("Failed reading from the idmap cache: {:?}", e);
        IdpError::BadRequest
    })?;

    let idmap = idmap.lock().await;
    let oidc_groups = oidc_group_tokens_from_claims(group_claims, &idmap, tenant_id);

    let (uid, gid) = match idmap_cache.get_user_by_name(&account_id) {
        Some(user) => (user.uid, user.gid),
        None => {
            let gid = idmap
                .gen_to_unix(&tenant_id.to_string(), &account_id)
                .map_err(|e| {
                    error!("{:?}", e);
                    IdpError::BadRequest
                })?;
            (gid, gid)
        }
    };

    let displayname = userinfo
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.to_string())
        .unwrap_or_default();

    let displayname = flip_displayname_comma(&displayname);

    let mut groups = vec![GroupToken {
        name: account_id.to_string(),
        spn: account_id.to_string(),
        uuid: object_id,
        gidnumber: gid,
    }];
    groups.extend(oidc_groups);

    Ok(UserToken {
        name: account_id.to_string(),
        spn: account_id.to_string(),
        uuid: object_id,
        real_gidnumber: Some(uid),
        gidnumber: gid,
        displayname,
        shell: Some(shell),
        groups,
        tenant_id: Some(*tenant_id),
        valid: true,
    })
}
