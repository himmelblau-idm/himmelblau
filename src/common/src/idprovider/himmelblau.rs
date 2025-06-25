/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

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
use super::interface::{
    AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, CacheState, GroupToken, Id,
    IdProvider, IdpError, UserToken,
};
use crate::auth_handle_mfa_resp;
use crate::config::split_username;
use crate::config::HimmelblauConfig;
use crate::config::IdAttr;
use crate::constants::DEFAULT_APP_ID;
use crate::constants::EDGE_BROWSER_CLIENT_ID;
use crate::constants::ID_MAP_CACHE;
use crate::db::KeyStoreTxn;
use crate::idmap_cache::StaticIdCache;
use crate::idprovider::interface::{tpm, UserTokenState};
use crate::unix_proto::PamAuthRequest;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use himmelblau::auth::{BrokerClientApplication, UserToken as UnixUserToken};
use himmelblau::discovery::EnrollAttrs;
use himmelblau::error::{MsalError, DEVICE_AUTH_FAIL};
use himmelblau::graph::{DirectoryObject, Graph};
use himmelblau::intune::IntuneForLinux;
use himmelblau::{AuthOption, MFAAuthContinue};
use idmap::{AadSid, Idmap};
use kanidm_hsm_crypto::{
    structures::LoadableMsDeviceEnrolmentKey, structures::LoadableMsHelloKey,
    structures::LoadableMsOapxbcRsaKey, structures::SealedData, PinValue,
};
use regex::Regex;
use reqwest;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::time::SystemTime;
use tokio::sync::{broadcast, Mutex, RwLock};
use uuid::Uuid;

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

#[derive(Deserialize, Serialize)]
struct Token(Option<String>, String);

pub struct HimmelblauMultiProvider {
    config: Arc<RwLock<HimmelblauConfig>>,
    providers: RwLock<HashMap<String, HimmelblauProvider>>,
}

struct RefreshCache {
    refresh_cache: RwLock<HashMap<String, (SealedData, SystemTime)>>,
}

impl RefreshCache {
    fn new() -> Self {
        RefreshCache {
            refresh_cache: RwLock::new(HashMap::new()),
        }
    }

    async fn refresh_token(&self, account_id: &str) -> Result<SealedData, IdpError> {
        self.purge().await;
        let refresh_cache = self.refresh_cache.read().await;
        match refresh_cache.get(account_id.to_lowercase().as_str()) {
            Some((refresh_token, _)) => Ok(refresh_token.clone()),
            None => Err(IdpError::NotFound),
        }
    }

    async fn purge(&self) {
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
    }

    async fn add(&self, account_id: &str, prt: &SealedData) {
        let mut refresh_cache = self.refresh_cache.write().await;
        refresh_cache.insert(
            account_id.to_string().to_lowercase(),
            (prt.clone(), SystemTime::now()),
        );
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
    pub fn new() -> Self {
        BadPinCounter {
            counter: RwLock::new(HashMap::new()),
        }
    }

    pub async fn bad_pin_count(&self, account_id: &str) -> u32 {
        let map = self.counter.read().await;
        *map.get(account_id).unwrap_or(&0)
    }

    pub async fn increment_bad_pin_count(&self, account_id: &str) {
        let mut map = self.counter.write().await;
        let counter = map.entry(account_id.to_string()).or_insert(0);
        *counter += 1;

        // Discourage attackers by waiting for an ever increasing wait time for each bad pin
        sleep(Duration::from_secs((*counter as u64) * 2));
    }

    pub async fn reset_bad_pin_count(&self, account_id: &str) {
        let mut map = self.counter.write().await;
        map.insert(account_id.to_string(), 0);
    }
}

impl HimmelblauMultiProvider {
    pub async fn new<D: KeyStoreTxn + Send>(
        config_filename: &str,
        keystore: &mut D,
    ) -> Result<Self> {
        let config = match HimmelblauConfig::new(Some(config_filename)) {
            Ok(config) => Arc::new(RwLock::new(config)),
            Err(e) => return Err(anyhow!("{}", e)),
        };
        let idmap = match Idmap::new() {
            Ok(idmap) => Arc::new(RwLock::new(idmap)),
            Err(e) => return Err(anyhow!("{:?}", e)),
        };

        let mut providers = HashMap::new();
        let cfg = config.read().await;
        let domains = cfg.get_configured_domains();
        if domains.is_empty() {
            return Err(anyhow!("No domains configured in himmelblau.conf"));
        }
        for domain in domains {
            debug!("Adding provider for domain {}", domain);
            let authority_host = cfg.get_authority_host(&domain);
            let tenant_id = cfg.get_tenant_id(&domain);
            let graph_url = cfg.get_graph_url(&domain);
            let graph = match Graph::new(
                &cfg.get_odc_provider(&domain),
                &domain,
                Some(&authority_host),
                tenant_id.as_deref(),
                graph_url.as_deref(),
            )
            .await
            {
                Ok(graph) => graph,
                Err(e) => {
                    error!("Failed initializing provider: {:?}", e);
                    continue;
                }
            };
            let app_id = cfg.get_app_id(&domain);
            let app = BrokerClientApplication::new(None, app_id.as_deref(), None, None)
                .map_err(|e| anyhow!("{:?}", e))?;
            let provider = HimmelblauProvider::new(app, &config, &domain, graph, &idmap)
                .map_err(|_| anyhow!("Failed to initialize the provider"))?;
            {
                // A client write lock is required here.
                let mut client = provider.client.write().await;
                if let Ok(transport_key) =
                    provider.fetch_loadable_transport_key_from_keystore(keystore)
                {
                    client.set_transport_key(transport_key);
                }
                if let Ok(cert_key) = provider.fetch_loadable_cert_key_from_keystore(keystore) {
                    client.set_cert_key(cert_key);
                }
            }
            providers.insert(domain.to_string(), provider);
        }

        Ok(HimmelblauMultiProvider {
            config: config.clone(),
            providers: RwLock::new(providers),
        })
    }
}

macro_rules! find_provider {
    ($hmp:ident, $providers:ident, $domain:ident) => {{
        match $providers.get($domain) {
            Some(provider) => Some(provider),
            None => {
                // Attempt to match a provider alias
                let mut cfg = $hmp.config.write().await;
                match cfg.get_primary_domain_from_alias($domain).await {
                    Some(domain) => $providers.get(&domain),
                    None => None,
                }
            }
        }
    }};
}

#[async_trait]
impl IdProvider for HimmelblauMultiProvider {
    /* TODO: Kanidm should be modified to provide the account_id to
     * provider_authenticate, so that we can test the correct provider here.
     * Currently we go offline if ANY provider is down, which could be
     * incorrect. */
    async fn check_online(&self, tpm: &mut tpm::provider::BoxedDynTpm, now: SystemTime) -> bool {
        for (_domain, provider) in self.providers.read().await.iter() {
            if !provider.check_online(tpm, now).await {
                return false;
            }
        }
        true
    }

    async fn unix_user_access(
        &self,
        id: &Id,
        scopes: Vec<String>,
        old_token: Option<&UserToken>,
        client_id: Option<String>,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<UnixUserToken, IdpError> {
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        match split_username(&account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match find_provider!(self, providers, domain) {
                    Some(provider) => {
                        provider
                            .unix_user_access(id, scopes, old_token, client_id, tpm, machine_key)
                            .await
                    }
                    None => Err(IdpError::NotFound),
                }
            }
            None => Err(IdpError::NotFound),
        }
    }

    async fn unix_user_ccaches(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> (Vec<u8>, Vec<u8>) {
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        match split_username(&account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match find_provider!(self, providers, domain) {
                    Some(provider) => {
                        provider
                            .unix_user_ccaches(id, old_token, tpm, machine_key)
                            .await
                    }
                    None => (vec![], vec![]),
                }
            }
            None => (vec![], vec![]),
        }
    }

    async fn unix_user_prt_cookie(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<String, IdpError> {
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        match split_username(&account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match find_provider!(self, providers, domain) {
                    Some(provider) => {
                        provider
                            .unix_user_prt_cookie(id, old_token, tpm, machine_key)
                            .await
                    }
                    None => Err(IdpError::NotFound),
                }
            }
            None => Err(IdpError::NotFound),
        }
    }

    async fn change_auth_token<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UnixUserToken,
        new_tok: &str,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<bool, IdpError> {
        match split_username(account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match find_provider!(self, providers, domain) {
                    Some(provider) => {
                        provider
                            .change_auth_token(
                                account_id,
                                token,
                                new_tok,
                                keystore,
                                tpm,
                                machine_key,
                            )
                            .await
                    }
                    None => Err(IdpError::NotFound),
                }
            }
            None => Err(IdpError::NotFound),
        }
    }

    async fn unix_user_get(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<UserTokenState, IdpError> {
        /* AAD doesn't permit user listing (must use cache entries from auth) */
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        match split_username(&account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match find_provider!(self, providers, domain) {
                    Some(provider) => {
                        provider
                            .unix_user_get(id, old_token, tpm, machine_key)
                            .await
                    }
                    None => Err(IdpError::NotFound),
                }
            }
            None => Err(IdpError::NotFound),
        }
    }

    async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: Option<&UserToken>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        match split_username(account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match find_provider!(self, providers, domain) {
                    Some(provider) => {
                        provider
                            .unix_user_online_auth_init(
                                account_id,
                                token,
                                keystore,
                                tpm,
                                machine_key,
                                shutdown_rx,
                            )
                            .await
                    }
                    None => Err(IdpError::NotFound),
                }
            }
            None => {
                debug!("Authentication ignored for local user '{}'", account_id);
                Err(IdpError::NotFound)
            }
        }
    }

    async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        old_token: &UserToken,
        service: &str,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        match split_username(account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match find_provider!(self, providers, domain) {
                    Some(provider) => {
                        provider
                            .unix_user_online_auth_step(
                                account_id,
                                old_token,
                                service,
                                cred_handler,
                                pam_next_req,
                                keystore,
                                tpm,
                                machine_key,
                                shutdown_rx,
                            )
                            .await
                    }
                    None => Err(IdpError::NotFound),
                }
            }
            None => {
                debug!("Authentication ignored for local user '{}'", account_id);
                Err(IdpError::NotFound)
            }
        }
    }

    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: Option<&UserToken>,
        keystore: &mut D,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        match split_username(account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match find_provider!(self, providers, domain) {
                    Some(provider) => {
                        provider
                            .unix_user_offline_auth_init(account_id, token, keystore)
                            .await
                    }
                    None => Err(IdpError::NotFound),
                }
            }
            None => {
                debug!("Authentication ignored for local user '{}'", account_id);
                Err(IdpError::NotFound)
            }
        }
    }

    async fn unix_user_offline_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UserToken,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        online_at_init: bool,
    ) -> Result<AuthResult, IdpError> {
        match split_username(account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match find_provider!(self, providers, domain) {
                    Some(provider) => {
                        provider
                            .unix_user_offline_auth_step(
                                account_id,
                                token,
                                cred_handler,
                                pam_next_req,
                                keystore,
                                tpm,
                                machine_key,
                                online_at_init,
                            )
                            .await
                    }
                    None => Err(IdpError::NotFound),
                }
            }
            None => {
                debug!("Authentication ignored for local user '{}'", account_id);
                Err(IdpError::NotFound)
            }
        }
    }

    async fn unix_group_get(
        &self,
        _id: &Id,
        _tpm: &mut tpm::provider::BoxedDynTpm,
    ) -> Result<GroupToken, IdpError> {
        /* AAD doesn't permit group listing (must use cache entries from auth) */
        Err(IdpError::BadRequest)
    }

    async fn get_cachestate(&self, account_id: Option<&str>) -> CacheState {
        match account_id {
            Some(account_id) => match split_username(account_id) {
                Some((_sam, domain)) => {
                    let providers = self.providers.read().await;
                    match find_provider!(self, providers, domain) {
                        Some(provider) => return provider.get_cachestate(Some(account_id)).await,
                        None => return CacheState::Offline,
                    }
                }
                None => return CacheState::Offline,
            },
            None => {
                for (_domain, provider) in self.providers.read().await.iter() {
                    match provider.get_cachestate(None).await {
                        CacheState::Offline => return CacheState::Offline,
                        CacheState::OfflineNextCheck(time) => {
                            return CacheState::OfflineNextCheck(time)
                        }
                        _ => continue,
                    }
                }
            }
        }
        CacheState::Online
    }
}

// If the provider is offline, we need to backoff and wait a bit.
const OFFLINE_NEXT_CHECK: Duration = Duration::from_secs(15);

pub struct HimmelblauProvider {
    state: Mutex<CacheState>,
    client: RwLock<BrokerClientApplication>,
    config: Arc<RwLock<HimmelblauConfig>>,
    domain: String,
    graph: Graph,
    refresh_cache: RefreshCache,
    idmap: Arc<RwLock<Idmap>>,
    init: RwLock<bool>,
    bad_pin_counter: BadPinCounter,
}

impl HimmelblauProvider {
    pub fn new(
        client: BrokerClientApplication,
        config: &Arc<RwLock<HimmelblauConfig>>,
        domain: &str,
        graph: Graph,
        idmap: &Arc<RwLock<Idmap>>,
    ) -> Result<Self, IdpError> {
        Ok(HimmelblauProvider {
            state: Mutex::new(CacheState::OfflineNextCheck(SystemTime::now())),
            client: RwLock::new(client),
            config: config.clone(),
            domain: domain.to_string(),
            graph,
            refresh_cache: RefreshCache::new(),
            idmap: idmap.clone(),
            init: RwLock::new(false),
            bad_pin_counter: BadPinCounter::new(),
        })
    }
}

#[async_trait]
impl IdProvider for HimmelblauProvider {
    #[instrument(level = "debug", skip_all)]
    async fn check_online(&self, tpm: &mut tpm::provider::BoxedDynTpm, now: SystemTime) -> bool {
        let state = self.state.lock().await.clone();
        match state {
            // Proceed
            CacheState::Online => true,
            CacheState::OfflineNextCheck(at_time) if now >= at_time => {
                // Attempt online. If fails, return token.
                self.attempt_online(tpm, now).await
            }
            CacheState::OfflineNextCheck(_) | CacheState::Offline => false,
        }
    }

    #[instrument(skip(self, old_token, tpm, machine_key))]
    async fn unix_user_access(
        &self,
        id: &Id,
        scopes: Vec<String>,
        old_token: Option<&UserToken>,
        client_id: Option<String>,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<UnixUserToken, IdpError> {
        if (self.delayed_init().await).is_err() {
            // We can't fetch an access_token when initialization hasn't
            // completed. This only happens when we're offline during first
            // startup. This should never happen!
            return Err(IdpError::BadRequest);
        }

        if !self.check_online(tpm, SystemTime::now()).await {
            // We can't fetch an access_token when offline
            return Err(IdpError::BadRequest);
        }

        /* Use the prt mem cache to refresh the user token */
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        let prt = self.refresh_cache.refresh_token(&account_id).await?;
        self.client
            .read()
            .await
            .exchange_prt_for_access_token(
                &prt,
                scopes.iter().map(|s| s.as_ref()).collect(),
                None,
                client_id.as_deref(),
                tpm,
                machine_key,
            )
            .await
            .map_err(|e| {
                error!("{:?}", e);
                IdpError::BadRequest
            })
    }

    #[instrument(skip(self, old_token, tpm, machine_key))]
    async fn unix_user_ccaches(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> (Vec<u8>, Vec<u8>) {
        if (self.delayed_init().await).is_err() {
            // We can't fetch krb5 tgts when initialization hasn't
            // completed. This only happens when we're offline during first
            // startup. This should never happen!
            return (vec![], vec![]);
        }

        if !self.check_online(tpm, SystemTime::now()).await {
            // We can't fetch krb5 tgts when offline
            return (vec![], vec![]);
        }

        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        let prt = match self.refresh_cache.refresh_token(&account_id).await {
            Ok(prt) => prt,
            Err(e) => {
                error!("Failed fetching PRT for Kerberos CCache: {:?}", e);
                return (vec![], vec![]);
            }
        };
        let cloud_ccache = self
            .client
            .read()
            .await
            .fetch_cloud_ccache(&prt, tpm, machine_key)
            .unwrap_or(vec![]);
        let ad_ccache = self
            .client
            .read()
            .await
            .fetch_ad_ccache(&prt, tpm, machine_key)
            .unwrap_or(vec![]);
        (cloud_ccache, ad_ccache)
    }

    #[instrument(skip(self, old_token, tpm, machine_key))]
    async fn unix_user_prt_cookie(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<String, IdpError> {
        if (self.delayed_init().await).is_err() {
            // We can't fetch a PRT cookie when initialization hasn't
            // completed. This only happens when we're offline during first
            // startup. This should never happen!
            return Err(IdpError::BadRequest);
        }

        /* Use the prt mem cache to generate the sso cookie */
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        let prt = self.refresh_cache.refresh_token(&account_id).await?;
        self.client
            .read()
            .await
            .acquire_prt_sso_cookie(&prt, tpm, machine_key)
            .await
            .map_err(|e| {
                error!("Failed to request prt cookie: {:?}", e);
                IdpError::BadRequest
            })
    }

    #[instrument(skip(self, token, new_tok, keystore, tpm, machine_key))]
    async fn change_auth_token<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UnixUserToken,
        new_tok: &str,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<bool, IdpError> {
        if (self.delayed_init().await).is_err() {
            // We can't change the Hello PIN when initialization hasn't
            // completed. This only happens when we're offline during first
            // startup.
            return Err(IdpError::BadRequest);
        }

        if !self.check_online(tpm, SystemTime::now()).await {
            // We can't change the Hello PIN when offline
            return Err(IdpError::BadRequest);
        }

        let hello_tag = self.fetch_hello_key_tag(account_id);

        // Ensure the user is setting the token for the account it has authenticated to
        if account_id.to_string().to_lowercase()
            != token
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
        let hello_key = match self
            .client
            .read()
            .await
            .provision_hello_for_business_key(token, tpm, machine_key, new_tok)
            .await
        {
            Ok(hello_key) => hello_key,
            Err(e) => {
                error!("Failed to provision hello key: {:?}", e);
                return Ok(false);
            }
        };
        keystore
            .insert_tagged_hsm_key(&hello_tag, &hello_key)
            .map_err(|e| {
                error!("Failed to provision hello key: {:?}", e);
                IdpError::Tpm
            })?;
        Ok(true)
    }

    #[instrument(skip(self, old_token, tpm, machine_key))]
    async fn unix_user_get(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<UserTokenState, IdpError> {
        macro_rules! net_down_check {
            ($res:expr, $($pat:pat => $result:expr),*) => {
                match $res {
                    Ok(val) => val,
                    Err(MsalError::RequestFailed(msg)) => {
                        let url = extract_base_url!(msg);
                        info!(?url, "Network down detected");
                        let mut state = self.state.lock().await;
                        *state = CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
                        return Ok(UserTokenState::UseCached)
                    },
                    $($pat => $result),*
                }
            }
        }

        if (self.delayed_init().await).is_err() {
            // Initialization failed. Report that the system is offline. We
            // can't proceed with initialization until the system is online.
            info!("Network down detected");
            let mut state = self.state.lock().await;
            *state = CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
            return Ok(UserTokenState::UseCached);
        }

        if !self.check_online(tpm, SystemTime::now()).await {
            // We are offline, return that we should use a cached token.
            return Ok(UserTokenState::UseCached);
        }

        /* Use the prt mem cache to refresh the user token */
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };

        let idmap_cache = StaticIdCache::new(ID_MAP_CACHE, false).map_err(|e| {
            error!("Failed reading from the idmap cache: {:?}", e);
            IdpError::BadRequest
        })?;

        macro_rules! fake_user {
            () => {
                match old_token {
                    // If we have an existing token, just keep it
                    Some(token) => return Ok(UserTokenState::Update(token.clone())),
                    // Otherwise, see if we should fake it
                    None => {
                        // Check if the user exists
                        let auth_init = net_down_check!(
                            self.client
                                .read()
                                .await
                                .check_user_exists(&account_id, &[])
                                .await,
                            Err(e) => {
                                error!("Failed checking if the user exists: {:?}", e);
                                return Err(IdpError::BadRequest);
                            }
                        );
                        if auth_init.exists() {
                            // Generate a UserToken, with invalid uuid. We can
                            // only fetch this from an authenticated token.
                            let config = self.config.read().await;
                            let (uid, gid) = match idmap_cache.get_user_by_name(&account_id) {
                                Some(user) => {
                                    (user.uid, user.gid)
                                },
                                None => match config.get_id_attr_map() {
                                    IdAttr::Uuid => {
                                        // Attempt to map the UPN to an Object Id.
                                        let sidtoname = self.client
                                            .read()
                                            .await
                                            .resolve_nametosid(
                                                &account_id,
                                                tpm,
                                                machine_key
                                            )
                                            .await
                                            .map_err(|e| {
                                                error!("Failed mapping UPN to Object Id: {:?}", e);
                                                IdpError::BadRequest
                                            })?;
                                        let idmap = self.idmap.read().await;
                                        let sid = AadSid::from_sid_str(&sidtoname.sid).map_err(|e| {
                                            error!("Failed parsing SID: {:?}", e);
                                            IdpError::BadRequest
                                        })?;
                                        let uid = idmap.object_id_to_unix_id(&self.graph.tenant_id().await.map_err(|e| {
                                            error!("Failed fetching tenant id: {:?}", e);
                                            IdpError::BadRequest
                                        })?, &sid).map_err(|e| {
                                            error!("Failed mapping object id to uid: {:?}", e);
                                            IdpError::BadRequest
                                        })?;
                                        (uid, uid)
                                    },
                                    IdAttr::Name | IdAttr::Rfc2307 => {
                                        let idmap = self.idmap.read().await;
                                        let gid = idmap.gen_to_unix(&self.graph.tenant_id().await.map_err(|e| {
                                            error!("{:?}", e);
                                            IdpError::BadRequest
                                        })?, &account_id).map_err(
                                            |e| {
                                                error!("{:?}", e);
                                                IdpError::BadRequest
                                            },
                                        )?;
                                        (gid, gid)
                                    }
                                },
                            };
                            let fake_uuid = Uuid::new_v4();
                            let groups = vec![GroupToken {
                                name: account_id.clone(),
                                spn: account_id.clone(),
                                uuid: fake_uuid,
                                gidnumber: uid,
                            }];
                            let config = self.config.read().await;
                            return Ok(UserTokenState::Update(UserToken {
                                name: account_id.clone(),
                                spn: account_id.clone(),
                                uuid: fake_uuid,
                                real_gidnumber: Some(gid),
                                gidnumber: uid,
                                displayname: "".to_string(),
                                shell: Some(config.get_shell(Some(&self.domain))),
                                groups,
                                tenant_id: Some(Uuid::parse_str(&self.graph.tenant_id().await.map_err(|e| {
                                        error!("{:?}", e);
                                        IdpError::BadRequest
                                    })?).map_err(|e| {
                                    error!("{:?}", e);
                                    IdpError::BadRequest
                                })?),
                                valid: true,
                            }));
                        } else {
                            // This is the one time we really should return
                            // UserTokenState::NotFound, because this user doesn't exist.
                            return Ok(UserTokenState::NotFound);
                        }
                    }
                }
            };
        }
        let prt = match self.refresh_cache.refresh_token(&account_id).await {
            Ok(prt) => prt,
            Err(_) => fake_user!(),
        };
        // If an app_id is defined in the config, the app should have the
        // GroupMember.Read.All API permission.
        let cfg = self.config.read().await;
        let (client_id, scopes) = if cfg.get_app_id(&self.domain).is_some() {
            (None, vec!["GroupMember.Read.All"])
        } else {
            (
                Some(EDGE_BROWSER_CLIENT_ID),
                vec!["https://graph.microsoft.com/.default"],
            )
        };
        let mtoken = self
            .client
            .read()
            .await
            .exchange_prt_for_access_token(&prt, scopes.clone(), None, client_id, tpm, machine_key)
            .await;
        let token = match mtoken {
            Ok(val) => val,
            Err(MsalError::RequestFailed(_)) => {
                // Retry on network failure, as these can be rather common
                sleep(Duration::from_millis(500));
                net_down_check!(
                    self.client
                        .read()
                        .await
                        .exchange_prt_for_access_token(&prt, scopes, None, client_id, tpm, machine_key)
                        .await,
                    Err(e) => {
                        error!("{:?}", e);
                        // Never return IdpError::NotFound. This deletes the existing
                        // user from the cache.
                        fake_user!()
                    }
                )
            }
            Err(e) => {
                error!("{:?}", e);
                // Never return IdpError::NotFound. This deletes the existing
                // user from the cache.
                fake_user!()
            }
        };
        match self.token_validate(&account_id, &token, old_token).await {
            Ok(AuthResult::Success { mut token }) => {
                /* Set the GECOS from the old_token, since MS doesn't
                 * provide this during a silent acquire
                 */
                if let Some(old_token) = old_token {
                    token.displayname.clone_from(&old_token.displayname)
                }
                Ok(UserTokenState::Update(token))
            }
            // Never return IdpError::NotFound. This deletes the existing
            // user from the cache.
            Ok(AuthResult::Denied(_)) | Ok(AuthResult::Next(_)) => fake_user!(),
            Err(_) => fake_user!(),
        }
    }

    #[instrument(skip(self, _token, keystore, tpm, _machine_key, _shutdown_rx))]
    async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        _token: Option<&UserToken>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        macro_rules! net_down_check {
            ($res:expr, $($pat:pat => $result:expr),*) => {
                match $res {
                    Ok(val) => val,
                    Err(MsalError::RequestFailed(msg)) => {
                        let url = extract_base_url!(msg);
                        info!(?url, "Network down detected");
                        let mut state = self.state.lock().await;
                        *state = CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
                        return Ok((
                            AuthRequest::InitDenied {
                                msg: "Network outage detected."
                                    .to_string(),
                            },
                            AuthCredHandler::None,
                        ));
                    },
                    $($pat => $result),*
                }
            }
        }

        let hello_tag = self.fetch_hello_key_tag(account_id);
        let hello_key: Option<LoadableMsHelloKey> =
            keystore.get_tagged_hsm_key(&hello_tag).map_err(|e| {
                error!("Failed fetching hello key from keystore: {:?}", e);
                IdpError::BadRequest
            })?;
        // Skip Hello authentication if it is disabled by config
        let hello_enabled = self.config.read().await.get_enable_hello();
        let hello_pin_retry_count = self.config.read().await.get_hello_pin_retry_count();
        if !self.is_domain_joined(keystore).await
            || hello_key.is_none()
            || !hello_enabled
            || self.bad_pin_counter.bad_pin_count(account_id).await > hello_pin_retry_count
        {
            if (self.delayed_init().await).is_err() {
                // Initialization failed. Report that the system is offline. We
                // can't proceed with initialization until the system is online.
                info!("Network down detected");
                let mut state = self.state.lock().await;
                *state = CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
                return Ok((
                    AuthRequest::InitDenied {
                        msg: "Network outage detected.".to_string(),
                    },
                    AuthCredHandler::None,
                ));
            }
            if self.config.read().await.get_enable_experimental_mfa() {
                let mut auth_options = vec![AuthOption::Fido, AuthOption::Passwordless];
                if self
                    .config
                    .read()
                    .await
                    .get_enable_experimental_passwordless_fido()
                {
                    auth_options.push(AuthOption::PasswordlessFido);
                }
                let auth_init = net_down_check!(
                    self.client
                        .read()
                        .await
                        .check_user_exists(account_id, &auth_options)
                        .await,
                    Err(e) => {
                        error!("{:?}", e);
                        return Err(IdpError::BadRequest);
                    }
                );
                if !auth_init.passwordless() {
                    // Check if the network is even up prior to sending a
                    // password prompt.
                    if !self.attempt_online(tpm, SystemTime::now()).await {
                        return Ok((
                            AuthRequest::InitDenied {
                                msg: "Network outage detected.".to_string(),
                            },
                            AuthCredHandler::None,
                        ));
                    }
                    Ok((AuthRequest::Password, AuthCredHandler::None))
                } else {
                    let flow = net_down_check!(
                        self.client
                            .read()
                            .await
                            .initiate_acquire_token_by_mfa_flow_for_device_enrollment(
                                account_id,
                                None,
                                &auth_options,
                                Some(auth_init),
                            )
                            .await,
                        Err(MsalError::PasswordRequired) => {
                            return Ok((AuthRequest::Password, AuthCredHandler::None));
                        },
                        Err(e) => {
                            error!("{:?}", e);
                            return Err(IdpError::BadRequest);
                        }
                    );
                    let msg = flow.msg.clone();
                    let polling_interval = flow.polling_interval.unwrap_or(5000);
                    Ok((
                        AuthRequest::MFAPoll {
                            msg,
                            // Kanidm pam expects a polling_interval in
                            // seconds, not milliseconds.
                            polling_interval: polling_interval / 1000,
                        },
                        AuthCredHandler::MFA {
                            flow,
                            password: None,
                        },
                    ))
                }
            } else {
                let resp = net_down_check!(
                    self.client
                        .read()
                        .await
                        .initiate_device_flow_for_device_enrollment()
                        .await,
                    Err(e) => {
                        error!("{:?}", e);
                        return Err(IdpError::BadRequest);
                    }
                );
                let mut flow: MFAAuthContinue = resp.into();
                if !self.is_domain_joined(keystore).await {
                    flow.resource = Some("https://enrollment.manage.microsoft.com".to_string());
                }
                let msg = flow.msg.clone();
                let polling_interval = flow.polling_interval.unwrap_or(5000);
                Ok((
                    AuthRequest::MFAPoll {
                        msg,
                        // Kanidm pam expects a polling_interval in
                        // seconds, not milliseconds.
                        polling_interval: polling_interval / 1000,
                    },
                    AuthCredHandler::MFA {
                        flow,
                        password: None,
                    },
                ))
            }
        } else {
            // Check if the network is even up prior to sending a PIN prompt,
            // otherwise we duplicate the PIN prompt when the network goes down.
            if !self.attempt_online(tpm, SystemTime::now()).await {
                // We are offline, fail the authentication now
                return Err(IdpError::BadRequest);
            }

            Ok((AuthRequest::Pin, AuthCredHandler::None))
        }
    }

    #[instrument(skip(
        self,
        old_token,
        cred_handler,
        pam_next_req,
        keystore,
        tpm,
        machine_key,
        _shutdown_rx
    ))]
    async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        old_token: &UserToken,
        service: &str,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        macro_rules! net_down_check {
            ($res:expr, $($pat:pat => $result:expr),*) => {
                match $res {
                    Err(MsalError::RequestFailed(msg)) => {
                        let url = extract_base_url!(msg);
                        info!(?url, "Network down detected");
                        let mut state = self.state.lock().await;
                        *state = CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
                        // Report the network outage to the user via PAM INFO.
                        return Ok((AuthResult::Denied("Network outage detected.".to_string()), AuthCacheAction::None));
                    },
                    $($pat => $result),*
                }
            }
        }

        if (self.delayed_init().await).is_err() {
            // Initialization failed. Report that the system is offline. We
            // can't proceed with initialization until the system is online.
            info!("Network down detected");
            let mut state = self.state.lock().await;
            *state = CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
            // Report the network outage to the user via PAM INFO.
            return Ok((
                AuthResult::Denied("Network outage detected.".to_string()),
                AuthCacheAction::None,
            ));
        }

        macro_rules! enroll_and_obtain_enrolled_token {
            ($token:ident) => {{
                if !self.is_domain_joined(keystore).await {
                    debug!("Device is not enrolled. Enrolling now.");
                    self.join_domain(tpm, &$token, keystore, machine_key)
                        .await
                        .map_err(|e| {
                            error!("Failed to join domain: {:?}", e);
                            IdpError::BadRequest
                        })?;
                }
                // If an app_id is defined in the config, the app should have the
                // GroupMember.Read.All API permission.
                let cfg = self.config.read().await;
                let (client_id, scopes) = if cfg.get_app_id(&self.domain).is_some() {
                    (None, vec!["GroupMember.Read.All"])
                } else {
                    (
                        Some(EDGE_BROWSER_CLIENT_ID),
                        vec!["https://graph.microsoft.com/.default"],
                    )
                };
                let mtoken2 = self
                    .client
                    .read()
                    .await
                    .acquire_token_by_refresh_token(
                        &$token.refresh_token,
                        scopes.clone(),
                        None,
                        client_id,
                        tpm,
                        machine_key,
                    )
                    .await;
                net_down_check!(mtoken2,
                    Ok(token) => token,
                    Err(e) => {
                        error!("{:?}", e);
                        match e {
                            MsalError::AcquireTokenFailed(err_resp) => {
                                if err_resp.error_codes.contains(&DEVICE_AUTH_FAIL) {
                                    /* A device authentication failure may happen
                                     * if Azure hasn't finished replicating the new
                                     * device object. Wait 5 seconds and try again. */
                                    info!("Azure hasn't finished replicating the device...");
                                    info!("Retrying in 5 seconds");
                                    sleep(Duration::from_secs(5));
                                    net_down_check!(
                                        self.client
                                            .read()
                                            .await
                                            .acquire_token_by_refresh_token(
                                                &$token.refresh_token,
                                                scopes,
                                                None,
                                                client_id,
                                                tpm,
                                                machine_key,
                                            )
                                            .await,
                                        Ok(token) => token,
                                        Err(e) => {
                                            error!("{:?}", e);
                                            return Err(IdpError::NotFound);
                                        }
                                    )
                                } else {
                                    return Err(IdpError::NotFound);
                                }
                            }
                            _ => return Err(IdpError::NotFound),
                        }
                    }
                )
            }};
        }
        macro_rules! auth_and_validate_hello_key {
            ($hello_key:ident, $cred:ident) => {{
                // CRITICAL: Validate that we can load the key, otherwise the offline
                // fallback will allow the user to authenticate with a bad PIN here.
                // `acquire_token_by_hello_for_business_key` CAN (and probably will)
                // respond with a `RequestFailed` prior to validating the PIN, since
                // the Nonce request will fail (which is sent prior to validation).
                let pin = PinValue::new(&$cred).map_err(|e| {
                    error!("Failed setting pin value: {:?}", e);
                    IdpError::Tpm
                })?;
                if let Err(e) = tpm.ms_hello_key_load(machine_key, &$hello_key, &pin) {
                    error!("{:?}", e);
                    self.bad_pin_counter
                        .increment_bad_pin_count(account_id)
                        .await;
                    return Ok((
                        AuthResult::Denied("Failed to authenticate with Hello PIN.".to_string()),
                        AuthCacheAction::None,
                    ));
                }

                // If an app_id is defined in the config, the app should have the
                // GroupMember.Read.All API permission.
                let cfg = self.config.read().await;
                let (client_id, scopes) = if cfg.get_app_id(&self.domain).is_some() {
                    (None, vec!["GroupMember.Read.All"])
                } else {
                    (
                        Some(EDGE_BROWSER_CLIENT_ID),
                        vec!["https://graph.microsoft.com/.default"],
                    )
                };
                let token = match self
                    .client
                    .read()
                    .await
                    .acquire_token_by_hello_for_business_key(
                        account_id,
                        &$hello_key,
                        scopes,
                        None,
                        client_id,
                        tpm,
                        machine_key,
                        &$cred,
                    )
                    .await
                {
                    Ok(token) => {
                        self.bad_pin_counter.reset_bad_pin_count(account_id).await;
                        token
                    }
                    // If the network goes down during an online PIN auth, we can downgrade to an
                    // offline auth and permit the authentication to proceed.
                    Err(MsalError::RequestFailed(msg)) => {
                        let url = extract_base_url!(msg);
                        info!(?url, "Network down detected");
                        let mut state = self.state.lock().await;
                        *state =
                            CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
                        return Ok((
                            AuthResult::Success {
                                token: old_token.clone(),
                            },
                            AuthCacheAction::None,
                        ));
                    }
                    Err(e) => {
                        self.bad_pin_counter
                            .increment_bad_pin_count(account_id)
                            .await;
                        error!("Failed to authenticate with hello key: {:?}", e);
                        return Ok((
                            AuthResult::Denied(
                                "Failed to authenticate with Hello PIN.".to_string(),
                            ),
                            AuthCacheAction::None,
                        ));
                    }
                };

                match self.token_validate(account_id, &token, None).await {
                    Ok(AuthResult::Success { token }) => {
                        debug!("Returning user token from successful Hello PIN authentication.");
                        Ok((AuthResult::Success { token }, AuthCacheAction::None))
                    }
                    /* This should never happen. It doesn't make sense to
                     * continue from a Pin auth. */
                    Ok(AuthResult::Next(_)) => {
                        debug!("Invalid additional authentication requested with Hello auth.");
                        Err(IdpError::BadRequest)
                    }
                    Ok(auth_result) => {
                        debug!("Hello auth failed.");
                        Ok((auth_result, AuthCacheAction::None))
                    }
                    Err(e) => {
                        error!("Error encountered during Hello auth: {:?}", e);
                        Err(e)
                    }
                }
            }};
        }
        match (&mut *cred_handler, pam_next_req) {
            (AuthCredHandler::SetupPin { token }, PamAuthRequest::SetupPin { pin }) => {
                let hello_tag = self.fetch_hello_key_tag(account_id);

                let hello_key = net_down_check!(
                    self.client
                        .read()
                        .await
                        .provision_hello_for_business_key(token, tpm, machine_key, &pin)
                        .await,
                    Ok(hello_key) => hello_key,
                    Err(e) => {
                        return Ok((
                            AuthResult::Next(AuthRequest::SetupPin {
                                msg: format!(
                                    "Failed to provision hello key: {:?}\n{}",
                                    e, "Create a PIN to use in place of passwords."
                                ),
                            }),
                            AuthCacheAction::None,
                        ));
                    }
                );
                keystore
                    .insert_tagged_hsm_key(&hello_tag, &hello_key)
                    .map_err(|e| {
                        error!("Failed to provision hello key: {:?}", e);
                        IdpError::Tpm
                    })?;

                auth_and_validate_hello_key!(hello_key, pin)
            }
            (_, PamAuthRequest::Pin { cred }) => {
                let hello_tag = self.fetch_hello_key_tag(account_id);
                let hello_key = keystore
                    .get_tagged_hsm_key(&hello_tag)
                    .map_err(|e| {
                        error!("Failed fetching hello key from keystore: {:?}", e);
                        IdpError::BadRequest
                    })?
                    .ok_or_else(|| {
                        error!("Authentication failed. Hello key missing.");
                        IdpError::BadRequest
                    })?;

                auth_and_validate_hello_key!(hello_key, cred)
            }
            (change_password, PamAuthRequest::Password { mut cred }) => {
                if let AuthCredHandler::ChangePassword { old_cred } = change_password {
                    // Report errors, but don't bail out. If the password change fails,
                    // we'll make another run at it in a moment.
                    let _ = net_down_check!(
                        self.client
                            .read()
                            .await
                            .handle_password_change(account_id, old_cred, &cred)
                            .await,
                        Ok(_) => {},
                        Err(e) => {
                            error!("Failed to change user password: {:?}", e);
                            cred = old_cred.to_string();
                        }
                    );
                }
                // Always attempt to force MFA when enrolling the device, otherwise
                // the device object will not have the MFA claim. If we are already
                // enrolled but creating a new Hello Pin, we follow the same process,
                // since only an enrollment token can be exchanged for a PRT (which
                // will be needed to enroll the Hello Pin).
                let mut opts = vec![];
                // Prohibit Fido over ssh (since it can't work)
                if service != "ssh" {
                    opts.push(AuthOption::Fido);
                    if self
                        .config
                        .read()
                        .await
                        .get_enable_experimental_passwordless_fido()
                    {
                        opts.push(AuthOption::PasswordlessFido);
                    }
                }
                // If SFA is enabled, disable the DAG fallback, otherwise SFA users
                // will always be prompted for DAG.
                let sfa_enabled = self.config.read().await.get_enable_sfa_fallback();
                if sfa_enabled {
                    opts.push(AuthOption::NoDAGFallback);
                }
                let mresp = self
                    .client
                    .read()
                    .await
                    .initiate_acquire_token_by_mfa_flow_for_device_enrollment(
                        account_id,
                        Some(&cred),
                        &opts,
                        None,
                    )
                    .await;
                // We need to wait to handle the response until after we've released
                // the write lock on the client, otherwise we will deadlock.
                let resp = net_down_check!(mresp,
                    Ok(resp) => resp,
                    Err(e) => {
                        // If SFA is disabled, we need to skip the SFA fallback.
                        let mtoken = if sfa_enabled {
                            // If we got an AADSTSError, then we don't want to
                            // perform a fallback, since the authentication
                            // legitimately failed.
                            if let MsalError::AADSTSError(ref e) = e {
                                // If the error is just requesting MFA (since we demanded it
                                // in the previous call), then continue with the SFA fallback.
                                // AADSTS50072: UserStrongAuthEnrollmentRequiredInterrupt
                                // AADSTS50074: UserStrongAuthClientAuthNRequiredInterrupt
                                // AADSTS50076: UserStrongAuthClientAuthNRequired
                                if ![50072, 50074, 50076].contains(&e.code) {
                                    error!(
                                        "Skipping SFA fallback because authentication failed: {:?}",
                                        e
                                    );
                                    return Ok((AuthResult::Denied(e.to_string()), AuthCacheAction::None));
                                }
                            }
                            // We can only do a password auth for an enrolled device
                            if self.is_domain_joined(keystore).await {
                                warn!("MFA auth failed, falling back to SFA: {:?}", e);
                                // Again, we need to wait to handle the response until after
                                // we've released the write lock on the client, otherwise we
                                // will deadlock.
                                let res = self
                                    .client
                                    .read()
                                    .await
                                    .acquire_token_by_username_password(
                                        account_id,
                                        &cred,
                                        vec![],
                                        Some("https://graph.microsoft.com".to_string()),
                                        None,
                                        tpm,
                                        machine_key,
                                    )
                                    .await;
                                net_down_check!(res,
                                    Ok(token) => Ok(token),
                                    Err(e) => {
                                        if let MsalError::ChangePassword = e {
                                            // The user needs to set a new password.
                                            *cred_handler =
                                                AuthCredHandler::ChangePassword { old_cred: cred };
                                            return Ok((
                                                AuthResult::Next(AuthRequest::ChangePassword {
                                                    msg: "Update your password\n\
                                                         You need to update your password because this is\n\
                                                         the first time you are signing in, or because your\n\
                                                         password has expired.".to_string(),
                                                }),
                                                AuthCacheAction::None,
                                            ));
                                        } else {
                                            Err(e)
                                        }
                                    }
                                )
                            } else {
                                error!("Single factor authentication is only permitted on an enrolled host: {:?}", e);
                                return Ok((AuthResult::Denied(e.to_string()), AuthCacheAction::None));
                            }
                        } else {
                            error!("{:?}", e);
                            return Ok((AuthResult::Denied(e.to_string()), AuthCacheAction::None));
                        };
                        let token = match mtoken {
                            Ok(token) => token,
                            Err(e) => {
                                error!("{:?}", e);
                                return Ok((AuthResult::Denied(e.to_string()), AuthCacheAction::None));
                            }
                        };
                        let token2 = enroll_and_obtain_enrolled_token!(token);
                        return match self.token_validate(account_id, &token2, None).await {
                            Ok(AuthResult::Success { token }) => {
                                // STOP! If we just enrolled with an SFA token, then we
                                // need to bail out here and refuse Hello enrollment
                                // (we can't enroll in Hello with an SFA token).
                                return Ok((
                                    AuthResult::Success { token },
                                    AuthCacheAction::PasswordHashUpdate { cred },
                                ));
                            }
                            Ok(auth_result) => Ok((auth_result, AuthCacheAction::None)),
                            Err(e) => Err(e),
                        };
                    }
                );
                auth_handle_mfa_resp!(
                    resp,
                    // FIDO
                    {
                        let fido_challenge =
                            resp.fido_challenge.clone().ok_or(IdpError::BadRequest)?;

                        let fido_allow_list =
                            resp.fido_allow_list.clone().ok_or(IdpError::BadRequest)?;
                        *cred_handler = AuthCredHandler::MFA {
                            flow: resp,
                            password: Some(cred),
                        };
                        return Ok((
                            AuthResult::Next(AuthRequest::Fido {
                                fido_allow_list,
                                fido_challenge,
                            }),
                            /* An MFA auth cannot cache the password. This would
                             * lead to a potential downgrade to SFA attack (where
                             * the attacker auths with a stolen password, then
                             * disconnects the network to complete the auth). */
                            AuthCacheAction::None,
                        ));
                    },
                    // PROMPT
                    {
                        let msg = resp.msg.clone();
                        *cred_handler = AuthCredHandler::MFA {
                            flow: resp,
                            password: Some(cred),
                        };
                        return Ok((
                            AuthResult::Next(AuthRequest::MFACode { msg }),
                            /* An MFA auth cannot cache the password. This would
                             * lead to a potential downgrade to SFA attack (where
                             * the attacker auths with a stolen password, then
                             * disconnects the network to complete the auth). */
                            AuthCacheAction::None,
                        ));
                    },
                    // POLL
                    {
                        let msg = resp.msg.clone();
                        let polling_interval = resp.polling_interval.unwrap_or(5000);
                        *cred_handler = AuthCredHandler::MFA {
                            flow: resp,
                            password: Some(cred),
                        };
                        return Ok((
                            AuthResult::Next(AuthRequest::MFAPoll {
                                msg,
                                // Kanidm pam expects a polling_interval in
                                // seconds, not milliseconds.
                                polling_interval: polling_interval / 1000,
                            }),
                            /* An MFA auth cannot cache the password. This would
                             * lead to a potential downgrade to SFA attack (where
                             * the attacker auths with a stolen password, then
                             * disconnects the network to complete the auth). */
                            AuthCacheAction::None,
                        ));
                    }
                )
            }
            (
                AuthCredHandler::MFA {
                    ref mut flow,
                    password,
                },
                PamAuthRequest::MFACode { cred },
            ) => {
                let token = net_down_check!(
                    self.client
                        .read()
                        .await
                        .acquire_token_by_mfa_flow(account_id, Some(&cred), None, flow)
                        .await,
                    Ok(token) => token,
                    Err(e) => {
                        if let MsalError::ChangePassword = e {
                            if let Some(old_cred) = password {
                                // The user needs to set a new password.
                                *cred_handler = AuthCredHandler::ChangePassword {
                                    old_cred: old_cred.to_string(),
                                };
                                return Ok((
                                    AuthResult::Next(AuthRequest::ChangePassword {
                                        msg: "Update your password\n\
                                             You need to update your password because this is\n\
                                             the first time you are signing in, or because your\n\
                                             password has expired."
                                            .to_string(),
                                    }),
                                    AuthCacheAction::None,
                                ));
                            } else {
                                error!("{:?}", e);
                                return Ok((AuthResult::Denied(e.to_string()), AuthCacheAction::None));
                            }
                        } else {
                            error!("{:?}", e);
                            return Ok((AuthResult::Denied(e.to_string()), AuthCacheAction::None));
                        }
                    }
                );
                let token2 = enroll_and_obtain_enrolled_token!(token);
                match self.token_validate(account_id, &token2, None).await {
                    Ok(AuthResult::Success { token: token3 }) => {
                        // Skip Hello enrollment if it is disabled by config
                        let hello_enabled = self.config.read().await.get_enable_hello();
                        // Skip Hello enrollment if the token doesn't have the ngcmfa amr
                        let amr_ngcmfa = token2.amr_ngcmfa().map_err(|e| {
                            error!("{:?}", e);
                            IdpError::NotFound
                        })?;
                        if !hello_enabled || !amr_ngcmfa {
                            info!("Skipping Hello enrollment because it is disabled");
                            return Ok((
                                AuthResult::Success { token: token3 },
                                AuthCacheAction::None,
                            ));
                        }

                        // Setup Windows Hello
                        *cred_handler = AuthCredHandler::SetupPin { token };
                        return Ok((
                            AuthResult::Next(AuthRequest::SetupPin {
                                msg: format!(
                                    "Set up a PIN\n {}{}",
                                    "A Hello PIN is a fast, secure way to sign",
                                    "in to your device, apps, and services."
                                ),
                            }),
                            AuthCacheAction::None,
                        ));
                    }
                    Ok(auth_result) => Ok((auth_result, AuthCacheAction::None)),
                    Err(e) => Err(e),
                }
            }
            (
                AuthCredHandler::MFA {
                    ref mut flow,
                    password,
                },
                PamAuthRequest::MFAPoll { poll_attempt },
            ) => {
                let max_poll_attempts = flow.max_poll_attempts.unwrap_or(180);
                if poll_attempt > max_poll_attempts {
                    error!("MFA polling timed out");
                    return Err(IdpError::BadRequest);
                }
                let token = net_down_check!(
                    self.client
                        .read()
                        .await
                        .acquire_token_by_mfa_flow(account_id, None, Some(poll_attempt), flow)
                        .await,
                    Ok(token) => token,
                    Err(e) => match e {
                        MsalError::ChangePassword => {
                            if let Some(old_cred) = password {
                                // The user needs to set a new password.
                                *cred_handler = AuthCredHandler::ChangePassword {
                                    old_cred: old_cred.to_string(),
                                };
                                return Ok((
                                    AuthResult::Next(AuthRequest::ChangePassword {
                                        msg: "Update your password\n\
                                             You need to update your password because this is\n\
                                             the first time you are signing in, or because your\n\
                                             password has expired."
                                            .to_string(),
                                    }),
                                    AuthCacheAction::None,
                                ));
                            } else {
                                error!("{:?}", e);
                                return Ok((AuthResult::Denied(e.to_string()), AuthCacheAction::None));
                            }
                        }
                        MsalError::MFAPollContinue => {
                            return Ok((
                                AuthResult::Next(AuthRequest::MFAPollWait),
                                AuthCacheAction::None,
                            ));
                        }
                        e => {
                            error!("{:?}", e);
                            return Ok((AuthResult::Denied(e.to_string()), AuthCacheAction::None));
                        }
                    }
                );
                let token2 = enroll_and_obtain_enrolled_token!(token);
                match self.token_validate(account_id, &token2, None).await {
                    Ok(AuthResult::Success { token: token3 }) => {
                        // Skip Hello enrollment if it is disabled by config
                        let hello_enabled = self.config.read().await.get_enable_hello();
                        // Skip Hello enrollment if the token doesn't have the ngcmfa amr
                        let amr_ngcmfa = token2.amr_ngcmfa().map_err(|e| {
                            error!("{:?}", e);
                            IdpError::NotFound
                        })?;
                        if !hello_enabled || !amr_ngcmfa {
                            info!("Skipping Hello enrollment because it is disabled");
                            return Ok((
                                AuthResult::Success { token: token3 },
                                AuthCacheAction::None,
                            ));
                        }

                        // Setup Windows Hello
                        *cred_handler = AuthCredHandler::SetupPin { token };
                        return Ok((
                            AuthResult::Next(AuthRequest::SetupPin {
                                msg: format!(
                                    "Set up a PIN\n {}{}",
                                    "A Hello PIN is a fast, secure way to sign",
                                    "in to your device, apps, and services."
                                ),
                            }),
                            AuthCacheAction::None,
                        ));
                    }
                    Ok(auth_result) => Ok((auth_result, AuthCacheAction::None)),
                    Err(e) => Err(e),
                }
            }
            (
                AuthCredHandler::MFA {
                    ref mut flow,
                    password,
                },
                PamAuthRequest::Fido { assertion },
            ) => {
                let token = net_down_check!(
                    self.client
                        .read()
                        .await
                        .acquire_token_by_mfa_flow(account_id, Some(&assertion), None, flow)
                        .await,
                    Ok(token) => token,
                    Err(e) => {
                        if let MsalError::ChangePassword = e {
                            if let Some(old_cred) = password {
                                // The user needs to set a new password.
                                *cred_handler = AuthCredHandler::ChangePassword {
                                    old_cred: old_cred.to_string(),
                                };
                                return Ok((
                                    AuthResult::Next(AuthRequest::ChangePassword {
                                        msg: "Update your password\n\
                                             You need to update your password because this is\n\
                                             the first time you are signing in, or because your\n\
                                             password has expired."
                                            .to_string(),
                                    }),
                                    AuthCacheAction::None,
                                ));
                            } else {
                                error!("{:?}", e);
                                return Ok((AuthResult::Denied(e.to_string()), AuthCacheAction::None));
                            }
                        } else {
                            error!("{:?}", e);
                            return Ok((AuthResult::Denied(e.to_string()), AuthCacheAction::None));
                        }
                    }
                );
                let token2 = enroll_and_obtain_enrolled_token!(token);
                match self.token_validate(account_id, &token2, None).await {
                    Ok(AuthResult::Success { token: token3 }) => {
                        // Skip Hello enrollment if it is disabled by config
                        let hello_enabled = self.config.read().await.get_enable_hello();
                        if !hello_enabled {
                            info!("Skipping Hello enrollment because it is disabled");
                            return Ok((
                                AuthResult::Success { token: token3 },
                                AuthCacheAction::None,
                            ));
                        }

                        // Setup Windows Hello
                        *cred_handler = AuthCredHandler::SetupPin { token };
                        return Ok((
                            AuthResult::Next(AuthRequest::SetupPin {
                                msg: format!(
                                    "Set up a PIN\n {}{}",
                                    "A Hello PIN is a fast, secure way to sign",
                                    "in to your device, apps, and services."
                                ),
                            }),
                            AuthCacheAction::None,
                        ));
                    }
                    Ok(auth_result) => Ok((auth_result, AuthCacheAction::None)),
                    Err(e) => Err(e),
                }
            }
            _ => {
                error!("Unexpected AuthCredHandler and PamAuthRequest pairing");
                Err(IdpError::NotFound)
            }
        }
    }

    #[instrument(skip(self, _token, keystore))]
    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        _token: Option<&UserToken>,
        keystore: &mut D,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        let hello_tag = self.fetch_hello_key_tag(account_id);
        let hello_key: Option<LoadableMsHelloKey> =
            keystore.get_tagged_hsm_key(&hello_tag).map_err(|e| {
                error!("Failed fetching hello key from keystore: {:?}", e);
                IdpError::BadRequest
            })?;
        let sfa_enabled = self.config.read().await.get_enable_sfa_fallback();
        let hello_pin_retry_count = self.config.read().await.get_hello_pin_retry_count();
        // We only have 2 options when performing an offline auth; Hello PIN,
        // or cached password for SFA users. If neither option is available,
        // we should respond with a resonable error indicating how to proceed.
        if hello_key.is_some()
            && self.bad_pin_counter.bad_pin_count(account_id).await <= hello_pin_retry_count
        {
            Ok((AuthRequest::Pin, AuthCredHandler::None))
        } else if sfa_enabled {
            Ok((AuthRequest::Password, AuthCredHandler::None))
        } else {
            Ok((
                AuthRequest::InitDenied {
                    msg: "Network outage detected.".to_string(),
                },
                AuthCredHandler::None,
            ))
        }
    }

    #[instrument(skip(
        self,
        token,
        cred_handler,
        pam_next_req,
        keystore,
        tpm,
        machine_key,
        _online_at_init
    ))]
    async fn unix_user_offline_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UserToken,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        _online_at_init: bool,
    ) -> Result<AuthResult, IdpError> {
        match (&cred_handler, pam_next_req) {
            (_, PamAuthRequest::Pin { cred }) => {
                let hello_tag = self.fetch_hello_key_tag(account_id);
                let hello_key: LoadableMsHelloKey = keystore
                    .get_tagged_hsm_key(&hello_tag)
                    .map_err(|e| {
                        error!("Failed fetching hello key from keystore: {:?}", e);
                        IdpError::BadRequest
                    })?
                    .ok_or_else(|| {
                        error!("Authentication failed. Hello key missing.");
                        IdpError::BadRequest
                    })?;

                let pin = PinValue::new(&cred).map_err(|e| {
                    error!("Failed setting pin value: {:?}", e);
                    IdpError::Tpm
                })?;
                match tpm.ms_hello_key_load(machine_key, &hello_key, &pin) {
                    Ok(_) => {
                        self.bad_pin_counter.reset_bad_pin_count(account_id).await;
                        Ok(AuthResult::Success {
                            token: token.clone(),
                        })
                    }
                    Err(e) => {
                        self.bad_pin_counter
                            .increment_bad_pin_count(account_id)
                            .await;
                        error!("{:?}", e);
                        Ok(AuthResult::Denied(
                            "Failed to authenticate with Hello PIN.".to_string(),
                        ))
                    }
                }
            }
            _ => Err(IdpError::BadRequest),
        }
    }

    async fn unix_group_get(
        &self,
        _id: &Id,
        _tpm: &mut tpm::provider::BoxedDynTpm,
    ) -> Result<GroupToken, IdpError> {
        /* AAD doesn't permit group listing (must use cache entries from auth) */
        Err(IdpError::BadRequest)
    }

    async fn get_cachestate(&self, _account_id: Option<&str>) -> CacheState {
        (*self.state.lock().await).clone()
    }
}

impl HimmelblauProvider {
    #[instrument(level = "debug", skip_all)]
    async fn delayed_init(&self) -> Result<(), IdpError> {
        // The purpose of this function is to delay initialization as long as
        // possible. This permits the daemon to start, without requiring we be
        // connected to the internet. This way we can send messages to the user
        // via PAM indicating that the network is down.
        let init = *self.init.read().await;
        if !init {
            // Send the federation provider request, if necessary. If these were
            // cached previously, then a network connection is not necessary at
            // this moment. If they were not cached, and supplied to the graph
            // object, then we require a network connection now.
            let tenant_id = self.graph.tenant_id().await.map_err(|e| {
                error!("Failed discovering the tenant_id: {}", e);
                IdpError::BadRequest
            })?;
            let authority_host = self.graph.authority_host().await.map_err(|e| {
                error!("Failed discovering the authority_host: {}", e);
                IdpError::BadRequest
            })?;
            let graph_url = self.graph.graph_url().await.map_err(|e| {
                error!("Failed discovering the graph_url: {}", e);
                IdpError::BadRequest
            })?;

            // Initialize the idmap range
            let cfg = self.config.read().await;
            let range = cfg.get_idmap_range(&self.domain);
            let mut idmap = self.idmap.write().await;
            idmap
                .add_gen_domain(&self.domain, &tenant_id, range)
                .map_err(|e| {
                    error!("Failed adding the idmap domain: {}", e);
                    IdpError::BadRequest
                })?;
            drop(cfg);

            // Set the authority on the app
            let authority_url = format!("https://{}/{}", authority_host, tenant_id);
            // A client write lock is required here.
            self.client
                .write()
                .await
                .set_authority(&authority_url)
                .map_err(|e| {
                    error!("Failed setting the authority_url: {}", e);
                    IdpError::BadRequest
                })?;

            // Mark the provider as initialized
            *self.init.write().await = true;

            // Cache the federation provider responses
            let mut cfg = self.config.write().await;
            cfg.set(&self.domain, "tenant_id", &tenant_id);
            debug!(
                "Setting domain {} config tenant_id to {}",
                self.domain, tenant_id
            );
            cfg.set(&self.domain, "authority_host", &authority_host);
            debug!(
                "Setting domain {} config authority_host to {}",
                self.domain, authority_host
            );
            cfg.set(&self.domain, "graph_url", &graph_url);
            debug!(
                "Setting domain {} config graph_url to {}",
                self.domain, graph_url
            );
            if let Err(e) = cfg.write_server_config() {
                error!("Failed to write federation provider configuration: {:?}", e);
            }
        }
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    async fn attempt_online(&self, _tpm: &mut tpm::provider::BoxedDynTpm, now: SystemTime) -> bool {
        let cfg = self.config.read().await;
        let authority_host = self
            .graph
            .authority_host()
            .await
            .unwrap_or(cfg.get_authority_host(&self.domain));
        match reqwest::get(format!("https://{}", authority_host)).await {
            Ok(resp) => {
                if resp.status().is_success() {
                    debug!("provider is now online");
                    let mut state = self.state.lock().await;
                    *state = CacheState::Online;
                    return true;
                } else {
                    error!("Provider online failed: {}", resp.status());
                    let mut state = self.state.lock().await;
                    *state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                    return false;
                }
            }
            Err(err) => {
                error!(?err, "Provider online failed");
                let mut state = self.state.lock().await;
                *state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                return false;
            }
        }
    }

    fn fetch_hello_key_tag(&self, account_id: &str) -> String {
        format!("{}/hello", account_id.to_lowercase())
    }

    fn fetch_cert_key_tag(&self) -> String {
        format!("{}/certificate", self.domain)
    }

    fn fetch_intune_key_tag(&self) -> String {
        format!("{}/intune", self.domain)
    }

    fn fetch_tranport_key_tag(&self) -> String {
        format!("{}/transport", self.domain)
    }

    fn fetch_loadable_transport_key_from_keystore<D: KeyStoreTxn + Send>(
        &self,
        keystore: &mut D,
    ) -> Result<Option<LoadableMsOapxbcRsaKey>, IdpError> {
        let transport_tag = self.fetch_tranport_key_tag();
        let loadable_id_key: Option<LoadableMsOapxbcRsaKey> = keystore
            .get_tagged_hsm_key(&transport_tag)
            .map_err(|ks_err| {
                error!(?ks_err);
                IdpError::KeyStore
            })?;

        Ok(loadable_id_key)
    }

    fn fetch_loadable_cert_key_from_keystore<D: KeyStoreTxn + Send>(
        &self,
        keystore: &mut D,
    ) -> Result<Option<LoadableMsDeviceEnrolmentKey>, IdpError> {
        let csr_tag = self.fetch_cert_key_tag();
        let loadable_id_key: Option<LoadableMsDeviceEnrolmentKey> =
            keystore.get_tagged_hsm_key(&csr_tag).map_err(|ks_err| {
                error!(?ks_err);
                IdpError::KeyStore
            })?;

        Ok(loadable_id_key)
    }

    async fn token_validate(
        &self,
        account_id: &str,
        token: &UnixUserToken,
        old_token: Option<&UserToken>,
    ) -> Result<AuthResult, IdpError> {
        match &token.access_token {
            Some(_) => {
                /* Fixes bug#37: MFA can respond with different user than requested.
                 * Azure resource names are case insensitive.
                 */
                let spn = token.spn().map_err(|e| {
                    error!("Failed fetching user spn: {:?}", e);
                    IdpError::BadRequest
                })?;
                if account_id.to_string().to_lowercase() != spn.to_string().to_lowercase() {
                    let msg = format!(
                        "Authenticated user {} does not match requested user {}",
                        spn, account_id
                    );
                    error!(msg);
                    return Ok(AuthResult::Denied(msg));
                }
                info!("Authentication successful for user '{}'", account_id);
                // If an encrypted PRT is present, store it in the mem cache
                if let Some(prt) = &token.prt {
                    self.refresh_cache.add(account_id, prt).await;
                }
                Ok(AuthResult::Success {
                    token: self
                        .user_token_from_unix_user_token(token, old_token)
                        .await?,
                })
            }
            None => {
                info!("Authentication failed for user '{}'", account_id);
                Err(IdpError::NotFound)
            }
        }
    }

    async fn user_token_from_unix_user_token(
        &self,
        value: &UnixUserToken,
        old_token: Option<&UserToken>,
    ) -> Result<UserToken, IdpError> {
        let config = self.config.read().await;
        let mut groups: Vec<GroupToken>;
        let posix_attrs: HashMap<String, String>;
        let spn = match value.spn() {
            Ok(spn) => spn,
            Err(e) => {
                debug!("Failed fetching user spn: {:?}", e);
                return Err(IdpError::BadRequest);
            }
        };
        let uuid = match value.uuid() {
            Ok(uuid) => uuid,
            Err(e) => {
                debug!("Failed fetching user uuid: {:?}", e);
                return Err(IdpError::BadRequest);
            }
        };
        match &value.access_token {
            Some(access_token) => {
                groups = match self.graph.request_user_groups(access_token).await {
                    Ok(groups) => {
                        let mut gt_groups = vec![];
                        for g in groups {
                            match self.group_token_from_directory_object(g).await {
                                Ok(group) => gt_groups.push(group),
                                Err(e) => {
                                    debug!("Failed fetching group for user {}: {}", &spn, e)
                                }
                            };
                        }
                        gt_groups
                    }
                    Err(_e) => {
                        debug!("Failed fetching user groups for {}", &spn);
                        /* If we failed to fetch the groups, and we have an old
                         * token, preserve the existing cached group memberships.
                         */
                        match old_token {
                            Some(old_token) => old_token.groups.clone(),
                            None => vec![],
                        }
                    }
                };
                posix_attrs = if config.get_id_attr_map() == IdAttr::Rfc2307 {
                    match self
                        .graph
                        .fetch_user_extension_attributes(
                            access_token,
                            vec![
                                "uidNumber",
                                "gidNumber",
                                "loginShell",
                                "gecos",
                                "unixHomeDirectory",
                            ],
                        )
                        .await
                    {
                        Ok(posix_attrs) => posix_attrs,
                        Err(e) => {
                            debug!("Failed fetching user posix attributes: {:?}", e);
                            HashMap::new()
                        }
                    }
                } else {
                    HashMap::new()
                };
            }
            None => {
                debug!("Failed fetching user groups for {}", &spn);
                /* If we failed to fetch the groups, and we have an old
                 * token, preserve the existing cached group memberships.
                 */
                groups = match old_token {
                    Some(old_token) => old_token.groups.clone(),
                    None => vec![],
                };
                posix_attrs = HashMap::new();
            }
        };
        let valid = true;
        let idmap = self.idmap.read().await;
        let idmap_cache = StaticIdCache::new(ID_MAP_CACHE, false).map_err(|e| {
            error!("Failed reading from the idmap cache: {:?}", e);
            IdpError::BadRequest
        })?;
        let (uidnumber, gidnumber) = match idmap_cache.get_user_by_name(&spn) {
            Some(user) => (user.uid, user.gid),
            None => {
                let uidnumber = match config.get_id_attr_map() {
                    IdAttr::Uuid => idmap
                        .object_id_to_unix_id(
                            &self.graph.tenant_id().await.map_err(|e| {
                                error!("{:?}", e);
                                IdpError::BadRequest
                            })?,
                            &AadSid::from_object_id(&uuid).map_err(|e| {
                                error!("Failed parsing object id: {:?}", e);
                                IdpError::BadRequest
                            })?,
                        )
                        .map_err(|e| {
                            error!("{:?}", e);
                            IdpError::BadRequest
                        })?,
                    IdAttr::Name => idmap
                        .gen_to_unix(
                            &self.graph.tenant_id().await.map_err(|e| {
                                error!("{:?}", e);
                                IdpError::BadRequest
                            })?,
                            &spn,
                        )
                        .map_err(|e| {
                            error!("{:?}", e);
                            IdpError::BadRequest
                        })?,
                    IdAttr::Rfc2307 => match posix_attrs.get("uidNumber") {
                        Some(uid_number) => uid_number.parse::<u32>().map_err(|e| {
                            error!(
                                "Invalid uidNumber ('{}') synced from on-prem AD: {:?}",
                                uid_number, e
                            );
                            IdpError::BadRequest
                        })?,
                        None => {
                            error!("User {} has no uidNumber defined in the directory!", spn);
                            return Err(IdpError::BadRequest);
                        }
                    },
                };

                // Utilize the existing primary group if set
                let gidnumber = if let Some(gid_number) = posix_attrs.get("gidNumber") {
                    gid_number.parse::<u32>().map_err(|e| {
                        error!(
                            "Invalid gidNumber ('{}') synced from on-prem AD: {:?}",
                            gid_number, e
                        );
                        IdpError::BadRequest
                    })?
                } else {
                    // Otherwise add a fake primary group
                    groups.push(GroupToken {
                        name: spn.clone(),
                        spn: spn.clone(),
                        uuid,
                        gidnumber: uidnumber,
                    });
                    uidnumber
                };
                (uidnumber, gidnumber)
            }
        };

        let displayname = match posix_attrs.get("gecos") {
            Some(gecos) => gecos.clone(),
            None => value.id_token.name.clone(),
        };

        let shell = match posix_attrs.get("loginShell") {
            Some(login_shell) => login_shell.clone(),
            None => config.get_shell(Some(&self.domain)),
        };

        if posix_attrs.contains_key("unixHomeDirectory") {
            // TODO: Implement homedir mapping
            warn!("Himmelblau did not map unixHomeDirectory from Azure Entra Connector sync for user {}", spn);
        }

        Ok(UserToken {
            name: spn.clone(),
            spn: spn.clone(),
            uuid,
            real_gidnumber: Some(gidnumber),
            gidnumber: uidnumber,
            displayname,
            shell: Some(shell),
            groups,
            tenant_id: Some(
                Uuid::parse_str(&self.graph.tenant_id().await.map_err(|e| {
                    error!("{:?}", e);
                    IdpError::BadRequest
                })?)
                .map_err(|e| {
                    error!("{:?}", e);
                    IdpError::BadRequest
                })?,
            ),
            valid,
        })
    }

    async fn group_token_from_directory_object(
        &self,
        value: DirectoryObject,
    ) -> Result<GroupToken> {
        let config = self.config.read().await;
        let name = match value.display_name {
            Some(name) => name,
            None => value.id.clone(),
        };
        let id =
            Uuid::parse_str(&value.id).map_err(|e| anyhow!("Failed parsing user uuid: {}", e))?;
        let idmap = self.idmap.read().await;
        let gidnumber = match config.get_id_attr_map() {
            IdAttr::Uuid => idmap
                .object_id_to_unix_id(
                    &self
                        .graph
                        .tenant_id()
                        .await
                        .map_err(|e| anyhow!("{:?}", e))?,
                    &AadSid::from_object_id(&id)
                        .map_err(|e| anyhow!("Failed parsing object id: {:?}", e))?,
                )
                .map_err(|e| anyhow!("Failed fetching gid for {}: {:?}", id, e))?,
            IdAttr::Name => idmap
                .gen_to_unix(
                    &self
                        .graph
                        .tenant_id()
                        .await
                        .map_err(|e| anyhow!("{:?}", e))?,
                    &name,
                )
                .map_err(|e| anyhow!("Failed fetching gid for {}: {:?}", name, e))?,
            IdAttr::Rfc2307 => match value.extension_attrs.get("gidNumber") {
                Some(gid_number) => gid_number.parse::<u32>().map_err(|e| {
                    anyhow!(
                        "Invalid gidNumber ('{}') synced from on-prem AD: {:?}",
                        gid_number,
                        e
                    )
                })?,
                None => match config.get_rfc2307_group_fallback_map() {
                    Some(IdAttr::Uuid) => idmap
                        .object_id_to_unix_id(
                            &self
                                .graph
                                .tenant_id()
                                .await
                                .map_err(|e| anyhow!("{:?}", e))?,
                            &AadSid::from_object_id(&id)
                                .map_err(|e| anyhow!("Failed parsing object id: {:?}", e))?,
                        )
                        .map_err(|e| anyhow!("Failed fetching gid for {}: {:?}", id, e))?,
                    Some(IdAttr::Name) => idmap
                        .gen_to_unix(
                            &self
                                .graph
                                .tenant_id()
                                .await
                                .map_err(|e| anyhow!("{:?}", e))?,
                            &name,
                        )
                        .map_err(|e| anyhow!("Failed fetching gid for {}: {:?}", name, e))?,
                    Some(_) | None => {
                        return Err(anyhow!(
                            "Group {} has no gidNumber defined in the directory and no fallback was set!",
                            name
                        ));
                    }
                },
            },
        };

        Ok(GroupToken {
            name: name.clone(),
            spn: name.to_string(),
            uuid: id,
            gidnumber,
        })
    }

    async fn join_domain<D: KeyStoreTxn + Send>(
        &self,
        tpm: &mut tpm::provider::BoxedDynTpm,
        token: &UnixUserToken,
        keystore: &mut D,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<(), MsalError> {
        /* If not already joined, join the domain now. */
        let attrs = EnrollAttrs::new(self.domain.clone(), None, None, None, None)?;
        // A client write lock is required here.
        let res = self
            .client
            .write()
            .await
            .enroll_device(&token.refresh_token, attrs.clone(), tpm, machine_key)
            .await;
        match res {
            Ok((new_loadable_transport_key, new_loadable_cert_key, device_id)) => {
                info!("Joined domain {} with device id {}", self.domain, device_id);
                // Store the new_loadable_cert_key in the keystore
                let csr_tag = self.fetch_cert_key_tag();
                if let Err(e) = keystore.insert_tagged_hsm_key(&csr_tag, &new_loadable_cert_key) {
                    return Err(MsalError::TPMFail(format!(
                        "Failed to join the domain: {:?}",
                        e
                    )));
                }
                // Store the new_loadable_transport_key
                let transport_tag = self.fetch_tranport_key_tag();
                if let Err(e) =
                    keystore.insert_tagged_hsm_key(&transport_tag, &new_loadable_transport_key)
                {
                    return Err(MsalError::TPMFail(format!(
                        "Failed to join the domain: {:?}",
                        e
                    )));
                }

                let mut config = self.config.write().await;

                // Enrolling the device in Intune
                let graph_token = self
                    .client
                    .read()
                    .await
                    .acquire_token_by_refresh_token(
                        &token.refresh_token,
                        vec!["00000003-0000-0000-c000-000000000000/.default"],
                        None,
                        Some(DEFAULT_APP_ID),
                        tpm,
                        machine_key,
                    )
                    .await?;
                let access_token = graph_token.access_token.clone().ok_or(MsalError::Missing(
                    "access_token missing from token".to_string(),
                ))?;
                let endpoints = self.graph.intune_service_endpoints(&access_token).await?;
                if let Ok(token) = self
                    .client
                    .read()
                    .await
                    .acquire_token_by_refresh_token(
                        &token.refresh_token,
                        vec!["d4ebce55-015a-49b5-a083-c84d1797ae8c/.default"],
                        None,
                        Some(DEFAULT_APP_ID),
                        tpm,
                        machine_key,
                    )
                    .await
                {
                    let intune = IntuneForLinux::new(endpoints)?;
                    match intune
                        .enroll(&token, &attrs, &device_id, tpm, machine_key)
                        .await
                    {
                        Ok((intune_key, intune_device_id)) => {
                            config.set(&self.domain, "intune_device_id", &intune_device_id);
                            let intune_tag = self.fetch_intune_key_tag();
                            if let Err(e) = keystore.insert_tagged_hsm_key(&intune_tag, &intune_key)
                            {
                                error!(?e, "Failed inserting the intune key into the keystore.");
                            }
                        }
                        Err(e) => info!(?e, "Intune device enrollment failed."),
                    }
                } else {
                    info!("Intune device enrollment failed.");
                }

                config.set(&self.domain, "device_id", &device_id);
                debug!(
                    "Setting domain {} config device_id to {}",
                    self.domain, &device_id
                );
                if let Err(e) = config.write_server_config() {
                    return Err(MsalError::GeneralFailure(format!(
                        "Failed to write domain join configuration: {:?}",
                        e
                    )));
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn is_domain_joined<D: KeyStoreTxn + Send>(&self, keystore: &mut D) -> bool {
        /* If we have access to tpm keys, and the domain device_id is
         * configured, we'll assume we are domain joined. */
        let config = self.config.read().await;
        if config.get(&self.domain, "device_id").is_none() {
            return false;
        }
        let transport_key = match self.fetch_loadable_transport_key_from_keystore(keystore) {
            Ok(transport_key) => transport_key,
            Err(_) => return false,
        };
        if transport_key.is_none() {
            return false;
        }
        let cert_key = match self.fetch_loadable_cert_key_from_keystore(keystore) {
            Ok(cert_key) => cert_key,
            Err(_) => return false,
        };
        if cert_key.is_none() {
            return false;
        }
        true
    }
}
