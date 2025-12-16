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
use crate::idprovider::common::KeyType;
use crate::idprovider::common::RefreshCacheEntry;
use crate::idprovider::common::{BadPinCounter, RefreshCache};
use crate::idprovider::interface::{tpm, UserTokenState};
use crate::idprovider::openidconnect::OidcProvider;
use crate::tpm::confidential_client_creds;
use crate::unix_proto::PamAuthRequest;
use crate::user_map::UserMap;
use crate::{
    entra_id_prt_token_fetch, entra_id_refresh_token_token_fetch, extract_base_url,
    handle_hello_bad_pin_count, impl_change_auth_token, impl_check_online,
    impl_create_decoupled_hello_key, impl_himmelblau_hello_key_helpers,
    impl_himmelblau_offline_auth_init, impl_himmelblau_offline_auth_step, impl_offline_break_glass,
    impl_provision_hello_key, impl_provision_or_create_hello_key, impl_unix_user_access,
    load_cached_prt,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use himmelblau::auth::{
    BrokerClientApplication, PublicClientApplication, UserToken as UnixUserToken, BROKER_APP_ID,
};
use himmelblau::discovery::EnrollAttrs;
use himmelblau::error::{MsalError, DEVICE_AUTH_FAIL};
use himmelblau::graph::UserObject;
use himmelblau::graph::{DirectoryObject, Graph};
use himmelblau::intune::IntuneForLinux;
use himmelblau::{AuthOption, MFAAuthContinue};
use himmelblau::{ClientToken, ConfidentialClientApplication};
use idmap::{AadSid, Idmap};
use kanidm_hsm_crypto::{
    structures::LoadableMsDeviceEnrolmentKey, structures::LoadableMsHelloKey,
    structures::LoadableMsOapxbcRsaKey, PinValue,
};
use libc::getpwnam;
use regex::Regex;
use reqwest;
use reqwest::Url;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::time::SystemTime;
use tokio::sync::{broadcast, Mutex, RwLock};
use uuid::Uuid;

#[allow(clippy::large_enum_variant)]
enum Providers {
    Oidc(OidcProvider),
    Himmelblau(HimmelblauProvider),
}

pub struct HimmelblauMultiProvider {
    config: Arc<RwLock<HimmelblauConfig>>,
    providers: Arc<RwLock<HashMap<String, Providers>>>,
    permit_new_providers: Arc<Mutex<bool>>,
    idmap: Arc<RwLock<Idmap>>,
}

impl HimmelblauMultiProvider {
    async fn add_tenant<D: KeyStoreTxn + Send>(
        &self,
        domain: &str,
        cfg: &HimmelblauConfig,
        keystore: &mut D,
    ) -> Result<(), IdpError> {
        if !*self.permit_new_providers.lock().await {
            return Err(IdpError::NotFound {
                what: "domain".to_string(),
                where_: domain.to_string(),
            });
        }
        debug!("Adding provider for domain {}", domain);
        let authority_host = cfg.get_authority_host(domain);
        let tenant_id = cfg.get_tenant_id(domain);
        let graph_url = cfg.get_graph_url(domain);
        let graph = match Graph::new(
            &cfg.get_odc_provider(domain),
            domain,
            Some(&authority_host),
            tenant_id.as_deref(),
            graph_url.as_deref(),
        )
        .await
        {
            Ok(graph) => graph,
            Err(e) => {
                error!("Failed initializing provider: {:?}", e);
                return Err(IdpError::BadRequest);
            }
        };
        let app_id = cfg.get_app_id(domain);
        let app =
            BrokerClientApplication::new(None, app_id.as_deref(), None, None).map_err(|e| {
                error!("Failed initializing provider: {:?}", e);
                IdpError::BadRequest
            })?;
        let provider = HimmelblauProvider::new(app, &self.config, domain, graph, &self.idmap)
            .map_err(|e| {
                error!("Failed to initialize the provider: {:?}", e);
                IdpError::BadRequest
            })?;
        {
            // A client write lock is required here.
            let mut client = provider.client.write().await;
            if let Ok(transport_key) = provider.fetch_loadable_transport_key_from_keystore(keystore)
            {
                client.set_transport_key(transport_key);
            }
            if let Ok(cert_key) = provider.fetch_loadable_cert_key_from_keystore(keystore) {
                client.set_cert_key(cert_key);
            }
        }
        self.providers
            .write()
            .await
            .insert(domain.to_string(), Providers::Himmelblau(provider));
        Ok(())
    }

    async fn add_oidc_tenant(&self, domain: &str) -> Result<(), IdpError> {
        let provider = OidcProvider::new(&self.config, domain, &self.idmap)?;

        self.providers
            .write()
            .await
            .insert(domain.to_string(), Providers::Oidc(provider));
        Ok(())
    }

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

        let providers = HashMap::new();
        let cfg = config.read().await;
        let domains = cfg.get_configured_domains();
        if domains.is_empty() {
            warn!("No domains configured in himmelblau.conf. All tenants will be allowed!");
        }

        let providers = HimmelblauMultiProvider {
            config: config.clone(),
            providers: Arc::new(RwLock::new(providers)),
            idmap,
            permit_new_providers: Arc::new(Mutex::new(true)),
        };

        let mut permit_new_providers = true;
        if cfg.get_oidc_issuer_url().is_none() {
            for domain in domains {
                providers
                    .add_tenant(&domain, &cfg, keystore)
                    .await
                    .map_err(|e| anyhow!("{:?}", e))?;
                // If a provide is already configured (or multiple providers), do
                // not permit new providers.
                permit_new_providers = false;
            }
        } else {
            // Add the oidc provider, if present
            for domain in domains {
                providers
                    .add_oidc_tenant(&domain)
                    .await
                    .map_err(|e| anyhow!("{:?}", e))?;
                permit_new_providers = false;
            }
        }
        *providers.permit_new_providers.lock().await = permit_new_providers;

        // Spawn periodic cookie clearing loop (Fixes bugs #591 and #491)
        let providers_ref = providers.providers.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(12 * 60 * 60)).await;
                let providers = providers_ref.read().await;
                for (_, provider) in providers.iter() {
                    match provider {
                        Providers::Oidc(_) => {}
                        Providers::Himmelblau(provider) => {
                            let app = provider.client.write().await;
                            app.clear_cookies();
                        }
                    }
                }
            }
        });

        Ok(providers)
    }
}

macro_rules! find_provider {
    ($hmp:ident, $providers:ident, $domain:ident, $keystore:ident) => {{
        match $providers.get($domain) {
            Some(provider) => Some(provider),
            None => {
                // Attempt to match a provider alias
                let mut cfg = $hmp.config.write().await;
                match cfg.get_primary_domain_from_alias($domain).await {
                    Some(domain) => $providers.get(&domain),
                    None => {
                        if cfg.get_configured_domains().len() == 0 {
                            // We have to drop $providers here, since
                            // `add_tenant` is about to take a write lock on
                            // it. We re-open the readlock to get the new
                            // provider after adding the tenant.
                            drop($providers);
                            let _ = $hmp.add_tenant($domain, &cfg, $keystore).await;
                            $providers = $hmp.providers.read().await;
                            match $providers.get($domain) {
                                Some(provider) => Some(provider),
                                None => None,
                            }
                        } else {
                            None
                        }
                    }
                }
            }
        }
        .ok_or(IdpError::NotFound {
            what: format!("domain: {}", $domain),
            where_: "providers".to_string(),
        })
    }};
}

fn idp_get_domain_for_account(account_id: &str) -> Result<&str, IdpError> {
    match split_username(account_id) {
        Some((_sam, domain)) => Ok(domain),
        None => {
            debug!("Authentication ignored for local user");
            Err(IdpError::NotFound {
                what: "domain".to_string(),
                where_: format!("account_id: {}", account_id),
            })
        }
    }
}

#[async_trait]
impl IdProvider for HimmelblauMultiProvider {
    async fn offline_break_glass(&self, ttl: Option<u64>) -> Result<(), IdpError> {
        for (_domain, provider) in self.providers.read().await.iter() {
            match provider {
                Providers::Oidc(provider) => provider.offline_break_glass(ttl).await?,
                Providers::Himmelblau(provider) => {
                    provider.offline_break_glass(ttl).await?;
                }
            }
        }
        Ok(())
    }

    /* TODO: Kanidm should be modified to provide the account_id to
     * provider_authenticate, so that we can test the correct provider here.
     * Currently we go offline if ANY provider is down, which could be
     * incorrect. */
    async fn check_online(&self, tpm: &mut tpm::provider::BoxedDynTpm, now: SystemTime) -> bool {
        for (_domain, provider) in self.providers.read().await.iter() {
            match provider {
                Providers::Oidc(provider) => {
                    if !provider.check_online(tpm, now).await {
                        return false;
                    }
                }
                Providers::Himmelblau(provider) => {
                    if !provider.check_online(tpm, now).await {
                        return false;
                    }
                }
            }
        }
        true
    }

    async fn unix_user_access<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        scopes: Vec<String>,
        old_token: Option<&UserToken>,
        client_id: Option<String>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<UnixUserToken, IdpError> {
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        let domain = idp_get_domain_for_account(&account_id)?;
        let mut providers = self.providers.read().await;
        let provider = find_provider!(self, providers, domain, keystore)?;

        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_access(id, scopes, old_token, client_id, keystore, tpm, machine_key)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_access(id, scopes, old_token, client_id, keystore, tpm, machine_key)
                    .await
            }
        }
    }

    async fn unix_user_ccaches<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> (Vec<u8>, Vec<u8>) {
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        let empty = (vec![], vec![]);
        let Ok(domain) = idp_get_domain_for_account(&account_id) else {
            return empty;
        };

        let mut providers = self.providers.read().await;
        let Ok(provider) = find_provider!(self, providers, domain, keystore) else {
            return empty;
        };

        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_ccaches(id, old_token, keystore, tpm, machine_key)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_ccaches(id, old_token, keystore, tpm, machine_key)
                    .await
            }
        }
    }

    async fn unix_user_prt_cookie<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<String, IdpError> {
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        let domain = idp_get_domain_for_account(&account_id)?;
        let mut providers = self.providers.read().await;
        let provider = find_provider!(self, providers, domain, keystore)?;

        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_prt_cookie(id, old_token, keystore, tpm, machine_key)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_prt_cookie(id, old_token, keystore, tpm, machine_key)
                    .await
            }
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
        let domain = idp_get_domain_for_account(account_id)?;
        let mut providers = self.providers.read().await;
        let provider = find_provider!(self, providers, domain, keystore)?;

        match provider {
            Providers::Oidc(provider) => {
                provider
                    .change_auth_token(account_id, token, new_tok, keystore, tpm, machine_key)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .change_auth_token(account_id, token, new_tok, keystore, tpm, machine_key)
                    .await
            }
        }
    }

    async fn unix_user_get<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<UserTokenState, IdpError> {
        /* AAD doesn't permit user listing (must use cache entries from auth) */
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        let domain = idp_get_domain_for_account(&account_id)?;
        let mut providers = self.providers.read().await;
        let provider = find_provider!(self, providers, domain, keystore)?;

        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_get(id, old_token, keystore, tpm, machine_key)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_get(id, old_token, keystore, tpm, machine_key)
                    .await
            }
        }
    }

    async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: Option<&UserToken>,
        no_hello_pin: bool,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        let domain = idp_get_domain_for_account(account_id)?;
        let mut providers = self.providers.read().await;
        let provider = find_provider!(self, providers, domain, keystore)?;

        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_online_auth_init(
                        account_id,
                        token,
                        no_hello_pin,
                        keystore,
                        tpm,
                        machine_key,
                        shutdown_rx,
                    )
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_online_auth_init(
                        account_id,
                        token,
                        no_hello_pin,
                        keystore,
                        tpm,
                        machine_key,
                        shutdown_rx,
                    )
                    .await
            }
        }
    }

    async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        old_token: &UserToken,
        service: &str,
        no_hello_pin: bool,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        let domain = idp_get_domain_for_account(account_id)?;
        let mut providers = self.providers.read().await;
        let provider = find_provider!(self, providers, domain, keystore)?;

        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_online_auth_step(
                        account_id,
                        old_token,
                        service,
                        no_hello_pin,
                        cred_handler,
                        pam_next_req,
                        keystore,
                        tpm,
                        machine_key,
                        shutdown_rx,
                    )
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_online_auth_step(
                        account_id,
                        old_token,
                        service,
                        no_hello_pin,
                        cred_handler,
                        pam_next_req,
                        keystore,
                        tpm,
                        machine_key,
                        shutdown_rx,
                    )
                    .await
            }
        }
    }

    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: Option<&UserToken>,
        no_hello_pin: bool,
        keystore: &mut D,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        let domain = idp_get_domain_for_account(account_id)?;
        let mut providers = self.providers.read().await;
        let provider = find_provider!(self, providers, domain, keystore)?;

        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_offline_auth_init(account_id, token, no_hello_pin, keystore)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_offline_auth_init(account_id, token, no_hello_pin, keystore)
                    .await
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
        let domain = idp_get_domain_for_account(account_id)?;
        let mut providers = self.providers.read().await;
        let provider = find_provider!(self, providers, domain, keystore)?;

        match provider {
            Providers::Oidc(provider) => {
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
            Providers::Himmelblau(provider) => {
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

    async fn get_cachestate<D: KeyStoreTxn + Send>(
        &self,
        account_id: Option<&str>,
        keystore: &mut D,
    ) -> CacheState {
        match account_id {
            Some(account_id) => match split_username(account_id) {
                Some((_sam, domain)) => {
                    let mut providers = self.providers.read().await;
                    match find_provider!(self, providers, domain, keystore) {
                        Ok(provider) => match provider {
                            Providers::Oidc(provider) => {
                                return provider.get_cachestate(Some(account_id), keystore).await
                            }
                            Providers::Himmelblau(provider) => {
                                return provider.get_cachestate(Some(account_id), keystore).await
                            }
                        },
                        Err(..) => return CacheState::Offline,
                    }
                }
                None => return CacheState::Offline,
            },
            None => {
                for (_domain, provider) in self.providers.read().await.iter() {
                    match provider {
                        Providers::Oidc(provider) => {
                            match provider.get_cachestate(None, keystore).await {
                                CacheState::Offline => return CacheState::Offline,
                                CacheState::OfflineNextCheck(time) => {
                                    return CacheState::OfflineNextCheck(time)
                                }
                                _ => continue,
                            }
                        }
                        Providers::Himmelblau(provider) => {
                            match provider.get_cachestate(None, keystore).await {
                                CacheState::Offline => return CacheState::Offline,
                                CacheState::OfflineNextCheck(time) => {
                                    return CacheState::OfflineNextCheck(time)
                                }
                                _ => continue,
                            }
                        }
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

enum TokenOrObj {
    UserToken(Box<UnixUserToken>),
    UserObj((ClientToken, UserObject)),
}

macro_rules! check_new_device_enrollment_required {
    ($aadsts_err:expr, $self:expr, $keystore:expr, $ret_fn:expr, $ret_fail:expr) => {{
        if $aadsts_err.error_codes.contains(&(135011 as u32))
            || $aadsts_err.error_codes.contains(&DEVICE_AUTH_FAIL)
        {
            let csr_tag = $self.fetch_cert_key_tag();
            if let Err(e) = $keystore.delete_tagged_hsm_key(&csr_tag) {
                return $ret_fail(format!("Failed to delete CSR key: {:?}", e));
            }
            let intune_tag = $self.fetch_intune_key_tag();
            if let Err(e) = $keystore.delete_tagged_hsm_key(&intune_tag) {
                return $ret_fail(format!("Failed to delete intune key: {:?}", e));
            }

            return $ret_fn(format!("Device has been removed from the domain."));
        }
        return $ret_fail(format!("{:?}", $aadsts_err));
    }};
}

#[async_trait]
impl IdProvider for HimmelblauProvider {
    async fn offline_break_glass(&self, ttl: Option<u64>) -> Result<(), IdpError> {
        impl_offline_break_glass!(self, ttl)
    }

    #[instrument(level = "debug", skip_all)]
    async fn check_online(&self, tpm: &mut tpm::provider::BoxedDynTpm, now: SystemTime) -> bool {
        impl_check_online!(self, tpm, now)
    }

    #[instrument(skip(self, id, old_token, _keystore, tpm, machine_key))]
    async fn unix_user_access<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        scopes: Vec<String>,
        old_token: Option<&UserToken>,
        client_id: Option<String>,
        _keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<UnixUserToken, IdpError> {
        impl_unix_user_access!(
            self,
            old_token,
            scopes,
            client_id,
            id,
            tpm,
            machine_key,
            entra_id_prt_token_fetch,
            entra_id_refresh_token_token_fetch
        )
    }

    #[instrument(skip_all)]
    async fn unix_user_ccaches<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        _keystore: &mut D,
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
        let refresh_cache_entry = match self.refresh_cache.refresh_token(&account_id).await {
            Ok(refresh_cache_entry) => refresh_cache_entry,
            Err(e) => {
                error!(
                    "Failed fetching refresh cache entry for Kerberos CCache: {:?}",
                    e
                );
                return (vec![], vec![]);
            }
        };
        let prt = match refresh_cache_entry {
            RefreshCacheEntry::Prt(prt) => prt,
            RefreshCacheEntry::RefreshToken(_) => {
                // We need a PRT to fetch Kerberos CCaches
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

    #[instrument(skip_all)]
    async fn unix_user_prt_cookie<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        _keystore: &mut D,
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
        let refresh_cache_entry = self.refresh_cache.refresh_token(&account_id).await?;
        let prt = match refresh_cache_entry {
            RefreshCacheEntry::Prt(prt) => prt,
            RefreshCacheEntry::RefreshToken(_) => {
                // We need a PRT to fetch a PRT cookie
                return Err(IdpError::BadRequest);
            }
        };
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

    #[instrument(skip_all)]
    async fn change_auth_token<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UnixUserToken,
        new_tok: &str,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<bool, IdpError> {
        impl_change_auth_token!(
            self,
            account_id,
            token,
            new_tok,
            keystore,
            tpm,
            machine_key,
            token.amr_ngcmfa().map_err(|e| {
                error!("{:?}", e);
                IdpError::NotFound {
                    what: "NGC MFA authorization in UnixUserToken".to_string(),
                    where_: format!("access token ({})", token.token_type),
                }
            })?,
            impl_provision_or_create_hello_key
        )
    }

    #[instrument(skip_all)]
    async fn unix_user_get<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        keystore: &mut D,
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

        // Look for common names of local systemd, sssd, etc users, and warn
        // that the nss configuration is possibly incorrect.
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        if let Some((cn, _)) = split_username(&account_id) {
            let other_module_warn_users =
                ["gdm", "sssd", "gnome-initial-setup", "systemd-coredump"];
            if other_module_warn_users.contains(&cn) {
                warn!(
                    "'{}' appears to be a systemd or other local user \
                      account. Please reconfigure your nsswitch.conf to \
                      place himmelblau at the end",
                    cn
                );
            }
        }

        macro_rules! fetch_user_confidential_client {
            ($client_id:expr, $client_credential:expr) => {{
                let cfg = self.config.read().await;
                let authority_host = cfg.get_authority_host(&self.domain);
                let tenant_id = cfg.get_tenant_id(&self.domain).ok_or_else(|| {
                    error!("tenant_id not found");
                    IdpError::BadRequest
                })?;
                let authority = format!("https://{}/{}", authority_host, tenant_id);
                let app = ConfidentialClientApplication::new(
                    $client_id,
                    Some(&authority),
                    $client_credential,
                )
                .map_err(|e| {
                    error!(?e, "Failed initializing confidential client");
                    IdpError::BadRequest
                })?;

                match app
                    .acquire_token_silent(
                        vec!["00000003-0000-0000-c000-000000000000/.default"],
                        Some(tpm),
                )
                .await
                {
                    Ok(token) => {
                        match self.graph.request_user(&token.access_token, &account_id).await {
                            Ok(userobj) => {
                                match self
                                    .user_token_from_unix_user_token(
                                        &account_id,
                                        TokenOrObj::UserObj((token, userobj)),
                                        old_token,
                                    )
                                    .await
                                {
                                    Ok(mut token) => {
                                        /* Set the GECOS from the old_token, since MS doesn't
                                         * provide this during a silent acquire
                                         */
                                        if let Some(old_token) = old_token {
                                            token.displayname.clone_from(&old_token.displayname)
                                        }
                                        return Ok(UserTokenState::Update(token));
                                    }
                                    Err(e) => {
                                        error!(?e, "Failed to obtain token from user object using confidential client");
                                    }
                                }
                            }
                            Err(e) => {
                                error!(?e, "Failed to acquire user object from graph using confidential client creds");
                            }
                        }
                    }
                    Err(e) => {
                        error!(?e, "Failed to acquire token silently using confidential client");
                    }
                }
            }};
        }

        // If we have ConfidentialClient creds, use those
        if let Ok(Some((client_id, creds))) =
            confidential_client_creds(tpm, keystore, machine_key, &self.domain)
        {
            fetch_user_confidential_client!(&client_id, creds)
        }

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
        let refresh_cache_entry = match self.refresh_cache.refresh_token(&account_id).await {
            Ok(refresh_cache_entry) => refresh_cache_entry,
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
        let token = match refresh_cache_entry {
            RefreshCacheEntry::Prt(prt) => {
                let mtoken = self
                    .client
                    .read()
                    .await
                    .exchange_prt_for_access_token(
                        &prt,
                        scopes.clone(),
                        None,
                        client_id,
                        tpm,
                        machine_key,
                    )
                    .await;
                match mtoken {
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
                }
            }
            RefreshCacheEntry::RefreshToken(refresh_token) => {
                let client = PublicClientApplication::new(BROKER_APP_ID, None).map_err(|e| {
                    error!("Failed to create public client application: {:?}", e);
                    IdpError::BadRequest
                })?;
                let mtoken = client
                    .acquire_token_by_refresh_token(&refresh_token, vec![])
                    .await;
                match mtoken {
                    Ok(val) => val,
                    Err(MsalError::RequestFailed(_)) => {
                        // Retry on network failure, as these can be rather common
                        sleep(Duration::from_millis(500));
                        net_down_check!(
                            client
                                .acquire_token_by_refresh_token(
                                    &refresh_token,
                                    vec![],
                                )
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
                }
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

    #[instrument(skip(self, account_id, _token, keystore, tpm, _machine_key, _shutdown_rx))]
    async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        _token: Option<&UserToken>,
        no_hello_pin: bool,
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

        let hello_key = match self.fetch_hello_key(account_id, keystore) {
            Ok((hello_key, _keytype)) => Some(hello_key),
            Err(_) => None,
        };
        // Skip Hello authentication if it is disabled by config
        let hello_enabled = self.config.read().await.get_enable_hello();
        let hello_pin_retry_count = self.config.read().await.get_hello_pin_retry_count();
        let intune_enrollment_required =
            self.config.read().await.get_apply_policy() && !self.is_intune_enrolled(keystore).await;
        if !self.is_domain_joined(keystore).await
            || hello_key.is_none()
            || !hello_enabled
            || self.bad_pin_counter.bad_pin_count(account_id).await > hello_pin_retry_count
            || intune_enrollment_required
            || no_hello_pin
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
                                self.config.read().await.get_mfa_method().as_deref()
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
                    // Check if Azure provided FIDO credentials (passwordless FIDO/passkey)
                    if let (Some(fido_challenge), Some(fido_allow_list)) =
                        (flow.fido_challenge.clone(), flow.fido_allow_list.clone())
                    {
                        return Ok((
                            AuthRequest::Fido {
                                fido_challenge,
                                fido_allow_list,
                            },
                            AuthCredHandler::MFA {
                                flow,
                                password: None,
                                extra_data: None,
                            },
                        ));
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
                            extra_data: None,
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
                        extra_data: None,
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
        account_id,
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
        no_hello_pin: bool,
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
                    Err(MsalError::AcquireTokenFailed(e)) => {
                        check_new_device_enrollment_required!(e, self, keystore,
                            |msg: String| {
                                return Ok((AuthResult::Denied(msg), AuthCacheAction::None))
                            },
                            |msg: String| {
                                error!("{}", msg);
                                return Err(IdpError::BadRequest)
                            }
                        )
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

        macro_rules! intune_enroll {
            ($token:ident) => {
                match self
                    .intune_enroll(None, None, tpm, &$token, machine_key)
                    .await
                {
                    Ok((intune_key, intune_device_id)) => {
                        let mut config = self.config.write().await;
                        config.set(&self.domain, "intune_device_id", &intune_device_id);
                        if let Err(e) = config.write_server_config() {
                            error!(?e, "Failed to write Intune join configuration.");
                            return Err(IdpError::BadRequest);
                        }
                        let intune_tag = self.fetch_intune_key_tag();
                        if let Err(e) = keystore.insert_tagged_hsm_key(&intune_tag, &intune_key) {
                            error!(?e, "Failed inserting the intune key into the keystore.");
                            return Err(IdpError::BadRequest);
                        }
                    }
                    Err(IdpError::NotFound { .. }) => {}
                    Err(e) => {
                        error!(?e, "Failed to enroll in Intune");
                        return Err(e);
                    }
                }
            };
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
                } else if !self.is_intune_enrolled(keystore).await {
                    intune_enroll!($token);
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
                                            return Err(IdpError::NotFound {
                                                what: "token".to_string(), where_: "refresh".to_string() });
                                        }
                                    )
                                } else {
                                    return Err(IdpError::NotFound {
                                        what: "DEVICE_AUTH_FAIL".to_string(), where_: "acq_token".to_string() });
                                }
                            }
                            _ => return Err(IdpError::NotFound {
                                what: "AcquireTokenFailed".to_string(), where_: "acq_token".to_string() }),
                        }
                    }
                )
            }};
        }
        macro_rules! auth_and_validate_hello_key {
            ($hello_key:ident, $keytype:ident, $cred:ident) => {{
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
                    handle_hello_bad_pin_count!(self, account_id, keystore, |msg: &str| {
                        Ok((AuthResult::Denied(msg.to_string()), AuthCacheAction::None))
                    });
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
                let token = if $keytype == KeyType::Hello {
                    match self
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
                        Err(MsalError::AcquireTokenFailed(e)) => {
                            check_new_device_enrollment_required!(e, self, keystore,
                                |msg: String| {
                                    return Ok((AuthResult::Denied(msg), AuthCacheAction::None))
                                },
                                |msg: String| {
                                    error!("{}", msg);
                                    return Err(IdpError::BadRequest)
                                }
                            )
                        }
                        Err(e) => {
                            error!("Failed to authenticate with hello key: {:?}", e);
                            handle_hello_bad_pin_count!(self, account_id, keystore, |msg: &str| {
                                Ok((AuthResult::Denied(msg.to_string()), AuthCacheAction::None))
                            });
                            return Ok((
                                AuthResult::Denied(
                                    "Failed to authenticate with Hello PIN.".to_string(),
                                ),
                                AuthCacheAction::None,
                            ));
                        }
                    }
                } else { // This Hello key is decoupled
                    // Check for and decrypt any cached tokens
                    let hello_prt_tag = self.fetch_hello_prt_key_tag(account_id);
                    let hello_refresh_token_tag = self.fetch_hello_refresh_token_key_tag(account_id);
                    let refresh_cache_entry = match keystore.get_tagged_hsm_key(&hello_prt_tag) {
                        Ok(Some(hello_prt)) => self
                            .client
                            .read()
                            .await
                            .unseal_user_prt_with_hello_key(
                                &hello_prt,
                                &$hello_key,
                                &$cred,
                                tpm,
                                machine_key,
                            ).ok().map(|prt| RefreshCacheEntry::Prt(prt)),
                        // If we don't have a cached PRT, check for a cached refresh token
                        Err(_) | Ok(None) => {
                            match keystore.get_tagged_hsm_key(&hello_refresh_token_tag) {
                                Ok(Some(sealed_refresh_token)) => {
                                    let pin = PinValue::new(&$cred).map_err(|e| {
                                        error!("Failed initializing pin value: {:?}", e);
                                        IdpError::Tpm
                                    })?;
                                    let (_key, win_hello_storage_key) = tpm
                                        .ms_hello_key_load(machine_key, &$hello_key, &pin)
                                        .map_err(|e| {
                                            error!("Failed loading hello key for prt cache: {:?}", e);
                                            IdpError::Tpm
                                        })?;
                                    match tpm.unseal_data(&win_hello_storage_key, &sealed_refresh_token) {
                                        Ok(refresh_token_bytes) => {
                                            let refresh_token = String::from_utf8(
                                                refresh_token_bytes.to_vec(),
                                            ).map_err(|e| {
                                                error!("Failed converting refresh token to string: {:?}", e);
                                                IdpError::Tpm
                                            })?;
                                            Some(RefreshCacheEntry::RefreshToken(refresh_token))
                                        }
                                        Err(_) => self.refresh_cache.refresh_token(account_id).await.ok(),
                                    }
                                }
                                // If we just authenticated for the first time, the PRT is instead
                                // in the mem cache.
                                Err(_) | Ok(None) => self.refresh_cache.refresh_token(account_id).await.ok(),
                            }
                        },
                    };
                    if let Some(RefreshCacheEntry::Prt(prt)) = refresh_cache_entry {
                        match self
                            .client
                            .read()
                            .await
                            .exchange_prt_for_access_token(
                                &prt,
                                scopes,
                                None,
                                client_id,
                                tpm,
                                machine_key,
                            ).await {
                                Ok(mut token) => {
                                    // Request a new PRT to attach to the token (kick
                                    // the can down the road).
                                    if let Ok(new_prt) = self
                                        .client
                                        .read()
                                        .await
                                        .exchange_prt_for_prt(
                                            &prt,
                                            tpm,
                                            machine_key,
                                            true,
                                        ).await {
                                            token.prt = Some(new_prt);
                                        };
                                    self.bad_pin_counter.reset_bad_pin_count(account_id).await;
                                    token
                                }
                                // If the network goes down during an online exchange auth, we can
                                // downgrade to an offline auth and permit the authentication to proceed.
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
                                Err(MsalError::AcquireTokenFailed(e)) => {
                                    check_new_device_enrollment_required!(e, self, keystore,
                                        |msg: String| {
                                            return Ok((AuthResult::Denied(msg), AuthCacheAction::None))
                                        },
                                        |msg: String| {
                                            error!("{}", msg);
                                            return Err(IdpError::BadRequest)
                                        }
                                    )
                                },
                                Err(_) => {
                                    // Access token request for this PRT failed. Delete the
                                    // PRT and hello key, then demand a new auth.
                                    keystore
                                        .delete_tagged_hsm_key(&hello_prt_tag)
                                        .map_err(|e| {
                                            error!("Failed to delete hello prt: {:?}", e);
                                            IdpError::Tpm
                                        })?;
                                    let hello_key_tag = self.fetch_hello_key_tag(account_id, false);
                                    keystore
                                        .delete_tagged_hsm_key(&hello_key_tag)
                                        .map_err(|e| {
                                            error!("Failed to delete hello key: {:?}", e);
                                            IdpError::Tpm
                                        })?;
                                    // It's ok to reset the pin count here, since they must
                                    // online auth at this point and create a new pin.
                                    self.bad_pin_counter.reset_bad_pin_count(account_id).await;
                                    return Err(IdpError::BadRequest);
                                }
                            }
                    } else if let Some(RefreshCacheEntry::RefreshToken(refresh_token)) = refresh_cache_entry {
                        // We have a refresh token, exchange that for an access token
                        let app = PublicClientApplication::new(BROKER_APP_ID, None).map_err(|e| {
                            error!("Failed to create PublicClientApplication: {:?}", e);
                            IdpError::BadRequest
                        })?;
                        match app.acquire_token_by_refresh_token(
                            &refresh_token,
                            vec![],
                        ).await {
                            Ok(token) => {
                                self.bad_pin_counter.reset_bad_pin_count(account_id).await;
                                token
                            },
                            // If the network goes down during an online exchange auth, we can
                            // downgrade to an offline auth and permit the authentication to proceed.
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
                                error!("Failed to exchange refresh token for access token: {:?}", e);
                                // Access token request for this refresh token failed. Delete the
                                // refresh token and hello key, then demand a new auth.
                                keystore
                                    .delete_tagged_hsm_key(&hello_refresh_token_tag)
                                    .map_err(|e| {
                                        error!("Failed to delete hello refresh token: {:?}", e);
                                        IdpError::Tpm
                                    })?;
                                let hello_key_tag = self.fetch_hello_key_tag(account_id, false);
                                keystore
                                    .delete_tagged_hsm_key(&hello_key_tag)
                                    .map_err(|e| {
                                        error!("Failed to delete hello key: {:?}", e);
                                        IdpError::Tpm
                                    })?;
                                // It's ok to reset the pin count here, since they must
                                // online auth at this point and create a new pin.
                                self.bad_pin_counter.reset_bad_pin_count(account_id).await;
                                return Err(IdpError::BadRequest);
                            }
                        }
                    } else {
                        error!("Failed fetching hello prt from cache");
                        // We don't have access to a PRT, and can't proceed. Delete
                        // the decoupled hello key.
                        let hello_key_tag = self.fetch_hello_key_tag(account_id, false);
                            keystore
                                .delete_tagged_hsm_key(&hello_key_tag)
                                .map_err(|e| {
                                    error!("Failed to delete hello key: {:?}", e);
                                    IdpError::Tpm
                                })?;
                        return Err(IdpError::BadRequest);
                    }
                };

                // Cache the PRT to disk for offline auth SSO
                if let Some(prt) = &token.prt {
                    match self.client.read().await.seal_user_prt_with_hello_key(
                        prt,
                        &$hello_key,
                        &$cred,
                        tpm,
                        machine_key,
                    ) {
                        Ok(hello_prt) => {
                            let hello_prt_tag = self.fetch_hello_prt_key_tag(account_id);
                            keystore
                                .insert_tagged_hsm_key(&hello_prt_tag, &hello_prt)
                                .map_err(|e| {
                                    let uuid = token.uuid().map(|v| v.to_string()).unwrap_or("".to_string());
                                    error!("Failed to cache hello prt for {}: {:?}", uuid, e);
                                    IdpError::Tpm
                                })?;
                        }
                        Err(e) => {
                            let uuid = token.uuid().map(|v| v.to_string()).unwrap_or("".to_string());
                            error!("Failed to cache hello prt for {}: {:?}", uuid, e);
                        }
                    }
                } else {
                    // If there is no PRT, cache the refresh token instead
                    let pin = PinValue::new(&$cred).map_err(|e| {
                        error!("Failed initializing pin value: {:?}", e);
                        IdpError::Tpm
                    })?;
                    let (_key, win_hello_storage_key) = tpm
                        .ms_hello_key_load(machine_key, &$hello_key, &pin)
                        .map_err(|e| {
                            error!("Failed loading hello key for prt cache: {:?}", e);
                            IdpError::Tpm
                        })?;
                    let refresh_token_zeroizing =
                        zeroize::Zeroizing::new(token.refresh_token.as_bytes().to_vec());
                    tpm.seal_data(&win_hello_storage_key, refresh_token_zeroizing)
                        .map_err(|e| {
                            let uuid = token.uuid().map(|v| v.to_string()).unwrap_or("".to_string());
                            error!("Failed to seal refresh token for {}: {:?}", uuid, e);
                            IdpError::Tpm
                        })
                        .and_then(|sealed_prt| {
                            let hello_prt_tag = self.fetch_hello_refresh_token_key_tag(account_id);
                            keystore.insert_tagged_hsm_key(&hello_prt_tag, &sealed_prt).map_err(|e| {
                                let uuid = token.uuid().map(|v| v.to_string()).unwrap_or("".to_string());
                                error!("Failed to cache hello refresh token for {}: {:?}", uuid, e);
                                IdpError::Tpm
                            })
                        })?;
                }

                if !self.is_intune_enrolled(keystore).await {
                    intune_enroll!(token);
                }

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
                let token = token.clone().ok_or_else(|| {
                    error!("Missing enrollment token for Hello PIN setup.");
                    IdpError::BadRequest
                })?;
                // Skip Hello enrollment if the token doesn't have the ngcmfa amr
                let amr_ngcmfa = token.amr_ngcmfa().unwrap_or(false);
                let hello_tag = self.fetch_hello_key_tag(account_id, amr_ngcmfa);

                let (hello_key, keytype) = if amr_ngcmfa {
                    net_down_check!(
                        impl_provision_hello_key!(self, token, pin, tpm, machine_key),
                        Ok(hello_key) => (hello_key, KeyType::Hello),
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
                    )
                } else {
                    (
                        impl_create_decoupled_hello_key!(
                            self,
                            token,
                            amr_ngcmfa,
                            tpm,
                            machine_key,
                            pin,
                            IdpError::Tpm
                        ),
                        KeyType::Decoupled,
                    )
                };
                keystore
                    .insert_tagged_hsm_key(&hello_tag, &hello_key)
                    .map_err(|e| {
                        error!("Failed to provision hello key: {:?}", e);
                        IdpError::Tpm
                    })?;

                auth_and_validate_hello_key!(hello_key, keytype, pin)
            }
            (_, PamAuthRequest::Pin { cred }) => {
                let (hello_key, keytype) =
                    self.fetch_hello_key(account_id, keystore).map_err(|e| {
                        error!("Online authentication failed. Hello key missing.");
                        e
                    })?;

                auth_and_validate_hello_key!(hello_key, keytype, cred)
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

                // Call the appropriate method based on whether mfa_method is configured
                let mresp = self
                    .client
                    .read()
                    .await
                    .initiate_acquire_token_by_mfa_flow_for_device_enrollment(
                        account_id,
                        Some(&cred),
                        &opts,
                        None,
                        self.config.read().await.get_mfa_method().as_deref(),
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
                            password: Some(cred.clone()),
                            extra_data: None,
                        };
                        let action = if self.config.read().await.get_offline_breakglass_enabled() {
                            AuthCacheAction::PasswordHashUpdate { cred }
                        } else {
                            AuthCacheAction::None
                        };
                        return Ok((
                            AuthResult::Next(AuthRequest::Fido {
                                fido_allow_list,
                                fido_challenge,
                            }),
                            /* Cache the offline password hash for breakglass
                             * conditions, if enabled. */
                            action,
                        ));
                    },
                    // PROMPT
                    {
                        let msg = resp.msg.clone();
                        *cred_handler = AuthCredHandler::MFA {
                            flow: resp,
                            password: Some(cred.clone()),
                            extra_data: None,
                        };
                        let action = if self.config.read().await.get_offline_breakglass_enabled() {
                            AuthCacheAction::PasswordHashUpdate { cred }
                        } else {
                            AuthCacheAction::None
                        };
                        return Ok((
                            AuthResult::Next(AuthRequest::MFACode { msg }),
                            /* Cache the offline password hash for breakglass
                             * conditions, if enabled. */
                            action,
                        ));
                    },
                    // POLL
                    {
                        let msg = resp.msg.clone();
                        let polling_interval = resp.polling_interval.unwrap_or(5000);
                        *cred_handler = AuthCredHandler::MFA {
                            flow: resp,
                            password: Some(cred.clone()),
                            extra_data: None,
                        };
                        let action = if self.config.read().await.get_offline_breakglass_enabled() {
                            AuthCacheAction::PasswordHashUpdate { cred }
                        } else {
                            AuthCacheAction::None
                        };
                        return Ok((
                            AuthResult::Next(AuthRequest::MFAPoll {
                                msg,
                                // Kanidm pam expects a polling_interval in
                                // seconds, not milliseconds.
                                polling_interval: polling_interval / 1000,
                            }),
                            /* Cache the offline password hash for breakglass
                             * conditions, if enabled. */
                            action,
                        ));
                    }
                )
            }
            (
                AuthCredHandler::MFA {
                    ref mut flow,
                    password,
                    extra_data: _,
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
                        let amr_ngcmfa = token2.amr_ngcmfa().unwrap_or(false);
                        // If the token at least has an mfa amr, then we can fake a hello key
                        let amr_mfa = token2.amr_mfa().unwrap_or(false);
                        if !hello_enabled || (!amr_ngcmfa && !amr_mfa) || no_hello_pin {
                            info!("Skipping Hello enrollment because it is disabled");
                            return Ok((
                                AuthResult::Success { token: token3 },
                                AuthCacheAction::None,
                            ));
                        }

                        // Setup Windows Hello
                        *cred_handler = AuthCredHandler::SetupPin { token: Some(token) };
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
                    extra_data: _,
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
                // Check whether the token is a for the special MSA tenant,
                // meaning we need skip device enrollment (it's a personal
                // account).
                let msa_tenant = token.tenant_id().map_err(|e| {
                    error!("{:?}", e);
                    IdpError::NotFound {
                        what: "tenant_id from token".to_string(),
                        where_: "unix_user_online_auth_step".to_string(),
                    }
                })? == "9188040d-6c67-4c5b-b112-36a304b66dad";
                let token2 = if msa_tenant {
                    token.clone()
                } else {
                    enroll_and_obtain_enrolled_token!(token)
                };
                match self.token_validate(account_id, &token2, None).await {
                    Ok(AuthResult::Success { token: token3 }) => {
                        // Skip Hello enrollment if it is disabled by config
                        let hello_enabled = self.config.read().await.get_enable_hello();
                        // Skip Hello enrollment if the token doesn't have the ngcmfa amr
                        let amr_ngcmfa = token2.amr_ngcmfa().unwrap_or(false);
                        // If the token at least has an mfa amr, then we can fake a hello key
                        let amr_mfa = token2.amr_mfa().unwrap_or(false);
                        if !hello_enabled
                            || (!amr_ngcmfa && !amr_mfa && !msa_tenant)
                            || no_hello_pin
                        {
                            info!("Skipping Hello enrollment because it is disabled");
                            return Ok((
                                AuthResult::Success { token: token3 },
                                AuthCacheAction::None,
                            ));
                        }

                        // Setup Windows Hello
                        *cred_handler = AuthCredHandler::SetupPin { token: Some(token) };
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
                    extra_data: _,
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
                        if !hello_enabled || no_hello_pin {
                            info!("Skipping Hello enrollment because it is disabled");
                            return Ok((
                                AuthResult::Success { token: token3 },
                                AuthCacheAction::None,
                            ));
                        }

                        // Setup Windows Hello
                        *cred_handler = AuthCredHandler::SetupPin { token: Some(token) };
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
                Err(IdpError::NotFound {
                    what: "AuthCredHandler, PamAuthRequest".to_string(),
                    where_: "cred_handler, pam_next_req".to_string(),
                })
            }
        }
    }

    #[instrument(skip(self, account_id, _token, keystore))]
    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        _token: Option<&UserToken>,
        no_hello_pin: bool,
        keystore: &mut D,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        impl_himmelblau_offline_auth_init!(self, account_id, no_hello_pin, keystore, true)
    }

    #[instrument(skip_all)]
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
        impl_himmelblau_offline_auth_step!(
            cred_handler,
            pam_next_req,
            self,
            account_id,
            keystore,
            tpm,
            machine_key,
            token,
            load_cached_prt
        )
    }

    async fn unix_group_get(
        &self,
        _id: &Id,
        _tpm: &mut tpm::provider::BoxedDynTpm,
    ) -> Result<GroupToken, IdpError> {
        /* AAD doesn't permit group listing (must use cache entries from auth) */
        Err(IdpError::BadRequest)
    }

    async fn get_cachestate<D: KeyStoreTxn + Send>(
        &self,
        _account_id: Option<&str>,
        _keystore: &mut D,
    ) -> CacheState {
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

    impl_himmelblau_hello_key_helpers!();

    fn fetch_cert_key_tag(&self) -> String {
        format!("{}/certificate", self.domain)
    }

    fn fetch_intune_key_tag(&self) -> String {
        format!("{}/intune", self.domain)
    }

    fn fetch_tranport_key_tag(&self) -> String {
        format!("{}/transport", self.domain)
    }

    #[instrument(level = "debug", skip_all)]
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

    #[instrument(level = "debug", skip_all)]
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

    #[instrument(level = "debug", skip_all)]
    async fn token_validate(
        &self,
        account_id: &str,
        token: &UnixUserToken,
        old_token: Option<&UserToken>,
    ) -> Result<AuthResult, IdpError> {
        let uuid = token.uuid().map_err(|e| {
            error!("Failed fetching user uuid: {:?}", e);
            IdpError::BadRequest
        })?;
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
                    /* Fixes bug#801: The authenticated user might have a mis-matched
                     * response because the domains are aliases of one another.
                     */
                    let mut cfg = self.config.write().await;
                    let (_, domain1) = split_username(account_id).ok_or(IdpError::BadRequest)?;
                    let (_, domain2) = split_username(&spn).ok_or(IdpError::BadRequest)?;
                    if !cfg.domains_are_aliases(domain1, domain2).await {
                        let msg =
                            format!("Authenticated user {} does not match requested user", uuid);
                        error!(msg);
                        return Ok(AuthResult::Denied(msg));
                    }
                }
                info!("Authentication successful for user '{}'", uuid);
                // If an encrypted PRT is present, store it in the mem cache
                if let Some(prt) = &token.prt {
                    self.refresh_cache
                        .add(account_id, &RefreshCacheEntry::Prt(prt.clone()))
                        .await;
                }
                // MSA Accounts don't have PRTs, so instead cache the refresh token
                else {
                    self.refresh_cache
                        .add(
                            account_id,
                            &RefreshCacheEntry::RefreshToken(token.refresh_token.clone()),
                        )
                        .await;
                }
                Ok(AuthResult::Success {
                    token: self
                        .user_token_from_unix_user_token(
                            account_id,
                            TokenOrObj::UserToken(Box::new(token.clone())),
                            old_token,
                        )
                        .await?,
                })
            }
            None => {
                info!("Authentication failed for user '{}'", uuid);
                Err(IdpError::NotFound {
                    what: "access_token".to_string(),
                    where_: "token_validate".to_string(),
                })
            }
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn user_token_from_unix_user_token(
        &self,
        spn: &str,
        value: TokenOrObj,
        old_token: Option<&UserToken>,
    ) -> Result<UserToken, IdpError> {
        let config = self.config.read().await;
        let mut groups: Vec<GroupToken>;
        let posix_attrs: HashMap<String, String>;
        let spn = spn.to_lowercase();
        let uuid = match &value {
            TokenOrObj::UserObj((_, value)) => Uuid::parse_str(&value.id).map_err(|e| {
                error!("Failed fetching user uuid: {:?}", e);
                IdpError::BadRequest
            })?,
            TokenOrObj::UserToken(value) => value.uuid().map_err(|e| {
                error!("Failed fetching user uuid: {:?}", e);
                IdpError::BadRequest
            })?,
        };
        let access_token = match &value {
            TokenOrObj::UserObj((token, _)) => Some(token.access_token.clone()),
            TokenOrObj::UserToken(value) => value.access_token.clone(),
        };
        match &access_token {
            Some(access_token) => {
                groups = match self
                    .graph
                    .request_user_groups_by_user_id(access_token, &uuid.to_string())
                    .await
                {
                    Ok(groups) => {
                        let mut gt_groups = vec![];
                        for g in groups {
                            match self.group_token_from_directory_object(g).await {
                                Ok(group) => gt_groups.push(group),
                                Err(e) => {
                                    debug!("Failed fetching group for user {}: {}", uuid, e)
                                }
                            };
                        }
                        gt_groups
                    }
                    Err(_e) => {
                        debug!("Failed fetching user groups for {}", uuid);
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
                        .fetch_user_extension_attributes_by_user_id(
                            access_token,
                            &uuid.to_string(),
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
                debug!("Failed fetching user groups for {}", uuid);
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
        let user_map = UserMap::new(&config.get_user_map_file());
        let (uidnumber, gidnumber) = match user_map.get_local_from_upn(&spn) {
            Some(user) => {
                let pwd = unsafe {
                    let cstr_user = CString::new(user).map_err(|e| {
                        error!("Failed converting username to CString: {}", e);
                        IdpError::BadRequest
                    })?;
                    let user = CString::into_raw(cstr_user);
                    let pwd = getpwnam(user);
                    if pwd.is_null() {
                        return Err(IdpError::NotFound {
                            what: "getpwnam".to_string(),
                            where_: "local user map".to_string(),
                        });
                    }
                    *pwd
                };
                (pwd.pw_uid as u32, pwd.pw_gid as u32)
            }
            None => {
                let idmap = self.idmap.read().await;
                let idmap_cache = StaticIdCache::new(ID_MAP_CACHE, false).map_err(|e| {
                    error!("Failed reading from the idmap cache: {:?}", e);
                    IdpError::BadRequest
                })?;
                match idmap_cache.get_user_by_name(&spn) {
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
                                    error!(
                                        "User {} has no uidNumber defined in the directory!",
                                        uuid
                                    );
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
                }
            }
        };

        let displayname = match posix_attrs.get("gecos") {
            Some(gecos) => gecos.clone(),
            None => match &value {
                TokenOrObj::UserObj((_, value)) => value.displayname.clone(),
                TokenOrObj::UserToken(value) => value.id_token.name.clone(),
            },
            //value.id_token.name.clone(),
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

    #[instrument(level = "debug", skip_all)]
    async fn group_token_from_directory_object(
        &self,
        value: DirectoryObject,
    ) -> Result<GroupToken> {
        let config = self.config.read().await;
        let name = match value.display_name {
            Some(name) => name,
            None => value.id.clone(),
        };
        // Prohibit group names which look like a UPN
        if name.contains("@") {
            // Including the "@" symbol in a group name is discouraged by MS,
            // and permits a potential name collision risk (a user could
            // create a group which collides with a fake primary group).
            // Group names with an "@" will also resolve via NSS, which we
            // NEVER permit (see CVE-2025-49012).
            return Err(anyhow!("Group names cannot contain the '@' symbol."));
        }
        let id =
            Uuid::parse_str(&value.id).map_err(|e| anyhow!("Failed parsing user uuid: {}", e))?;
        let idmap = self.idmap.read().await;
        let idmap_cache_entry = StaticIdCache::new(ID_MAP_CACHE, false)
            .ok()
            .and_then(|idmap_cache| idmap_cache.get_group_by_name(&id.to_string()));
        let gidnumber = match idmap_cache_entry {
            Some(group) => group.gid,
            None => match config.get_id_attr_map() {
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
                        &id.to_string(),
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
            },
        };

        Ok(GroupToken {
            name: name.clone(),
            spn: name.to_string(),
            uuid: id,
            gidnumber,
        })
    }

    #[instrument(level = "debug", skip_all)]
    async fn join_domain<D: KeyStoreTxn + Send>(
        &self,
        tpm: &mut tpm::provider::BoxedDynTpm,
        token: &UnixUserToken,
        keystore: &mut D,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<(), MsalError> {
        let join_type = self.config.read().await.get_join_type();
        /* If not already joined, join the domain now. */
        let attrs = EnrollAttrs::new(
            self.domain.clone(),
            None,
            None,
            Some(join_type.into()),
            None,
        )?;
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

                let intune_device_id = match self
                    .intune_enroll(Some(&device_id), Some(&attrs), tpm, token, machine_key)
                    .await
                {
                    Ok((intune_key, intune_device_id)) => {
                        let intune_tag = self.fetch_intune_key_tag();
                        if let Err(e) = keystore.insert_tagged_hsm_key(&intune_tag, &intune_key) {
                            error!(?e, "Failed inserting the intune key into the keystore.");
                            return Err(MsalError::GeneralFailure(format!(
                                "Failed to enroll in Intune: {:?}",
                                e
                            )));
                        }
                        Some(intune_device_id)
                    }
                    Err(IdpError::NotFound { .. }) => None,
                    Err(e) => {
                        return Err(MsalError::GeneralFailure(format!(
                            "Failed to enroll in Intune: {:?}",
                            e
                        )));
                    }
                };

                let mut config = self.config.write().await;
                if let Some(intune_device_id) = intune_device_id {
                    config.set(&self.domain, "intune_device_id", &intune_device_id);
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

    #[instrument(level = "debug", skip_all)]
    async fn intune_enroll(
        &self,
        device_id: Option<&str>,
        attrs: Option<&EnrollAttrs>,
        tpm: &mut tpm::provider::BoxedDynTpm,
        token: &UnixUserToken,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<(LoadableMsDeviceEnrolmentKey, String), IdpError> {
        // Enrolling the device in Intune
        let config = self.config.read().await;
        if config.get_apply_policy() {
            let graph_token = match self
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
                .await
            {
                Ok(token) => token,
                Err(MsalError::AcquireTokenFailed(e)) => {
                    if e.error_codes.contains(&DEVICE_AUTH_FAIL) {
                        error!(
                            ?e,
                            "Device auth failed for Intune device enrollment, delaying enrollment."
                        );
                        // TODO: Is NotFound the correct error type here? BadRequest better here?
                        return Err(IdpError::NotFound {
                            what: "refresh_token".to_string(),
                            where_: "intune_enroll".to_string(),
                        });
                    } else {
                        error!(?e, "Acquiring token for Intune device enrollment failed.");
                        return Err(IdpError::BadRequest);
                    }
                }
                Err(e) => {
                    error!(?e, "Acquiring token for Intune device enrollment failed.");
                    return Err(IdpError::BadRequest);
                }
            };
            let access_token = graph_token.access_token.clone().ok_or_else(|| {
                error!("Acquiring token for Intune device enrollment failed: access_token missing");
                IdpError::BadRequest
            })?;
            let endpoints = self
                .graph
                .intune_service_endpoints(&access_token)
                .await
                .map_err(|e| {
                    error!("Failed fetching Intune service endpoints: {:?}", e);
                    IdpError::BadRequest
                })?;
            match self
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
                Ok(token) => {
                    let intune = IntuneForLinux::new(endpoints).map_err(|e| {
                        error!(?e, "Intune device enrollment failed.");
                        IdpError::BadRequest
                    })?;
                    let device_id = match device_id {
                        Some(v) => v.to_string(),
                        None => config
                            .get(&self.domain, "device_id")
                            .ok_or(IdpError::BadRequest)?,
                    };
                    let attrs = attrs.cloned().unwrap_or(
                        EnrollAttrs::new(self.domain.clone(), None, None, None, None).map_err(
                            |e| {
                                error!("Failed creating enroll attrs: {:?}", e);
                                IdpError::BadRequest
                            },
                        )?,
                    );
                    match intune
                        .enroll(&token, &attrs, &device_id, tpm, machine_key)
                        .await
                    {
                        Ok((intune_key, intune_device_id)) => Ok((intune_key, intune_device_id)),
                        Err(e) => {
                            error!(?e, "Intune device enrollment failed.");
                            Err(IdpError::BadRequest)
                        }
                    }
                }
                Err(e) => {
                    error!(?e, "Intune device enrollment failed.");
                    Err(IdpError::BadRequest)
                }
            }
        } else {
            Err(IdpError::NotFound {
                what: "apply_policy".to_string(),
                where_: "intune_enroll".to_string(),
            })
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn is_domain_joined<D: KeyStoreTxn + Send>(&self, keystore: &mut D) -> bool {
        if self.is_consumer_tenant().await {
            // Pretend we are always joined for MSA accounts
            return true;
        }
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

    #[instrument(level = "debug", skip_all)]
    async fn is_consumer_tenant(&self) -> bool {
        let config = self.config.read().await;
        let tenant_id = config
            .get(&self.domain, "tenant_id")
            .unwrap_or("".to_string());
        tenant_id == "9188040d-6c67-4c5b-b112-36a304b66dad"
            || tenant_id == "9cd80435-793b-4f48-844b-6b3f37d1c1f3"
    }

    #[instrument(level = "debug", skip_all)]
    async fn is_intune_enrolled<D: KeyStoreTxn + Send>(&self, keystore: &mut D) -> bool {
        if self.is_consumer_tenant().await {
            // Pretend we are always enrolled for MSA accounts
            return true;
        }
        let config = self.config.read().await;
        if config.get(&self.domain, "intune_device_id").is_none() {
            return false;
        }
        let intune_tag = self.fetch_intune_key_tag();
        let intune_key: Option<LoadableMsDeviceEnrolmentKey> =
            match keystore.get_tagged_hsm_key(&intune_tag) {
                Ok(intune_key) => intune_key,
                Err(_) => return false,
            };
        if intune_key.is_none() {
            return false;
        }
        true
    }
}
