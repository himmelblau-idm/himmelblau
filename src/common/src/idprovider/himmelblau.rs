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
    AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, GroupToken, Id, IdProvider,
    IdpError, UserToken,
};
use crate::config::split_username;
use crate::config::HimmelblauConfig;
use crate::config::IdAttr;
use crate::db::KeyStoreTxn;
use crate::idprovider::interface::tpm;
use crate::unix_proto::PamAuthRequest;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use himmelblau::auth::{BrokerClientApplication, UserToken as UnixUserToken};
use himmelblau::discovery::EnrollAttrs;
use himmelblau::error::{MsalError, DEVICE_AUTH_FAIL};
use himmelblau::graph::{DirectoryObject, Graph};
use himmelblau::{AuthOption, MFAAuthContinue};
use idmap::Idmap;
use kanidm_hsm_crypto::{LoadableIdentityKey, LoadableMsOapxbcRsaKey, PinValue, SealedData, Tpm};
use reqwest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::time::SystemTime;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

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
        match refresh_cache.get(account_id) {
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
        refresh_cache.insert(account_id.to_string(), (prt.clone(), SystemTime::now()));
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
        for domain in cfg.get_configured_domains() {
            debug!("Adding provider for domain {}", domain);
            let range = cfg.get_idmap_range(&domain);
            let mut idmap_lk = idmap.write().await;
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
            let authority_host = graph
                .authority_host()
                .await
                .map_err(|e| anyhow!("{:?}", e))?;
            let tenant_id = graph.tenant_id().await.map_err(|e| anyhow!("{:?}", e))?;
            idmap_lk
                .add_gen_domain(&domain, &tenant_id, range)
                .map_err(|e| anyhow!("{:?}", e))?;
            let authority_url = format!("https://{}/{}", authority_host, tenant_id);
            let app = BrokerClientApplication::new(Some(authority_url.as_str()), None, None)
                .map_err(|e| anyhow!("{:?}", e))?;
            let provider = HimmelblauProvider::new(
                app,
                &config,
                &tenant_id,
                &domain,
                &authority_host,
                graph,
                &idmap,
            )
            .map_err(|_| anyhow!("Failed to initialize the provider"))?;
            {
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
    async fn provider_authenticate(&self, tpm: &mut tpm::BoxedDynTpm) -> Result<(), IdpError> {
        for (_domain, provider) in self.providers.read().await.iter() {
            match provider.provider_authenticate(tpm).await {
                Ok(()) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    async fn unix_user_access(
        &self,
        id: &Id,
        scopes: Vec<String>,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
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
                            .unix_user_access(id, scopes, old_token, tpm, machine_key)
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
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
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
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
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
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
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
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> Result<UserToken, IdpError> {
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
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
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
        service: &str,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
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
                match providers.get(domain) {
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
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
        online_at_init: bool,
    ) -> Result<AuthResult, IdpError> {
        match split_username(account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match providers.get(domain) {
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
        _tpm: &mut tpm::BoxedDynTpm,
    ) -> Result<GroupToken, IdpError> {
        /* AAD doesn't permit group listing (must use cache entries from auth) */
        Err(IdpError::BadRequest)
    }
}

pub struct HimmelblauProvider {
    client: RwLock<BrokerClientApplication>,
    config: Arc<RwLock<HimmelblauConfig>>,
    tenant_id: String,
    domain: String,
    authority_host: String,
    graph: Graph,
    refresh_cache: RefreshCache,
    idmap: Arc<RwLock<Idmap>>,
}

impl HimmelblauProvider {
    pub fn new(
        client: BrokerClientApplication,
        config: &Arc<RwLock<HimmelblauConfig>>,
        tenant_id: &str,
        domain: &str,
        authority_host: &str,
        graph: Graph,
        idmap: &Arc<RwLock<Idmap>>,
    ) -> Result<Self, IdpError> {
        Ok(HimmelblauProvider {
            client: RwLock::new(client),
            config: config.clone(),
            tenant_id: tenant_id.to_string(),
            domain: domain.to_string(),
            authority_host: authority_host.to_string(),
            graph,
            refresh_cache: RefreshCache::new(),
            idmap: idmap.clone(),
        })
    }
}

#[async_trait]
impl IdProvider for HimmelblauProvider {
    async fn provider_authenticate(&self, _tpm: &mut tpm::BoxedDynTpm) -> Result<(), IdpError> {
        /* Determine if the authority is up by sending a simple get request */
        let resp = match reqwest::get(format!("https://{}", self.authority_host)).await {
            Ok(resp) => resp,
            Err(_e) => return Err(IdpError::BadRequest),
        };
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(IdpError::BadRequest)
        }
    }

    async fn unix_user_access(
        &self,
        id: &Id,
        scopes: Vec<String>,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> Result<UnixUserToken, IdpError> {
        /* Use the prt mem cache to refresh the user token */
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        let prt = self.refresh_cache.refresh_token(&account_id).await?;
        self.client
            .write()
            .await
            .exchange_prt_for_access_token(
                &prt,
                scopes.iter().map(|s| s.as_ref()).collect(),
                None,
                tpm,
                machine_key,
            )
            .await
            .map_err(|e| {
                error!("{:?}", e);
                IdpError::BadRequest
            })
    }

    async fn unix_user_ccaches(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> (Vec<u8>, Vec<u8>) {
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
            .write()
            .await
            .fetch_cloud_ccache(&prt, tpm, machine_key)
            .unwrap_or(vec![]);
        let ad_ccache = self
            .client
            .write()
            .await
            .fetch_ad_ccache(&prt, tpm, machine_key)
            .unwrap_or(vec![]);
        (cloud_ccache, ad_ccache)
    }

    async fn unix_user_prt_cookie(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> Result<String, IdpError> {
        /* Use the prt mem cache to refresh the user token */
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        let prt = self.refresh_cache.refresh_token(&account_id).await?;
        self.client
            .write()
            .await
            .acquire_prt_sso_cookie(&prt, tpm, machine_key)
            .await
            .map_err(|e| {
                error!("Failed to request prt cookie: {:?}", e);
                IdpError::BadRequest
            })
    }

    async fn change_auth_token<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UnixUserToken,
        new_tok: &str,
        keystore: &mut D,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> Result<bool, IdpError> {
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
            .write()
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

    async fn unix_user_get(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> Result<UserToken, IdpError> {
        /* Use the prt mem cache to refresh the user token */
        let account_id = match old_token {
            Some(token) => token.spn.clone(),
            None => id.to_string().clone(),
        };
        macro_rules! fake_user {
            () => {
                match old_token {
                    // If we have an existing token, just keep it
                    Some(token) => return Ok(token.clone()),
                    // Otherwise, see if we should fake it
                    None => {
                        // Check if the user exists
                        let exists = self
                            .client
                            .write()
                            .await
                            .check_user_exists(&account_id)
                            .await
                            .map_err(|e| {
                                error!("Failed checking if the user exists: {:?}", e);
                                IdpError::BadRequest
                            })?;
                        if exists {
                            // Generate a UserToken, with invalid uuid. We can
                            // only fetch this from an authenticated token.
                            let config = self.config.read().await;
                            let gidnumber = match config.get_id_attr_map() {
                                // If Uuid mapping is enabled, bail out now.
                                // We can only provide a valid idmapping with
                                // name idmapping at this point.
                                IdAttr::Uuid => return Err(IdpError::BadRequest),
                                IdAttr::Name => {
                                    let idmap = self.idmap.read().await;
                                    idmap.gen_to_unix(&self.tenant_id, &account_id).map_err(
                                        |e| {
                                            error!("{:?}", e);
                                            IdpError::BadRequest
                                        },
                                    )?
                                }
                            };
                            let fake_uuid = Uuid::new_v4();
                            let groups = vec![GroupToken {
                                name: account_id.clone(),
                                spn: account_id.clone(),
                                uuid: fake_uuid,
                                gidnumber,
                            }];
                            let config = self.config.read().await;
                            return Ok(UserToken {
                                name: account_id.clone(),
                                spn: account_id.clone(),
                                uuid: fake_uuid,
                                gidnumber,
                                displayname: "".to_string(),
                                shell: Some(config.get_shell(Some(&self.domain))),
                                groups,
                                tenant_id: Uuid::parse_str(&self.tenant_id).map_err(|e| {
                                    error!("{:?}", e);
                                    IdpError::BadRequest
                                })?,
                                valid: true,
                            });
                        } else {
                            // This is the one time we really should return
                            // IdpError::NotFound, because this user doesn't exist.
                            return Err(IdpError::NotFound);
                        }
                    }
                }
            };
        }
        let prt = match self.refresh_cache.refresh_token(&account_id).await {
            Ok(prt) => prt,
            Err(_) => fake_user!(),
        };
        let token = match self
            .client
            .write()
            .await
            .exchange_prt_for_access_token(
                &prt,
                vec![],
                Some("https://graph.microsoft.com".to_string()),
                tpm,
                machine_key,
            )
            .await
        {
            Ok(token) => token,
            Err(e) => {
                error!("{:?}", e);
                // Never return IdpError::NotFound. This deletes the existing
                // user from the cache.
                fake_user!()
            }
        };
        match self.token_validate(&account_id, &token).await {
            Ok(AuthResult::Success { mut token }) => {
                /* Set the GECOS from the old_token, since MS doesn't
                 * provide this during a silent acquire
                 */
                if let Some(old_token) = old_token {
                    token.displayname.clone_from(&old_token.displayname)
                }
                Ok(token)
            }
            // Never return IdpError::NotFound. This deletes the existing
            // user from the cache.
            Ok(AuthResult::Denied) | Ok(AuthResult::Next(_)) => fake_user!(),
            Err(_) => fake_user!(),
        }
    }

    async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        _token: Option<&UserToken>,
        keystore: &mut D,
        _tpm: &mut tpm::BoxedDynTpm,
        _machine_key: &tpm::MachineKey,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        let hello_tag = self.fetch_hello_key_tag(account_id);
        let hello_key: Option<LoadableIdentityKey> =
            keystore.get_tagged_hsm_key(&hello_tag).map_err(|e| {
                error!("Failed fetching hello key from keystore: {:?}", e);
                IdpError::BadRequest
            })?;
        // Skip Hello authentication if it is disabled by config
        let hello_enabled = self.config.read().await.get_enable_hello();
        if !self.is_domain_joined(keystore).await || hello_key.is_none() || !hello_enabled {
            if self.config.read().await.get_enable_experimental_mfa() {
                Ok((AuthRequest::Password, AuthCredHandler::None))
            } else {
                let resp = self
                    .client
                    .write()
                    .await
                    .initiate_device_flow_for_device_enrollment()
                    .await
                    .map_err(|e| {
                        error!("{:?}", e);
                        IdpError::BadRequest
                    })?;
                let mut flow: MFAAuthContinue = resp.into();
                if !self.is_domain_joined(keystore).await {
                    flow.resource = Some("https://enrollment.manage.microsoft.com".to_string());
                }
                let msg = flow.msg.clone();
                let polling_interval = flow.polling_interval.ok_or_else(|| {
                    error!("Invalid response from the server");
                    IdpError::BadRequest
                })?;
                Ok((
                    AuthRequest::MFAPoll {
                        msg,
                        // Kanidm pam expects a polling_interval in
                        // seconds, not milliseconds.
                        polling_interval: polling_interval / 1000,
                    },
                    AuthCredHandler::MFA { flow },
                ))
            }
        } else {
            Ok((AuthRequest::Pin, AuthCredHandler::None))
        }
    }

    async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        service: &str,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
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
                let mtoken2 = self
                    .client
                    .write()
                    .await
                    .acquire_token_by_refresh_token(
                        &$token.refresh_token,
                        vec![],
                        Some("https://graph.microsoft.com".to_string()),
                        tpm,
                        machine_key,
                    )
                    .await;
                match mtoken2 {
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
                                    self.client
                                        .write()
                                        .await
                                        .acquire_token_by_refresh_token(
                                            &$token.refresh_token,
                                            vec![],
                                            Some("https://graph.microsoft.com".to_string()),
                                            tpm,
                                            machine_key,
                                        )
                                        .await
                                        .map_err(|e| {
                                            error!("{:?}", e);
                                            IdpError::NotFound
                                        })?
                                } else {
                                    return Err(IdpError::NotFound);
                                }
                            }
                            _ => return Err(IdpError::NotFound),
                        }
                    }
                }
            }};
        }
        macro_rules! auth_and_validate_hello_key {
            ($hello_key:ident, $cred:ident) => {{
                let token = self
                    .client
                    .write()
                    .await
                    .acquire_token_by_hello_for_business_key(
                        account_id,
                        &$hello_key,
                        vec![],
                        Some("https://graph.microsoft.com".to_string()),
                        tpm,
                        machine_key,
                        &$cred,
                    )
                    .await
                    .map_err(|e| {
                        error!("Failed to authenticate with hello key: {:?}", e);
                        IdpError::BadRequest
                    })?;

                match self.token_validate(account_id, &token).await {
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

                let hello_key = match self
                    .client
                    .write()
                    .await
                    .provision_hello_for_business_key(token, tpm, machine_key, &pin)
                    .await
                {
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
                };
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
            (_, PamAuthRequest::Password { cred }) => {
                // Always attempt to force MFA when enrolling the device, otherwise
                // the device object will not have the MFA claim. If we are already
                // enrolled but creating a new Hello Pin, we follow the same process,
                // since only an enrollment token can be exchanged for a PRT (which
                // will be needed to enroll the Hello Pin).
                let mut opts = vec![];
                // Prohibit Fido over ssh (since it can't work)
                if service != "ssh" {
                    opts.push(AuthOption::Fido);
                }
                let mresp = self
                    .client
                    .write()
                    .await
                    .initiate_acquire_token_by_mfa_flow_for_device_enrollment(
                        account_id, &cred, opts,
                    )
                    .await;
                // We need to wait to handle the response until after we've released
                // the write lock on the client, otherwise we will deadlock.
                let resp = match mresp {
                    Ok(resp) => resp,
                    Err(e) => {
                        // If SFA is disabled, we need to skip the SFA fallback.
                        let sfa_enabled = self.config.read().await.get_enable_sfa_fallback();
                        let mtoken = if sfa_enabled {
                            // If we got an AADSTSError, then we don't want to
                            // perform a fallback, since the authentication
                            // legitimately failed.
                            if let MsalError::AADSTSError(_) = e {
                                error!("{:?}", e);
                                return Err(IdpError::BadRequest);
                            }
                            warn!("MFA auth failed, falling back to SFA: {:?}", e);
                            // Again, we need to wait to handle the response until after
                            // we've released the write lock on the client, otherwise we
                            // will deadlock.
                            self.client
                                .write()
                                .await
                                .acquire_token_by_username_password_for_device_enrollment(
                                    account_id, &cred,
                                )
                                .await
                        } else {
                            error!("{:?}", e);
                            return Err(IdpError::BadRequest);
                        };
                        let token = match mtoken {
                            Ok(token) => token,
                            Err(e) => {
                                error!("{:?}", e);
                                return Err(IdpError::BadRequest);
                            }
                        };
                        let token2 = enroll_and_obtain_enrolled_token!(token);
                        return match self.token_validate(account_id, &token2).await {
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
                };
                match resp.mfa_method.as_str() {
                    "FidoKey" => {
                        let fido_challenge =
                            resp.fido_challenge.clone().ok_or(IdpError::BadRequest)?;

                        let fido_allow_list =
                            resp.fido_allow_list.clone().ok_or(IdpError::BadRequest)?;
                        *cred_handler = AuthCredHandler::MFA { flow: resp };
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
                    }
                    "PhoneAppOTP" | "OneWaySMS" | "ConsolidatedTelephony" => {
                        let msg = resp.msg.clone();
                        *cred_handler = AuthCredHandler::MFA { flow: resp };
                        return Ok((
                            AuthResult::Next(AuthRequest::MFACode { msg }),
                            /* An MFA auth cannot cache the password. This would
                             * lead to a potential downgrade to SFA attack (where
                             * the attacker auths with a stolen password, then
                             * disconnects the network to complete the auth). */
                            AuthCacheAction::None,
                        ));
                    }
                    _ => {
                        let msg = resp.msg.clone();
                        let polling_interval = resp.polling_interval.ok_or_else(|| {
                            error!("Invalid response from the server");
                            IdpError::BadRequest
                        })?;
                        *cred_handler = AuthCredHandler::MFA { flow: resp };
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
                }
            }
            (AuthCredHandler::MFA { ref mut flow }, PamAuthRequest::MFACode { cred }) => {
                let token = self
                    .client
                    .write()
                    .await
                    .acquire_token_by_mfa_flow(account_id, Some(&cred), None, flow)
                    .await
                    .map_err(|e| {
                        error!("{:?}", e);
                        IdpError::NotFound
                    })?;
                let token2 = enroll_and_obtain_enrolled_token!(token);
                match self.token_validate(account_id, &token2).await {
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
            (AuthCredHandler::MFA { ref mut flow }, PamAuthRequest::MFAPoll { poll_attempt }) => {
                let max_poll_attempts = flow.max_poll_attempts.ok_or_else(|| {
                    error!("Invalid response from the server");
                    IdpError::BadRequest
                })?;
                if poll_attempt > max_poll_attempts {
                    error!("MFA polling timed out");
                    return Err(IdpError::BadRequest);
                }
                let token = match self
                    .client
                    .write()
                    .await
                    .acquire_token_by_mfa_flow(account_id, None, Some(poll_attempt), flow)
                    .await
                {
                    Ok(token) => token,
                    Err(e) => match e {
                        MsalError::MFAPollContinue => {
                            return Ok((
                                AuthResult::Next(AuthRequest::MFAPollWait),
                                AuthCacheAction::None,
                            ));
                        }
                        e => {
                            error!("{:?}", e);
                            return Err(IdpError::NotFound);
                        }
                    },
                };
                let token2 = enroll_and_obtain_enrolled_token!(token);
                match self.token_validate(account_id, &token2).await {
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
            (AuthCredHandler::MFA { ref mut flow }, PamAuthRequest::Fido { assertion }) => {
                let token = self
                    .client
                    .write()
                    .await
                    .acquire_token_by_mfa_flow(account_id, Some(&assertion), None, flow)
                    .await
                    .map_err(|e| {
                        error!("{:?}", e);
                        IdpError::NotFound
                    })?;
                let token2 = enroll_and_obtain_enrolled_token!(token);
                match self.token_validate(account_id, &token2).await {
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

    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        _token: Option<&UserToken>,
        keystore: &mut D,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        let hello_tag = self.fetch_hello_key_tag(account_id);
        let hello_key: Option<LoadableIdentityKey> =
            keystore.get_tagged_hsm_key(&hello_tag).map_err(|e| {
                error!("Failed fetching hello key from keystore: {:?}", e);
                IdpError::BadRequest
            })?;
        if !self.is_domain_joined(keystore).await || hello_key.is_none() {
            Ok((AuthRequest::Password, AuthCredHandler::None))
        } else {
            Ok((AuthRequest::Pin, AuthCredHandler::None))
        }
    }

    async fn unix_user_offline_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UserToken,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
        _online_at_init: bool,
    ) -> Result<AuthResult, IdpError> {
        match (&cred_handler, pam_next_req) {
            (_, PamAuthRequest::Pin { cred }) => {
                let hello_tag = self.fetch_hello_key_tag(account_id);
                let hello_key: LoadableIdentityKey = keystore
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
                tpm.identity_key_load(machine_key, Some(&pin), &hello_key)
                    .map_err(|e| {
                        error!("{:?}", e);
                        IdpError::BadRequest
                    })?;
                Ok(AuthResult::Success {
                    token: token.clone(),
                })
            }
            _ => Err(IdpError::BadRequest),
        }
    }

    async fn unix_group_get(
        &self,
        _id: &Id,
        _tpm: &mut tpm::BoxedDynTpm,
    ) -> Result<GroupToken, IdpError> {
        /* AAD doesn't permit group listing (must use cache entries from auth) */
        Err(IdpError::BadRequest)
    }
}

impl HimmelblauProvider {
    fn fetch_hello_key_tag(&self, account_id: &str) -> String {
        format!("{}/hello", account_id)
    }

    fn fetch_cert_key_tag(&self) -> String {
        format!("{}/certificate", self.domain)
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
    ) -> Result<Option<LoadableIdentityKey>, IdpError> {
        let csr_tag = self.fetch_cert_key_tag();
        let loadable_id_key: Option<LoadableIdentityKey> =
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
                    error!(
                        "Authenticated user {} does not match requested user {}",
                        spn, account_id
                    );
                    return Ok(AuthResult::Denied);
                }
                info!("Authentication successful for user '{}'", account_id);
                // If an encrypted PRT is present, store it in the mem cache
                if let Some(prt) = &token.prt {
                    self.refresh_cache.add(account_id, prt).await;
                }
                Ok(AuthResult::Success {
                    token: self.user_token_from_unix_user_token(token).await?,
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
    ) -> Result<UserToken, IdpError> {
        let config = self.config.read().await;
        let mut groups: Vec<GroupToken>;
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
                        vec![]
                    }
                };
            }
            None => {
                debug!("Failed fetching user groups for {}", &spn);
                groups = vec![];
            }
        };
        let valid = true;
        let idmap = self.idmap.read().await;
        let gidnumber = match config.get_id_attr_map() {
            IdAttr::Uuid => idmap
                .object_id_to_unix_id(&self.tenant_id, &uuid)
                .map_err(|e| {
                    error!("{:?}", e);
                    IdpError::BadRequest
                })?,
            IdAttr::Name => idmap.gen_to_unix(&self.tenant_id, &spn).map_err(|e| {
                error!("{:?}", e);
                IdpError::BadRequest
            })?,
        };

        // Add the fake primary group
        groups.push(GroupToken {
            name: spn.clone(),
            spn: spn.clone(),
            uuid,
            gidnumber,
        });

        Ok(UserToken {
            name: spn.clone(),
            spn: spn.clone(),
            uuid,
            gidnumber,
            displayname: value.id_token.name.clone(),
            shell: Some(config.get_shell(Some(&self.domain))),
            groups,
            tenant_id: Uuid::parse_str(&self.tenant_id).map_err(|e| {
                error!("{:?}", e);
                IdpError::BadRequest
            })?,
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
                .object_id_to_unix_id(&self.tenant_id, &id)
                .map_err(|e| anyhow!("Failed fetching gid for {}: {:?}", id, e))?,
            IdAttr::Name => idmap
                .gen_to_unix(&self.tenant_id, &name)
                .map_err(|e| anyhow!("Failed fetching gid for {}: {:?}", name, e))?,
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
        tpm: &mut tpm::BoxedDynTpm,
        token: &UnixUserToken,
        keystore: &mut D,
        machine_key: &tpm::MachineKey,
    ) -> Result<(), MsalError> {
        /* If not already joined, join the domain now. */
        let attrs = EnrollAttrs::new(self.domain.clone(), None, None, None, None)?;
        match self
            .client
            .write()
            .await
            .enroll_device(&token.refresh_token, attrs, tpm, machine_key)
            .await
        {
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
                config.set(&self.domain, "device_id", &device_id);
                debug!(
                    "Setting domain {} config device_id to {}",
                    self.domain, &device_id
                );
                config.set(&self.domain, "tenant_id", &self.tenant_id);
                debug!(
                    "Setting domain {} config tenant_id to {}",
                    self.domain, &self.tenant_id
                );
                config.set(&self.domain, "authority_host", &self.authority_host);
                debug!(
                    "Setting domain {} config authority_host to {}",
                    self.domain, &self.authority_host
                );
                let graph_url = self.graph.graph_url().await?;
                config.set(&self.domain, "graph_url", &graph_url);
                debug!(
                    "Setting domain {} config graph_url to {}",
                    self.domain, &graph_url
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
