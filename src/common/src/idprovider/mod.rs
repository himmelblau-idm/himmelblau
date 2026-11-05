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
use crate::config::{split_username, HimmelblauConfig, ProviderConfig, ProviderKind};
use crate::db::KeyStoreTxn;
use crate::idprovider::himmelblau::HimmelblauProvider;
use crate::idprovider::interface::{
    tpm, AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, CacheState, GroupToken, Id,
    IdProvider, IdpError, UserToken, UserTokenState,
};
use crate::idprovider::oidc_router::OidcRouter;
use crate::unix_proto::PamAuthRequest;
use ::himmelblau::auth::UserToken as UnixUserToken;
use ::himmelblau::graph::Graph;
use ::himmelblau::BrokerClientApplication;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::future::join_all;
use idmap::Idmap;
use libkrimes::proto::KerberosCredentials;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, Mutex};

pub(crate) mod common;
pub mod himmelblau;
pub(crate) mod oidc_router;
pub mod okta;
pub mod openidconnect;

pub mod interface;

#[allow(clippy::large_enum_variant)]
enum Providers {
    Oidc(OidcRouter),
    Himmelblau(HimmelblauProvider),
}

pub struct IdProviderProxy {
    config: Arc<Mutex<HimmelblauConfig>>,
    settings: HimmelblauConfig,
    providers: HashMap<String, Arc<Providers>>,
}

impl Providers {
    async fn new(
        config: &Arc<Mutex<HimmelblauConfig>>,
        settings: &ProviderConfig,
        idmap: &Arc<Mutex<Idmap>>,
    ) -> Result<Self> {
        let domain = &settings.domain;
        let provider = match settings.kind {
            ProviderKind::Oidc => {
                let provider = OidcRouter::new(config, domain, idmap)
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?;
                Providers::Oidc(provider)
            }
            ProviderKind::Entra => {
                let (authority_host, tenant_id, graph_url, odc_provider, app_id, ip_versions) = {
                    let cfg = config.lock().await;
                    (
                        settings.get_authority_host(&cfg),
                        cfg.get_tenant_id(domain),
                        cfg.get_graph_url(domain),
                        cfg.get_odc_provider(domain),
                        settings.get_app_id(&cfg),
                        cfg.get_ip_versions(),
                    )
                };
                let request_timeout = config.lock().await.get_request_timeout();
                let graph = Graph::new(
                    &odc_provider,
                    domain,
                    Some(&authority_host),
                    tenant_id.as_deref(),
                    graph_url.as_deref(),
                    Duration::from_secs(request_timeout),
                    &ip_versions,
                )
                .await
                .map_err(|e| anyhow!("{e:?}"))?;
                let app = BrokerClientApplication::new(
                    None,
                    app_id.as_deref(),
                    None,
                    None,
                    Duration::from_secs(request_timeout),
                    &ip_versions,
                )
                .map_err(|e| anyhow!("{e:?}"))?;
                let provider = HimmelblauProvider::new(app, config, domain, graph, idmap)
                    .map_err(|e| anyhow!("{e:?}"))?;
                Providers::Himmelblau(provider)
            }
        };
        Ok(provider)
    }

    async fn state(&self) -> CacheState {
        match self {
            Self::Oidc(p) => p.get_cachestate(None).await,
            Self::Himmelblau(p) => p.get_cachestate(None).await,
        }
    }

    async fn probe(&self, now: SystemTime) -> bool {
        match self {
            Self::Oidc(p) => p.probe_online(None, now).await,
            Self::Himmelblau(p) => p.probe_online(None, now).await,
        }
    }

    async fn check(&self, now: SystemTime) -> bool {
        match self.state().await {
            CacheState::Online => true,
            CacheState::OfflineNextCheck(at) if now >= at => self.probe(now).await,
            _ => false,
        }
    }
}

impl IdProviderProxy {
    pub async fn new<D: KeyStoreTxn + Send>(
        config_filename: &str,
        keystore: &mut D,
    ) -> Result<Self> {
        let settings = HimmelblauConfig::new(Some(config_filename)).map_err(|e| anyhow!(e))?;
        let report = settings.validate();
        if !report.is_ok() {
            return Err(anyhow!("{}", report.errors.join("; ")));
        }
        let definitions = settings
            .parse_providers()
            .map_err(|e| anyhow!("{}", e.join("; ")))?;
        if definitions.is_empty() {
            return Err(anyhow!("No provider was configured"));
        }
        let config = Arc::new(Mutex::new(settings.clone()));
        let idmap = Arc::new(Mutex::new(Idmap::new().map_err(|e| anyhow!("{e:?}"))?));
        let initialized = join_all(
            definitions
                .iter()
                .map(|p| Providers::new(&config, p, &idmap)),
        )
        .await;
        let mut providers = HashMap::new();
        for (definition, result) in definitions.into_iter().zip(initialized) {
            let provider = match result {
                Ok(provider) => provider,
                Err(error) => {
                    error!(provider = %definition.label, domain = %definition.domain, ?error, "Skipping provider that failed initialization");
                    continue;
                }
            };
            if let Providers::Himmelblau(p) = &provider {
                let mut client = p.client().lock().await;
                if let Ok(key) = p.fetch_loadable_transport_key_from_keystore(keystore) {
                    client.set_transport_key(key);
                }
                if let Ok(key) = p.fetch_loadable_cert_key_from_keystore(keystore) {
                    client.set_cert_key(key);
                }
            }
            providers.insert(definition.domain, Arc::new(provider));
        }
        if providers.is_empty() {
            return Err(anyhow!("No configured provider could be initialized"));
        }
        let proxy = Self {
            config,
            settings,
            providers,
        };
        let providers_ref = proxy.providers.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(12 * 60 * 60)).await;
                for provider in providers_ref.values() {
                    if let Providers::Himmelblau(provider) = provider.as_ref() {
                        let app = provider.client().lock().await;
                        app.clear_cookies();
                    }
                }
            }
        });

        Ok(proxy)
    }
    async fn find_provider(&self, account: &str) -> Result<&Providers, IdpError> {
        let mut selected = self.config.lock().await.provider_for_account(account);
        if selected.is_none() {
            if let Some((name, domain)) = split_username(account) {
                if !name.is_empty() && !domain.is_empty() {
                    // Discovery must not hold the shared config lock or create providers.
                    let snapshot = self.config.lock().await.clone();
                    selected = snapshot.discover_provider_for_domain(domain).await;
                    if let Some(provider) = &selected {
                        self.config
                            .lock()
                            .await
                            .record_domain_alias(provider, domain);
                    }
                }
            }
        }
        self.lookup_provider(selected.as_ref())
    }

    fn lookup_provider(&self, selected: Option<&ProviderConfig>) -> Result<&Providers, IdpError> {
        selected
            .and_then(|p| self.providers.get(&p.domain))
            .map(Arc::as_ref)
            .ok_or_else(|| IdpError::NotFound {
                what: "configured provider".to_string(),
                where_: "providers".to_string(),
            })
    }

    async fn find_provider_for_id(
        &self,
        id: &Id,
        token: Option<&UserToken>,
    ) -> Result<&Providers, IdpError> {
        if let Some(token) = token {
            return self.find_provider(&token.spn).await;
        }
        match id {
            Id::Name(name) => self.find_provider(name).await,
            Id::Gid(gid) => self.lookup_provider(self.settings.provider_for_gid(*gid).as_ref()),
        }
    }

    async fn validate_token_provider(
        &self,
        provider: &Providers,
        token: &UserToken,
    ) -> Result<(), IdpError> {
        let owner = self.find_provider(&token.spn).await?;
        if !std::ptr::eq(provider, owner) {
            error!("Provider returned an account routed to another tenant");
            return Err(IdpError::BadRequest);
        }
        Ok(())
    }
}

fn aggregate_state(states: impl IntoIterator<Item = CacheState>) -> CacheState {
    let mut next = None;
    for state in states {
        match state {
            CacheState::Online => return CacheState::Online,
            CacheState::OfflineNextCheck(at) => {
                next = Some(next.map_or(at, |old: SystemTime| old.min(at)))
            }
            CacheState::Offline => {}
        }
    }
    next.map(CacheState::OfflineNextCheck)
        .unwrap_or(CacheState::Offline)
}

#[async_trait]
impl IdProvider for IdProviderProxy {
    fn provider_config(&self) -> Option<&HimmelblauConfig> {
        Some(&self.settings)
    }

    async fn provider_for_account(&self, account: &str) -> Option<ProviderConfig> {
        self.find_provider(account).await.ok()?;
        self.config.lock().await.provider_for_account(account)
    }

    async fn provider_status(&self) -> Vec<(String, bool)> {
        let definitions = self.settings.parse_providers().unwrap_or_default();
        join_all(definitions.iter().map(|p| async {
            let online = match self.providers.get(&p.domain) {
                Some(provider) => provider.probe(SystemTime::now()).await,
                None => false,
            };
            (p.domain.clone(), online)
        }))
        .await
    }

    async fn offline_break_glass(&self, ttl: Option<u64>) -> Result<(), IdpError> {
        let results = join_all(self.providers.values().map(|p| async {
            match p.as_ref() {
                Providers::Oidc(provider) => provider.offline_break_glass(ttl).await,
                Providers::Himmelblau(provider) => provider.offline_break_glass(ttl).await,
            }
        }))
        .await;
        for result in results {
            result?;
        }
        Ok(())
    }

    async fn check_online(&self, _tpm: &mut tpm::provider::BoxedDynTpm, now: SystemTime) -> bool {
        join_all(self.providers.values().map(|p| p.check(now)))
            .await
            .into_iter()
            .any(|online| online)
    }

    async fn check_online_for_account(
        &self,
        account: &str,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        now: SystemTime,
    ) -> bool {
        match self.find_provider(account).await {
            Ok(provider) => provider.check(now).await,
            Err(_) => false,
        }
    }

    async fn probe_online(&self, account_id: Option<&str>, now: SystemTime) -> bool {
        let provider = match account_id {
            Some(id) => {
                let Ok(provider) = self.find_provider(id).await else {
                    return false;
                };
                provider
            }
            None => {
                return join_all(self.providers.values().map(|p| p.probe(now)))
                    .await
                    .into_iter()
                    .any(|online| online)
            }
        };
        match provider {
            Providers::Oidc(provider) => provider.probe_online(account_id, now).await,
            Providers::Himmelblau(provider) => provider.probe_online(account_id, now).await,
        }
    }

    async fn unix_user_access<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        scopes: Vec<String>,
        old_token: Option<&UserToken>,
        client_id: Option<String>,
        redirect_uri: Option<String>,
        req_cnf: Option<String>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<UnixUserToken, IdpError> {
        let provider = self.find_provider_for_id(id, old_token).await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_access(
                        id,
                        scopes,
                        old_token,
                        client_id,
                        redirect_uri,
                        req_cnf,
                        keystore,
                        tpm,
                        machine_key,
                    )
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_access(
                        id,
                        scopes,
                        old_token,
                        client_id,
                        redirect_uri,
                        req_cnf,
                        keystore,
                        tpm,
                        machine_key,
                    )
                    .await
            }
        }
    }

    async fn unix_user_tgts<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> (
        Option<Box<KerberosCredentials>>,
        Option<Box<KerberosCredentials>>,
        Option<String>,
        Option<String>,
    ) {
        let Ok(provider) = self.find_provider_for_id(id, old_token).await else {
            return (None, None, None, None);
        };
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_tgts(id, old_token, keystore, tpm, machine_key)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_tgts(id, old_token, keystore, tpm, machine_key)
                    .await
            }
        }
    }

    async fn unix_user_prt_cookie<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        sso_nonce: Option<&str>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<String, IdpError> {
        let provider = self.find_provider_for_id(id, old_token).await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_prt_cookie(id, old_token, sso_nonce, keystore, tpm, machine_key)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_prt_cookie(id, old_token, sso_nonce, keystore, tpm, machine_key)
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
        let provider = self.find_provider(account_id).await?;
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
        let provider = self.find_provider_for_id(id, old_token).await?;
        let result = match provider {
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
        }?;
        if let UserTokenState::Update(token) | UserTokenState::LookupOnly(token) = &result {
            self.validate_token_provider(provider, token).await?;
        }
        Ok(result)
    }

    async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: Option<&UserToken>,
        service: &str,
        no_hello_pin: bool,
        force_reauth: bool,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        let provider = self
            .find_provider(token.map_or(account_id, |t| t.spn.as_str()))
            .await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_online_auth_init(
                        account_id,
                        token,
                        service,
                        no_hello_pin,
                        force_reauth,
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
                        service,
                        no_hello_pin,
                        force_reauth,
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
        let provider = self.find_provider(&old_token.spn).await?;
        let result = match provider {
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
        }?;
        if let AuthResult::Success { token } = &result.0 {
            self.validate_token_provider(provider, token).await?;
        }
        Ok(result)
    }

    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: Option<&UserToken>,
        service: &str,
        no_hello_pin: bool,
        keystore: &mut D,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        let provider = self
            .find_provider(token.map_or(account_id, |t| t.spn.as_str()))
            .await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_offline_auth_init(account_id, token, service, no_hello_pin, keystore)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_offline_auth_init(account_id, token, service, no_hello_pin, keystore)
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
        let provider = self.find_provider(&token.spn).await?;
        let result = match provider {
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
        }?;
        if let AuthResult::Success { token } = &result {
            self.validate_token_provider(provider, token).await?;
        }
        Ok(result)
    }

    async fn unix_user_try_unseal<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        cred: &str,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        online: bool,
    ) -> Result<bool, IdpError> {
        let provider = self.find_provider(account_id).await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_try_unseal(account_id, cred, keystore, tpm, machine_key, online)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_try_unseal(account_id, cred, keystore, tpm, machine_key, online)
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
        debug!("Group fetching not supported");
        Err(IdpError::BadRequest)
    }

    async fn get_cachestate(&self, account_id: Option<&str>) -> CacheState {
        let provider = match account_id {
            Some(id) => {
                let Ok(provider) = self.find_provider(id).await else {
                    return CacheState::Offline;
                };
                provider
            }
            None => {
                return aggregate_state(join_all(self.providers.values().map(|p| p.state())).await)
            }
        };
        match provider {
            Providers::Oidc(provider) => provider.get_cachestate(account_id).await,
            Providers::Himmelblau(provider) => provider.get_cachestate(account_id).await,
        }
    }

    async fn export_broker_prts(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut all: HashMap<String, Vec<u8>> = HashMap::new();
        for provider in self.providers.values() {
            if let Providers::Himmelblau(p) = provider.as_ref() {
                let data = p.export_broker_prts().await?;
                all.insert(p.domain().to_owned(), data);
            }
        }
        serde_json::to_vec(&all)
    }

    async fn import_broker_prts(&self, data: &[u8]) -> Result<(), serde_json::Error> {
        let all: HashMap<String, Vec<u8>> = serde_json::from_slice(data)?;
        for (domain, blob) in &all {
            if let Some(provider) = self.providers.get(domain) {
                if let Providers::Himmelblau(provider) = provider.as_ref() {
                    if let Err(error) = provider.import_broker_prts(blob).await {
                        warn!(domain, ?error, "Failed to import PRTs");
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_proxy() -> IdProviderProxy {
        let settings = HimmelblauConfig::from_test_config(
            "[global]\napp_id=linux\n\
             [tenant.a]\ntype=oidc\ndomain=a.example\ndomain_aliases=alias.example\ndefault=true\nidmap_range=200000-300000\noidc_issuer_url=https://a.example\n\
             [tenant.b]\ntype=oidc\ndomain=b.example\nidmap_range=300001-400000\noidc_issuer_url=https://b.example\n"
        );
        assert!(settings.validate().is_ok());
        let config = Arc::new(Mutex::new(settings.clone()));
        let idmap = Arc::new(Mutex::new(Idmap::new().unwrap()));
        let mut providers = HashMap::new();
        for (domain, state) in [
            ("a.example", CacheState::Offline),
            ("b.example", CacheState::Online),
        ] {
            providers.insert(
                domain.to_string(),
                Arc::new(Providers::Oidc(
                    OidcRouter::for_test(&config, domain, &idmap, state).await,
                )),
            );
        }
        IdProviderProxy {
            settings,
            config,
            providers,
        }
    }

    fn token(spn: &str) -> UserToken {
        UserToken {
            name: spn.to_string(),
            spn: spn.to_string(),
            uuid: uuid::Uuid::nil(),
            real_gidnumber: None,
            gidnumber: 300001,
            displayname: String::new(),
            shell: None,
            groups: Vec::new(),
            tenant_id: None,
            valid: true,
        }
    }

    #[tokio::test]
    async fn routes_names_aliases_cached_tokens_and_numeric_ids() {
        let proxy = test_proxy().await;
        let a = proxy.find_provider("alice@a.example").await.unwrap();
        let b = proxy.find_provider("bob@b.example").await.unwrap();
        assert!(!std::ptr::eq(a, b));
        for account in ["alice", "alice@ALIAS.EXAMPLE"] {
            assert!(std::ptr::eq(a, proxy.find_provider(account).await.unwrap()));
        }
        assert!(std::ptr::eq(
            b,
            proxy
                .find_provider_for_id(
                    &Id::Name("wrong@a.example".to_string()),
                    Some(&token("bob@b.example")),
                )
                .await
                .unwrap()
        ));
        assert!(std::ptr::eq(
            b,
            proxy
                .find_provider_for_id(&Id::Gid(300001), None)
                .await
                .unwrap()
        ));
        assert!(proxy
            .find_provider_for_id(&Id::Gid(400001), None)
            .await
            .is_err());
        for account in ["alice@unknown.example", "alice@a@b", ""] {
            assert!(proxy.find_provider(account).await.is_err());
        }
        assert!(proxy
            .validate_token_provider(a, &token("bob@b.example"))
            .await
            .is_err());
        proxy
            .config
            .lock()
            .await
            .set("b.example", "domain_aliases", "discovered.example");
        assert!(proxy
            .settings
            .provider_for_account("bob@discovered.example")
            .is_none());
        assert_eq!(
            proxy
                .provider_for_account("bob@discovered.example")
                .await
                .unwrap()
                .domain,
            "b.example"
        );
        assert!(std::ptr::eq(
            b,
            proxy.find_provider("bob@discovered.example").await.unwrap()
        ));
    }

    #[tokio::test]
    async fn offline_or_failed_provider_does_not_redirect_or_disable_another() {
        let mut proxy = test_proxy().await;
        assert!(matches!(
            proxy.get_cachestate(Some("alice")).await,
            CacheState::Offline
        ));
        assert!(matches!(
            proxy.get_cachestate(Some("bob@b.example")).await,
            CacheState::Online
        ));
        assert!(matches!(
            proxy.get_cachestate(None).await,
            CacheState::Online
        ));
        let mut tpm = tpm::provider::BoxedDynTpm::new(tpm::provider::SoftTpm::new());
        assert!(
            !proxy
                .check_online_for_account("alice", &mut tpm, SystemTime::now())
                .await
        );
        assert!(
            proxy
                .check_online_for_account("bob@b.example", &mut tpm, SystemTime::now())
                .await
        );
        proxy.providers.remove("a.example");
        assert!(proxy.find_provider("alice").await.is_err());
        assert!(proxy.find_provider("bob@b.example").await.is_ok());
    }

    #[tokio::test]
    async fn prt_roundtrip_keeps_all_configured_entra_domains() {
        async fn entra_proxy() -> IdProviderProxy {
            let settings = HimmelblauConfig::from_test_config(
                "[tenant.a]\ndomain=a.example\ndefault=true\nidmap_range=200000-300000\n\
                 [tenant.b]\ndomain=b.example\nidmap_range=300001-400000\n",
            );
            let config = Arc::new(Mutex::new(settings.clone()));
            let idmap = Arc::new(Mutex::new(Idmap::new().unwrap()));
            let mut providers = HashMap::new();
            for definition in settings.parse_providers().unwrap() {
                let provider = Providers::new(&config, &definition, &idmap).await.unwrap();
                providers.insert(definition.domain, Arc::new(provider));
            }
            IdProviderProxy {
                settings,
                config,
                providers,
            }
        }
        let proxy = entra_proxy().await;
        let mut expected = HashMap::new();
        for (domain, byte) in [("a.example", 1), ("b.example", 2)] {
            let sealed = tpm::structures::SealedData::SoftV1 {
                data: zeroize::Zeroizing::new(vec![byte]),
                tag: [byte; 16],
                iv: [byte; 16],
            };
            let entries = HashMap::from([(format!("alice@{domain}"), (sealed, 123_u64))]);
            let blob = serde_json::to_vec(&entries).unwrap();
            let Providers::Himmelblau(provider) = proxy.providers[domain].as_ref() else {
                panic!("expected an Entra provider");
            };
            provider.import_broker_prts(&blob).await.unwrap();
            expected.insert(domain.to_string(), blob);
        }
        let mut data: HashMap<String, Vec<u8>> =
            serde_json::from_slice(&proxy.export_broker_prts().await.unwrap()).unwrap();
        assert_eq!(data, expected);
        data.insert("unconfigured.example".to_string(), b"invalid blob".to_vec());
        let restored = entra_proxy().await;
        restored
            .import_broker_prts(&serde_json::to_vec(&data).unwrap())
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<HashMap<String, Vec<u8>>>(
                &restored.export_broker_prts().await.unwrap()
            )
            .unwrap(),
            expected
        );
        assert!(restored.import_broker_prts(b"invalid JSON").await.is_err());
    }

    #[test]
    fn aggregate_state_preserves_online_providers_and_earliest_retry() {
        let now = SystemTime::now();
        assert!(matches!(
            aggregate_state([CacheState::Offline, CacheState::Online]),
            CacheState::Online
        ));
        assert!(matches!(
            aggregate_state([CacheState::Offline]),
            CacheState::Offline
        ));
        assert!(matches!(aggregate_state([
            CacheState::OfflineNextCheck(now + Duration::from_secs(60)),
            CacheState::Offline,
            CacheState::OfflineNextCheck(now),
        ]), CacheState::OfflineNextCheck(at) if at == now));
    }
}
