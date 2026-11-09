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
use crate::db::{CacheError, CacheTxn, KeyStoreTxn, ScopedKeyStore};
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
    fn domain(&self) -> &str {
        match self {
            Self::Oidc(p) => p.domain(),
            Self::Himmelblau(p) => p.domain(),
        }
    }

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

struct ProviderRequest<'a> {
    provider: &'a Providers,
    definition: ProviderConfig,
    tenant_id: Option<uuid::Uuid>,
    id: Id,
    token: Option<UserToken>,
}

fn rename_token(token: &mut UserToken, name: String) {
    token.name.clone_from(&name);
    for group in &mut token.groups {
        if group.uuid == token.uuid {
            group.name.clone_from(&name);
            group.spn.clone_from(&name);
        }
    }
    token.spn = name;
}

fn localize_oidc_token(
    definition: &ProviderConfig,
    tenant_id: Option<uuid::Uuid>,
    token: &mut UserToken,
) -> Result<(), IdpError> {
    if definition.kind != ProviderKind::Oidc {
        return Ok(());
    }
    if tenant_id.is_none() || token.tenant_id != tenant_id {
        error!(provider = %definition.label, "OIDC token belongs to another issuer");
        return Err(IdpError::BadRequest);
    }
    if definition.scopes_oidc_accounts() {
        let account = token
            .oidc_account_id
            .clone()
            .unwrap_or_else(|| token.spn.clone());
        rename_token(token, definition.local_account_name(&account));
        token.oidc_account_id = Some(account);
    }
    Ok(())
}

impl ProviderRequest<'_> {
    fn account_id(&self) -> Result<&str, IdpError> {
        match &self.id {
            Id::Name(name) => Ok(name),
            Id::Gid(_) => Err(IdpError::BadRequest),
        }
    }

    fn keystore<'a, D>(&self, inner: &'a mut D) -> ScopedKeyStore<'a, D> {
        ScopedKeyStore::new(
            inner,
            self.definition
                .scopes_oidc_accounts()
                .then_some(self.tenant_id)
                .flatten(),
        )
    }

    fn localize(&self, token: &mut UserToken) -> Result<(), IdpError> {
        localize_oidc_token(&self.definition, self.tenant_id, token)
    }
}

fn migrate_oidc_accounts<D: CacheTxn + KeyStoreTxn>(
    settings: &HimmelblauConfig,
    db: &mut D,
) -> Result<(), CacheError> {
    for mut token in db.get_accounts()? {
        let Some(definition) = settings
            .provider_for_token(&token)
            .filter(ProviderConfig::scopes_oidc_accounts)
        else {
            continue;
        };
        let tenant_id = definition.oidc_tenant_id(settings);
        let original = token.clone();
        localize_oidc_token(&definition, tenant_id, &mut token).map_err(|_| CacheError::Parse)?;
        if original.oidc_account_id == token.oidc_account_id && original.spn == token.spn {
            continue;
        }
        if original.oidc_account_id.is_none() {
            for suffix in [
                "hello",
                "hello_decoupled",
                "hello_prt",
                "hello_refresh_token",
                "hello_totp",
            ] {
                let tag = format!("{}/{suffix}", original.spn.to_lowercase());
                if let Some(key) = db.get_tagged_hsm_key::<serde_json::Value>(&tag)? {
                    let mut scoped = ScopedKeyStore::new(db, tenant_id);
                    if scoped
                        .get_tagged_hsm_key::<serde_json::Value>(&tag)?
                        .is_some()
                    {
                        error!(provider = %definition.label, "OIDC credential migration would overwrite a key");
                        return Err(CacheError::TooManyResults);
                    }
                    scoped.insert_tagged_hsm_key(&tag, &key)?;
                    db.delete_tagged_hsm_key(&tag)?;
                }
            }
        }
        let (_, expiry) = db
            .get_account(&Id::Name(token.uuid.to_string()))?
            .ok_or(CacheError::Parse)?;
        db.delete_replaced_accounts(&token)?;
        for group in &token.groups {
            db.update_group(group, expiry)?;
        }
        db.update_account(&token, expiry)?;
    }
    Ok(())
}

impl IdProviderProxy {
    pub async fn new<D: KeyStoreTxn + CacheTxn + Send>(
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
        migrate_oidc_accounts(&settings, keystore)
            .map_err(|error| anyhow!("Failed to migrate OIDC accounts: {error:?}"))?;
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
                    if snapshot.routing_name_is_known(domain) {
                        error!(domain, "Ambiguous provider selection");
                        return Err(IdpError::BadRequest);
                    }
                    selected = snapshot.discover_provider_for_domain(domain).await;
                    if let Some(provider) = &selected {
                        if !self
                            .config
                            .lock()
                            .await
                            .record_domain_alias(provider, domain)
                        {
                            return Err(IdpError::BadRequest);
                        }
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
            let selected = self.config.lock().await.provider_for_token(token);
            return self.lookup_provider(selected.as_ref());
        }
        match id {
            Id::Name(name) => self.find_provider(name).await,
            Id::Gid(gid) => self.lookup_provider(self.settings.provider_for_gid(*gid).as_ref()),
        }
    }

    async fn prepare_request(
        &self,
        id: &Id,
        token: Option<&UserToken>,
    ) -> Result<ProviderRequest<'_>, IdpError> {
        let provider = self.find_provider_for_id(id, token).await?;
        let definition = self
            .settings
            .provider_for_domain(provider.domain())
            .ok_or(IdpError::BadRequest)?;
        let tenant_id = definition.oidc_tenant_id(&self.settings);
        let token = token.map(|token| {
            let mut token = token.clone();
            if let Some(account) = token.oidc_account_id.take() {
                rename_token(&mut token, account);
            }
            token
        });
        let id = match id {
            Id::Name(account) => Id::Name(match &token {
                Some(token) => token.spn.clone(),
                None => definition
                    .upstream_account_name(account)
                    .ok_or(IdpError::BadRequest)?,
            }),
            Id::Gid(gid) => Id::Gid(*gid),
        };
        Ok(ProviderRequest {
            provider,
            definition,
            tenant_id,
            id,
            token,
        })
    }

    async fn validate_token_provider(
        &self,
        provider: &Providers,
        token: &UserToken,
    ) -> Result<(), IdpError> {
        let owner = self
            .find_provider_for_id(&Id::Name(token.spn.clone()), Some(token))
            .await?;
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

    async fn provider_for_token(&self, token: &UserToken) -> Option<ProviderConfig> {
        // Runtime-discovered aliases exist only in the live configuration.
        self.config.lock().await.provider_for_token(token)
    }

    async fn provider_status(&self) -> Vec<(String, bool)> {
        let definitions = self.settings.parse_providers().unwrap_or_default();
        join_all(definitions.iter().map(|p| async {
            let online = match self.providers.get(&p.domain) {
                Some(provider) => provider.probe(SystemTime::now()).await,
                None => false,
            };
            (
                if p.kind == ProviderKind::Oidc {
                    p.label.clone()
                } else {
                    p.domain.clone()
                },
                online,
            )
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
        let request = self.prepare_request(id, old_token).await?;
        let id = &request.id;
        let old_token = request.token.as_ref();
        let mut scoped = request.keystore(keystore);
        let keystore = &mut scoped;
        match request.provider {
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
        let Ok(request) = self.prepare_request(id, old_token).await else {
            return (None, None, None, None);
        };
        let id = &request.id;
        let old_token = request.token.as_ref();
        let mut scoped = request.keystore(keystore);
        let keystore = &mut scoped;
        match request.provider {
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
        let request = self.prepare_request(id, old_token).await?;
        let id = &request.id;
        let old_token = request.token.as_ref();
        let mut scoped = request.keystore(keystore);
        let keystore = &mut scoped;
        match request.provider {
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
        let request = self
            .prepare_request(&Id::Name(account_id.to_string()), None)
            .await?;
        let account_id = request.account_id()?;
        let mut scoped = request.keystore(keystore);
        let keystore = &mut scoped;
        match request.provider {
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
        let request = self.prepare_request(id, old_token).await?;
        let id = &request.id;
        let old_token = request.token.as_ref();
        let mut scoped = request.keystore(keystore);
        let keystore = &mut scoped;
        let mut result = match request.provider {
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
        if let UserTokenState::Update(token) | UserTokenState::LookupOnly(token) = &mut result {
            request.localize(token)?;
            self.validate_token_provider(request.provider, token)
                .await?;
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
        let request = self
            .prepare_request(&Id::Name(account_id.to_string()), token)
            .await?;
        let account_id = request.account_id()?;
        let token = request.token.as_ref();
        let mut scoped = request.keystore(keystore);
        let keystore = &mut scoped;
        match request.provider {
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
        let request = self
            .prepare_request(&Id::Name(account_id.to_string()), Some(old_token))
            .await?;
        let account_id = request.account_id()?;
        let old_token = request.token.as_ref().ok_or(IdpError::BadRequest)?;
        let mut scoped = request.keystore(keystore);
        let keystore = &mut scoped;
        let mut result = match request.provider {
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
        if let AuthResult::Success { token } = &mut result.0 {
            request.localize(token)?;
            self.validate_token_provider(request.provider, token)
                .await?;
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
        let request = self
            .prepare_request(&Id::Name(account_id.to_string()), token)
            .await?;
        let account_id = request.account_id()?;
        let token = request.token.as_ref();
        let mut scoped = request.keystore(keystore);
        let keystore = &mut scoped;
        match request.provider {
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
        let request = self
            .prepare_request(&Id::Name(account_id.to_string()), Some(token))
            .await?;
        let account_id = request.account_id()?;
        let token = request.token.as_ref().ok_or(IdpError::BadRequest)?;
        let mut scoped = request.keystore(keystore);
        let keystore = &mut scoped;
        let mut result = match request.provider {
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
        if let AuthResult::Success { token } = &mut result {
            request.localize(token)?;
            self.validate_token_provider(request.provider, token)
                .await?;
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
        let request = self
            .prepare_request(&Id::Name(account_id.to_string()), None)
            .await?;
        let account_id = request.account_id()?;
        let mut scoped = request.keystore(keystore);
        let keystore = &mut scoped;
        match request.provider {
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::db::Cache;

    async fn test_proxy() -> IdProviderProxy {
        let settings = HimmelblauConfig::from_test_config(
            "[global]\napp_id=linux\n\
             [tenant.a]\ndefault=true\nidmap_range=200000-300000\noidc_issuer_url=https://a.example\n\
             [tenant.b]\nidmap_range=300001-400000\noidc_issuer_url=https://b.example\n"
        );
        assert!(settings.validate().is_ok());
        let config = Arc::new(Mutex::new(settings.clone()));
        let idmap = Arc::new(Mutex::new(Idmap::new().unwrap()));
        let mut providers = HashMap::new();
        for definition in settings.parse_providers().unwrap() {
            let domain = &definition.domain;
            let state = if definition.label == "a" {
                CacheState::Offline
            } else {
                CacheState::Online
            };
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
            oidc_account_id: None,
            valid: true,
        }
    }

    #[tokio::test]
    async fn routes_labels_cached_tokens_and_numeric_ids() {
        let proxy = test_proxy().await;
        let a = proxy.find_provider("alice@a").await.unwrap();
        let b = proxy.find_provider("bob@b").await.unwrap();
        assert!(!std::ptr::eq(a, b));
        for account in ["alice", "alice@A"] {
            assert!(std::ptr::eq(a, proxy.find_provider(account).await.unwrap()));
        }
        let mut cached = token("bob@b.example");
        cached.tenant_id = proxy
            .settings
            .provider_for_account("bob@b")
            .unwrap()
            .oidc_tenant_id(&proxy.settings);
        assert!(std::ptr::eq(
            b,
            proxy
                .find_provider_for_id(&Id::Name("wrong@a".to_string()), Some(&cached),)
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
        for account in [
            "alice@unknown.example",
            "alice@a@unknown",
            "alice@b.example",
            "",
        ] {
            assert!(proxy.find_provider(account).await.is_err());
        }
        assert!(proxy.validate_token_provider(a, &cached).await.is_err());
        let mut late = token("alice@late.example");
        late.tenant_id = proxy
            .settings
            .provider_for_account("alice@a")
            .unwrap()
            .oidc_tenant_id(&proxy.settings);
        assert_eq!(
            proxy
                .settings
                .provider_for_gid(late.gidnumber)
                .unwrap()
                .label,
            "b"
        );
        assert_eq!(proxy.provider_for_token(&late).await.unwrap().label, "a");
        assert!(proxy
            .provider_for_token(&token("alice@unknown.example"))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn oidc_request_boundary_keeps_names_and_credentials_provider_scoped() {
        let proxy = test_proxy().await;
        let db = crate::db::Db::new("").unwrap();
        let mut txn = db.write().await;
        txn.migrate().unwrap();
        for (label, gid) in [("a", 200001), ("b", 300001)] {
            let request = proxy
                .prepare_request(&Id::Name(format!("alice@example.org@{label}")), None)
                .await
                .unwrap();
            assert_eq!(request.account_id().unwrap(), "alice@example.org");
            let mut native = token("alice@example.org");
            native.uuid = uuid::Uuid::new_v5(&request.tenant_id.unwrap(), b"subject");
            native.tenant_id = request.tenant_id;
            native.gidnumber = gid;
            native.groups = vec![GroupToken {
                name: native.name.clone(),
                spn: native.spn.clone(),
                uuid: native.uuid,
                gidnumber: gid,
            }];
            let uuid = native.uuid;
            request.localize(&mut native).unwrap();
            assert_eq!(native.spn, format!("alice@example.org@{label}"));
            assert_eq!(native.name, native.spn);
            assert_eq!(native.groups[0].name, native.spn);
            assert_eq!(native.oidc_account_id.as_deref(), Some("alice@example.org"));
            assert_eq!(native.uuid, uuid);
            assert_eq!(native.gidnumber, gid);
            txn.update_group(&native.groups[0], 123).unwrap();
            txn.update_account(&native, 123).unwrap();
            request
                .keystore(&mut txn)
                .insert_tagged_hsm_key("alice@example.org/hello_totp", &label)
                .unwrap();
            let refreshed = proxy
                .prepare_request(&Id::Name(native.spn.clone()), Some(&native))
                .await
                .unwrap();
            assert_eq!(refreshed.account_id().unwrap(), "alice@example.org");
            assert_eq!(refreshed.token.as_ref().unwrap().spn, "alice@example.org");
            assert_eq!(
                refreshed.token.as_ref().unwrap().groups[0].spn,
                "alice@example.org"
            );
            assert!(refreshed.token.as_ref().unwrap().oidc_account_id.is_none());
            let mut wrong_issuer = token("alice@example.org");
            wrong_issuer.tenant_id = Some(uuid::Uuid::nil());
            assert!(request.localize(&mut wrong_issuer).is_err());
        }
        assert_eq!(txn.get_accounts().unwrap().len(), 2);
        assert!(txn
            .get_tagged_hsm_key::<String>("alice@example.org/hello_totp")
            .unwrap()
            .is_none());
        for label in ["a", "b"] {
            let request = proxy
                .prepare_request(&Id::Name(format!("alice@example.org@{label}")), None)
                .await
                .unwrap();
            assert_eq!(
                request
                    .keystore(&mut txn)
                    .get_tagged_hsm_key::<String>("alice@example.org/hello_totp")
                    .unwrap()
                    .as_deref(),
                Some(label)
            );
        }
    }

    #[tokio::test]
    async fn oidc_migration_and_label_rename_preserve_identity_credentials_and_expiry() {
        use tpm::provider::Tpm;

        let proxy = test_proxy().await;
        let request = proxy
            .prepare_request(&Id::Name("alice@example.org@b".into()), None)
            .await
            .unwrap();
        let db = crate::db::Db::new("").unwrap();
        let mut txn = db.write().await;
        txn.migrate().unwrap();
        let mut native = token("alice@example.org");
        native.uuid = uuid::Uuid::new_v4();
        native.tenant_id = request.tenant_id;
        txn.update_account(&native, 456).unwrap();
        let mut hsm = tpm::provider::BoxedDynTpm::new(tpm::provider::SoftTpm::new());
        let auth = tpm::AuthValue::ephemeral().unwrap();
        let loadable = hsm.root_storage_key_create(&auth).unwrap();
        let machine = hsm.root_storage_key_load(&auth, &loadable).unwrap();
        let loadable_hmac = hsm.hmac_s256_create(&machine).unwrap();
        let hmac = hsm.hmac_s256_load(&machine, &loadable_hmac).unwrap();
        txn.update_account_password(native.uuid, "cached-password", &mut hsm, &hmac)
            .unwrap();
        txn.insert_tagged_hsm_key("alice@example.org/hello_refresh_token", &"sealed")
            .unwrap();
        migrate_oidc_accounts(&proxy.settings, &mut txn).unwrap();
        let (migrated, expiry) = txn
            .get_account(&Id::Name("alice@example.org@b".into()))
            .unwrap()
            .unwrap();
        assert_eq!(expiry, 456);
        assert_eq!(migrated.uuid, native.uuid);
        assert_eq!(migrated.gidnumber, native.gidnumber);
        assert!(txn
            .get_tagged_hsm_key::<String>("alice@example.org/hello_refresh_token")
            .unwrap()
            .is_none());
        assert_eq!(
            request
                .keystore(&mut txn)
                .get_tagged_hsm_key::<String>("alice@example.org/hello_refresh_token")
                .unwrap()
                .as_deref(),
            Some("sealed")
        );
        let renamed = HimmelblauConfig::from_test_config(
            "[global]\napp_id=linux\n[tenant.renamed]\n\
             oidc_issuer_url=https://b.example\nidmap_range=300001-400000\n",
        );
        migrate_oidc_accounts(&renamed, &mut txn).unwrap();
        migrate_oidc_accounts(&renamed, &mut txn).unwrap();
        let (renamed_token, expiry) = txn
            .get_account(&Id::Name("alice@example.org@renamed".into()))
            .unwrap()
            .unwrap();
        assert_eq!(renamed_token.uuid, native.uuid);
        assert_eq!(
            renamed_token.oidc_account_id.as_deref(),
            Some("alice@example.org")
        );
        assert_eq!(expiry, 456);
        assert!(txn.get_account(&Id::Name(migrated.spn)).unwrap().is_none());
        assert!(txn
            .check_account_password(native.uuid, "cached-password", &mut hsm, &hmac)
            .unwrap());
        assert_eq!(
            request
                .keystore(&mut txn)
                .get_tagged_hsm_key::<String>("alice@example.org/hello_refresh_token")
                .unwrap()
                .as_deref(),
            Some("sealed")
        );
    }

    #[tokio::test]
    async fn credential_migration_and_cross_provider_account_collisions_fail_closed() {
        let proxy = test_proxy().await;
        let request = proxy
            .prepare_request(&Id::Name("alice@b".into()), None)
            .await
            .unwrap();
        let db = crate::db::Db::new("").unwrap();
        let mut txn = db.write().await;
        txn.migrate().unwrap();
        let mut cached = token("alice");
        cached.tenant_id = request.tenant_id;
        txn.update_account(&cached, 123).unwrap();
        txn.insert_tagged_hsm_key("alice/hello_decoupled", &"old")
            .unwrap();
        request
            .keystore(&mut txn)
            .insert_tagged_hsm_key("alice/hello_decoupled", &"existing")
            .unwrap();
        assert!(matches!(
            migrate_oidc_accounts(&proxy.settings, &mut txn),
            Err(CacheError::TooManyResults)
        ));
        assert!(txn
            .get_account(&Id::Name("alice".into()))
            .unwrap()
            .is_some());
        assert_eq!(
            txn.get_tagged_hsm_key::<String>("alice/hello_decoupled")
                .unwrap()
                .as_deref(),
            Some("old")
        );
        let mut other = cached.clone();
        other.uuid = uuid::Uuid::new_v4();
        other.tenant_id = Some(uuid::Uuid::new_v4());
        assert!(matches!(
            txn.update_account(&other, 456),
            Err(CacheError::TooManyResults)
        ));
        assert_eq!(txn.get_accounts().unwrap()[0].uuid, cached.uuid);
    }

    #[tokio::test]
    async fn a_colliding_runtime_alias_cannot_select_or_discover_a_provider() {
        let proxy = entra_proxy().await;
        let mut config = proxy.config.lock().await;
        let a = config.provider_for_domain("a.example").unwrap();
        assert!(!config.record_domain_alias(&a, "b"));
        config.set("a.example", "domain_aliases", "b.example,b");
        drop(config);
        for account in ["alice@b", "alice@b.example"] {
            assert!(
                tokio::time::timeout(Duration::from_secs(1), proxy.find_provider(account))
                    .await
                    .unwrap()
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn offline_or_failed_provider_does_not_redirect_or_disable_another() {
        let mut proxy = test_proxy().await;
        assert!(matches!(
            proxy.get_cachestate(Some("alice")).await,
            CacheState::Offline
        ));
        assert!(matches!(
            proxy.get_cachestate(Some("bob@b")).await,
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
                .check_online_for_account("bob@b", &mut tpm, SystemTime::now())
                .await
        );
        proxy
            .providers
            .remove(&proxy.settings.default_provider().unwrap().domain);
        assert!(proxy.find_provider("alice").await.is_err());
        assert!(proxy.find_provider("bob@b").await.is_ok());
    }

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

    #[tokio::test]
    async fn cached_entra_token_ownership_uses_live_discovered_aliases() {
        let proxy = entra_proxy().await;
        proxy
            .config
            .lock()
            .await
            .set("a.example", "domain_aliases", "discovered.example");
        assert!(proxy
            .settings
            .provider_for_account("alice@discovered.example")
            .is_none());
        let cached = token("alice@discovered.example");
        assert_eq!(
            proxy
                .settings
                .provider_for_gid(cached.gidnumber)
                .unwrap()
                .label,
            "b"
        );
        assert_eq!(proxy.provider_for_token(&cached).await.unwrap().label, "a");
        let provider = proxy
            .find_provider_for_id(&Id::Gid(cached.gidnumber), Some(&cached))
            .await
            .unwrap();
        assert!(std::ptr::eq(
            provider,
            proxy
                .find_provider("alice@discovered.example")
                .await
                .unwrap()
        ));
    }

    #[tokio::test]
    async fn prt_roundtrip_keeps_all_configured_entra_domains() {
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
