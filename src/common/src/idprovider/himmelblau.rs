use super::interface::{
    AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, GroupToken, Id, IdProvider,
    IdpError, UserToken,
};
use crate::config::split_username;
use crate::config::HimmelblauConfig;
use crate::config::IdAttr;
use crate::db::KeyStoreTxn;
use crate::idprovider::interface::tpm;
use crate::unix_proto::{DeviceAuthorizationResponse, PamAuthRequest};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use himmelblau::auth::{
    BrokerClientApplication, ClientInfo,
    DeviceAuthorizationResponse as msal_DeviceAuthorizationResponse, IdToken, MFAAuthContinue,
    UserToken as UnixUserToken,
};
use himmelblau::discovery::EnrollAttrs;
use himmelblau::error::{ErrorResponse, MsalError, AUTH_PENDING, DEVICE_AUTH_FAIL, REQUIRES_MFA};
use himmelblau::graph::{DirectoryObject, Graph};
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
            let graph = Graph::new(&cfg.get_odc_provider(&domain), &domain)
                .await
                .map_err(|e| anyhow!("{:?}", e))?;
            let authority_host = graph.authority_host();
            let tenant_id = graph.tenant_id();
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
            providers: RwLock::new(providers),
        })
    }
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
                match providers.get(domain) {
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
                match providers.get(domain) {
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
                match providers.get(domain) {
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
                match providers.get(domain) {
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
                match providers.get(domain) {
                    Some(provider) => {
                        provider
                            .unix_user_online_auth_step(
                                account_id,
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

impl From<msal_DeviceAuthorizationResponse> for DeviceAuthorizationResponse {
    fn from(src: msal_DeviceAuthorizationResponse) -> Self {
        Self {
            device_code: src.device_code.clone(),
            user_code: src.user_code.clone(),
            verification_uri: src.verification_uri.clone(),
            verification_uri_complete: src.verification_uri_complete.clone(),
            expires_in: src.expires_in,
            interval: src.interval,
            message: src.message.clone(),
        }
    }
}

impl From<DeviceAuthorizationResponse> for msal_DeviceAuthorizationResponse {
    fn from(src: DeviceAuthorizationResponse) -> Self {
        Self {
            device_code: src.device_code,
            user_code: src.user_code,
            verification_uri: src.verification_uri,
            verification_uri_complete: src.verification_uri_complete,
            expires_in: src.expires_in,
            interval: src.interval,
            message: src.message,
        }
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
                            let groups = vec![GroupToken {
                                name: account_id.clone(),
                                spn: account_id.clone(),
                                uuid: Uuid::max(),
                                gidnumber,
                            }];
                            let config = self.config.read().await;
                            return Ok(UserToken {
                                name: account_id.clone(),
                                spn: account_id.clone(),
                                uuid: Uuid::new_v4(),
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
                vec!["User.Read"],
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
            Ok((AuthRequest::Password, AuthCredHandler::Password))
        } else {
            Ok((AuthRequest::Pin, AuthCredHandler::Pin))
        }
    }

    async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
        shutdown_rx: &broadcast::Receiver<()>,
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
                        vec!["User.Read"],
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
                                            vec!["User.Read"],
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
                        vec!["User.Read"],
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
        let mut shutdown_rx_cl = shutdown_rx.resubscribe();
        match (&cred_handler, pam_next_req) {
            (AuthCredHandler::MFA { data }, PamAuthRequest::SetupPin { pin }) => {
                let hello_tag = self.fetch_hello_key_tag(account_id);
                let token: Token = serde_json::from_str(data).map_err(|e| {
                    error!("{:?}", e);
                    IdpError::BadRequest
                })?;
                let token = UnixUserToken {
                    token_type: "".to_string(),
                    scope: None,
                    expires_in: 0,
                    ext_expires_in: 0,
                    access_token: token.0,
                    refresh_token: token.1,
                    id_token: IdToken::default(),
                    client_info: ClientInfo::default(),
                    prt: None,
                };

                let hello_key = match self
                    .client
                    .write()
                    .await
                    .provision_hello_for_business_key(&token, tpm, machine_key, &pin)
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
            (AuthCredHandler::Pin, PamAuthRequest::Pin { cred }) => {
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
            (AuthCredHandler::Password, PamAuthRequest::Password { cred }) => {
                // Always attempt to force MFA when enrolling the device, otherwise
                // the device object will not have the MFA claim. If we are already
                // enrolled but creating a new Hello Pin, we follow the same process,
                // since only an enrollment token can be exchanged for a PRT (which
                // will be needed to enroll the Hello Pin).
                let mresp = self
                    .client
                    .write()
                    .await
                    .initiate_acquire_token_by_mfa_flow_for_device_enrollment(account_id, &cred)
                    .await;
                // We need to wait to handle the response until after we've released
                // the write lock on the client, otherwise we will deadlock.
                let resp = match mresp {
                    Ok(resp) => resp,
                    Err(e) => {
                        // If SFA is disabled, we need to skip the SFA fallback.
                        let sfa_enabled = self.config.read().await.get_enable_sfa_fallback();
                        let mtoken = match sfa_enabled {
                            true => {
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
                            }
                            // If SFA fallback is disabled, set mtoken to an
                            // MsalError in order to permit DAG fallback. If
                            // the DAG produces SFA, it will be rejected also.
                            false => {
                                error!("{:?}", e);
                                Err(MsalError::AcquireTokenFailed(ErrorResponse {
                                    error: "SFA Disabled".to_string(),
                                    error_description: "SFA fallback is disabled by configuration"
                                        .to_string(),
                                    error_codes: vec![REQUIRES_MFA],
                                }))
                            }
                        };
                        let token = match mtoken {
                            Ok(token) => token,
                            Err(e) => {
                                error!("{:?}", e);
                                match e {
                                    MsalError::AcquireTokenFailed(err_resp) => {
                                        if err_resp.error_codes.contains(&REQUIRES_MFA) {
                                            warn!(
                                                "SFA auth failed, falling back to DAG: {}",
                                                err_resp.error_description
                                            );
                                            // We've exhausted alternatives, and must perform a DAG
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
                                            return Ok((
                                                AuthResult::Next(
                                                    AuthRequest::DeviceAuthorizationGrant {
                                                        data: resp.into(),
                                                    },
                                                ),
                                                /* An MFA auth cannot cache the password. This would
                                                 * lead to a potential downgrade to SFA attack (where
                                                 * the attacker auths with a stolen password, then
                                                 * disconnects the network to complete the auth). */
                                                AuthCacheAction::None,
                                            ));
                                        }
                                        return Err(IdpError::BadRequest);
                                    }
                                    _ => return Err(IdpError::BadRequest),
                                }
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
                    "PhoneAppOTP" | "OneWaySMS" | "ConsolidatedTelephony" => {
                        let msg = resp.msg.clone();
                        *cred_handler = AuthCredHandler::MFA {
                            data: serde_json::to_string(&resp).map_err(|e| {
                                error!("{:?}", e);
                                IdpError::BadRequest
                            })?,
                        };
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
                        *cred_handler = AuthCredHandler::MFA {
                            data: serde_json::to_string(&resp).map_err(|e| {
                                error!("{:?}", e);
                                IdpError::BadRequest
                            })?,
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
                }
            }
            (_, PamAuthRequest::DeviceAuthorizationGrant { data }) => {
                let sleep_interval: u64 = match data.interval.as_ref() {
                    Some(val) => *val as u64,
                    None => 5,
                };
                let mut mtoken = self
                    .client
                    .write()
                    .await
                    .acquire_token_by_device_flow(data.clone().into())
                    .await;
                while let Err(MsalError::AcquireTokenFailed(ref resp)) = mtoken {
                    if resp.error_codes.contains(&AUTH_PENDING) {
                        debug!("Polling for acquire_token_by_device_flow");
                        sleep(Duration::from_secs(sleep_interval));
                        mtoken = self
                            .client
                            .write()
                            .await
                            .acquire_token_by_device_flow(data.clone().into())
                            .await;
                    } else {
                        break;
                    }
                }
                let token = mtoken.map_err(|e| {
                    error!("{:?}", e);
                    IdpError::NotFound
                })?;
                let token2 = enroll_and_obtain_enrolled_token!(token);
                match self.token_validate(account_id, &token2).await {
                    Ok(AuthResult::Success { token: token3 }) => {
                        let mfa = token2.amr_mfa().map_err(|e| {
                            error!("{:?}", e);
                            IdpError::NotFound
                        })?;
                        // If the DAG didn't obtain an MFA amr, and SFA fallback
                        // is disabled, we need to reject the authentication
                        // attempt here.
                        let sfa_enabled = self.config.read().await.get_enable_sfa_fallback();
                        if !mfa && !sfa_enabled {
                            info!("A DAG produced an SFA token, yet SFA fallback is disabled by configuration");
                            return Ok((AuthResult::Denied, AuthCacheAction::None));
                        }
                        // STOP! If the DAG doesn't hold an MFA amr, then we
                        // need to bail out here and refuse Hello enrollment
                        // (we can't enroll in Hello with an SFA token).
                        // Also skip Hello enrollment if it is disabled by config
                        let hello_enabled = self.config.read().await.get_enable_hello();
                        if !mfa || !hello_enabled {
                            if !mfa {
                                info!("Skipping Hello enrollment because the token doesn't contain an MFA amr");
                            } else if !hello_enabled {
                                info!("Skipping Hello enrollment because it is disabled");
                            }
                            return Ok((
                                AuthResult::Success { token: token3 },
                                AuthCacheAction::None,
                            ));
                        }

                        // Setup Windows Hello
                        *cred_handler = AuthCredHandler::MFA {
                            data: serde_json::to_string(&Token(
                                token.access_token.clone(),
                                token.refresh_token.to_string(),
                            ))
                            .map_err(|e| {
                                error!("{:?}", e);
                                IdpError::BadRequest
                            })?,
                        };
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
            (AuthCredHandler::MFA { data }, PamAuthRequest::MFACode { cred }) => {
                let mut flow: MFAAuthContinue = serde_json::from_str(data).map_err(|e| {
                    error!("{:?}", e);
                    IdpError::BadRequest
                })?;
                let token = self
                    .client
                    .write()
                    .await
                    .acquire_token_by_mfa_flow(account_id, Some(&cred), None, &mut flow)
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
                        *cred_handler = AuthCredHandler::MFA {
                            data: serde_json::to_string(&Token(
                                token.access_token.clone(),
                                token.refresh_token.to_string(),
                            ))
                            .map_err(|e| {
                                error!("{:?}", e);
                                IdpError::BadRequest
                            })?,
                        };
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
            (AuthCredHandler::MFA { data }, PamAuthRequest::MFAPoll) => {
                let mut flow: MFAAuthContinue = serde_json::from_str(data).map_err(|e| {
                    error!("{:?}", e);
                    IdpError::BadRequest
                })?;
                let max_poll_attempts = flow.max_poll_attempts.ok_or_else(|| {
                    error!("Invalid response from the server");
                    IdpError::BadRequest
                })?;
                let polling_interval = flow.polling_interval.ok_or_else(|| {
                    error!("Invalid response from the server");
                    IdpError::BadRequest
                })?;
                let mut poll_attempt = 1;
                let token = loop {
                    if poll_attempt > max_poll_attempts {
                        error!("MFA polling timed out");
                        return Err(IdpError::BadRequest);
                    }
                    if shutdown_rx_cl.try_recv().ok().is_some() {
                        debug!("Received a signal to shutdown, bailing MFA poll");
                        return Err(IdpError::BadRequest);
                    }
                    sleep(Duration::from_millis(polling_interval.into()));
                    match self
                        .client
                        .write()
                        .await
                        .acquire_token_by_mfa_flow(account_id, None, Some(poll_attempt), &mut flow)
                        .await
                    {
                        Ok(token) => break token,
                        Err(e) => match e {
                            MsalError::MFAPollContinue => {
                                poll_attempt += 1;
                                continue;
                            }
                            e => {
                                error!("{:?}", e);
                                return Err(IdpError::NotFound);
                            }
                        },
                    }
                };
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
                        *cred_handler = AuthCredHandler::MFA {
                            data: serde_json::to_string(&Token(
                                token.access_token.clone(),
                                token.refresh_token.to_string(),
                            ))
                            .map_err(|e| {
                                error!("{:?}", e);
                                IdpError::BadRequest
                            })?,
                        };
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
            Ok((AuthRequest::Password, AuthCredHandler::Password))
        } else {
            Ok((AuthRequest::Pin, AuthCredHandler::Pin))
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
            (AuthCredHandler::Pin, PamAuthRequest::Pin { cred }) => {
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
