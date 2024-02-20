use super::interface::{
    AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, GroupToken, Id, IdProvider,
    IdpError, UserToken,
};
use crate::config::split_username;
use crate::config::HimmelblauConfig;
use crate::db::KeyStoreTxn;
use crate::idprovider::interface::tpm;
use crate::unix_proto::{DeviceAuthorizationResponse, PamAuthRequest};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use graph::user::{request_user_groups, DirectoryObject};
use himmelblau_policies::policies::apply_group_policy;
use kanidm_hsm_crypto::{LoadableIdentityKey, LoadableMsOapxbcRsaKey, SealedData};
use msal::auth::{
    BrokerClientApplication, DeviceAuthorizationResponse as msal_DeviceAuthorizationResponse,
    EnrollAttrs, UserToken as UnixUserToken,
};
use msal::error::{MsalError, AUTH_PENDING, NO_CONSENT, NO_GROUP_CONSENT, REQUIRES_MFA};
use reqwest;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::time::SystemTime;
use tokio::sync::RwLock;
use uuid::Uuid;

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

async fn gen_unique_account_uid(
    rconfig: &Arc<RwLock<HimmelblauConfig>>,
    domain: &str,
    oid: &str,
) -> u32 {
    let config = rconfig.read();
    let mut hash = DefaultHasher::new();
    oid.hash(&mut hash);
    let seed = hash.finish();
    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    let (min, max): (u32, u32) = config.await.get_idmap_range(domain);
    rng.gen_range(min..=max)
}

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

        let mut providers = HashMap::new();
        let cfg = config.read().await;
        for domain in cfg.get_configured_domains() {
            debug!("Adding provider for domain {}", domain);
            let (authority_host, tenant_id, graph) =
                match cfg.get_tenant_id_authority_and_graph(&domain).await {
                    Ok(res) => res,
                    Err(e) => return Err(anyhow!("{}", e)),
                };
            let authority_url = format!("https://{}/{}", authority_host, tenant_id);
            let app = BrokerClientApplication::new(Some(authority_url.as_str()), None, None);
            let provider =
                HimmelblauProvider::new(app, &config, &tenant_id, &domain, &authority_host, &graph);
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

    async fn unix_user_get(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> Result<UserToken, IdpError> {
        /* AAD doesn't permit user listing (must use cache entries from auth) */
        let account_id = id.to_string().clone();
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

    async fn unix_user_online_auth_init(
        &self,
        account_id: &str,
        token: Option<&UserToken>,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        match split_username(account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match providers.get(domain) {
                    Some(provider) => {
                        provider
                            .unix_user_online_auth_init(account_id, token, tpm, machine_key)
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

    async fn unix_user_offline_auth_init(
        &self,
        account_id: &str,
        token: Option<&UserToken>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        match split_username(account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match providers.get(domain) {
                    Some(provider) => {
                        provider
                            .unix_user_offline_auth_init(account_id, token)
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
    graph_url: String,
    refresh_cache: RefreshCache,
}

impl HimmelblauProvider {
    pub fn new(
        client: BrokerClientApplication,
        config: &Arc<RwLock<HimmelblauConfig>>,
        tenant_id: &str,
        domain: &str,
        authority_host: &str,
        graph_url: &str,
    ) -> Self {
        HimmelblauProvider {
            client: RwLock::new(client),
            config: config.clone(),
            tenant_id: tenant_id.to_string(),
            domain: domain.to_string(),
            authority_host: authority_host.to_string(),
            graph_url: graph_url.to_string(),
            refresh_cache: RefreshCache::new(),
        }
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

    async fn unix_user_get(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> Result<UserToken, IdpError> {
        /* Use the prt mem cache to refresh the user token */
        let account_id = id.to_string().clone();
        let prt = self.refresh_cache.refresh_token(&account_id).await?;
        let scopes = vec!["GroupMember.Read.All"];
        let token = match self
            .client
            .write()
            .await
            .exchange_prt_for_access_token(&prt, scopes, tpm, machine_key, None)
            .await
        {
            Ok(token) => token,
            Err(MsalError::AcquireTokenFailed(resp)) => {
                // We may have been denied GroupMember.Read.All, try again without it
                if resp.error_codes.contains(&NO_GROUP_CONSENT)
                    || resp.error_codes.contains(&NO_CONSENT)
                {
                    debug!("Failed auth with GroupMember.Read.All permissions.");
                    debug!("Group memberships will be missing display names.");
                    debug!("{}: {}", resp.error, resp.error_description);
                    match self
                        .client
                        .write()
                        .await
                        .exchange_prt_for_access_token(&prt, vec![], tpm, machine_key, None)
                        .await
                    {
                        Ok(token) => token,
                        Err(_e) => return Err(IdpError::NotFound),
                    }
                } else {
                    return Err(IdpError::NotFound);
                }
            }
            Err(_e) => return Err(IdpError::NotFound),
        };
        match self.token_validate(&account_id, &token).await {
            Ok(AuthResult::Success { mut token }) => {
                /* Set the GECOS from the old_token, since MS doesn't
                 * provide this during a silent acquire
                 */
                if let Some(old_token) = old_token {
                    token.displayname = old_token.displayname.clone()
                }
                Ok(token)
            }
            Ok(AuthResult::Denied) | Ok(AuthResult::Next(_)) => Err(IdpError::NotFound),
            Err(e) => Err(e),
        }
    }

    async fn unix_user_online_auth_init(
        &self,
        _account_id: &str,
        _token: Option<&UserToken>,
        _tpm: &mut tpm::BoxedDynTpm,
        _machine_key: &tpm::MachineKey,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        Ok((AuthRequest::Password, AuthCredHandler::Password))
    }

    async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        match (cred_handler, pam_next_req) {
            (AuthCredHandler::Password, PamAuthRequest::Password { cred }) => {
                let mut scopes = vec!["GroupMember.Read.All"];
                if !self.is_domain_joined(keystore).await {
                    let token = match self
                        .client
                        .write()
                        .await
                        .acquire_token_by_username_password_for_device_enrollment(account_id, &cred)
                        .await
                    {
                        Ok(token) => token,
                        Err(MsalError::AcquireTokenFailed(resp)) => {
                            if resp.error_codes.contains(&REQUIRES_MFA) {
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
                                    AuthResult::Next(AuthRequest::DeviceAuthorizationGrant {
                                        data: resp.into(),
                                    }),
                                    /* An MFA auth cannot cache the password. This would
                                     * lead to a potential downgrade to SFA attack (where
                                     * the attacker auths with a stolen password, then
                                     * disconnects the network to complete the auth). */
                                    AuthCacheAction::None,
                                ));
                            } else {
                                error!("Failed to authenticate for domain join: {:?}", resp);
                                return Err(IdpError::BadRequest);
                            }
                        }
                        Err(e) => {
                            error!("Failed to authenticate for domain join: {:?}", e);
                            return Err(IdpError::BadRequest);
                        }
                    };
                    if let Err(e) = self.join_domain(tpm, &token, keystore, machine_key).await {
                        error!("Failed to join domain: {:?}", e);
                        return Err(IdpError::BadRequest);
                    }
                }
                let uutoken = match self
                    .client
                    .write()
                    .await
                    .acquire_token_by_username_password(
                        account_id,
                        &cred,
                        scopes.clone(),
                        tpm,
                        machine_key,
                    )
                    .await
                {
                    Ok(token) => token,
                    Err(MsalError::AcquireTokenFailed(resp)) => {
                        if (resp.error_codes.contains(&NO_GROUP_CONSENT)
                            || resp.error_codes.contains(&NO_CONSENT))
                            && scopes.contains(&"GroupMember.Read.All")
                        {
                            // We may have been denied GroupMember.Read.All, try again without it
                            debug!("Failed auth with GroupMember.Read.All permissions.");
                            debug!("Group memberships will be missing display names.");
                            debug!("{}: {}", resp.error, resp.error_description);

                            scopes.retain(|&s| s != "GroupMember.Read.All");
                            self.client
                                .write()
                                .await
                                .acquire_token_by_username_password(
                                    account_id,
                                    &cred,
                                    scopes,
                                    tpm,
                                    machine_key,
                                )
                                .await
                                .map_err(|e| {
                                    error!("{:?}", e);
                                    IdpError::NotFound
                                })?
                        } else {
                            error!("{}: {}", resp.error, resp.error_description);
                            return Err(IdpError::NotFound);
                        }
                    }
                    Err(e) => {
                        error!("{:?}", e);
                        return Err(IdpError::NotFound);
                    }
                };
                match self.token_validate(account_id, &uutoken).await {
                    Ok(AuthResult::Success { token }) => Ok((
                        AuthResult::Success { token },
                        AuthCacheAction::PasswordHashUpdate { cred },
                    )),
                    Ok(AuthResult::Next(req)) => {
                        Ok((
                            AuthResult::Next(req),
                            /* An MFA auth cannot cache the password. This would
                             * lead to a potential downgrade to SFA attack (where
                             * the attacker auths with a stolen password, then
                             * disconnects the network to complete the auth). */
                            AuthCacheAction::None,
                        ))
                    }
                    Ok(auth_result) => Ok((auth_result, AuthCacheAction::None)),
                    Err(e) => Err(e),
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
                let mut uutoken = mtoken.map_err(|e| {
                    error!("{:?}", e);
                    IdpError::NotFound
                })?;
                if !self.is_domain_joined(keystore).await {
                    self.join_domain(tpm, &uutoken, keystore, machine_key)
                        .await
                        .map_err(|e| {
                            error!("Failed to join domain: {:?}", e);
                            IdpError::BadRequest
                        })?;
                }
                uutoken = self
                    .client
                    .write()
                    .await
                    .acquire_token_by_refresh_token(
                        &uutoken.refresh_token,
                        vec![],
                        tpm,
                        machine_key,
                    )
                    .await
                    .map_err(|e| {
                        error!("{:?}", e);
                        IdpError::NotFound
                    })?;
                match self.token_validate(account_id, &uutoken).await {
                    Ok(AuthResult::Success { token }) => {
                        Ok((AuthResult::Success { token }, AuthCacheAction::None))
                    }
                    Ok(auth_result) => Ok((auth_result, AuthCacheAction::None)),
                    Err(e) => Err(e),
                }
            }
            _ => Err(IdpError::NotFound),
        }
    }

    async fn unix_user_offline_auth_init(
        &self,
        _account_id: &str,
        _token: Option<&UserToken>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        /* If we are offline, then just perform a password auth */
        Ok((AuthRequest::Password, AuthCredHandler::Password))
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
                /* Process Group Policy (spawn non-blocking process to prevent auth timeout),
                 * if it is enabled via config */
                if self.config.read().await.get_apply_policy() {
                    let graph_url = self.graph_url.clone();
                    let access_token = match token.access_token.as_ref() {
                        Some(access_token) => access_token.clone(),
                        None => return Err(IdpError::BadRequest),
                    };
                    let uuid = token
                        .uuid()
                        .map_err(|e| {
                            error!("Failed fetching user uuid: {:?}", e);
                            IdpError::BadRequest
                        })?
                        .to_string();
                    tokio::spawn(async move {
                        match apply_group_policy(&graph_url, &access_token, &uuid).await {
                            Ok(res) => {
                                if res {
                                    info!("Successfully applied group policies");
                                } else {
                                    error!("Failed to apply group policies");
                                }
                            }
                            Err(res) => {
                                error!("Failed to apply group policies: {}", res);
                            }
                        }
                    });
                }
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
        let config = self.config.read();
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
                groups = match request_user_groups(&self.graph_url, access_token).await {
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
        let sshkeys: Vec<String> = vec![];
        let valid = true;
        let gidnumber = gen_unique_account_uid(&self.config, &self.domain, &uuid.to_string()).await;
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
            shell: Some(config.await.get_shell(Some(&self.domain))),
            groups,
            sshkeys,
            valid,
        })
    }

    async fn group_token_from_directory_object(
        &self,
        value: DirectoryObject,
    ) -> Result<GroupToken> {
        let name = match value.get("display_name") {
            Some(name) => name,
            None => return Err(anyhow!("Failed retrieving group display_name")),
        };
        let id = match value.get("id") {
            Some(id) => id,
            None => return Err(anyhow!("Failed retrieving group uuid")),
        };
        let gidnumber = gen_unique_account_uid(&self.config, &self.domain, id).await;
        Ok(GroupToken {
            name: name.clone(),
            spn: name.to_string(),
            uuid: match Uuid::parse_str(id) {
                Ok(uuid) => uuid,
                Err(e) => return Err(anyhow!("Failed parsing user uuid: {}", e)),
            },
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
        return match self
            .client
            .write()
            .await
            .enroll_device(token, attrs, tpm, machine_key)
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
                config.set(&self.domain, "graph", &self.graph_url);
                debug!(
                    "Setting domain {} config graph to {}",
                    self.domain, &self.graph_url
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
                let mut allow_groups = match config.get(&self.domain, "pam_allow_groups") {
                    Some(allowed) => allowed.split(',').map(|g| g.to_string()).collect(),
                    None => vec![],
                };
                allow_groups.push(token.spn()?.clone());
                /* Remove duplicates from the allow_groups */
                allow_groups.sort();
                allow_groups.dedup();
                config.set(&self.domain, "pam_allow_groups", &allow_groups.join(","));
                debug!(
                    "Setting global pam_allow_groups to {}",
                    &allow_groups.join(",")
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
        };
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
