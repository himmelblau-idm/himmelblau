use super::interface::{
    AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, GroupToken, Id, IdProvider,
    IdpError, UserToken,
};
use crate::config::split_username;
use crate::config::HimmelblauConfig;
use crate::constants::DRS_APP_ID;
use crate::db::KeyStoreTxn;
use crate::idprovider::interface::tpm;
use crate::unix_proto::{DeviceAuthorizationResponse, PamAuthRequest};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use himmelblau_policies::policies::apply_group_policy;
use kanidm_hsm_crypto::{KeyAlgorithm, Tpm};
use msal::auth::{ClientApplication as ConfidentialClientApplication, Credentials};
use msal::constants::BROKER_APP_ID;
use msal::enroll::register_device;
use msal::py_auth::DeviceAuthorizationResponse as msal_DeviceAuthorizationResponse;
use msal::py_auth::{
    ClientApplication, PublicClientApplication, UnixUserToken, AUTH_PENDING, NO_CONSENT,
    NO_GROUP_CONSENT, NO_SECRET, REQUIRES_MFA,
};
use msal::user::{request_user_groups, DirectoryObject};
use reqwest;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
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

impl HimmelblauMultiProvider {
    pub async fn new(config_filename: &str) -> Result<Self> {
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
            let app_id = cfg.get_app_id(&domain);
            let app = match PublicClientApplication::new(&app_id, authority_url.as_str(), None) {
                Ok(app) => app,
                Err(e) => return Err(anyhow!("{}", e)),
            };
            providers.insert(
                domain.to_string(),
                HimmelblauProvider::new(
                    app,
                    &config,
                    &tenant_id,
                    &domain,
                    &authority_url,
                    &authority_host,
                    &graph,
                    &app_id,
                ),
            );
        }

        Ok(HimmelblauMultiProvider {
            providers: RwLock::new(providers),
        })
    }
}

#[async_trait]
impl IdProvider for HimmelblauMultiProvider {
    async fn configure_hsm_keys<D: KeyStoreTxn + Send>(
        &self,
        keystore: &mut D,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> Result<(), IdpError> {
        for (_domain, provider) in self.providers.read().await.iter() {
            match provider
                .configure_hsm_keys(keystore, tpm, machine_key)
                .await
            {
                Ok(()) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

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
    ) -> Result<UserToken, IdpError> {
        /* AAD doesn't permit user listing (must use cache entries from auth) */
        let account_id = id.to_string().clone();
        match split_username(&account_id) {
            Some((_sam, domain)) => {
                let providers = self.providers.read().await;
                match providers.get(domain) {
                    Some(provider) => provider.unix_user_get(id, old_token, tpm).await,
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
    client: RwLock<PublicClientApplication>,
    config: Arc<RwLock<HimmelblauConfig>>,
    tenant_id: String,
    domain: String,
    authority_url: String,
    authority_host: String,
    graph_url: String,
    app_id: String,
}

impl HimmelblauProvider {
    pub fn new(
        client: PublicClientApplication,
        config: &Arc<RwLock<HimmelblauConfig>>,
        tenant_id: &str,
        domain: &str,
        authority_url: &str,
        authority_host: &str,
        graph_url: &str,
        app_id: &str,
    ) -> Self {
        HimmelblauProvider {
            client: RwLock::new(client),
            config: config.clone(),
            tenant_id: tenant_id.to_string(),
            domain: domain.to_string(),
            authority_url: authority_url.to_string(),
            authority_host: authority_host.to_string(),
            graph_url: graph_url.to_string(),
            app_id: app_id.to_string(),
        }
    }
}

impl From<msal_DeviceAuthorizationResponse> for DeviceAuthorizationResponse {
    fn from(src: msal_DeviceAuthorizationResponse) -> Self {
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
    async fn configure_hsm_keys<D: KeyStoreTxn + Send>(
        &self,
        keystore: &mut D,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> Result<(), IdpError> {
        let csr_tag = format!("{}/certificate", self.domain);
        let id_key: Option<tpm::LoadableIdentityKey> =
            keystore.get_tagged_hsm_key(&csr_tag).map_err(|ks_err| {
                error!(?ks_err);
                IdpError::KeyStore
            })?;

        if id_key.is_none() {
            let loadable_id_key = tpm
                .identity_key_create(machine_key, KeyAlgorithm::Rsa2048)
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    IdpError::Tpm
                })?;

            keystore
                .insert_tagged_hsm_key(&csr_tag, &loadable_id_key)
                .map_err(|ks_err| {
                    error!(?ks_err);
                    IdpError::KeyStore
                })?;
        }

        Ok(())
    }

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
        _tpm: &mut tpm::BoxedDynTpm,
    ) -> Result<UserToken, IdpError> {
        /* Use the msal user cache to refresh the user token */
        let account_id = id.to_string().clone();
        let mut scopes = vec![];
        if self.app_id != BROKER_APP_ID {
            scopes = vec!["GroupMember.Read.All"];
        }
        let mut token = match self
            .client
            .write()
            .await
            .acquire_token_silent(scopes.clone(), &account_id)
        {
            Ok(token) => token,
            Err(_e) => return Err(IdpError::NotFound),
        };
        // We may have been denied GroupMember.Read.All, try again without it
        if (token.errors.contains(&NO_GROUP_CONSENT) || token.errors.contains(&NO_CONSENT))
            && scopes.contains(&"GroupMember.Read.All")
        {
            debug!("Failed auth with GroupMember.Read.All permissions.");
            debug!("Group memberships will be missing display names.");
            debug!("{}: {}", token.error, token.error_description);
            token = match self
                .client
                .write()
                .await
                .acquire_token_silent(vec![], &account_id)
            {
                Ok(token) => token,
                Err(_e) => return Err(IdpError::NotFound),
            };
        }
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
                let mut scopes = vec![];
                if self.app_id != BROKER_APP_ID {
                    scopes.push("GroupMember.Read.All");
                }
                let drs_scope = format!("{}/.default", DRS_APP_ID);
                if !self.is_domain_joined().await {
                    /* If we're authenticating as a Broker, and we're
                     * using a PublicClientApplication, then we need to
                     * perform a domain join. Request access to the DRS
                     * resource (Domain Registration Service). */
                    if self.app_id == BROKER_APP_ID {
                        scopes.push(drs_scope.as_str());
                    }
                }
                let mut uutoken = match self
                    .client
                    .write()
                    .await
                    .acquire_token_by_username_password(account_id, &cred, scopes.clone())
                {
                    Ok(token) => token,
                    Err(_e) => return Err(IdpError::NotFound),
                };
                // We may have been denied GroupMember.Read.All, try again without it
                if (uutoken.errors.contains(&NO_GROUP_CONSENT)
                    || uutoken.errors.contains(&NO_CONSENT))
                    && scopes.contains(&"GroupMember.Read.All")
                {
                    debug!("Failed auth with GroupMember.Read.All permissions.");
                    debug!("Group memberships will be missing display names.");
                    debug!("{}: {}", uutoken.error, uutoken.error_description);

                    scopes.retain(|&s| s != "GroupMember.Read.All");
                    uutoken = match self
                        .client
                        .write()
                        .await
                        .acquire_token_by_username_password(account_id, &cred, scopes)
                    {
                        Ok(token) => token,
                        Err(_e) => return Err(IdpError::NotFound),
                    };
                }
                match self.token_validate(account_id, &uutoken).await {
                    Ok(AuthResult::Success { token }) => {
                        if let Err(e) = self.join_domain(tpm, &uutoken, keystore, machine_key).await
                        {
                            // Invalidate cached creds if PRT req fails
                            if let Err(e) = self.client.write().await.remove_account(account_id) {
                                error!("Removing the account failed: {:?}", e);
                            }
                            error!("Failed to join domain: {:?}", e);
                            return Err(IdpError::BadRequest);
                        } else {
                            /* We switched from Public to Confidential due to a
                             * domain join and now need to obtain a PRT */
                            let capp = match ConfidentialClientApplication::new(
                                &self.tenant_id,
                                &self.authority_host,
                            ) {
                                Ok(capp) => capp,
                                Err(e) => {
                                    // Invalidate cached creds if PRT req fails
                                    if let Err(e) =
                                        self.client.write().await.remove_account(account_id)
                                    {
                                        error!("Removing the account failed: {:?}", e);
                                    }
                                    error!("Failed to initialize ConfidentialClient: {:?}", e);
                                    return Err(IdpError::BadRequest);
                                }
                            };
                            let csr_tag = format!("{}/certificate", self.domain);
                            let loadable_id_key: Option<tpm::LoadableIdentityKey> =
                                match keystore.get_tagged_hsm_key(&csr_tag) {
                                    Ok(loadable_id_key) => loadable_id_key,
                                    Err(e) => {
                                        // Invalidate cached creds if PRT req fails
                                        if let Err(e) =
                                            self.client.write().await.remove_account(account_id)
                                        {
                                            error!("Removing the account failed: {:?}", e);
                                        }
                                        error!("Failed to load LoadableIdentityKey: {:?}", e);
                                        return Err(IdpError::KeyStore);
                                    }
                                };
                            let cert_id_key = match loadable_id_key {
                                Some(loadable_id_key) => {
                                    match tpm.identity_key_load(machine_key, &loadable_id_key) {
                                        Ok(cert_id_key) => cert_id_key,
                                        Err(e) => {
                                            // Invalidate cached creds if PRT req fails
                                            if let Err(e) =
                                                self.client.write().await.remove_account(account_id)
                                            {
                                                error!("Removing the account failed: {:?}", e);
                                            }
                                            error!("Failed to load IdentityKey: {:?}", e);
                                            return Err(IdpError::KeyStore);
                                        }
                                    }
                                }
                                None => {
                                    // Invalidate cached creds if PRT req fails
                                    if let Err(e) =
                                        self.client.write().await.remove_account(account_id)
                                    {
                                        error!("Removing the account failed: {:?}", e);
                                    }
                                    error!("IdentityKey not found");
                                    return Err(IdpError::KeyStore);
                                }
                            };
                            /* For now we do nothing with the PRT, except
                             * verify that we can obtain it. */
                            debug!("Requesting PRT using username/password");
                            if let Err(e) = capp
                                .request_user_prt(
                                    Credentials::UsernamePassword(
                                        account_id.to_string(),
                                        cred.clone(),
                                    ),
                                    tpm,
                                    &cert_id_key,
                                )
                                .await
                            {
                                // Invalidate cached creds if PRT req fails
                                if let Err(e) = self.client.write().await.remove_account(account_id)
                                {
                                    error!("Removing the account failed: {:?}", e);
                                }
                                error!("Failed to request PRT for user on joined device: {:?}", e);
                                return Err(IdpError::BadRequest);
                            }
                        }
                        Ok((
                            AuthResult::Success { token },
                            AuthCacheAction::PasswordHashUpdate { cred },
                        ))
                    }
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
                let mut uutoken = match self
                    .client
                    .write()
                    .await
                    .acquire_token_by_device_flow(data.clone().into())
                {
                    Ok(token) => token,
                    Err(_e) => return Err(IdpError::NotFound),
                };
                while uutoken.errors.contains(&AUTH_PENDING) {
                    debug!("Polling for acquire_token_by_device_flow");
                    sleep(Duration::from_secs(sleep_interval));
                    uutoken = match self
                        .client
                        .write()
                        .await
                        .acquire_token_by_device_flow(data.clone().into())
                    {
                        Ok(token) => token,
                        Err(_e) => return Err(IdpError::NotFound),
                    };
                }
                match self.token_validate(account_id, &uutoken).await {
                    Ok(AuthResult::Success { token }) => {
                        if let Err(e) = self.join_domain(tpm, &uutoken, keystore, machine_key).await
                        {
                            // Invalidate cached creds if PRT req fails
                            if let Err(e) = self.client.write().await.remove_account(account_id) {
                                error!("Removing the account failed: {:?}", e);
                            }
                            error!("Failed to join domain: {:?}", e);
                            return Err(IdpError::BadRequest);
                        } else if let Some(refresh_token) = uutoken.refresh_token {
                            /* We switched from Public to Confidential due to a
                             * domain join and now need to obtain a PRT */
                            let capp = match ConfidentialClientApplication::new(
                                &self.tenant_id,
                                &self.authority_host,
                            ) {
                                Ok(capp) => capp,
                                Err(e) => {
                                    // Invalidate cached creds if PRT req fails
                                    if let Err(e) =
                                        self.client.write().await.remove_account(account_id)
                                    {
                                        error!("Removing the account failed: {:?}", e);
                                    }
                                    error!("Failed to initialize ConfidentialClient: {:?}", e);
                                    return Err(IdpError::BadRequest);
                                }
                            };
                            let csr_tag = format!("{}/certificate", self.domain);
                            let loadable_id_key: Option<tpm::LoadableIdentityKey> =
                                match keystore.get_tagged_hsm_key(&csr_tag) {
                                    Ok(loadable_id_key) => loadable_id_key,
                                    Err(e) => {
                                        // Invalidate cached creds if PRT req fails
                                        if let Err(e) =
                                            self.client.write().await.remove_account(account_id)
                                        {
                                            error!("Removing the account failed: {:?}", e);
                                        }
                                        error!("Failed to load LoadableIdentityKey: {:?}", e);
                                        return Err(IdpError::KeyStore);
                                    }
                                };
                            let cert_id_key = match loadable_id_key {
                                Some(loadable_id_key) => {
                                    match tpm.identity_key_load(machine_key, &loadable_id_key) {
                                        Ok(cert_id_key) => cert_id_key,
                                        Err(e) => {
                                            // Invalidate cached creds if PRT req fails
                                            if let Err(e) =
                                                self.client.write().await.remove_account(account_id)
                                            {
                                                error!("Removing the account failed: {:?}", e);
                                            }
                                            error!("Failed to load IdentityKey: {:?}", e);
                                            return Err(IdpError::KeyStore);
                                        }
                                    }
                                }
                                None => {
                                    // Invalidate cached creds if PRT req fails
                                    if let Err(e) =
                                        self.client.write().await.remove_account(account_id)
                                    {
                                        error!("Removing the account failed: {:?}", e);
                                    }
                                    error!("IdentityKey not found");
                                    return Err(IdpError::KeyStore);
                                }
                            };
                            /* For now we do nothing with the PRT, except
                             * verify that we can obtain it. */
                            debug!("Requesting PRT using refresh token");
                            if let Err(e) = capp
                                .request_user_prt(
                                    Credentials::RefreshToken(refresh_token),
                                    tpm,
                                    &cert_id_key,
                                )
                                .await
                            {
                                // Invalidate cached creds if PRT req fails
                                if let Err(e) = self.client.write().await.remove_account(account_id)
                                {
                                    error!("Removing the account failed: {:?}", e);
                                }
                                error!("Failed to request PRT for user on joined device: {:?}", e);
                                return Err(IdpError::BadRequest);
                            }
                        }
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
                if account_id.to_string().to_lowercase() != token.spn.to_string().to_lowercase() {
                    error!(
                        "Authenticated user {} does not match requested user {}",
                        token.spn, account_id
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
                    let uuid = token.uuid.to_string();
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
                Ok(AuthResult::Success {
                    token: self.user_token_from_unix_user_token(token).await,
                })
            }
            None => {
                info!("Authentication failed for user '{}'", account_id);
                if token.errors.contains(&REQUIRES_MFA) {
                    info!("Azure AD application requires MFA");
                    let drs_scope = format!("{}/.default", DRS_APP_ID);
                    let mut scopes = vec!["GroupMember.Read.All"];
                    if !self.is_domain_joined().await {
                        /* If we're authenticating as a Broker, and
                         * we're using a PublicClientApplication, then
                         * we need to perform a domain join. Request
                         * access to the DRS resource (Domain
                         * Registration Service). */
                        if self.app_id == BROKER_APP_ID {
                            scopes.push(drs_scope.as_str());
                        }
                    }
                    let resp = match self.client.write().await.initiate_device_flow(scopes) {
                        Ok(resp) => resp,
                        Err(_e) => return Err(IdpError::BadRequest),
                    };
                    return Ok(AuthResult::Next(AuthRequest::DeviceAuthorizationGrant {
                        data: resp.into(),
                    }));
                }
                if token.errors.contains(&NO_CONSENT) {
                    let url = format!(
                        "{}/adminconsent?client_id={}",
                        self.authority_url, self.app_id
                    );
                    error!("Azure AD application requires consent, either from tenant, or from user, go to: {}", url);
                }
                if token.errors.contains(&NO_SECRET) {
                    let url = "https://learn.microsoft.com/en-us/azure/active-directory/develop/scenario-desktop-app-registration#redirect-uris";
                    error!(
                        "Azure AD application requires enabling 'Allow public client flows'. {}",
                        url
                    );
                }
                error!("{}: {}", token.error, token.error_description);
                Err(IdpError::NotFound)
            }
        }
    }

    async fn user_token_from_unix_user_token(&self, value: &UnixUserToken) -> UserToken {
        let config = self.config.read();
        let mut groups: Vec<GroupToken>;
        match &value.access_token {
            Some(access_token) => {
                groups = match request_user_groups(&self.graph_url, access_token).await {
                    Ok(groups) => {
                        let mut gt_groups = vec![];
                        for g in groups {
                            match self.group_token_from_directory_object(g).await {
                                Ok(group) => gt_groups.push(group),
                                Err(e) => {
                                    debug!("Failed fetching group for user {}: {}", &value.spn, e)
                                }
                            };
                        }
                        gt_groups
                    }
                    Err(_e) => {
                        debug!("Failed fetching user groups for {}", &value.spn);
                        vec![]
                    }
                };
            }
            None => {
                debug!("Failed fetching user groups for {}", &value.spn);
                groups = vec![];
            }
        };
        let sshkeys: Vec<String> = vec![];
        let valid = true;
        let gidnumber =
            gen_unique_account_uid(&self.config, &self.domain, &value.uuid.to_string()).await;
        // Add the fake primary group
        groups.push(GroupToken {
            name: value.spn.clone(),
            spn: value.spn.clone(),
            uuid: value.uuid,
            gidnumber,
        });

        UserToken {
            name: value.spn.clone(),
            spn: value.spn.clone(),
            uuid: value.uuid,
            gidnumber,
            displayname: value.displayname.clone(),
            shell: Some(config.await.get_shell(Some(&self.domain))),
            groups,
            sshkeys,
            valid,
        }
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
    ) -> Result<()> {
        /* If not already joined, and we requested the DRS resource, join the
         * domain now. */
        if !self.is_domain_joined().await && self.app_id == BROKER_APP_ID {
            if let Some(access_token) = &token.access_token {
                let csr_tag = format!("{}/certificate", self.domain);
                let loadable_cert_key: tpm::LoadableIdentityKey = match keystore
                    .get_tagged_hsm_key(&csr_tag)
                {
                    Ok(Some(loadable_cert_key)) => loadable_cert_key,
                    Ok(None) => return Err(anyhow!("No tagged hsm key was found for the domain")),
                    Err(e) => return Err(anyhow!("Failed to join the domain: {:?}", e)),
                };

                debug!(
                    "Domain {} is not currently joined, registering device with Entra ID",
                    self.domain
                );
                match register_device(
                    machine_key,
                    access_token,
                    &self.domain,
                    tpm,
                    &loadable_cert_key,
                    &loadable_cert_key,
                )
                .await
                {
                    Ok((new_loadable_cert_key, device_id)) => {
                        info!("Joined domain {} with device id {}", self.domain, device_id);
                        // Remove the old tagged hsm key from the keystore
                        let csr_tag = format!("{}/certificate", self.domain);
                        if let Err(e) = keystore.delete_tagged_hsm_key(&csr_tag) {
                            return Err(anyhow!("Failed to join the domain: {:?}", e));
                        }
                        // Store the new_loadable_cert_key in the keystore
                        if let Err(e) =
                            keystore.insert_tagged_hsm_key(&csr_tag, &new_loadable_cert_key)
                        {
                            return Err(anyhow!("Failed to join the domain: {:?}", e));
                        }
                        let mut config = self.config.write().await;
                        config.set(&self.domain, "app_id", BROKER_APP_ID);
                        debug!(
                            "Setting domain {} config app_id to {}",
                            self.domain, BROKER_APP_ID
                        );
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
                        allow_groups.push(token.spn.clone());
                        /* Remove duplicates from the allow_groups */
                        allow_groups.sort();
                        allow_groups.dedup();
                        config.set(&self.domain, "pam_allow_groups", &allow_groups.join(","));
                        debug!(
                            "Setting global pam_allow_groups to {}",
                            &allow_groups.join(",")
                        );
                        if let Err(e) = config.write_server_config() {
                            return Err(anyhow!(
                                "Failed to write domain join configuration: {:?}",
                                e
                            ));
                        }
                    }
                    Err(e) => {
                        return Err(anyhow!("Failed to join the domain: {:?}", e));
                    }
                }
            }
        }
        Ok(())
    }

    async fn is_domain_joined(&self) -> bool {
        /* If we have access to tpm keys, and the domain device_id is
         * configured, we'll assume we are domain joined. */
        let config = self.config.read().await;
        if config.get(&self.domain, "device_id").is_none() {
            return false;
        }
        true
    }
}
