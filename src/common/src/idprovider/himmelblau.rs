use super::interface::{
    AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, GroupToken, Id, IdProvider,
    IdpError, UserToken,
};
use crate::config::split_username;
use crate::config::HimmelblauConfig;
use crate::db::KeyStoreTxn;
use crate::idmap::object_id_to_unix_id;
use crate::idprovider::interface::tpm;
use crate::unix_proto::{DeviceAuthorizationResponse, PamAuthRequest};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use graph::user::{request_user_groups, DirectoryObject};
use himmelblau_policies::policies::apply_group_policy;
use kanidm_hsm_crypto::{LoadableIdentityKey, LoadableMsOapxbcRsaKey, PinValue, SealedData, Tpm};
use msal::auth::{
    BrokerClientApplication, ClientInfo,
    DeviceAuthorizationResponse as msal_DeviceAuthorizationResponse, EnrollAttrs, IdToken,
    MFAAuthContinue, UserToken as UnixUserToken,
};
use msal::error::{
    MsalError, AUTH_PENDING, DEVICE_AUTH_FAIL, NO_CONSENT, NO_GROUP_CONSENT, REQUIRES_MFA,
};
use reqwest;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::time::SystemTime;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

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
            let app = BrokerClientApplication::new(Some(authority_url.as_str()), None, None)
                .map_err(|e| anyhow!("{:?}", e))?;
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

struct MFAAuthContinueI(MFAAuthContinue);

#[allow(clippy::from_over_into)]
impl Into<Vec<String>> for MFAAuthContinueI {
    fn into(self) -> Vec<String> {
        let max_poll_attempts = match self.0.max_poll_attempts {
            Some(n) => n.to_string(),
            None => String::new(),
        };
        let polling_interval = match self.0.polling_interval {
            Some(n) => n.to_string(),
            None => String::new(),
        };
        vec![
            self.0.mfa_method,
            self.0.msg,
            self.0.session_id,
            self.0.flow_token,
            self.0.ctx,
            self.0.canary,
            self.0.url_end_auth,
            self.0.url_begin_auth,
            self.0.url_post,
            max_poll_attempts,
            polling_interval,
        ]
    }
}

impl From<&Vec<String>> for MFAAuthContinueI {
    fn from(src: &Vec<String>) -> Self {
        let max_poll_attempts: Option<u32> = if src[9].is_empty() {
            None
        } else {
            src[9].parse().ok()
        };
        let polling_interval: Option<u32> = if src[10].is_empty() {
            None
        } else {
            src[10].parse().ok()
        };
        MFAAuthContinueI(MFAAuthContinue {
            mfa_method: src[0].clone(),
            msg: src[1].clone(),
            max_poll_attempts,
            polling_interval,
            session_id: src[2].clone(),
            flow_token: src[3].clone(),
            ctx: src[4].clone(),
            canary: src[5].clone(),
            url_end_auth: src[6].clone(),
            url_begin_auth: src[7].clone(),
            url_post: src[8].clone(),
        })
    }
}

struct UnixUserTokenI(UnixUserToken);

#[allow(clippy::from_over_into)]
impl Into<Vec<String>> for UnixUserTokenI {
    fn into(self) -> Vec<String> {
        let access_token = match &self.0.access_token {
            Some(n) => n.clone(),
            None => String::new(),
        };
        vec![access_token, self.0.refresh_token.clone()]
    }
}

impl From<&Vec<String>> for UnixUserTokenI {
    /// We don't care about most of the UserToken values when passing it to an
    /// AuthCredHandler, so most of these are intentionally left blank.
    fn from(src: &Vec<String>) -> Self {
        let access_token: Option<String> = if src[0].is_empty() {
            None
        } else {
            Some(src[0].clone())
        };
        UnixUserTokenI(UnixUserToken {
            token_type: "".to_string(),
            scope: None,
            expires_in: 0,
            ext_expires_in: 0,
            access_token,
            refresh_token: src[1].clone(),
            id_token: IdToken::default(),
            client_info: ClientInfo::default(),
            prt: None,
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
                            // Generate a UserToken, with invalid uuid and gid. We can
                            // only fetch these from an authenticated token. We have to
                            // provide something, or SSH will fail.
                            let groups = vec![GroupToken {
                                name: account_id.clone(),
                                spn: account_id.clone(),
                                uuid: Uuid::max(),
                                gidnumber: i32::MAX as u32,
                            }];
                            let config = self.config.read().await;
                            return Ok(UserToken {
                                name: account_id.clone(),
                                spn: account_id.clone(),
                                uuid: Uuid::max(),
                                gidnumber: i32::MAX as u32,
                                displayname: "".to_string(),
                                shell: Some(config.get_shell(Some(&self.domain))),
                                groups,
                                sshkeys: vec![],
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
                        Err(e) => {
                            error!("{:?}", e);
                            // Never return IdpError::NotFound. This deletes
                            // the existing user from the cache.
                            fake_user!()
                        }
                    }
                } else {
                    // Never return IdpError::NotFound. This deletes the
                    // existing user from the cache.
                    fake_user!()
                }
            }
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
                    token.displayname = old_token.displayname.clone()
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
                        vec![],
                        None,
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
                                            None,
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
                let token = UnixUserTokenI::from(data).0;

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
                        warn!("MFA auth failed, falling back to SFA: {:?}", e);
                        // Again, we need to wait to handle the response until after
                        // we've released the write lock on the client, otherwise we
                        // will deadlock.
                        let mtoken = self
                            .client
                            .write()
                            .await
                            .acquire_token_by_username_password_for_device_enrollment(
                                account_id, &cred,
                            )
                            .await;
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
                    "PhoneAppNotification" | "PhoneAppOTP" => {
                        let msg = resp.msg.clone();
                        *cred_handler = AuthCredHandler::MFA {
                            data: MFAAuthContinueI(resp).into(),
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
                            data: MFAAuthContinueI(resp).into(),
                        };
                        return Ok((
                            AuthResult::Next(AuthRequest::MFAPoll {
                                msg,
                                polling_interval,
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
                        // STOP! If the DAG doesn't hold an MFA amr, then we
                        // need to bail out here and refuse Hello enrollment
                        // (we can't enroll in Hello with an SFA token).
                        let mfa = token2.amr_mfa().map_err(|e| {
                            error!("{:?}", e);
                            IdpError::NotFound
                        })?;
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
                            data: UnixUserTokenI(token).into(),
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
                let token = self
                    .client
                    .write()
                    .await
                    .acquire_token_by_mfa_flow(
                        account_id,
                        Some(&cred),
                        None,
                        MFAAuthContinueI::from(data).0,
                    )
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
                            data: UnixUserTokenI(token).into(),
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
                let flow = MFAAuthContinueI::from(data).0;
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
                    sleep(Duration::from_secs(polling_interval.into()));
                    match self
                        .client
                        .write()
                        .await
                        .acquire_token_by_mfa_flow(
                            account_id,
                            None,
                            Some(poll_attempt),
                            MFAAuthContinueI::from(data).0,
                        )
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
                            data: UnixUserTokenI(token).into(),
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
        let idmap_range = config.get_idmap_range(&self.domain);
        let gidnumber = object_id_to_unix_id(&uuid, idmap_range).map_err(|e| {
            debug!("Failed mapping uuid to unix uid/gid: {:?}", e);
            IdpError::BadRequest
        })?;

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
            Some(id) => {
                Uuid::parse_str(id).map_err(|e| anyhow!("Failed parsing user uuid: {}", e))?
            }
            None => return Err(anyhow!("Failed retrieving group uuid")),
        };
        let config = self.config.read();
        let idmap_range = config.await.get_idmap_range(&self.domain);
        let gidnumber = object_id_to_unix_id(&id, idmap_range)
            .map_err(|e| anyhow!("Failed mapping uuid to unix gid: {:?}", e))?;

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
