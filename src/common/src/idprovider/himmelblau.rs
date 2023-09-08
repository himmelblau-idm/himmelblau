use super::interface::{
    AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, GroupToken, Id, IdProvider,
    IdpError, UserToken,
};
use crate::config::split_username;
use crate::config::HimmelblauConfig;
use crate::constants::{DEFAULT_APP_ID, DEFAULT_CONFIG_PATH};
use crate::unix_proto::{DeviceAuthorizationResponse, PamAuthRequest};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use himmelblau_policies::policies::apply_group_policy;
use msal::authentication::DeviceAuthorizationResponse as msal_DeviceAuthorizationResponse;
use msal::authentication::{
    PublicClientApplication, UnixUserToken, AUTH_PENDING, NO_CONSENT, NO_GROUP_CONSENT, NO_SECRET,
    REQUIRES_MFA,
};
use msal::misc::{request_user_groups, DirectoryObject};
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
    config: Arc<RwLock<HimmelblauConfig>>,
    providers: RwLock<HashMap<String, HimmelblauProvider>>,
}

impl HimmelblauMultiProvider {
    pub fn new() -> Result<Self> {
        let config = match HimmelblauConfig::new(DEFAULT_CONFIG_PATH) {
            Ok(config) => config,
            Err(e) => return Err(anyhow!("{}", e)),
        };
        Ok(HimmelblauMultiProvider {
            config: RwLock::new(config).into(),
            providers: RwLock::new(HashMap::new()),
        })
    }
}

#[async_trait]
impl IdProvider for HimmelblauMultiProvider {
    /* TODO: Kanidm should be modified to provide the account_id to
     * provider_authenticate, so that we can test the correct provider here.
     * Currently we go offline if ANY provider is down, which could be
     * incorrect. */
    async fn provider_authenticate(&self) -> Result<(), IdpError> {
        for (_domain, provider) in self.providers.read().await.iter() {
            match provider.provider_authenticate().await {
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
    ) -> Result<UserToken, IdpError> {
        /* AAD doesn't permit user listing (must use cache entries from auth) */
        let account_id = id.to_string().clone();
        match split_username(&account_id) {
            Some((_sam, domain)) => {
                match self.check_insert_provider(domain).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("{}", e);
                        return Err(IdpError::NotFound);
                    }
                }
                let providers = self.providers.read().await;
                match providers.get(domain) {
                    Some(provider) => provider.unix_user_get(id, old_token).await,
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
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        match split_username(account_id) {
            Some((_sam, domain)) => {
                match self.check_insert_provider(domain).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("{}", e);
                        return Err(IdpError::NotFound);
                    }
                }
                let providers = self.providers.read().await;
                match providers.get(domain) {
                    Some(provider) => provider.unix_user_online_auth_init(account_id, token).await,
                    None => Err(IdpError::NotFound),
                }
            }
            None => {
                debug!("Authentication ignored for local user '{}'", account_id);
                Err(IdpError::NotFound)
            }
        }
    }

    async fn unix_user_online_auth_step(
        &self,
        account_id: &str,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        match split_username(account_id) {
            Some((_sam, domain)) => {
                match self.check_insert_provider(domain).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("{}", e);
                        return Err(IdpError::NotFound);
                    }
                }
                let providers = self.providers.read().await;
                match providers.get(domain) {
                    Some(provider) => {
                        provider
                            .unix_user_online_auth_step(account_id, cred_handler, pam_next_req)
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
                match self.check_insert_provider(domain).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("{}", e);
                        return Err(IdpError::NotFound);
                    }
                }
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

    async fn unix_group_get(&self, _id: &Id) -> Result<GroupToken, IdpError> {
        /* AAD doesn't permit group listing (must use cache entries from auth) */
        Err(IdpError::BadRequest)
    }
}

impl HimmelblauMultiProvider {
    async fn check_insert_provider(&self, domain: &str) -> Result<()> {
        let mut providers = self.providers.write().await;
        if !providers.contains_key(domain) {
            let config = self.config.read().await;
            let (_tenant_id, authority_url, graph) = match config.get_authority_url(domain).await {
                Ok(res) => res,
                Err(e) => return Err(anyhow!("{}", e)),
            };
            let app_id = config.get_app_id(domain);
            let app = match PublicClientApplication::new(&app_id, authority_url.as_str()) {
                Ok(app) => app,
                Err(e) => return Err(anyhow!("{}", e)),
            };
            providers.insert(
                domain.to_string(),
                HimmelblauProvider::new(app, &self.config, domain, &authority_url, &graph, &app_id),
            );
        }
        Ok(())
    }
}

pub struct HimmelblauProvider {
    client: RwLock<PublicClientApplication>,
    config: Arc<RwLock<HimmelblauConfig>>,
    domain: String,
    authority_url: String,
    graph_url: String,
    app_id: String,
}

impl HimmelblauProvider {
    pub fn new(
        client: PublicClientApplication,
        config: &Arc<RwLock<HimmelblauConfig>>,
        domain: &str,
        authority_url: &str,
        graph_url: &str,
        app_id: &str,
    ) -> Self {
        HimmelblauProvider {
            client: RwLock::new(client),
            config: config.clone(),
            domain: domain.to_string(),
            authority_url: authority_url.to_string(),
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
    // Needs .read on all types except re-auth.

    async fn provider_authenticate(&self) -> Result<(), IdpError> {
        /* Determine if the authority is up by sending a simple get request */
        let resp = match reqwest::get(self.authority_url.clone()).await {
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
    ) -> Result<UserToken, IdpError> {
        /* Use the msal user cache to refresh the user token */
        let account_id = id.to_string().clone();
        let mut scopes = vec![];
        if self.app_id != DEFAULT_APP_ID {
            scopes.push("GroupMember.Read.All");
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
        match self.token_validate(&account_id, token).await {
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
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        Ok((AuthRequest::Password, AuthCredHandler::Password))
    }

    async fn unix_user_online_auth_step(
        &self,
        account_id: &str,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        match (cred_handler, pam_next_req) {
            (AuthCredHandler::Password, PamAuthRequest::Password { cred }) => {
                let mut scopes = vec![];
                if self.app_id != DEFAULT_APP_ID {
                    scopes.push("GroupMember.Read.All");
                }
                let mut token = match self
                    .client
                    .write()
                    .await
                    .acquire_token_by_username_password(account_id, &cred, scopes.clone())
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
                        .acquire_token_by_username_password(account_id, &cred, vec![])
                    {
                        Ok(token) => token,
                        Err(_e) => return Err(IdpError::NotFound),
                    };
                }
                match self.token_validate(account_id, token).await {
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
            (
                AuthCredHandler::DeviceAuthorizationGrant,
                PamAuthRequest::DeviceAuthorizationGrant { data },
            ) => {
                let sleep_interval: u64 = match data.interval.as_ref() {
                    Some(val) => *val as u64,
                    None => 5,
                };
                let mut token = match self
                    .client
                    .write()
                    .await
                    .acquire_token_by_device_flow(data.clone().into())
                {
                    Ok(token) => token,
                    Err(_e) => return Err(IdpError::NotFound),
                };
                while token.errors.contains(&AUTH_PENDING) {
                    debug!("Polling for acquire_token_by_device_flow");
                    sleep(Duration::from_secs(sleep_interval));
                    token = match self
                        .client
                        .write()
                        .await
                        .acquire_token_by_device_flow(data.clone().into())
                    {
                        Ok(token) => token,
                        Err(_e) => return Err(IdpError::NotFound),
                    };
                }
                match self.token_validate(account_id, token).await {
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

    async fn unix_group_get(&self, _id: &Id) -> Result<GroupToken, IdpError> {
        /* AAD doesn't permit group listing (must use cache entries from auth) */
        Err(IdpError::BadRequest)
    }
}

impl HimmelblauProvider {
    async fn token_validate(
        &self,
        account_id: &str,
        token: UnixUserToken,
    ) -> Result<AuthResult, IdpError> {
        match token.access_token {
            Some(_) => {
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
                    let resp = match self
                        .client
                        .write()
                        .await
                        .initiate_device_flow(vec!["GroupMember.Read.All"])
                    {
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

    async fn user_token_from_unix_user_token(&self, value: UnixUserToken) -> UserToken {
        let config = self.config.read();
        let mut groups: Vec<GroupToken>;
        match value.access_token {
            Some(access_token) => {
                groups = match request_user_groups(&self.graph_url, &access_token).await {
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
            spn: value.spn,
            uuid: value.uuid,
            gidnumber,
            displayname: value.displayname,
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
}
