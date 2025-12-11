/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2025

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

use crate::config::HimmelblauConfig;
use crate::constants::ID_MAP_CACHE;
use crate::db::KeyStoreTxn;
use crate::idmap_cache::StaticIdCache;
use crate::idprovider::interface::{
    tpm, AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, CacheState, GroupToken, Id,
    IdProvider, IdpError, UserToken, UserTokenState,
};
use crate::unix_proto::PamAuthRequest;
use async_trait::async_trait;
use himmelblau::{error::MsalError, MFAAuthContinue, UserToken as UnixUserToken};
use idmap::Idmap;
use oauth2::basic::BasicTokenType;
use oauth2::{
    DeviceAuthorizationResponse as OauthDeviceAuthResponse, EmptyExtraTokenFields,
    RequestTokenError, StandardTokenResponse,
};
use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod,
    CoreGenderClaim, CoreGrantType, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
    CoreSubjectIdentifierType, CoreUserInfoClaims,
};
use openidconnect::{
    AdditionalProviderMetadata, AuthType, ClientId, DeviceAuthorizationResponse,
    DeviceAuthorizationUrl, EmptyAdditionalClaims, EmptyExtraDeviceAuthorizationFields,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields, IssuerUrl, OAuth2TokenResponse,
    ProviderMetadata, Scope,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, Mutex, RwLock};
use uuid::Uuid;

#[instrument(level = "debug", skip_all)]
fn mfa_from_oidc_device(
    details: OauthDeviceAuthResponse<EmptyExtraDeviceAuthorizationFields>,
) -> Result<(MFAAuthContinue, String), IdpError> {
    let polling_interval = details.interval().as_secs() as u32;
    let expires_in = details.expires_in().as_secs() as u32;

    let msg = format!(
        "Using a browser on another device, visit:\n{}\n\
             And enter the code:\n{}",
        details.verification_uri(),
        details.user_code().secret()
    );

    let max_poll_attempts = if polling_interval == 0 {
        0
    } else {
        expires_in / polling_interval
    };

    Ok((
        MFAAuthContinue {
            msg,
            max_poll_attempts: Some(max_poll_attempts),
            polling_interval: Some(polling_interval * 1000),
            ..Default::default()
        },
        serde_json::to_string(&details).map_err(|e| {
            error!(?e, "Failed to serialize OIDC DAG");
            IdpError::BadRequest
        })?,
    ))
}

const HIMMELBLAU_OIDC_NAMESPACE: uuid::Uuid = uuid::uuid!("e669513b-1345-4853-96a7-596243184319");
const OFFLINE_NEXT_CHECK: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DeviceEndpointProviderMetadata {
    device_authorization_endpoint: DeviceAuthorizationUrl,
}

impl AdditionalProviderMetadata for DeviceEndpointProviderMetadata {}

type DeviceProviderMetadata = ProviderMetadata<
    DeviceEndpointProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

type DagClient = CoreClient<
    EndpointSet,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

type OidcTokenResponse = StandardTokenResponse<
    IdTokenFields<
        EmptyAdditionalClaims,
        EmptyExtraTokenFields,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >,
    BasicTokenType,
>;

struct OidcDelayedInit {
    client: DagClient,
    http_client: reqwest::Client,
    authorization_endpoint: String,
}

pub struct OidcProvider {
    cfg: Arc<RwLock<HimmelblauConfig>>,
    idmap: Arc<RwLock<Idmap>>,
    state: Mutex<CacheState>,
    client: RwLock<Option<OidcDelayedInit>>,
}

impl OidcProvider {
    #[instrument(level = "debug", skip_all)]
    pub async fn new(
        cfg: &Arc<RwLock<HimmelblauConfig>>,
        idmap: &Arc<RwLock<Idmap>>,
    ) -> Result<Self, IdpError> {
        Ok(Self {
            cfg: cfg.clone(),
            idmap: idmap.clone(),
            state: Mutex::new(CacheState::OfflineNextCheck(SystemTime::now())),
            client: RwLock::new(None),
        })
    }

    #[instrument(level = "debug", skip_all)]
    async fn initiate_device_flow(
        &self,
    ) -> Result<DeviceAuthorizationResponse<EmptyExtraDeviceAuthorizationFields>, MsalError> {
        if (self.delayed_init().await).is_err() {
            // Initialization failed. Report that the system is offline. We
            // can't proceed with initialization until the system is online.
            let mut state = self.state.lock().await;
            *state = CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
            return Err(MsalError::RequestFailed(
                "Network down detected".to_string(),
            ));
        }

        let scopes = vec![
            Scope::new("openid".to_string()),
            Scope::new("profile".to_string()),
            Scope::new("email".to_string()),
        ];
        if let Some(delayed_init) = &*self.client.read().await {
            let details = delayed_init
                .client
                .exchange_device_code()
                .add_scopes(scopes)
                .request_async(&delayed_init.http_client)
                .await
                .map_err(|e| {
                    error!(?e, "Error requesting device code");
                    match e {
                        RequestTokenError::Request(resp) => MsalError::RequestFailed(format!(
                            "HTTP error during device code request: {}",
                            resp
                        )),
                        _ => MsalError::GeneralFailure("Failed to acquire device code".to_string()),
                    }
                })?;

            Ok(details)
        } else {
            Err(MsalError::RequestFailed(
                "OIDC client not initialized".to_string(),
            ))
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn acquire_token_by_device_flow(
        &self,
        flow: &DeviceAuthorizationResponse<EmptyExtraDeviceAuthorizationFields>,
    ) -> Result<UserToken, MsalError> {
        if (self.delayed_init().await).is_err() {
            // Initialization failed. Report that the system is offline. We
            // can't proceed with initialization until the system is online.
            let mut state = self.state.lock().await;
            *state = CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
            return Err(MsalError::RequestFailed(
                "Network down detected".to_string(),
            ));
        }

        if let Some(delayed_init) = &*self.client.read().await {
            // Try to get the token endpoint URL from the oauth2 Client
            let token_url = delayed_init
                .client
                .token_uri()
                .map(|u| u.url().clone())
                .ok_or_else(|| {
                    MsalError::GeneralFailure("OIDC client missing token endpoint URL".to_string())
                })?;

            // Pull the device_code + client_id out in string form
            let device_code = flow.device_code().secret().clone();
            let client_id = delayed_init.client.client_id().as_str().to_owned();

            #[derive(Serialize)]
            struct DeviceAccessTokenRequest<'a> {
                grant_type: &'static str,
                device_code: &'a str,
                client_id: &'a str,
            }

            let body = DeviceAccessTokenRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                device_code: &device_code,
                client_id: &client_id,
            };

            // Single HTTP POST – no polling or sleeping.
            let resp = delayed_init
                .http_client
                .post(token_url)
                .header(reqwest::header::ACCEPT, "application/json")
                .form(&body)
                .send()
                .await
                .map_err(|e| {
                    MsalError::GeneralFailure(format!(
                        "Failed to send device access token request: {e}"
                    ))
                })?;
            let status = resp.status();
            let bytes = resp.bytes().await.map_err(|e| {
                MsalError::GeneralFailure(format!(
                    "Failed to read device access token response body: {e}"
                ))
            })?;
            if status.is_success() {
                self.user_token_from_oidc(
                    &serde_json::from_slice::<OidcTokenResponse>(&bytes).map_err(|e| {
                        MsalError::GeneralFailure(format!(
                            "Failed to parse device access token response: {e}"
                        ))
                    })?,
                )
                .await
                .map_err(|e| {
                    MsalError::GeneralFailure(format!(
                        "Failed to convert OIDC token to user token: {:?}",
                        e
                    ))
                })
            } else {
                // Not a success token; interpret as device-flow error.
                #[derive(Deserialize, Debug)]
                struct DeviceAccessTokenErrorResponse {
                    error: String,
                    #[allow(dead_code)]
                    error_description: Option<String>,
                }

                let err: DeviceAccessTokenErrorResponse =
                    serde_json::from_slice(&bytes).map_err(|e| {
                        error!(
                            ?e,
                            status = ?status,
                            body = %String::from_utf8_lossy(&bytes),
                            "Unexpected device access token response"
                        );
                        MsalError::GeneralFailure(format!(
                            "Failed to parse device access token error response: {e}"
                        ))
                    })?;

                match err.error.as_str() {
                    // These mean "keep polling" in RFC 8628; we just surface that
                    // to the caller instead of sleeping in here.
                    "authorization_pending" | "slow_down" => {
                        debug!(
                            error = %err.error,
                            desc = ?err.error_description,
                            "Device flow still pending; caller should poll again later",
                        );
                        Err(MsalError::MFAPollContinue)
                    }
                    "access_denied" => {
                        error!(
                            desc = ?err.error_description,
                            "User denied authorization during device flow"
                        );
                        Err(MsalError::GeneralFailure(
                            "User denied authorization during device flow".to_string(),
                        ))
                    }
                    "expired_token" => {
                        error!(
                            desc = ?err.error_description,
                            "Device code expired during device flow"
                        );
                        Err(MsalError::GeneralFailure(
                            "Device code expired during device flow".to_string(),
                        ))
                    }
                    other => {
                        error!(
                            error = %other,
                            desc = ?err.error_description,
                            status = ?status,
                            "Device flow failed with unexpected error"
                        );
                        Err(MsalError::GeneralFailure(format!(
                            "Device flow failed with error: {}",
                            other
                        )))
                    }
                }
            }
        } else {
            Err(MsalError::RequestFailed(
                "OIDC client not initialized".to_string(),
            ))
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn tenant_id(&self) -> Result<Uuid, IdpError> {
        let config = self.cfg.read().await;
        let issuer = config.get_oidc_issuer_url().ok_or({
            error!("Missing OIDC issuer URL in config");
            IdpError::BadRequest
        })?;
        Ok(Uuid::new_v5(&HIMMELBLAU_OIDC_NAMESPACE, issuer.as_bytes()))
    }

    #[instrument(level = "debug", skip_all)]
    async fn user_token_from_oidc(
        &self,
        token: &openidconnect::core::CoreTokenResponse,
    ) -> Result<UserToken, IdpError> {
        let access_token = token.access_token();
        let userinfo: CoreUserInfoClaims = if let Some(delayed_init) = &*self.client.read().await {
            delayed_init
                .client
                .user_info(access_token.clone(), None)
                .map_err(|e| {
                    error!(?e, "Error building userinfo request");
                    IdpError::BadRequest
                })?
                .request_async(&delayed_init.http_client)
                .await
                .map_err(|e| {
                    error!(?e, "Error calling userinfo endpoint");
                    IdpError::BadRequest
                })?
        } else {
            error!("OIDC client not initialized");
            return Err(IdpError::BadRequest);
        };

        let account_id = userinfo
            .email()
            .map(|email| email.to_string())
            .ok_or_else(|| {
                error!("Missing email claim in userinfo");
                IdpError::BadRequest
            })?;

        let tenant_id = self.tenant_id().await?;
        let subject = userinfo.subject().to_string();
        let object_id = uuid::Uuid::new_v5(&tenant_id, subject.as_bytes());

        let idmap_cache = StaticIdCache::new(ID_MAP_CACHE, false).map_err(|e| {
            error!("Failed reading from the idmap cache: {:?}", e);
            IdpError::BadRequest
        })?;

        let (uid, gid) = match idmap_cache.get_user_by_name(&account_id) {
            Some(user) => (user.uid, user.gid),
            None => {
                let idmap = self.idmap.read().await;
                let gid = idmap
                    .gen_to_unix(&tenant_id.to_string(), &account_id)
                    .map_err(|e| {
                        error!("{:?}", e);
                        IdpError::BadRequest
                    })?;
                (gid, gid)
            }
        };

        Ok(UserToken {
            name: account_id.to_string(),
            spn: account_id.to_string(),
            uuid: object_id,
            real_gidnumber: Some(uid),
            gidnumber: gid,
            displayname: userinfo
                .name()
                .and_then(|n| n.get(None))
                .map(|n| n.to_string())
                .unwrap_or_default(),
            shell: Some(self.cfg.read().await.get_shell(None)),
            groups: vec![GroupToken {
                name: account_id.to_string(),
                spn: account_id.to_string(),
                uuid: object_id,
                gidnumber: gid,
            }],
            tenant_id: Some(tenant_id),
            valid: true,
        })
    }

    #[instrument(level = "debug", skip(self))]
    async fn attempt_online(&self, now: SystemTime) -> bool {
        if (self.delayed_init().await).is_err() {
            // Initialization failed. Report that the system is offline. We
            // can't proceed with initialization until the system is online.
            info!("Network down detected");
            let mut state = self.state.lock().await;
            *state = CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
            return false;
        }
        let authorization_endpoint = match self.client.read().await.as_ref() {
            Some(init) => init.authorization_endpoint.clone(),
            None => {
                error!("OIDC client not initialized");
                let mut state = self.state.lock().await;
                *state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                return false;
            }
        };
        match reqwest::get(&authorization_endpoint).await {
            Ok(resp) => {
                if resp.status().is_success() {
                    debug!("provider is now online");
                    let mut state = self.state.lock().await;
                    *state = CacheState::Online;
                    return true;
                } else {
                    error!(
                        ?authorization_endpoint,
                        "Provider online failed: {}",
                        resp.status()
                    );
                    let mut state = self.state.lock().await;
                    *state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                    return false;
                }
            }
            Err(err) => {
                error!(?err, ?authorization_endpoint, "Provider online failed");
                let mut state = self.state.lock().await;
                *state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                return false;
            }
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn delayed_init(&self) -> Result<(), IdpError> {
        // The purpose of this function is to delay initialization as long as
        // possible. This permits the daemon to start, without requiring we be
        // connected to the internet. This way we can send messages to the user
        // via PAM indicating that the network is down.
        let init = self.client.read().await.is_some();
        if !init {
            let cfg = self.cfg.read().await;

            let client_id = ClientId::new(cfg.get_oidc_client_id().ok_or({
                error!("Missing OIDC client ID in config");
                IdpError::BadRequest
            })?);

            let issuer_url = IssuerUrl::new(cfg.get_oidc_issuer_url().ok_or({
                error!("Missing OIDC issuer URL in config");
                IdpError::BadRequest
            })?)
            .map_err(|e| {
                error!(
                    ?e,
                    "Invalid OIDC issuer URL: {:?}",
                    cfg.get_oidc_issuer_url()
                );
                IdpError::BadRequest
            })?;

            let http_client = reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| {
                    error!(?e, "Failed to build HTTP client for OIDC");
                    IdpError::BadRequest
                })?;

            // Discover provider metadata (includes our custom device endpoint field).
            let provider_metadata =
                DeviceProviderMetadata::discover_async(issuer_url, &http_client)
                    .await
                    .map_err(|e| {
                        error!(?e, "Failed to discover OIDC provider metadata");
                        IdpError::BadRequest
                    })?;
            let authorization_endpoint = provider_metadata.authorization_endpoint().to_string();

            let device_endpoint = provider_metadata
                .additional_metadata()
                .device_authorization_endpoint
                .clone();

            // Create a public client: pass None for the client secret.
            // Whether this works depends on provider configuration. Many support it.
            let client = CoreClient::from_provider_metadata(provider_metadata, client_id, None)
                .set_device_authorization_url(device_endpoint)
                .set_auth_type(AuthType::RequestBody);

            // Initialize the idmap range
            let domain = cfg.get_oidc_domain().ok_or({
                error!("Missing OIDC domain in config");
                IdpError::BadRequest
            })?;
            let tenant_id = self.tenant_id().await?.to_string();
            let range = cfg.get_idmap_range(&domain);
            let mut idmap = self.idmap.write().await;
            idmap
                .add_gen_domain(&domain, &tenant_id, range)
                .map_err(|e| {
                    error!("Failed adding the idmap domain: {}", e);
                    IdpError::BadRequest
                })?;
            drop(cfg);

            // Store provider initialization
            self.client.write().await.replace(OidcDelayedInit {
                client,
                http_client,
                authorization_endpoint,
            });
        }
        Ok(())
    }
}

#[async_trait]
impl IdProvider for OidcProvider {
    #[instrument(level = "debug", skip(self, _tpm))]
    async fn check_online(&self, _tpm: &mut tpm::provider::BoxedDynTpm, now: SystemTime) -> bool {
        let state = self.state.lock().await.clone();
        match state {
            // Proceed
            CacheState::Online => true,
            CacheState::OfflineNextCheck(at_time) if now >= at_time => {
                // Attempt online. If fails, return token.
                self.attempt_online(now).await
            }
            CacheState::OfflineNextCheck(_) | CacheState::Offline => false,
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_get<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        token: Option<&UserToken>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<UserTokenState, IdpError> {
        if (self.delayed_init().await).is_err() {
            // Initialization failed. Report that the system is offline. We
            // can't proceed with initialization until the system is online.
            info!("Network down detected");
            let mut state = self.state.lock().await;
            *state = CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
            return Ok(UserTokenState::UseCached);
        }

        let account_id = match id {
            Id::Name(account_id) => account_id,
            _ => match token {
                Some(tok) => &tok.name,
                None => {
                    return Ok(UserTokenState::UseCached);
                }
            },
        };
        let displayname = match token {
            Some(tok) => tok.displayname.clone(),
            None => "".to_string(),
        };

        let tenant_id = self.tenant_id().await?;
        let object_id = match token {
            Some(tok) => tok.uuid,
            None => {
                // Produce a fake object_id if this user has yet to authenticate
                uuid::Uuid::new_v4()
            }
        };

        let idmap_cache = StaticIdCache::new(ID_MAP_CACHE, false).map_err(|e| {
            error!("Failed reading from the idmap cache: {:?}", e);
            IdpError::BadRequest
        })?;

        let (uid, gid) = match idmap_cache.get_user_by_name(account_id) {
            Some(user) => (user.uid, user.gid),
            None => {
                let idmap = self.idmap.read().await;
                let gid = idmap
                    .gen_to_unix(&tenant_id.to_string(), account_id)
                    .map_err(|e| {
                        error!("{:?}", e);
                        IdpError::BadRequest
                    })?;
                (gid, gid)
            }
        };

        Ok(UserTokenState::Update(UserToken {
            name: account_id.to_string(),
            spn: account_id.to_string(),
            uuid: object_id,
            real_gidnumber: Some(uid),
            gidnumber: gid,
            displayname,
            shell: Some(self.cfg.read().await.get_shell(None)),
            groups: vec![GroupToken {
                name: account_id.to_string(),
                spn: account_id.to_string(),
                uuid: object_id,
                gidnumber: gid,
            }],
            tenant_id: Some(tenant_id),
            valid: true,
        }))
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
        &self,
        _account_id: &str,
        _token: Option<&UserToken>,
        _no_hello_pin: bool,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
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

        let (flow, extra_data) =
            mfa_from_oidc_device(self.initiate_device_flow().await.map_err(|e| {
                error!(?e, "Failed to initiate device flow");
                IdpError::BadRequest
            })?)?;

        let polling_interval = flow.polling_interval.unwrap_or(5000);
        Ok((
            AuthRequest::MFAPoll {
                msg: flow.msg.clone(),
                polling_interval: polling_interval / 1000,
            },
            AuthCredHandler::MFA {
                flow,
                password: None,
                extra_data: Some(extra_data),
            },
        ))
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        _old_token: &UserToken,
        _service: &str,
        _no_hello_pin: bool,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        if (self.delayed_init().await).is_err() {
            // Initialization failed. Report that the system is offline. We
            // can't proceed with initialization until the system is online.
            info!("Network down detected");
            let mut state = self.state.lock().await;
            *state = CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
            return Ok((
                AuthResult::Denied("Network outage detected.".to_string()),
                AuthCacheAction::None,
            ));
        }

        match (&mut *cred_handler, pam_next_req) {
            (
                AuthCredHandler::MFA {
                    ref mut flow,
                    password: _,
                    extra_data,
                },
                PamAuthRequest::MFAPoll { poll_attempt },
            ) => {
                let max_poll_attempts = flow.max_poll_attempts.unwrap_or(180);
                if poll_attempt > max_poll_attempts {
                    error!("MFA polling timed out");
                    return Err(IdpError::BadRequest);
                }
                let dag_json = extra_data.as_ref().ok_or_else(|| {
                    error!("Missing extra_data in OIDC MFA handler");
                    IdpError::BadRequest
                })?;
                let flow = serde_json::from_str(dag_json).map_err(|e| {
                    error!(?e, "Failed to deserialize OIDC DAG");
                    IdpError::BadRequest
                })?;
                match self.acquire_token_by_device_flow(&flow).await {
                    Ok(token) => {
                        if account_id.to_string().to_lowercase()
                            != token.name.to_string().to_lowercase()
                        {
                            let msg = format!(
                                "Authenticated user {} does not match requested user",
                                token.uuid
                            );
                            error!(msg);
                            return Ok((AuthResult::Denied(msg), AuthCacheAction::None));
                        }
                        Ok((AuthResult::Success { token }, AuthCacheAction::None))
                    }
                    Err(MsalError::MFAPollContinue) => Ok((
                        AuthResult::Next(AuthRequest::MFAPollWait),
                        AuthCacheAction::None,
                    )),
                    Err(e) => {
                        error!("{:?}", e);
                        return Err(IdpError::BadRequest);
                    }
                }
            }
            _ => {
                error!("Invalid auth step");
                Err(IdpError::BadRequest)
            }
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn get_cachestate<D: KeyStoreTxn + Send>(
        &self,
        _account_id: Option<&str>,
        _keystore: &mut D,
    ) -> CacheState {
        self.state.lock().await.clone()
    }

    #[instrument(level = "debug", skip_all)]
    async fn offline_break_glass(&self, _ttl: Option<u64>) -> Result<(), IdpError> {
        // TODO
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_access<D: KeyStoreTxn + Send>(
        &self,
        _id: &Id,
        _scopes: Vec<String>,
        _token: Option<&UserToken>,
        _client_id: Option<String>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<UnixUserToken, IdpError> {
        //TODO
        Err(IdpError::BadRequest)
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_ccaches<D: KeyStoreTxn + Send>(
        &self,
        _id: &Id,
        _old_token: Option<&UserToken>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> (Vec<u8>, Vec<u8>) {
        (vec![], vec![])
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_prt_cookie<D: KeyStoreTxn + Send>(
        &self,
        _id: &Id,
        _token: Option<&UserToken>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<String, IdpError> {
        Err(IdpError::BadRequest)
    }

    #[instrument(level = "debug", skip_all)]
    async fn change_auth_token<D: KeyStoreTxn + Send>(
        &self,
        _account_id: &str,
        _token: &UnixUserToken,
        _new_tok: &str,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<bool, IdpError> {
        Err(IdpError::BadRequest)
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        _account_id: &str,
        _token: Option<&UserToken>,
        _no_hello_pin: bool,
        _keystore: &mut D,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        Err(IdpError::BadRequest)
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_offline_auth_step<D: KeyStoreTxn + Send>(
        &self,
        _account_id: &str,
        _token: &UserToken,
        _cred_handler: &mut AuthCredHandler,
        _pam_next_req: PamAuthRequest,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
        _online_at_init: bool,
    ) -> Result<AuthResult, IdpError> {
        Err(IdpError::BadRequest)
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_group_get(
        &self,
        _id: &Id,
        _tpm: &mut tpm::provider::BoxedDynTpm,
    ) -> Result<GroupToken, IdpError> {
        Err(IdpError::BadRequest)
    }
}
