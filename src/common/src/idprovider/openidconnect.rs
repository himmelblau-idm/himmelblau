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
use crate::idprovider::common::KeyType;
use crate::idprovider::common::{BadPinCounter, RefreshCache, RefreshCacheEntry};
use crate::idprovider::interface::{
    tpm, AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, CacheState, GroupToken, Id,
    IdProvider, IdpError, UserToken, UserTokenState,
};
use crate::unix_proto::PamAuthRequest;
use crate::{
    extract_base_url, handle_hello_bad_pin_count, impl_change_auth_token,
    impl_create_decoupled_hello_key, impl_himmelblau_hello_key_helpers,
    impl_himmelblau_offline_auth_init, impl_himmelblau_offline_auth_step, impl_offline_break_glass,
    impl_unix_user_access, load_cached_prt_no_op, no_op_prt_token_fetch,
    oidc_refresh_token_token_fetch,
};
use async_trait::async_trait;
use himmelblau::{error::MsalError, MFAAuthContinue, UserToken as UnixUserToken};
use himmelblau::{ClientInfo, IdToken};
use idmap::Idmap;
use kanidm_hsm_crypto::structures::LoadableMsHelloKey;
use kanidm_hsm_crypto::PinValue;
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
use regex::Regex;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
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

pub trait OidcTokenResponseExt {
    fn into_user_token(self) -> Result<UnixUserToken, MsalError>;
}

impl OidcTokenResponseExt for OidcTokenResponse {
    fn into_user_token(self) -> Result<UnixUserToken, MsalError> {
        let refresh_token = self
            .refresh_token()
            .ok_or(MsalError::InvalidParse("Missing refresh token".to_string()))?
            .secret()
            .to_owned();

        let scope = self.scopes().and_then(|scopes| {
            if scopes.is_empty() {
                None
            } else {
                Some(
                    scopes
                        .iter()
                        .map(|s| s.as_ref())
                        .collect::<Vec<_>>()
                        .join(" "),
                )
            }
        });

        let expires_in = self
            .expires_in()
            .map(|d: Duration| d.as_secs().min(u64::from(u32::MAX)) as u32)
            .unwrap_or(0);

        let ext_expires_in = expires_in;

        let token_type = self.token_type().as_ref().to_owned();
        let access_token = Some(self.access_token().secret().to_owned());

        let id_token = {
            let raw = self
                .extra_fields()
                .id_token()
                .ok_or_else(|| MsalError::InvalidParse("Missing id_token".to_string()))?
                .to_string();

            IdToken::from_str(&raw).map_err(|e| {
                MsalError::InvalidParse(format!("Failed to parse id_token: {:?}", e))
            })?
        };

        Ok(UnixUserToken {
            token_type,
            scope,
            expires_in,
            ext_expires_in,
            access_token,
            refresh_token,
            id_token,
            client_info: ClientInfo::default(),
            prt: None,
        })
    }
}

struct OidcDelayedInit {
    client: DagClient,
    http_client: reqwest::Client,
    authorization_endpoint: String,
}

pub struct OidcProvider {
    config: Arc<RwLock<HimmelblauConfig>>,
    idmap: Arc<RwLock<Idmap>>,
    state: Mutex<CacheState>,
    client: RwLock<Option<OidcDelayedInit>>,
    refresh_cache: RefreshCache,
    bad_pin_counter: BadPinCounter,
}

impl OidcProvider {
    #[instrument(level = "debug", skip_all)]
    pub async fn new(
        cfg: &Arc<RwLock<HimmelblauConfig>>,
        idmap: &Arc<RwLock<Idmap>>,
    ) -> Result<Self, IdpError> {
        Ok(Self {
            config: cfg.clone(),
            idmap: idmap.clone(),
            state: Mutex::new(CacheState::OfflineNextCheck(SystemTime::now())),
            client: RwLock::new(None),
            refresh_cache: RefreshCache::new(),
            bad_pin_counter: BadPinCounter::new(),
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
            Scope::new("offline_access".to_string()),
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
    ) -> Result<OidcTokenResponse, MsalError> {
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
                serde_json::from_slice::<OidcTokenResponse>(&bytes).map_err(|e| {
                    MsalError::GeneralFailure(format!(
                        "Failed to parse device access token response: {e}"
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
    async fn acquire_token_by_refresh_token(
        &self,
        refresh_token: &str,
        scopes: Vec<&str>,
    ) -> Result<OidcTokenResponse, MsalError> {
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
            // Token endpoint
            let token_url = delayed_init
                .client
                .token_uri()
                .map(|u| u.url().clone())
                .ok_or_else(|| {
                    MsalError::GeneralFailure("OIDC client missing token endpoint URL".to_string())
                })?;

            // Client id as string (used for public clients; confidential clients may also require secret)
            let client_id = delayed_init.client.client_id().as_str().to_owned();

            // Space-separated scopes per OAuth2
            let scope_string = scopes.join(" ");

            #[derive(Serialize)]
            struct RefreshTokenRequest<'a> {
                grant_type: &'static str,
                refresh_token: &'a str,
                client_id: &'a str,
                #[serde(skip_serializing_if = "str::is_empty")]
                scope: &'a str,
            }

            let body = RefreshTokenRequest {
                grant_type: "refresh_token",
                refresh_token,
                client_id: &client_id,
                scope: &scope_string,
            };

            let resp = delayed_init
                .http_client
                .post(token_url)
                .header(reqwest::header::ACCEPT, "application/json")
                .form(&body)
                .send()
                .await
                .map_err(|e| {
                    MsalError::GeneralFailure(format!("Failed to send refresh token request: {e}"))
                })?;

            let status = resp.status();
            let bytes = resp.bytes().await.map_err(|e| {
                MsalError::GeneralFailure(format!(
                    "Failed to read refresh token response body: {e}"
                ))
            })?;

            if status.is_success() {
                serde_json::from_slice::<OidcTokenResponse>(&bytes).map_err(|e| {
                    MsalError::GeneralFailure(format!(
                        "Failed to parse refresh token response: {e}"
                    ))
                })
            } else {
                #[derive(Deserialize, Debug)]
                struct RefreshTokenErrorResponse {
                    error: String,
                    #[allow(dead_code)]
                    error_description: Option<String>,
                }

                let err: RefreshTokenErrorResponse =
                    serde_json::from_slice(&bytes).map_err(|e| {
                        error!(
                            ?e,
                            status = ?status,
                            body = %String::from_utf8_lossy(&bytes),
                            "Unexpected refresh token response"
                        );
                        MsalError::GeneralFailure(format!(
                            "Failed to parse refresh token error response: {e}"
                        ))
                    })?;

                match err.error.as_str() {
                    // Most common refresh failures
                    "invalid_grant" => {
                        error!(
                            desc = ?err.error_description,
                            "Refresh token rejected (invalid_grant)"
                        );
                        Err(MsalError::GeneralFailure(
                            "Refresh token rejected (invalid_grant)".to_string(),
                        ))
                    }
                    "invalid_client" => {
                        error!(
                            desc = ?err.error_description,
                            "Client authentication failed (invalid_client)"
                        );
                        Err(MsalError::GeneralFailure(
                            "Client authentication failed (invalid_client)".to_string(),
                        ))
                    }
                    "invalid_scope" => {
                        error!(
                            desc = ?err.error_description,
                            "Requested scope is invalid for refresh (invalid_scope)"
                        );
                        Err(MsalError::GeneralFailure(
                            "Requested scope is invalid for refresh (invalid_scope)".to_string(),
                        ))
                    }
                    other => {
                        error!(
                            error = %other,
                            desc = ?err.error_description,
                            status = ?status,
                            "Refresh token grant failed with unexpected error"
                        );
                        Err(MsalError::GeneralFailure(format!(
                            "Refresh token grant failed with error: {}",
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
        let config = self.config.read().await;
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
            shell: Some(self.config.read().await.get_shell(None)),
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
            let cfg = self.config.read().await;

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

    impl_himmelblau_hello_key_helpers!();

    #[instrument(level = "debug", skip_all)]
    async fn token_validate(
        &self,
        account_id: &str,
        token: &OidcTokenResponse,
    ) -> Result<AuthResult, IdpError> {
        let token2 = self.user_token_from_oidc(token).await?;
        if account_id.to_string().to_lowercase() != token2.name.to_string().to_lowercase() {
            let msg = format!(
                "Authenticated user {} does not match requested user",
                token2.uuid
            );
            error!(msg);
            return Ok(AuthResult::Denied(msg));
        }
        info!("Authentication successful for user '{}'", token2.uuid);
        if let Some(refresh_token) = token.refresh_token() {
            debug!("Caching refresh token for user '{}'", token2.uuid);
            self.refresh_cache
                .add(
                    account_id,
                    &RefreshCacheEntry::RefreshToken(refresh_token.secret().to_string()),
                )
                .await;
        }
        Ok(AuthResult::Success {
            token: token2.clone(),
        })
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
            shell: Some(self.config.read().await.get_shell(None)),
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
        account_id: &str,
        _token: Option<&UserToken>,
        no_hello_pin: bool,
        keystore: &mut D,
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

        let hello_key = match self.fetch_hello_key(account_id, keystore) {
            Ok((hello_key, _keytype)) => Some(hello_key),
            Err(_) => None,
        };
        // Skip Hello authentication if it is disabled by config
        let hello_enabled = self.config.read().await.get_enable_hello();
        let hello_pin_retry_count = self.config.read().await.get_hello_pin_retry_count();
        if hello_key.is_none()
            || !hello_enabled
            || self.bad_pin_counter.bad_pin_count(account_id).await > hello_pin_retry_count
            || no_hello_pin
        {
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
        } else {
            // Check if the network is even up prior to sending a PIN prompt,
            // otherwise we duplicate the PIN prompt when the network goes down.
            if !self.attempt_online(SystemTime::now()).await {
                // We are offline, fail the authentication now
                return Err(IdpError::BadRequest);
            }

            Ok((AuthRequest::Pin, AuthCredHandler::None))
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        old_token: &UserToken,
        _service: &str,
        no_hello_pin: bool,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
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

        macro_rules! auth_and_validate_hello_key {
            ($hello_key:ident, $keytype:ident, $cred:ident) => {{
                // CRITICAL: Validate that we can load the key, otherwise the offline
                // fallback will allow the user to authenticate with a bad PIN here.
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

                let hello_refresh_token_tag = self.fetch_hello_refresh_token_key_tag(account_id);
                let refresh_cache_entry = keystore.get_tagged_hsm_key(&hello_refresh_token_tag);
                let token = if $keytype == KeyType::Decoupled {
                    // Check for and decrypt any cached tokens
                    let hello_refresh_token_tag = self.fetch_hello_refresh_token_key_tag(account_id);
                    let refresh_token = if let Ok(Some(sealed_refresh_token)) = refresh_cache_entry {
                        let pin = PinValue::new(&$cred).map_err(|e| {
                            error!("Failed initializing pin value: {:?}", e);
                            IdpError::Tpm
                        })?;
                        let (_key, win_hello_storage_key) = tpm
                            .ms_hello_key_load(machine_key, &$hello_key, &pin)
                            .map_err(|e| {
                                error!("Failed loading hello key for refresh token cache: {:?}", e);
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
                                refresh_token
                            }
                            Err(e) => match self.refresh_cache.refresh_token(account_id).await {
                                Ok(RefreshCacheEntry::RefreshToken(refresh_token)) => refresh_token,
                                Ok(_) => {
                                    error!("Invalid refresh cache entry type");
                                    return Err(IdpError::BadRequest);
                                }
                                Err(e2) => {
                                    error!(?e, "Failed unsealing hello refresh token from TPM");
                                    error!(?e2, "Failed retrieving refresh token from mem cache");
                                    return Err(IdpError::BadRequest);
                                }
                            },
                        }
                    } else {
                        match self.refresh_cache.refresh_token(account_id).await {
                            Ok(RefreshCacheEntry::RefreshToken(refresh_token)) => refresh_token,
                            Ok(_) => {
                                error!("Invalid refresh cache entry type");
                                return Err(IdpError::BadRequest);
                            }
                            Err(e) => {
                                error!(?e, "Failed retrieving refresh token from mem cache");
                                return Err(IdpError::BadRequest);
                            }
                        }
                    };
                    // We have a refresh token, exchange that for an access token
                    match self.acquire_token_by_refresh_token(
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
                    error!("Unsupported Hello key type for online auth");
                    let hello_key_tag = self.fetch_hello_key_tag(account_id, false);
                        keystore
                            .delete_tagged_hsm_key(&hello_key_tag)
                            .map_err(|e| {
                                error!("Failed to delete hello key: {:?}", e);
                                IdpError::Tpm
                            })?;
                    return Err(IdpError::BadRequest);
                };

                // Cache the refresh token to disk for offline auth SSO
                let (_key, win_hello_storage_key) = tpm
                    .ms_hello_key_load(machine_key, &$hello_key, &pin)
                    .map_err(|e| {
                        error!("Failed loading hello key for refresh token cache: {:?}", e);
                        IdpError::Tpm
                    })?;
                let refresh_token_zeroizing =
                    zeroize::Zeroizing::new(token.refresh_token().map(|r| r.secret().to_owned()).ok_or_else(|| {
                        error!("Missing refresh token in OIDC response");
                        IdpError::BadRequest
                    })?.as_bytes().to_vec());
                let token2 = self.user_token_from_oidc(&token).await?;
                tpm.seal_data(&win_hello_storage_key, refresh_token_zeroizing)
                    .map_err(|e| {
                        let uuid = token2.uuid.to_string();
                        error!("Failed to seal refresh token for {}: {:?}", uuid, e);
                        IdpError::Tpm
                    })
                    .and_then(|sealed_prt| {
                        let hello_prt_tag = self.fetch_hello_refresh_token_key_tag(account_id);
                        keystore.insert_tagged_hsm_key(&hello_prt_tag, &sealed_prt).map_err(|e| {
                            let uuid = token2.uuid.to_string();
                            error!("Failed to cache hello refresh token for {}: {:?}", uuid, e);
                            IdpError::Tpm
                        })
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
            (AuthCredHandler::SetupPin { token: _ }, PamAuthRequest::SetupPin { pin: cred }) => {
                let hello_tag = self.fetch_hello_key_tag(account_id, false);

                let pin = PinValue::new(&cred).map_err(|e| {
                    error!("Failed setting pin value: {:?}", e);
                    IdpError::Tpm
                })?;
                let (hello_key, keytype) = (
                    tpm.ms_hello_key_create(machine_key, &pin).map_err(|e| {
                        error!("Failed to create hello key: {:?}", e);
                        IdpError::Tpm
                    })?,
                    KeyType::Decoupled,
                );

                keystore
                    .insert_tagged_hsm_key(&hello_tag, &hello_key)
                    .map_err(|e| {
                        error!("Failed to provision hello key: {:?}", e);
                        IdpError::Tpm
                    })?;

                auth_and_validate_hello_key!(hello_key, keytype, cred)
            }
            (_, PamAuthRequest::Pin { cred }) => {
                let (hello_key, keytype) =
                    self.fetch_hello_key(account_id, keystore).map_err(|e| {
                        error!("Online authentication failed. Hello key missing.");
                        e
                    })?;

                auth_and_validate_hello_key!(hello_key, keytype, cred)
            }
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
                    Ok(token) => match self.token_validate(account_id, &token).await {
                        Ok(AuthResult::Success { token: token2 }) => {
                            // Skip Hello enrollment if it is disabled by config
                            let hello_enabled = self.config.read().await.get_enable_hello();
                            if !hello_enabled || no_hello_pin {
                                info!("Skipping Hello enrollment because it is disabled");
                                return Ok((
                                    AuthResult::Success { token: token2 },
                                    AuthCacheAction::None,
                                ));
                            }

                            // Setup Windows Hello
                            *cred_handler = AuthCredHandler::SetupPin { token: None };
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
                    },
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
    async fn offline_break_glass(&self, ttl: Option<u64>) -> Result<(), IdpError> {
        impl_offline_break_glass!(self, ttl)
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_access<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        scopes: Vec<String>,
        old_token: Option<&UserToken>,
        _client_id: Option<String>,
        _keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<UnixUserToken, IdpError> {
        impl_unix_user_access!(
            self,
            old_token,
            scopes,
            _client_id,
            id,
            tpm,
            _machine_key,
            no_op_prt_token_fetch,
            oidc_refresh_token_token_fetch
        )
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
            false,
            impl_create_decoupled_hello_key
        )
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        _token: Option<&UserToken>,
        no_hello_pin: bool,
        keystore: &mut D,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        impl_himmelblau_offline_auth_init!(self, account_id, no_hello_pin, keystore, false)
    }

    #[instrument(level = "debug", skip_all)]
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
            load_cached_prt_no_op
        )
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
