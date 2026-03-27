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
use crate::idprovider::common::flip_displayname_comma;
use crate::idprovider::common::KeyType;
use crate::idprovider::common::TotpEnrollmentRecord;
use crate::idprovider::common::{BadPinCounter, RefreshCache, RefreshCacheEntry};
use crate::idprovider::interface::{
    tpm, AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, CacheState, GroupToken, Id,
    IdProvider, IdpError, UserToken, UserTokenState,
};
use crate::unix_proto::PamAuthRequest;
use crate::{
    check_hello_totp_enabled, check_hello_totp_setup, extract_base_url, handle_hello_bad_pin_count,
    impl_change_auth_token, impl_check_online, impl_create_decoupled_hello_key,
    impl_handle_hello_pin_totp_auth, impl_himmelblau_hello_key_helpers,
    impl_himmelblau_offline_auth_init, impl_himmelblau_offline_auth_step, impl_offline_break_glass,
    impl_setup_hello_totp, impl_unix_user_access, load_cached_prt_no_op, no_op_prt_token_fetch,
    oidc_refresh_token_token_fetch,
};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use himmelblau::{error::MsalError, MFAAuthContinue, UserToken as UnixUserToken};
use himmelblau::{ClientInfo, IdToken};
use idmap::Idmap;
use kanidm_hsm_crypto::structures::LoadableMsHelloKey;
use kanidm_hsm_crypto::structures::SealedData;
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
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::UnixStream;
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::time::timeout;
use tokio_util::codec::{Decoder, Encoder, Framed};
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;
use zeroize::Zeroizing;

#[instrument(level = "debug", skip_all)]
pub fn mfa_from_oidc_device(
    details: &OauthDeviceAuthResponse<EmptyExtraDeviceAuthorizationFields>,
) -> Result<(MFAAuthContinue, String), IdpError> {
    let polling_interval = details.interval().as_secs() as u32;
    let expires_in = details.expires_in().as_secs() as u32;

    let msg = match details.verification_uri_complete() {
        Some(complete) => format!(
            "Scan the QR code to continue sign-in, or open this link on another device:\n{}\nIf you cannot scan, visit:\n{}\nAnd enter the code:\n{}",
            complete.secret(),
            details.verification_uri(),
            details.user_code().secret()
        ),
        None => format!(
            "Using a browser on another device, visit:\n{}\nAnd enter the code:\n{}",
            details.verification_uri(),
            details.user_code().secret()
        ),
    };

    /* Allowing this pattern, since the clippy recommendation makes this
     * construct far _less_ clear. */
    #[allow(clippy::manual_checked_ops)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OrchestratorInputType {
    Text,
    Password,
    Otp,
    Confirmation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrchestratorProvidedInput {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrchestratorRequiredInput {
    name: String,
    #[serde(rename = "type")]
    input_type: OrchestratorInputType,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    optional: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct OrchestratorTokenBundle {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    authorization_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum OrchestratorCommand {
    StartSession {
        session_id: String,
        #[serde(default)]
        provider: Option<String>,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        issuer_url: Option<String>,
        #[serde(default)]
        dag_auth_url: Option<String>,
        #[serde(default)]
        dag_user_code: Option<String>,
    },
    NextStep {
        session_id: String,
        #[serde(default)]
        provided_inputs: Vec<OrchestratorProvidedInput>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum OrchestratorResponse {
    NextStep {
        session_id: String,
        required_inputs: Vec<OrchestratorRequiredInput>,
        #[serde(default)]
        message: Option<String>,
    },
    SessionComplete {
        session_id: String,
        success: bool,
        tokens: OrchestratorTokenBundle,
    },
    SessionError {
        session_id: String,
        error: String,
    },
    Error {
        error: String,
    },
    Ack {
        #[serde(default)]
        session_id: Option<String>,
        message: String,
    },
    SessionStatus {
        session_id: String,
        provider: String,
        state: String,
        #[serde(default)]
        detail: Option<String>,
    },
    Pong {
        protocol_version: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrchestratorFlowState {
    session_id: String,
    required_inputs: Vec<OrchestratorRequiredInput>,
    #[serde(default)]
    dag_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum OidcMfaExtraData {
    DeviceFlow { dag_json: String },
    Orchestrator { state: OrchestratorFlowState },
}

#[derive(Debug, Clone)]
struct OidcOrchestratorConfig {
    enabled: bool,
    socket_path: String,
    provider: Option<String>,
    timeout: Duration,
    poll_interval_secs: u32,
}

fn orchestrator_input_type_label(input_type: &OrchestratorInputType) -> &'static str {
    match input_type {
        OrchestratorInputType::Text => "text",
        OrchestratorInputType::Password => "password",
        OrchestratorInputType::Otp => "otp",
        OrchestratorInputType::Confirmation => "confirmation",
    }
}

fn orchestrator_required_inputs_summary(
    required_inputs: &[OrchestratorRequiredInput],
) -> Vec<String> {
    required_inputs
        .iter()
        .map(|input| {
            format!(
                "{}:{}:{}",
                input.name,
                orchestrator_input_type_label(&input.input_type),
                if input.optional {
                    "optional"
                } else {
                    "required"
                }
            )
        })
        .collect()
}

fn orchestrator_provided_input_names(provided_inputs: &[OrchestratorProvidedInput]) -> Vec<String> {
    provided_inputs
        .iter()
        .map(|input| input.name.clone())
        .collect()
}

fn pam_auth_request_kind(pam_next_req: &PamAuthRequest) -> &'static str {
    match pam_next_req {
        PamAuthRequest::Password { .. } => "password",
        PamAuthRequest::MFACode { .. } => "mfa_code",
        PamAuthRequest::MFAPoll { .. } => "mfa_poll",
        PamAuthRequest::Pin { .. } => "pin",
        PamAuthRequest::SetupPin { .. } => "setup_pin",
        PamAuthRequest::HelloTOTP { .. } => "hello_totp",
        PamAuthRequest::Fido { .. } => "fido",
    }
}

fn auth_request_kind(auth_req: &AuthRequest) -> &'static str {
    match auth_req {
        AuthRequest::Password => "password",
        AuthRequest::MFACode { .. } => "mfa_code",
        AuthRequest::HelloTOTP { .. } => "hello_totp",
        AuthRequest::MFAPoll { .. } => "mfa_poll",
        AuthRequest::MFAPollWait => "mfa_poll_wait",
        AuthRequest::SetupPin { .. } => "setup_pin",
        AuthRequest::Pin => "pin",
        AuthRequest::Fido { .. } => "fido",
        AuthRequest::ChangePassword { .. } => "change_password",
        AuthRequest::InitDenied { .. } => "init_denied",
    }
}

fn orchestrator_response_kind(response: &OrchestratorResponse) -> &'static str {
    match response {
        OrchestratorResponse::NextStep { .. } => "next_step",
        OrchestratorResponse::SessionComplete { .. } => "session_complete",
        OrchestratorResponse::SessionError { .. } => "session_error",
        OrchestratorResponse::Error { .. } => "error",
        OrchestratorResponse::Ack { .. } => "ack",
        OrchestratorResponse::SessionStatus { .. } => "session_status",
        OrchestratorResponse::Pong { .. } => "pong",
    }
}

fn orchestrator_command_kind(command: &OrchestratorCommand) -> &'static str {
    match command {
        OrchestratorCommand::StartSession { .. } => "start_session",
        OrchestratorCommand::NextStep { .. } => "next_step",
    }
}

fn orchestrator_command_session_id(command: &OrchestratorCommand) -> Option<&str> {
    match command {
        OrchestratorCommand::StartSession { session_id, .. }
        | OrchestratorCommand::NextStep { session_id, .. } => Some(session_id.as_str()),
    }
}

#[derive(Default)]
struct OrchestratorCodec;

const MAX_ORCHESTRATOR_RESPONSE_BYTES: usize = 64 * 1024;

impl Decoder for OrchestratorCodec {
    type Error = std::io::Error;
    type Item = OrchestratorResponse;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() > MAX_ORCHESTRATOR_RESPONSE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "orchestrator response exceeds {} bytes (got {})",
                    MAX_ORCHESTRATOR_RESPONSE_BYTES,
                    src.len()
                ),
            ));
        }

        match serde_json::from_slice::<OrchestratorResponse>(src) {
            Ok(message) => {
                src.clear();
                Ok(Some(message))
            }
            Err(err) if err.is_eof() => Ok(None),
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to decode orchestrator response: {err}"),
            )),
        }
    }
}

impl Encoder<OrchestratorCommand> for OrchestratorCodec {
    type Error = std::io::Error;

    fn encode(&mut self, msg: OrchestratorCommand, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = serde_json::to_vec(&msg).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed encoding orchestrator command: {err}"),
            )
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

async fn orchestrator_send_command(
    cfg: &OidcOrchestratorConfig,
    command: OrchestratorCommand,
) -> Result<OrchestratorResponse, IdpError> {
    let command_kind = orchestrator_command_kind(&command);
    let command_session_id = orchestrator_command_session_id(&command)
        .map(str::to_string)
        .unwrap_or_else(|| "-".to_string());
    match &command {
        OrchestratorCommand::StartSession {
            provider,
            username,
            issuer_url,
            dag_auth_url,
            dag_user_code,
            ..
        } => {
            debug!(
                socket = %cfg.socket_path,
                command = command_kind,
                session_id = command_session_id,
                provider = ?provider,
                has_username = username.is_some(),
                has_issuer_url = issuer_url.is_some(),
                has_dag_auth_url = dag_auth_url.is_some(),
                has_dag_user_code = dag_user_code.is_some(),
                timeout = ?cfg.timeout,
                "Sending orchestrator start session command"
            );
        }
        OrchestratorCommand::NextStep {
            provided_inputs, ..
        } => {
            debug!(
                socket = %cfg.socket_path,
                command = command_kind,
                session_id = command_session_id,
                provided_input_count = provided_inputs.len(),
                provided_input_names = ?orchestrator_provided_input_names(provided_inputs),
                timeout = ?cfg.timeout,
                "Sending orchestrator next step command"
            );
        }
    }

    let stream = timeout(cfg.timeout, UnixStream::connect(&cfg.socket_path))
        .await
        .map_err(|_| {
            error!(
                socket = %cfg.socket_path,
                command = command_kind,
                session_id = command_session_id,
                timeout = ?cfg.timeout,
                "Timed out connecting to orchestrator socket"
            );
            IdpError::BadRequest
        })?
        .map_err(|err| {
            debug!(
                ?err,
                socket = %cfg.socket_path,
                command = command_kind,
                session_id = command_session_id,
                "Orchestrator socket unavailable"
            );
            IdpError::BadRequest
        })?;

    let mut framed = Framed::new(stream, OrchestratorCodec);
    timeout(cfg.timeout, framed.send(command))
        .await
        .map_err(|_| {
            error!(
                command = command_kind,
                session_id = command_session_id,
                timeout = ?cfg.timeout,
                "Timed out sending orchestrator command"
            );
            IdpError::BadRequest
        })?
        .map_err(|err| {
            error!(
                ?err,
                command = command_kind,
                session_id = command_session_id,
                "Failed sending orchestrator command"
            );
            IdpError::BadRequest
        })?;

    let response = timeout(cfg.timeout, framed.next()).await.map_err(|_| {
        error!(
            command = command_kind,
            session_id = command_session_id,
            timeout = ?cfg.timeout,
            "Timed out waiting orchestrator response"
        );
        IdpError::BadRequest
    })?;

    match response {
        Some(Ok(message)) => {
            debug!(
                command = command_kind,
                session_id = command_session_id,
                response = orchestrator_response_kind(&message),
                "Received orchestrator response"
            );
            Ok(message)
        }
        Some(Err(err)) => {
            error!(
                ?err,
                command = command_kind,
                session_id = command_session_id,
                "Failed decoding orchestrator response"
            );
            Err(IdpError::BadRequest)
        }
        None => {
            error!(
                command = command_kind,
                session_id = command_session_id,
                "Orchestrator closed connection before response"
            );
            Err(IdpError::BadRequest)
        }
    }
}

async fn orchestrator_try_start(
    cfg: &OidcOrchestratorConfig,
    account_id: &str,
    issuer_url: Option<String>,
    dag_auth_url: Option<String>,
    dag_user_code: Option<String>,
    dag_json: Option<String>,
) -> Result<Option<OidcMfaExtraData>, IdpError> {
    let session_id = Uuid::new_v4().to_string();
    debug!(
        %session_id,
        provider = ?cfg.provider,
        account_id = %account_id,
        has_issuer_url = issuer_url.is_some(),
        has_dag_auth_url = dag_auth_url.is_some(),
        has_dag_user_code = dag_user_code.is_some(),
        has_dag_json = dag_json.is_some(),
        "Attempting orchestrator session start"
    );

    let response = match orchestrator_send_command(
        cfg,
        OrchestratorCommand::StartSession {
            session_id,
            provider: cfg.provider.clone(),
            username: Some(account_id.to_string()),
            issuer_url,
            dag_auth_url,
            dag_user_code,
        },
    )
    .await
    {
        Ok(response) => response,
        Err(_) => {
            debug!(
                provider = ?cfg.provider,
                account_id = %account_id,
                "Orchestrator start failed; falling back to direct OIDC device flow"
            );
            return Ok(None);
        }
    };

    match response {
        OrchestratorResponse::NextStep {
            session_id,
            required_inputs,
            message,
        } => {
            if let Some(msg) = message {
                debug!(%session_id, %msg, "Orchestrator start response message");
            }
            debug!(
                %session_id,
                required_input_count = required_inputs.len(),
                required_inputs = ?orchestrator_required_inputs_summary(&required_inputs),
                has_dag_json = dag_json.is_some(),
                "Orchestrator start returned next step"
            );
            Ok(Some(OidcMfaExtraData::Orchestrator {
                state: OrchestratorFlowState {
                    session_id,
                    required_inputs,
                    dag_json,
                },
            }))
        }
        OrchestratorResponse::SessionComplete {
            session_id,
            success,
            tokens,
        } => {
            debug!(
                %session_id,
                success,
                has_access = tokens.access_token.is_some(),
                has_id = tokens.id_token.is_some(),
                has_refresh = tokens.refresh_token.is_some(),
                has_authorization_code = tokens.authorization_code.is_some(),
                "Orchestrator completed at session start"
            );
            if success {
                info!(
                    %session_id,
                    has_access = tokens.access_token.is_some(),
                    has_id = tokens.id_token.is_some(),
                    has_refresh = tokens.refresh_token.is_some(),
                    "Orchestrator completed during session start"
                );
            } else {
                warn!(%session_id, "Orchestrator reported unsuccessful completion");
            }
            Ok(None)
        }
        OrchestratorResponse::SessionError { session_id, error } => {
            warn!(%session_id, %error, "Orchestrator rejected start request");
            Ok(None)
        }
        OrchestratorResponse::Error { error } => {
            warn!(%error, "Orchestrator returned error response");
            Ok(None)
        }
        other => {
            warn!(
                response = orchestrator_response_kind(&other),
                ?other,
                "Unexpected orchestrator start response; falling back"
            );
            Ok(None)
        }
    }
}

async fn orchestrator_continue(
    cfg: &OidcOrchestratorConfig,
    state: &OrchestratorFlowState,
    provided_inputs: Vec<OrchestratorProvidedInput>,
) -> Result<OrchestratorResponse, IdpError> {
    debug!(
        session_id = %state.session_id,
        required_input_count = state.required_inputs.len(),
        required_inputs = ?orchestrator_required_inputs_summary(&state.required_inputs),
        provided_input_count = provided_inputs.len(),
        provided_input_names = ?orchestrator_provided_input_names(&provided_inputs),
        has_dag_json = state.dag_json.is_some(),
        "Continuing orchestrator session"
    );

    orchestrator_send_command(
        cfg,
        OrchestratorCommand::NextStep {
            session_id: state.session_id.clone(),
            provided_inputs,
        },
    )
    .await
}

fn parse_oidc_mfa_extra_data(raw: &str) -> Result<OidcMfaExtraData, IdpError> {
    match serde_json::from_str::<OidcMfaExtraData>(raw) {
        Ok(extra) => Ok(extra),
        Err(_) => Ok(OidcMfaExtraData::DeviceFlow {
            dag_json: raw.to_string(),
        }),
    }
}

fn serialize_oidc_mfa_extra_data(extra: &OidcMfaExtraData) -> Result<String, IdpError> {
    serde_json::to_string(extra).map_err(|err| {
        error!(?err, "Failed serializing OIDC MFA state");
        IdpError::BadRequest
    })
}

fn auth_request_from_orchestrator_inputs(
    required_inputs: &[OrchestratorRequiredInput],
    poll_interval_secs: u32,
) -> AuthRequest {
    debug!(
        required_input_count = required_inputs.len(),
        required_inputs = ?orchestrator_required_inputs_summary(required_inputs),
        poll_interval_secs,
        "Selecting next PAM request from orchestrator inputs"
    );

    if required_inputs
        .iter()
        .any(|input| matches!(input.input_type, OrchestratorInputType::Password))
    {
        debug!("Selected Password prompt from orchestrator inputs");
        return AuthRequest::Password;
    }

    if let Some(input) = required_inputs.iter().find(|input| {
        matches!(
            input.input_type,
            OrchestratorInputType::Otp | OrchestratorInputType::Text
        )
    }) {
        let msg = input
            .prompt
            .clone()
            .unwrap_or_else(|| format!("Enter value for {}", input.name));
        debug!(
            selected_input = %input.name,
            input_type = orchestrator_input_type_label(&input.input_type),
            "Selected MFACode prompt from orchestrator inputs"
        );
        return AuthRequest::MFACode { msg };
    }

    if let Some(input) = required_inputs
        .iter()
        .find(|input| matches!(input.input_type, OrchestratorInputType::Confirmation))
    {
        debug!(
            selected_input = %input.name,
            "Selected MFAPoll prompt from orchestrator confirmation input"
        );
        return AuthRequest::MFAPoll {
            msg: input.prompt.clone().unwrap_or_else(|| {
                "Approve sign-in in your authenticator app, then wait...".to_string()
            }),
            polling_interval: poll_interval_secs,
        };
    }

    debug!("No explicit orchestrator input matched; defaulting to MFAPoll waiting prompt");
    AuthRequest::MFAPoll {
        msg: "Waiting for browser authentication to complete...".to_string(),
        polling_interval: poll_interval_secs,
    }
}

fn orchestrator_inputs_from_pam_request(
    pam_next_req: PamAuthRequest,
    required_inputs: &[OrchestratorRequiredInput],
) -> Result<Vec<OrchestratorProvidedInput>, IdpError> {
    debug!(
        pam_request = pam_auth_request_kind(&pam_next_req),
        required_input_count = required_inputs.len(),
        required_inputs = ?orchestrator_required_inputs_summary(required_inputs),
        "Mapping PAM auth input to orchestrator provided inputs"
    );

    match pam_next_req {
        PamAuthRequest::MFAPoll { .. } => {
            let confirmation_inputs = required_inputs
                .iter()
                .filter(|input| matches!(input.input_type, OrchestratorInputType::Confirmation))
                .map(|input| OrchestratorProvidedInput {
                    name: input.name.clone(),
                    value: "true".to_string(),
                })
                .collect::<Vec<_>>();

            debug!(
                provided_input_count = confirmation_inputs.len(),
                provided_input_names = ?orchestrator_provided_input_names(&confirmation_inputs),
                "Mapped MFAPoll request to orchestrator confirmation inputs"
            );

            Ok(confirmation_inputs)
        }
        PamAuthRequest::Password { cred } => {
            let target = required_inputs
                .iter()
                .find(|input| matches!(input.input_type, OrchestratorInputType::Password))
                .or_else(|| {
                    if required_inputs.len() == 1 {
                        required_inputs.first()
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    error!("Orchestrator requested no password input for Password prompt");
                    IdpError::BadRequest
                })?;

            let mapped = vec![OrchestratorProvidedInput {
                name: target.name.clone(),
                value: cred,
            }];

            debug!(
                target_input = %target.name,
                provided_input_count = mapped.len(),
                provided_input_names = ?orchestrator_provided_input_names(&mapped),
                "Mapped Password request to orchestrator input"
            );

            Ok(mapped)
        }
        PamAuthRequest::MFACode { cred } => {
            let target = required_inputs
                .iter()
                .find(|input| {
                    matches!(
                        input.input_type,
                        OrchestratorInputType::Otp | OrchestratorInputType::Text
                    )
                })
                .or_else(|| {
                    if required_inputs.len() == 1 {
                        required_inputs.first()
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    error!("Orchestrator requested no MFA code/text input for MFACode prompt");
                    IdpError::BadRequest
                })?;

            let mapped = vec![OrchestratorProvidedInput {
                name: target.name.clone(),
                value: cred,
            }];

            debug!(
                target_input = %target.name,
                provided_input_count = mapped.len(),
                provided_input_names = ?orchestrator_provided_input_names(&mapped),
                "Mapped MFACode request to orchestrator input"
            );

            Ok(mapped)
        }
        _ => {
            error!("Invalid PAM request type for orchestrator MFA flow");
            Err(IdpError::BadRequest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        auth_request_from_orchestrator_inputs, mfa_from_oidc_device,
        orchestrator_inputs_from_pam_request, parse_oidc_mfa_extra_data,
        serialize_oidc_mfa_extra_data, OidcMfaExtraData, OrchestratorFlowState,
        OrchestratorInputType, OrchestratorRequiredInput,
    };
    use crate::idprovider::interface::AuthRequest;
    use crate::unix_proto::PamAuthRequest;
    use oauth2::DeviceAuthorizationResponse;
    use serde_json::json;

    #[test]
    fn mfa_message_prefers_verification_uri_complete() {
        let payload = json!({
            "device_code": "device-code",
            "user_code": "USER-CODE",
            "verification_uri": "https://login.example/device",
            "verification_uri_complete": "https://login.example/device?user_code=USER-CODE",
            "expires_in": 900,
            "interval": 5
        });
        let details: DeviceAuthorizationResponse<_> = serde_json::from_value(payload).unwrap();
        let (mfa, _) = mfa_from_oidc_device(&details).unwrap();

        assert!(mfa
            .msg
            .contains("https://login.example/device?user_code=USER-CODE"));
        assert!(mfa.msg.contains("https://login.example/device"));
        assert!(mfa.msg.contains("USER-CODE"));
    }

    #[test]
    fn mfa_message_falls_back_to_verification_uri() {
        let payload = json!({
            "device_code": "device-code",
            "user_code": "USER-CODE",
            "verification_uri": "https://login.example/device",
            "expires_in": 900,
            "interval": 5
        });
        let details: DeviceAuthorizationResponse<_> = serde_json::from_value(payload).unwrap();
        let (mfa, _) = mfa_from_oidc_device(&details).unwrap();

        assert!(mfa.msg.contains("https://login.example/device"));
        assert!(mfa.msg.contains("USER-CODE"));
    }

    #[test]
    fn orchestrator_extra_data_round_trip() {
        let original = OidcMfaExtraData::Orchestrator {
            state: OrchestratorFlowState {
                session_id: "session-1".to_string(),
                required_inputs: vec![OrchestratorRequiredInput {
                    name: "password".to_string(),
                    input_type: OrchestratorInputType::Password,
                    prompt: Some("Password".to_string()),
                    optional: false,
                }],
                dag_json: Some("{\"device_code\":\"abc\"}".to_string()),
            },
        };

        let serialized = serialize_oidc_mfa_extra_data(&original).unwrap();
        let parsed = parse_oidc_mfa_extra_data(&serialized).unwrap();

        match parsed {
            OidcMfaExtraData::Orchestrator { state } => {
                assert_eq!(state.session_id, "session-1");
                assert_eq!(state.required_inputs.len(), 1);
                assert_eq!(state.required_inputs[0].name, "password");
                assert_eq!(state.dag_json.as_deref(), Some("{\"device_code\":\"abc\"}"));
            }
            OidcMfaExtraData::DeviceFlow { .. } => panic!("expected orchestrator state"),
        }
    }

    #[test]
    fn legacy_extra_data_defaults_to_device_flow() {
        let legacy = "{\"legacy\":\"dag\"}";
        let parsed = parse_oidc_mfa_extra_data(legacy).unwrap();

        match parsed {
            OidcMfaExtraData::DeviceFlow { dag_json } => assert_eq!(dag_json, legacy),
            OidcMfaExtraData::Orchestrator { .. } => panic!("expected device flow fallback"),
        }
    }

    #[test]
    fn auth_request_prefers_password_prompt() {
        let required_inputs = vec![
            OrchestratorRequiredInput {
                name: "otp".to_string(),
                input_type: OrchestratorInputType::Otp,
                prompt: Some("OTP".to_string()),
                optional: false,
            },
            OrchestratorRequiredInput {
                name: "password".to_string(),
                input_type: OrchestratorInputType::Password,
                prompt: Some("Password".to_string()),
                optional: false,
            },
        ];

        let request = auth_request_from_orchestrator_inputs(&required_inputs, 2);
        assert!(matches!(request, AuthRequest::Password));
    }

    #[test]
    fn auth_request_confirmation_maps_to_poll() {
        let required_inputs = vec![OrchestratorRequiredInput {
            name: "approve".to_string(),
            input_type: OrchestratorInputType::Confirmation,
            prompt: Some("Approve in app".to_string()),
            optional: false,
        }];

        let request = auth_request_from_orchestrator_inputs(&required_inputs, 5);
        match request {
            AuthRequest::MFAPoll {
                msg,
                polling_interval,
            } => {
                assert_eq!(msg, "Approve in app");
                assert_eq!(polling_interval, 5);
            }
            _ => panic!("expected MFAPoll request"),
        }
    }

    #[test]
    fn pam_password_maps_to_orchestrator_input() {
        let required_inputs = vec![OrchestratorRequiredInput {
            name: "password".to_string(),
            input_type: OrchestratorInputType::Password,
            prompt: None,
            optional: false,
        }];

        let mapped = orchestrator_inputs_from_pam_request(
            PamAuthRequest::Password {
                cred: "secret".to_string(),
            },
            &required_inputs,
        )
        .unwrap();

        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].name, "password");
        assert_eq!(mapped[0].value, "secret");
    }

    #[test]
    fn pam_invalid_step_returns_error() {
        let required_inputs = vec![OrchestratorRequiredInput {
            name: "password".to_string(),
            input_type: OrchestratorInputType::Password,
            prompt: None,
            optional: false,
        }];

        let result = orchestrator_inputs_from_pam_request(
            PamAuthRequest::Pin {
                cred: "1234".to_string(),
            },
            &required_inputs,
        );

        assert!(result.is_err());
    }

    #[test]
    fn pam_poll_maps_confirmation_to_orchestrator_input() {
        let required_inputs = vec![OrchestratorRequiredInput {
            name: "approve".to_string(),
            input_type: OrchestratorInputType::Confirmation,
            prompt: Some("Approve sign-in".to_string()),
            optional: false,
        }];

        let mapped = orchestrator_inputs_from_pam_request(
            PamAuthRequest::MFAPoll { poll_attempt: 1 },
            &required_inputs,
        )
        .unwrap();

        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].name, "approve");
        assert_eq!(mapped[0].value, "true");
    }

    #[test]
    fn pam_poll_without_confirmation_inputs_returns_empty() {
        let required_inputs = vec![OrchestratorRequiredInput {
            name: "password".to_string(),
            input_type: OrchestratorInputType::Password,
            prompt: None,
            optional: false,
        }];

        let mapped = orchestrator_inputs_from_pam_request(
            PamAuthRequest::MFAPoll { poll_attempt: 1 },
            &required_inputs,
        )
        .unwrap();

        assert!(mapped.is_empty());
    }
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
    fn into_unix_user_token(self) -> Result<UnixUserToken, MsalError>;
}

#[derive(Deserialize)]
struct OidcIdTokenPayload {
    name: Option<String>,
    oid: Option<String>,
    preferred_username: Option<String>,
    puid: Option<String>,
    tenant_region_scope: Option<String>,
    tid: Option<String>,
}

impl OidcTokenResponseExt for OidcTokenResponse {
    fn into_unix_user_token(self) -> Result<UnixUserToken, MsalError> {
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

            let mut siter = raw.splitn(3, '.');
            siter.next();
            let payload_str = match siter.next() {
                Some(payload_str) => URL_SAFE_NO_PAD
                    .decode(payload_str)
                    .map_err(|e| MsalError::InvalidParse(format!("Failed parsing id_token: {}", e)))
                    .and_then(|bytes| {
                        String::from_utf8(bytes).map_err(|e| {
                            MsalError::InvalidParse(format!("Failed parsing id_token: {}", e))
                        })
                    })?,
                None => {
                    return Err(MsalError::InvalidParse(
                        "Failed parsing id_token payload".to_string(),
                    ));
                }
            };

            let payload: OidcIdTokenPayload = serde_json::from_str(&payload_str).map_err(|e| {
                MsalError::InvalidParse(format!("Failed parsing id_token from json: {}", e))
            })?;
            IdToken {
                name: payload.name.unwrap_or_default(),
                oid: payload.oid.unwrap_or_default(),
                preferred_username: payload.preferred_username,
                puid: payload.puid,
                tenant_region_scope: payload.tenant_region_scope,
                tid: payload.tid.unwrap_or_default(),
                raw: Some(raw),
            }
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
    openid_configuration_url: String,
}

pub struct OidcApplication {
    client: RwLock<Option<OidcDelayedInit>>,
}

impl OidcApplication {
    #[instrument(level = "debug", skip_all)]
    pub fn new() -> Self {
        Self {
            client: RwLock::new(None),
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn with_init(config: &HimmelblauConfig, domain: &str) -> Result<Self, IdpError> {
        let app = Self::new();
        app.delayed_init(config, domain).await?;
        Ok(app)
    }

    #[instrument(level = "debug", skip_all)]
    async fn delayed_init(&self, config: &HimmelblauConfig, domain: &str) -> Result<(), IdpError> {
        let init = self.client.read().await.is_some();
        if !init {
            let client_id = ClientId::new(config.get_app_id(domain).ok_or_else(|| {
                error!(
                    "Missing OIDC client ID in config: `[global] app_id` required for OIDC auth"
                );
                IdpError::BadRequest
            })?);

            let issuer_url = IssuerUrl::new(config.get_oidc_issuer_url().ok_or_else(|| {
                error!("Missing OIDC issuer URL in config");
                IdpError::BadRequest
            })?)
            .map_err(|e| {
                error!(
                    ?e,
                    "Invalid OIDC issuer URL: {:?}",
                    config.get_oidc_issuer_url()
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
            let openid_configuration_url = format!(
                "{}/.well-known/openid-configuration",
                provider_metadata.issuer().as_str().trim_end_matches('/')
            );

            let device_endpoint = provider_metadata
                .additional_metadata()
                .device_authorization_endpoint
                .clone();

            // Create a public client: pass None for the client secret.
            // Whether this works depends on provider configuration. Many support it.
            let client = CoreClient::from_provider_metadata(provider_metadata, client_id, None)
                .set_device_authorization_url(device_endpoint)
                .set_auth_type(AuthType::RequestBody);

            // Store provider initialization
            self.client.write().await.replace(OidcDelayedInit {
                client,
                http_client,
                authorization_endpoint,
                openid_configuration_url,
            });
        }
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, Option<OidcDelayedInit>> {
        self.client.read().await
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn initiate_device_flow(
        &self,
    ) -> Result<DeviceAuthorizationResponse<EmptyExtraDeviceAuthorizationFields>, MsalError> {
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
    pub async fn acquire_token_by_device_flow(
        &self,
        flow: &DeviceAuthorizationResponse<EmptyExtraDeviceAuthorizationFields>,
    ) -> Result<OidcTokenResponse, MsalError> {
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
    pub async fn acquire_token_by_refresh_token(
        &self,
        refresh_token: &str,
        scopes: Vec<&str>,
    ) -> Result<OidcTokenResponse, MsalError> {
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
    async fn user_token_from_oidc(
        &self,
        token: &openidconnect::core::CoreTokenResponse,
        config: &HimmelblauConfig,
        idmap: &Idmap,
        tenant_id: &Uuid,
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
            .preferred_username()
            .map(|username| username.to_string())
            .or_else(|| userinfo.email().map(|email| email.to_string()))
            .ok_or_else(|| {
                error!("Missing preferred_username and email claims in userinfo");
                IdpError::BadRequest
            })?;

        let subject = userinfo.subject().to_string();
        let object_id = uuid::Uuid::new_v5(tenant_id, subject.as_bytes());

        let idmap_cache = StaticIdCache::new(ID_MAP_CACHE, false).map_err(|e| {
            error!("Failed reading from the idmap cache: {:?}", e);
            IdpError::BadRequest
        })?;

        let (uid, gid) = match idmap_cache.get_user_by_name(&account_id) {
            Some(user) => (user.uid, user.gid),
            None => {
                let gid = idmap
                    .gen_to_unix(&tenant_id.to_string(), &account_id)
                    .map_err(|e| {
                        error!("{:?}", e);
                        IdpError::BadRequest
                    })?;
                (gid, gid)
            }
        };

        let displayname = userinfo
            .name()
            .and_then(|n| n.get(None))
            .map(|n| n.to_string())
            .unwrap_or_default();

        let displayname = flip_displayname_comma(&displayname);

        Ok(UserToken {
            name: account_id.to_string(),
            spn: account_id.to_string(),
            uuid: object_id,
            real_gidnumber: Some(uid),
            gidnumber: gid,
            displayname,
            shell: Some(config.get_shell(None)),
            groups: vec![GroupToken {
                name: account_id.to_string(),
                spn: account_id.to_string(),
                uuid: object_id,
                gidnumber: gid,
            }],
            tenant_id: Some(*tenant_id),
            valid: true,
        })
    }
}

impl Default for OidcApplication {
    fn default() -> Self {
        Self::new()
    }
}

pub struct OidcProvider {
    config: Arc<RwLock<HimmelblauConfig>>,
    idmap: Arc<RwLock<Idmap>>,
    state: Mutex<CacheState>,
    client: OidcApplication,
    refresh_cache: RefreshCache,
    bad_pin_counter: BadPinCounter,
    domain: String,
}

impl OidcProvider {
    #[instrument(level = "debug", skip_all)]
    pub fn new(
        cfg: &Arc<RwLock<HimmelblauConfig>>,
        domain: &str,
        idmap: &Arc<RwLock<Idmap>>,
    ) -> Result<Self, IdpError> {
        Ok(Self {
            config: cfg.clone(),
            idmap: idmap.clone(),
            state: Mutex::new(CacheState::OfflineNextCheck(SystemTime::now())),
            client: OidcApplication::new(),
            refresh_cache: RefreshCache::new(),
            bad_pin_counter: BadPinCounter::new(),
            domain: domain.to_string(),
        })
    }

    #[instrument(level = "debug", skip_all)]
    async fn tenant_id(&self) -> Result<Uuid, IdpError> {
        let config = self.config.read().await;
        let issuer = config.get_oidc_issuer_url().ok_or_else(|| {
            error!("Missing OIDC issuer URL in config");
            IdpError::BadRequest
        })?;
        Ok(Uuid::new_v5(&HIMMELBLAU_OIDC_NAMESPACE, issuer.as_bytes()))
    }

    #[instrument(level = "debug", skip(self, _tpm))]
    async fn attempt_online(&self, _tpm: &mut tpm::provider::BoxedDynTpm, now: SystemTime) -> bool {
        if (self.delayed_init().await).is_err() {
            // Initialization failed. Report that the system is offline. We
            // can't proceed with initialization until the system is online.
            info!("Network down detected");
            let mut state = self.state.lock().await;
            *state = CacheState::OfflineNextCheck(SystemTime::now() + OFFLINE_NEXT_CHECK);
            return false;
        }
        let (authorization_endpoint, openid_configuration_url) =
            match self.client.read().await.as_ref() {
                Some(init) => (
                    init.authorization_endpoint.clone(),
                    init.openid_configuration_url.clone(),
                ),
                None => {
                    error!("OIDC client not initialized");
                    let mut state = self.state.lock().await;
                    *state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                    return false;
                }
            };

        // First try the authorization endpoint
        match reqwest::get(&authorization_endpoint).await {
            Ok(resp) => {
                if resp.status().is_success() {
                    debug!("provider is now online");
                    let mut state = self.state.lock().await;
                    *state = CacheState::Online;
                    return true;
                }
                // Authorization endpoint returned non-success (e.g., Keycloak returns 400).
                // Fallback to the openid-configuration URL which should always respond.
                debug!(
                    ?authorization_endpoint,
                    status = %resp.status(),
                    "Authorization endpoint returned non-success, trying openid-configuration"
                );
            }
            Err(err) => {
                // Network error - provider is definitely offline
                error!(?err, ?authorization_endpoint, "Provider online failed");
                let mut state = self.state.lock().await;
                *state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                return false;
            }
        }

        // Fallback: try the .well-known/openid-configuration URL
        match reqwest::get(&openid_configuration_url).await {
            Ok(resp) => {
                if resp.status().is_success() {
                    debug!("provider is now online (via openid-configuration)");
                    let mut state = self.state.lock().await;
                    *state = CacheState::Online;
                    return true;
                } else {
                    error!(
                        ?openid_configuration_url,
                        "Provider online failed: {}",
                        resp.status()
                    );
                    let mut state = self.state.lock().await;
                    *state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                    return false;
                }
            }
            Err(err) => {
                error!(?err, ?openid_configuration_url, "Provider online failed");
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

            // Initialize the idmap range
            let tenant_id = self.tenant_id().await?.to_string();
            let range = cfg.get_idmap_range(&self.domain);
            let mut idmap = self.idmap.write().await;
            idmap
                .add_gen_domain(&self.domain, &tenant_id, range)
                .map_err(|e| {
                    error!("Failed adding the idmap domain: {}", e);
                    IdpError::BadRequest
                })?;

            self.client.delayed_init(&cfg, &self.domain).await?;
        }
        Ok(())
    }

    async fn orchestrator_config(&self) -> OidcOrchestratorConfig {
        let cfg = self.config.read().await;

        let enabled = cfg.get_orchestrator_enabled();

        let socket_path = cfg.get_orchestrator_socket();
        let provider = cfg.get_orchestrator_provider();
        let timeout_secs = cfg.get_orchestrator_timeout_secs();
        let poll_interval_secs = cfg.get_orchestrator_poll_secs();

        if enabled {
            debug!(
                socket = %socket_path,
                provider = ?provider,
                timeout_secs,
                poll_interval_secs,
                "OIDC orchestrator integration is enabled"
            );
        }

        OidcOrchestratorConfig {
            enabled,
            socket_path,
            provider,
            timeout: Duration::from_secs(timeout_secs.max(1)),
            poll_interval_secs: poll_interval_secs.max(1),
        }
    }

    async fn maybe_start_orchestrator_flow(
        &self,
        account_id: &str,
        dag_details: &OauthDeviceAuthResponse<EmptyExtraDeviceAuthorizationFields>,
    ) -> Result<Option<(AuthRequest, AuthCredHandler)>, IdpError> {
        let cfg = self.orchestrator_config().await;
        if !cfg.enabled {
            debug!(account_id = %account_id, "Orchestrator disabled; using direct OIDC device flow");
            return Ok(None);
        }

        let dag_auth_url = dag_details
            .verification_uri_complete()
            .map(|complete| complete.secret().to_string())
            .unwrap_or_else(|| dag_details.verification_uri().to_string());
        let dag_user_code = Some(dag_details.user_code().secret().to_string());
        let (_, dag_json) = mfa_from_oidc_device(dag_details)?;
        debug!(
            account_id = %account_id,
            provider = ?cfg.provider,
            dag_poll_interval_secs = dag_details.interval().as_secs(),
            dag_expires_in_secs = dag_details.expires_in().as_secs(),
            has_verification_uri_complete = dag_details.verification_uri_complete().is_some(),
            "Prepared DAG details for orchestrator start"
        );

        let issuer_url = self.config.read().await.get_oidc_issuer_url();
        let Some(extra_data) = orchestrator_try_start(
            &cfg,
            account_id,
            issuer_url,
            Some(dag_auth_url),
            dag_user_code,
            Some(dag_json),
        )
        .await?
        else {
            debug!(
                account_id = %account_id,
                provider = ?cfg.provider,
                "Orchestrator flow not started; continuing with direct OIDC MFA"
            );
            return Ok(None);
        };

        let OidcMfaExtraData::Orchestrator { state } = extra_data else {
            return Ok(None);
        };

        let auth_request =
            auth_request_from_orchestrator_inputs(&state.required_inputs, cfg.poll_interval_secs);
        debug!(
            session_id = %state.session_id,
            account_id = %account_id,
            required_input_count = state.required_inputs.len(),
            required_inputs = ?orchestrator_required_inputs_summary(&state.required_inputs),
            selected_auth_request = auth_request_kind(&auth_request),
            poll_interval_secs = cfg.poll_interval_secs,
            "Orchestrator flow started successfully"
        );
        let serialized = serialize_oidc_mfa_extra_data(&OidcMfaExtraData::Orchestrator { state })?;

        Ok(Some((
            auth_request,
            AuthCredHandler::MFA {
                flow: Box::new(MFAAuthContinue {
                    polling_interval: Some(cfg.poll_interval_secs.saturating_mul(1000)),
                    ..Default::default()
                }),
                password: None,
                extra_data: Some(serialized),
                reauth_hello_pin: None,
            },
        )))
    }

    async fn finalize_mfa_success(
        &self,
        account_id: &str,
        no_hello_pin: bool,
        cred_handler: &mut AuthCredHandler,
        token: OidcTokenResponse,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        match self.token_validate(account_id, &token).await {
            Ok(AuthResult::Success { token: token2 }) => {
                let hello_enabled = self.config.read().await.get_enable_hello();
                if !hello_enabled || no_hello_pin {
                    info!("Skipping Hello enrollment because it is disabled");
                    return Ok((AuthResult::Success { token: token2 }, AuthCacheAction::None));
                }

                *cred_handler = AuthCredHandler::SetupPin {
                    token: Box::new(None),
                };
                Ok((
                    AuthResult::Next(AuthRequest::SetupPin {
                        msg: format!(
                            "Set up a PIN\n {}{}",
                            "A Hello PIN is a fast, secure way to sign",
                            "in to your device, apps, and services."
                        ),
                    }),
                    AuthCacheAction::None,
                ))
            }
            Ok(auth_result) => Ok((auth_result, AuthCacheAction::None)),
            Err(e) => Err(e),
        }
    }

    impl_himmelblau_hello_key_helpers!();

    #[instrument(level = "debug", skip_all)]
    async fn token_validate(
        &self,
        account_id: &str,
        token: &OidcTokenResponse,
    ) -> Result<AuthResult, IdpError> {
        let token2 = self
            .client
            .user_token_from_oidc(
                token,
                &*self.config.read().await,
                &*self.idmap.read().await,
                &self.tenant_id().await?,
            )
            .await?;
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
    #[instrument(level = "debug", skip(self, tpm))]
    async fn check_online(&self, tpm: &mut tpm::provider::BoxedDynTpm, now: SystemTime) -> bool {
        impl_check_online!(self, tpm, now)
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

        let displayname = flip_displayname_comma(&displayname);

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
        service: &str,
        no_hello_pin: bool,
        force_reauth: bool,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
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
        let remote_services = self
            .config
            .read()
            .await
            .get_password_only_remote_services_deny_list();
        // Check if this is a remote service:
        // - Service starts with "remote:" (set by PAM module when PAM_RHOST is set)
        // - Service name contains any entry from remote_services_deny_list
        let is_remote_service = service.starts_with("remote:")
            || remote_services
                .iter()
                .any(|s| !s.is_empty() && service.contains(s));
        let hello_totp_enabled = check_hello_totp_enabled!(self);
        let allow_remote_hello = self.config.read().await.get_allow_remote_hello();
        // Skip Hello authentication if it is disabled by config
        let hello_enabled = self.config.read().await.get_enable_hello();
        let hello_pin_retry_count = self.config.read().await.get_hello_pin_retry_count();
        if hello_key.is_none()
            || !hello_enabled
            || (is_remote_service && !hello_totp_enabled && !allow_remote_hello)
            || self.bad_pin_counter.bad_pin_count(account_id).await > hello_pin_retry_count
            || no_hello_pin
            || force_reauth
        {
            let device_flow = self.client.initiate_device_flow().await.map_err(|e| {
                error!(?e, "Failed to initiate device flow");
                IdpError::BadRequest
            })?;

            if let Some(orchestrator_flow) = self
                .maybe_start_orchestrator_flow(account_id, &device_flow)
                .await?
            {
                return Ok(orchestrator_flow);
            }

            let (flow, extra_data) = mfa_from_oidc_device(&device_flow)?;

            let extra_data = serialize_oidc_mfa_extra_data(&OidcMfaExtraData::DeviceFlow {
                dag_json: extra_data,
            })?;

            let polling_interval = flow.polling_interval.unwrap_or(5000);
            Ok((
                AuthRequest::MFAPoll {
                    msg: flow.msg.clone(),
                    polling_interval: polling_interval / 1000,
                },
                AuthCredHandler::MFA {
                    flow: Box::new(flow),
                    password: None,
                    extra_data: Some(extra_data),
                    reauth_hello_pin: None,
                },
            ))
        } else {
            // Check if the network is even up prior to sending a PIN prompt,
            // otherwise we duplicate the PIN prompt when the network goes down.
            if !self.attempt_online(tpm, SystemTime::now()).await {
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
                                    return Ok((
                                        AuthResult::Denied("Session data corrupted. Please sign in again.".to_string()),
                                        AuthCacheAction::None,
                                    ));
                                }
                                Err(e2) => {
                                    error!(?e, "Failed unsealing hello refresh token from TPM");
                                    error!(?e2, "Failed retrieving refresh token from mem cache");
                                    return Ok((
                                        AuthResult::Denied("Your session has expired. Please sign in again.".to_string()),
                                        AuthCacheAction::None,
                                    ));
                                }
                            },
                        }
                    } else {
                        match self.refresh_cache.refresh_token(account_id).await {
                            Ok(RefreshCacheEntry::RefreshToken(refresh_token)) => refresh_token,
                            Ok(_) => {
                                error!("Invalid refresh cache entry type");
                                return Ok((
                                    AuthResult::Denied("Session data corrupted. Please sign in again.".to_string()),
                                    AuthCacheAction::None,
                                ));
                            }
                            Err(e) => {
                                error!(?e, "Failed retrieving refresh token from mem cache");
                                return Ok((
                                    AuthResult::Denied("Your session has expired. Please sign in again.".to_string()),
                                    AuthCacheAction::None,
                                ));
                            }
                        }
                    };
                    // We have a refresh token, exchange that for an access token
                    match self.client.acquire_token_by_refresh_token(
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
                            if check_hello_totp_enabled!(self) {
                                if !check_hello_totp_setup!(self, account_id, keystore) {
                                    return impl_setup_hello_totp!(
                                        self,
                                        account_id,
                                        keystore,
                                        old_token,
                                        $cred,
                                        tpm,
                                        machine_key,
                                        cred_handler
                                    );
                                } else {
                                    *cred_handler = AuthCredHandler::HelloTOTP {
                                        cred: $cred.clone(),
                                        pending_sealed_totp: None,
                                    };
                                    return Ok((AuthResult::Next(AuthRequest::HelloTOTP {
                                        msg: "Please enter your Hello TOTP code from your Authenticator: "
                                            .to_string(),
                                    }), AuthCacheAction::None));
                                }
                            } else {
                                return Ok((
                                    AuthResult::Success {
                                        token: old_token.clone(),
                                    },
                                    AuthCacheAction::None,
                                ));
                            }
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
                            return Ok((
                                AuthResult::Denied("Your session has expired. Please sign in again.".to_string()),
                                AuthCacheAction::None,
                            ));
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
                    return Ok((
                        AuthResult::Denied("Your session has expired. Please sign in again.".to_string()),
                        AuthCacheAction::None,
                    ));
                };

                // Cache the refresh token to disk for offline auth SSO
                let (_key, win_hello_storage_key) = tpm
                    .ms_hello_key_load(machine_key, &$hello_key, &pin)
                    .map_err(|e| {
                        error!("Failed loading hello key for refresh token cache: {:?}", e);
                        IdpError::Tpm
                    })?;
                let refresh_token_zeroizing = match token.refresh_token().map(|r| r.secret().to_owned()) {
                    Some(rt) => zeroize::Zeroizing::new(rt.as_bytes().to_vec()),
                    None => {
                        error!("Missing refresh token in OIDC response");
                        return Ok((
                            AuthResult::Denied("Authentication incomplete. Please try again.".to_string()),
                            AuthCacheAction::None,
                        ));
                    }
                };
                let token2 = self.client.user_token_from_oidc(
                    &token,
                    &*self.config.read().await,
                    &*self.idmap.read().await,
                    &self.tenant_id().await?,
                ).await?;
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
                        if check_hello_totp_enabled!(self) {
                            if !check_hello_totp_setup!(self, account_id, keystore) {
                                return impl_setup_hello_totp!(
                                    self,
                                    account_id,
                                    keystore,
                                    old_token,
                                    $cred,
                                    tpm,
                                    machine_key,
                                    cred_handler
                                );
                            } else {
                                *cred_handler = AuthCredHandler::HelloTOTP {
                                    cred: $cred.clone(),
                                    pending_sealed_totp: None,
                                };
                                return Ok((AuthResult::Next(AuthRequest::HelloTOTP {
                                    msg: "Please enter your Hello TOTP code from your Authenticator: "
                                        .to_string(),
                                }), AuthCacheAction::None));
                            }
                        } else {
                            debug!("Returning user token from successful Hello PIN authentication.");
                            Ok((AuthResult::Success { token }, AuthCacheAction::None))
                        }
                    }
                    /* This should never happen. It doesn't make sense to
                     * continue from a Pin auth. */
                    Ok(AuthResult::Next(_)) => {
                        debug!("Invalid additional authentication requested with Hello auth.");
                        Ok((
                            AuthResult::Denied("Unexpected authentication step. Please try signing in again.".to_string()),
                            AuthCacheAction::None,
                        ))
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

                let hello_key = impl_create_decoupled_hello_key!(
                    self,
                    None,
                    false,
                    tpm,
                    machine_key,
                    cred,
                    IdpError::Tpm
                );
                let keytype = KeyType::Decoupled;

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
                    reauth_hello_pin: _,
                },
                pam_next_req,
            ) => {
                let stored_state = match extra_data.as_ref() {
                    Some(data) => data,
                    None => {
                        error!("Missing extra_data in OIDC MFA handler");
                        return Ok((
                            AuthResult::Denied(
                                "Authentication session data missing. Please try again."
                                    .to_string(),
                            ),
                            AuthCacheAction::None,
                        ));
                    }
                };

                let parsed_state = match parse_oidc_mfa_extra_data(stored_state) {
                    Ok(state) => state,
                    Err(_) => {
                        error!("Failed to deserialize OIDC MFA state");
                        return Ok((
                            AuthResult::Denied(
                                "Authentication session corrupted. Please try again.".to_string(),
                            ),
                            AuthCacheAction::None,
                        ));
                    }
                };

                match parsed_state {
                    OidcMfaExtraData::DeviceFlow { dag_json } => {
                        let poll_attempt = match pam_next_req {
                            PamAuthRequest::MFAPoll { poll_attempt } => poll_attempt,
                            _ => {
                                error!("Invalid auth step for OIDC device flow MFA handler");
                                return Ok((
                                    AuthResult::Denied(
                                        "Unexpected authentication step. Please try signing in again."
                                            .to_string(),
                                    ),
                                    AuthCacheAction::None,
                                ));
                            }
                        };

                        let max_poll_attempts = flow.max_poll_attempts.unwrap_or(180);
                        if poll_attempt > max_poll_attempts {
                            error!("MFA polling timed out");
                            return Ok((
                                AuthResult::Denied(
                                    "Authentication timed out. Please try again.".to_string(),
                                ),
                                AuthCacheAction::None,
                            ));
                        }

                        let flow = match serde_json::from_str(&dag_json) {
                            Ok(f) => f,
                            Err(e) => {
                                error!(?e, "Failed to deserialize OIDC DAG");
                                return Ok((
                                    AuthResult::Denied(
                                        "Authentication session corrupted. Please try again."
                                            .to_string(),
                                    ),
                                    AuthCacheAction::None,
                                ));
                            }
                        };

                        match self.client.acquire_token_by_device_flow(&flow).await {
                            Ok(token) => {
                                self.finalize_mfa_success(
                                    account_id,
                                    no_hello_pin,
                                    cred_handler,
                                    token,
                                )
                                .await
                            }
                            Err(MsalError::MFAPollContinue) => Ok((
                                AuthResult::Next(AuthRequest::MFAPollWait),
                                AuthCacheAction::None,
                            )),
                            Err(e) => {
                                error!("{:?}", e);
                                Ok((
                                    AuthResult::Denied(format!("Authentication failed: {}", e)),
                                    AuthCacheAction::None,
                                ))
                            }
                        }
                    }
                    OidcMfaExtraData::Orchestrator { state } => {
                        let cfg = self.orchestrator_config().await;
                        debug!(
                            session_id = %state.session_id,
                            account_id = %account_id,
                            pam_request = pam_auth_request_kind(&pam_next_req),
                            required_input_count = state.required_inputs.len(),
                            required_inputs = ?orchestrator_required_inputs_summary(&state.required_inputs),
                            has_dag_json = state.dag_json.is_some(),
                            "Handling orchestrator-backed MFA step"
                        );

                        let poll_attempt = match &pam_next_req {
                            PamAuthRequest::MFAPoll { poll_attempt } => Some(*poll_attempt),
                            _ => None,
                        };
                        let dag_flow = match state.dag_json.as_deref() {
                            Some(raw) => {
                                match serde_json::from_str::<
                                    OauthDeviceAuthResponse<EmptyExtraDeviceAuthorizationFields>,
                                >(raw)
                                {
                                    Ok(flow_state) => Some(flow_state),
                                    Err(e) => {
                                        error!(?e, "Failed to deserialize orchestrator DAG state");
                                        return Ok((
                                            AuthResult::Denied(
                                                "Authentication session corrupted. Please try again."
                                                    .to_string(),
                                            ),
                                            AuthCacheAction::None,
                                        ));
                                    }
                                }
                            }
                            None => None,
                        };

                        if let Some(poll_attempt) = poll_attempt {
                            let max_poll_attempts = flow.max_poll_attempts.unwrap_or(180);
                            debug!(
                                session_id = %state.session_id,
                                poll_attempt,
                                max_poll_attempts,
                                has_dag_flow = dag_flow.is_some(),
                                "Processing orchestrator MFA poll request"
                            );
                            if poll_attempt > max_poll_attempts {
                                error!(
                                    session_id = %state.session_id,
                                    poll_attempt,
                                    max_poll_attempts,
                                    "Orchestrator MFA polling timed out"
                                );
                                return Ok((
                                    AuthResult::Denied(
                                        "Authentication timed out. Please try again.".to_string(),
                                    ),
                                    AuthCacheAction::None,
                                ));
                            }

                            if let Some(flow_state) = dag_flow.as_ref() {
                                debug!(
                                    session_id = %state.session_id,
                                    poll_attempt,
                                    "Polling DAG token endpoint before orchestrator continuation"
                                );
                                match self.client.acquire_token_by_device_flow(flow_state).await {
                                    Ok(token) => {
                                        info!(
                                            session_id = %state.session_id,
                                            poll_attempt,
                                            "DAG token endpoint returned success during orchestrator poll"
                                        );
                                        return self
                                            .finalize_mfa_success(
                                                account_id,
                                                no_hello_pin,
                                                cred_handler,
                                                token,
                                            )
                                            .await;
                                    }
                                    Err(MsalError::MFAPollContinue) => {
                                        debug!(
                                            session_id = %state.session_id,
                                            poll_attempt,
                                            "DAG token endpoint still pending; returning MFAPollWait"
                                        );
                                        return Ok((
                                            AuthResult::Next(AuthRequest::MFAPollWait),
                                            AuthCacheAction::None,
                                        ));
                                    }
                                    Err(e) => {
                                        error!(
                                            ?e,
                                            session_id = %state.session_id,
                                            poll_attempt,
                                            "Failed polling DAG token endpoint"
                                        );
                                        return Ok((
                                            AuthResult::Denied(format!(
                                                "Authentication failed: {}",
                                                e
                                            )),
                                            AuthCacheAction::None,
                                        ));
                                    }
                                }
                            }
                        }

                        let provided_inputs = match orchestrator_inputs_from_pam_request(
                            pam_next_req,
                            &state.required_inputs,
                        ) {
                            Ok(inputs) => inputs,
                            Err(_) => {
                                return Ok((
                                    AuthResult::Denied(
                                        "Unexpected authentication step. Please try signing in again."
                                            .to_string(),
                                    ),
                                    AuthCacheAction::None,
                                ));
                            }
                        };

                        debug!(
                            session_id = %state.session_id,
                            provided_input_count = provided_inputs.len(),
                            provided_input_names = ?orchestrator_provided_input_names(&provided_inputs),
                            "Mapped PAM step to orchestrator continuation inputs"
                        );

                        match orchestrator_continue(&cfg, &state, provided_inputs).await {
                            Ok(OrchestratorResponse::NextStep {
                                session_id,
                                required_inputs,
                                message,
                            }) => {
                                if let Some(msg) = message {
                                    debug!(%session_id, %msg, "Orchestrator step response");
                                }

                                debug!(
                                    %session_id,
                                    required_input_count = required_inputs.len(),
                                    required_inputs = ?orchestrator_required_inputs_summary(&required_inputs),
                                    "Orchestrator returned next step"
                                );

                                let next_state = OidcMfaExtraData::Orchestrator {
                                    state: OrchestratorFlowState {
                                        session_id: session_id.clone(),
                                        required_inputs: required_inputs.clone(),
                                        dag_json: state.dag_json.clone(),
                                    },
                                };
                                *extra_data = Some(serialize_oidc_mfa_extra_data(&next_state)?);

                                let next_req = auth_request_from_orchestrator_inputs(
                                    &required_inputs,
                                    cfg.poll_interval_secs,
                                );
                                debug!(
                                    %session_id,
                                    next_auth_request = auth_request_kind(&next_req),
                                    poll_interval_secs = cfg.poll_interval_secs,
                                    "Returning next auth request from orchestrator step"
                                );
                                flow.polling_interval =
                                    Some(cfg.poll_interval_secs.saturating_mul(1000));
                                Ok((AuthResult::Next(next_req), AuthCacheAction::None))
                            }
                            Ok(OrchestratorResponse::SessionComplete {
                                session_id,
                                success,
                                tokens,
                            }) => {
                                info!(
                                    %session_id,
                                    success,
                                    has_access = tokens.access_token.is_some(),
                                    has_id = tokens.id_token.is_some(),
                                    has_refresh = tokens.refresh_token.is_some(),
                                    has_authorization_code = tokens.authorization_code.is_some(),
                                    "Orchestrator session reported completion"
                                );

                                if !success {
                                    return Ok((
                                        AuthResult::Denied(
                                            "Authentication failed in browser flow.".to_string(),
                                        ),
                                        AuthCacheAction::None,
                                    ));
                                }

                                if let Some(flow_state) = dag_flow.as_ref() {
                                    debug!(
                                        %session_id,
                                        "Attempting DAG token polling after orchestrator completion"
                                    );
                                    match self.client.acquire_token_by_device_flow(flow_state).await
                                    {
                                        Ok(token) => {
                                            info!(
                                                %session_id,
                                                "DAG token endpoint succeeded after orchestrator completion"
                                            );
                                            return self
                                                .finalize_mfa_success(
                                                    account_id,
                                                    no_hello_pin,
                                                    cred_handler,
                                                    token,
                                                )
                                                .await;
                                        }
                                        Err(MsalError::MFAPollContinue) => {
                                            debug!(
                                                %session_id,
                                                "DAG token still pending after orchestrator completion"
                                            );
                                            return Ok((
                                                AuthResult::Next(AuthRequest::MFAPollWait),
                                                AuthCacheAction::None,
                                            ));
                                        }
                                        Err(e) => {
                                            error!(
                                                ?e,
                                                %session_id,
                                                "Failed polling DAG token endpoint"
                                            );
                                            return Ok((
                                                AuthResult::Denied(format!(
                                                    "Authentication failed: {}",
                                                    e
                                                )),
                                                AuthCacheAction::None,
                                            ));
                                        }
                                    }
                                }

                                let refresh_token = match tokens.refresh_token {
                                    Some(token) => token,
                                    None => {
                                        error!(
                                            %session_id,
                                            "Orchestrator completion missing refresh token"
                                        );
                                        return Ok((
                                            AuthResult::Denied(
                                                "Authentication did not return a refresh token. Please try again."
                                                    .to_string(),
                                            ),
                                            AuthCacheAction::None,
                                        ));
                                    }
                                };

                                match self
                                    .client
                                    .acquire_token_by_refresh_token(&refresh_token, vec![])
                                    .await
                                {
                                    Ok(token) => {
                                        info!(
                                            %session_id,
                                            "Refresh token exchange succeeded after orchestrator completion"
                                        );
                                        self.finalize_mfa_success(
                                            account_id,
                                            no_hello_pin,
                                            cred_handler,
                                            token,
                                        )
                                        .await
                                    }
                                    Err(e) => {
                                        error!(
                                            ?e,
                                            %session_id,
                                            "Failed exchanging orchestrator refresh token"
                                        );
                                        Ok((
                                            AuthResult::Denied(
                                                "Authentication flow completed but token exchange failed. Please try again."
                                                    .to_string(),
                                            ),
                                            AuthCacheAction::None,
                                        ))
                                    }
                                }
                            }
                            Ok(OrchestratorResponse::SessionError { session_id, error }) => {
                                warn!(
                                    %session_id,
                                    %error,
                                    "Orchestrator returned session error during MFA step"
                                );
                                Ok((
                                    AuthResult::Denied(format!("Authentication failed: {}", error)),
                                    AuthCacheAction::None,
                                ))
                            }
                            Ok(OrchestratorResponse::Error { error }) => {
                                warn!(
                                    %error,
                                    "Orchestrator returned generic error during MFA step"
                                );
                                Ok((
                                    AuthResult::Denied(format!("Authentication failed: {}", error)),
                                    AuthCacheAction::None,
                                ))
                            }
                            Ok(other) => {
                                warn!(
                                    response = orchestrator_response_kind(&other),
                                    ?other,
                                    "Unexpected orchestrator response during MFA step"
                                );
                                Ok((
                                    AuthResult::Denied(
                                        "Authentication session returned an unexpected state. Please try again."
                                            .to_string(),
                                    ),
                                    AuthCacheAction::None,
                                ))
                            }
                            Err(_) => {
                                error!(
                                    session_id = %state.session_id,
                                    "Orchestrator continue command failed"
                                );
                                Ok((
                                    AuthResult::Denied(
                                        "Browser authentication backend unavailable. Please try again."
                                            .to_string(),
                                    ),
                                    AuthCacheAction::None,
                                ))
                            }
                        }
                    }
                }
            }
            (
                AuthCredHandler::HelloTOTP {
                    cred: hello_pin,
                    pending_sealed_totp,
                },
                PamAuthRequest::HelloTOTP { cred },
            ) => {
                impl_handle_hello_pin_totp_auth!(
                    self,
                    account_id,
                    keystore,
                    old_token,
                    cred,
                    hello_pin,
                    tpm,
                    machine_key,
                    pending_sealed_totp,
                    |auth_result| { (auth_result, AuthCacheAction::None) }
                )
            }
            _ => {
                error!("Invalid auth step");
                Ok((
                    AuthResult::Denied(
                        "Unexpected authentication step. Please try signing in again.".to_string(),
                    ),
                    AuthCacheAction::None,
                ))
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
    async fn unix_user_tgts<D: KeyStoreTxn + Send>(
        &self,
        _id: &Id,
        _old_token: Option<&UserToken>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> (
        Option<Box<libkrimes::proto::KerberosCredentials>>,
        Option<Box<libkrimes::proto::KerberosCredentials>>,
        Option<String>,
        Option<String>,
    ) {
        (None, None, None, None)
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_prt_cookie<D: KeyStoreTxn + Send>(
        &self,
        _id: &Id,
        _token: Option<&UserToken>,
        _sso_nonce: Option<&str>,
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
