/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use crate::db::KeyStoreTxn;
use crate::unix_proto::{PamAuthRequest, PamAuthResponse};
use async_trait::async_trait;
use himmelblau::{AuthOption, MFAAuthContinue, UserToken as UnixUserToken};
use kanidm_hsm_crypto::structures::SealedData;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::SystemTime;
use tokio::sync::broadcast;
use uuid::Uuid;

pub use kanidm_hsm_crypto as tpm;

/// Errors that the IdProvider may return. These drive the resolver state machine
/// and should be carefully selected to match your expected errors.
#[derive(Debug)]
pub enum IdpError {
    /// An error occurred in the underlying communication to the Idp. A timeout or
    /// or other communication issue exists. The resolver will take this provider
    /// offline.
    Transport,
    /// The provider is online but the provider module is not current authorised with
    /// the idp. After returning this error the operation will be retried after a
    /// successful authentication.
    ProviderUnauthorised,
    /// The provider made an invalid or illogical request to the idp, and a result
    /// is not able to be provided to the resolver.
    BadRequest,
    /// The idp has indicated that the requested resource does not exist and should
    /// be considered deleted, removed, or not present.
    NotFound { what: String, where_: String },
    /// The idp was unable to perform an operation on the underlying hsm keystorage
    KeyStore,
    /// The idp failed to interact with the configured TPM
    Tpm,
}

#[derive(Debug, Clone)]
pub enum CacheState {
    Online,
    Offline,
    OfflineNextCheck(SystemTime),
}

pub enum UserTokenState {
    /// Indicate to the resolver that the cached UserToken should be used, if present.
    UseCached,
    /// The requested entity is not found, or has been removed.
    NotFound,

    /// Update the cache state with the data found in this UserToken.
    Update(UserToken),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Id {
    Name(String),
    Gid(u32),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupToken {
    pub name: String,
    pub spn: String,
    pub uuid: Uuid,
    pub gidnumber: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserToken {
    pub name: String,
    pub spn: String,
    pub uuid: Uuid,
    #[serde(default)]
    pub real_gidnumber: Option<u32>, // This is the actual gidnumber.
    pub gidnumber: u32, // This is actually the uid, and is a legacy carryover from Kanidm
    pub displayname: String,
    pub shell: Option<String>,
    pub groups: Vec<GroupToken>,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    // Defaults to false.
    pub valid: bool,
}

pub enum AuthCredHandler {
    MFA {
        flow: Box<MFAAuthContinue>,
        password: Option<String>,
        extra_data: Option<String>,
    },
    SetupPin {
        token: Box<Option<UnixUserToken>>,
    },
    HelloTOTP {
        cred: String,
        /// Sealed TOTP secret pending validation - only set during initial setup.
        /// Will be saved to HSM after successful TOTP validation.
        pending_sealed_totp: Option<SealedData>,
    },
    ChangePassword {
        old_cred: String,
    },
    /// Password-first authentication for console_password_only mode.
    /// When this handler is active, we first validate the password via ROPC,
    /// then check if sign-in frequency is satisfied via PRT exchange before
    /// prompting for MFA. This allows skipping MFA when Azure's sign-in
    /// frequency policy is already satisfied.
    PasswordFirst {
        /// Auth options to pass if we need to initiate MFA flow
        auth_options: Vec<AuthOption>,
        /// Whether the user is domain joined (affects resource URL in MFA flow)
        is_domain_joined: bool,
    },
    None,
}

impl fmt::Debug for AuthCredHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthCredHandler::MFA { .. } => f.write_str("MFA { .. }"),
            AuthCredHandler::SetupPin { .. } => f.write_str("SetupPin { .. }"),
            AuthCredHandler::HelloTOTP { .. } => f.write_str("HelloTOTP { .. }"),
            AuthCredHandler::ChangePassword { .. } => f.write_str("ChangePassword { .. }"),
            AuthCredHandler::PasswordFirst { .. } => f.write_str("PasswordFirst { .. }"),
            AuthCredHandler::None => f.write_str("None"),
        }
    }
}

pub enum AuthRequest {
    Password,
    MFACode {
        msg: String,
    },
    HelloTOTP {
        msg: String,
    },
    MFAPoll {
        /// Message to display to the user.
        msg: String,
        /// Interval in seconds between poll attemts.
        polling_interval: u32,
    },
    MFAPollWait,
    SetupPin {
        /// Message to display to the user.
        msg: String,
    },
    Pin,
    Fido {
        fido_challenge: String,
        fido_allow_list: Vec<String>,
    },
    ChangePassword {
        /// Message to display to the user.
        msg: String,
    },
    InitDenied {
        /// Message to display to the user.
        msg: String,
    },
}

#[allow(clippy::from_over_into)]
impl Into<PamAuthResponse> for AuthRequest {
    fn into(self) -> PamAuthResponse {
        match self {
            AuthRequest::Password => PamAuthResponse::Password,
            AuthRequest::MFACode { msg } => PamAuthResponse::MFACode { msg },
            AuthRequest::HelloTOTP { msg } => PamAuthResponse::HelloTOTP { msg },
            AuthRequest::MFAPoll {
                msg,
                polling_interval,
            } => PamAuthResponse::MFAPoll {
                msg,
                polling_interval,
            },
            AuthRequest::MFAPollWait => PamAuthResponse::MFAPollWait,
            AuthRequest::SetupPin { msg } => PamAuthResponse::SetupPin { msg },
            AuthRequest::Pin => PamAuthResponse::Pin,
            AuthRequest::Fido {
                fido_challenge,
                fido_allow_list,
            } => PamAuthResponse::Fido {
                fido_challenge,
                fido_allow_list,
            },
            AuthRequest::ChangePassword { msg } => PamAuthResponse::ChangePassword { msg },
            AuthRequest::InitDenied { msg } => PamAuthResponse::InitDenied { msg },
        }
    }
}

pub enum AuthResult {
    Success { token: UserToken },
    Denied(String),
    Next(AuthRequest),
}

pub enum AuthCacheAction {
    None,
    PasswordHashUpdate { cred: String },
}

#[async_trait]
pub trait IdProvider {
    async fn configure_hsm_keys<D: KeyStoreTxn + Send>(
        &self,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<(), IdpError> {
        Ok(())
    }

    async fn check_online(&self, _tpm: &mut tpm::provider::BoxedDynTpm, _now: SystemTime) -> bool;

    async fn unix_user_get<D: KeyStoreTxn + Send>(
        &self,
        _id: &Id,
        _token: Option<&UserToken>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<UserTokenState, IdpError>;

    async fn unix_user_access<D: KeyStoreTxn + Send>(
        &self,
        _id: &Id,
        _scopes: Vec<String>,
        _token: Option<&UserToken>,
        _client_id: Option<String>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<UnixUserToken, IdpError>;

    async fn unix_user_ccaches<D: KeyStoreTxn + Send>(
        &self,
        _id: &Id,
        _old_token: Option<&UserToken>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> (Vec<u8>, Vec<u8>);

    async fn unix_user_prt_cookie<D: KeyStoreTxn + Send>(
        &self,
        _id: &Id,
        _token: Option<&UserToken>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<String, IdpError>;

    async fn change_auth_token<D: KeyStoreTxn + Send>(
        &self,
        _account_id: &str,
        _token: &UnixUserToken,
        _new_tok: &str,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<bool, IdpError>;

    async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
        &self,
        _account_id: &str,
        _token: Option<&UserToken>,
        _service: &str,
        _no_hello_pin: bool,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError>;

    #[allow(clippy::too_many_arguments)]
    async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
        &self,
        _account_id: &str,
        _old_token: &UserToken,
        _service: &str,
        _no_hello_pin: bool,
        _cred_handler: &mut AuthCredHandler,
        _pam_next_req: PamAuthRequest,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError>;

    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        _account_id: &str,
        _token: Option<&UserToken>,
        _no_hello_pin: bool,
        _keystore: &mut D,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError>;

    // I thought about this part of the interface a lot. we could have the
    // provider actually need to check the password or credentials, but then
    // we need to rework the tpm/crypto engine to be an argument to pass here
    // as well the cached credentials.
    //
    // As well, since this is "offline auth" the provider isn't really "doing"
    // anything special here - when you say you want offline password auth, the
    // resolver can just do it for you for all the possible implementations.
    // This is similar for offline ctap2 as well, or even offline totp.
    //
    // I think in the future we could reconsider this and let the provider be
    // involved if there is some "custom logic" or similar that is needed but
    // for now I think making it generic is a good first step and we can change
    // it later.
    //
    // EDIT 04042024: When we're performing an offline PIN auth, the PIN can
    // unlock the associated TPM key. While we can't perform a full request
    // for an auth token, we can verify that the PIN successfully unlocks the
    // TPM key.
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
    ) -> Result<AuthResult, IdpError>;

    async fn unix_group_get(
        &self,
        id: &Id,
        _tpm: &mut tpm::provider::BoxedDynTpm,
    ) -> Result<GroupToken, IdpError>;

    async fn get_cachestate<D: KeyStoreTxn + Send>(
        &self,
        _account_id: Option<&str>,
        _keystore: &mut D,
    ) -> CacheState;

    async fn offline_break_glass(&self, _ttl: Option<u64>) -> Result<(), IdpError>;
}
