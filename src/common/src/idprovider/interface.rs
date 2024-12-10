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
use himmelblau::{MFAAuthContinue, UserToken as UnixUserToken};
use serde::{Deserialize, Serialize};
use std::fmt;
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
    NotFound,
    /// The idp was unable to perform an operation on the underlying hsm keystorage
    KeyStore,
    /// The idp failed to interact with the configured TPM
    Tpm,
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
    pub gidnumber: u32,
    pub displayname: String,
    pub shell: Option<String>,
    pub groups: Vec<GroupToken>,
    pub tenant_id: Uuid,
    // Defaults to false.
    pub valid: bool,
}

pub enum AuthCredHandler {
    MFA { flow: MFAAuthContinue },
    SetupPin { token: UnixUserToken },
    None,
}

impl fmt::Debug for AuthCredHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthCredHandler::MFA { .. } => f.write_str("MFA { .. }"),
            AuthCredHandler::SetupPin { .. } => f.write_str("SetupPin { .. }"),
            AuthCredHandler::None => f.write_str("None"),
        }
    }
}

pub enum AuthRequest {
    Password,
    MFACode {
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
}

#[allow(clippy::from_over_into)]
impl Into<PamAuthResponse> for AuthRequest {
    fn into(self) -> PamAuthResponse {
        match self {
            AuthRequest::Password => PamAuthResponse::Password,
            AuthRequest::MFACode { msg } => PamAuthResponse::MFACode { msg },
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
        }
    }
}

pub enum AuthResult {
    Success { token: UserToken },
    Denied,
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
        _tpm: &mut tpm::BoxedDynTpm,
        _machine_key: &tpm::MachineKey,
    ) -> Result<(), IdpError> {
        Ok(())
    }

    /// This is similar to a "domain join" process. What do we actually need to pass here
    /// for this to work for kanidm or himmelblau? Should we make it take a generic?
    /*
    async fn configure_machine_identity<D: KeyStoreTxn + Send>(
        &self,
        _keystore: &mut D,
        _tpm: &mut (dyn tpm::Tpm + Send),
        _machine_key: &tpm::MachineKey,
    ) -> Result<(), IdpError> {
        Ok(())
    }
    */

    async fn provider_authenticate(&self, _tpm: &mut tpm::BoxedDynTpm) -> Result<(), IdpError>;

    async fn unix_user_get(
        &self,
        _id: &Id,
        _token: Option<&UserToken>,
        _tpm: &mut tpm::BoxedDynTpm,
        _machine_key: &tpm::MachineKey,
    ) -> Result<UserToken, IdpError>;

    async fn unix_user_access(
        &self,
        _id: &Id,
        _scopes: Vec<String>,
        _token: Option<&UserToken>,
        _tpm: &mut tpm::BoxedDynTpm,
        _machine_key: &tpm::MachineKey,
    ) -> Result<UnixUserToken, IdpError>;

    async fn unix_user_prt_cookie(
        &self,
        _id: &Id,
        _token: Option<&UserToken>,
        _tpm: &mut tpm::BoxedDynTpm,
        _machine_key: &tpm::MachineKey,
    ) -> Result<String, IdpError>;

    async fn change_auth_token<D: KeyStoreTxn + Send>(
        &self,
        _account_id: &str,
        _token: &UnixUserToken,
        _new_tok: &str,
        _keystore: &mut D,
        _tpm: &mut tpm::BoxedDynTpm,
        _machine_key: &tpm::MachineKey,
    ) -> Result<bool, IdpError>;

    async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
        &self,
        _account_id: &str,
        _token: Option<&UserToken>,
        _keystore: &mut D,
        _tpm: &mut tpm::BoxedDynTpm,
        _machine_key: &tpm::MachineKey,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError>;

    async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
        &self,
        _account_id: &str,
        _cred_handler: &mut AuthCredHandler,
        _pam_next_req: PamAuthRequest,
        _keystore: &mut D,
        _tpm: &mut tpm::BoxedDynTpm,
        _machine_key: &tpm::MachineKey,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError>;

    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        _account_id: &str,
        _token: Option<&UserToken>,
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
        _tpm: &mut tpm::BoxedDynTpm,
        _machine_key: &tpm::MachineKey,
        _online_at_init: bool,
    ) -> Result<AuthResult, IdpError>;

    async fn unix_group_get(
        &self,
        id: &Id,
        _tpm: &mut tpm::BoxedDynTpm,
    ) -> Result<GroupToken, IdpError>;
}
