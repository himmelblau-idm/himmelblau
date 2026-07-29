/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use crate::i18n;
use himmelblau::intune::NoncompliantRule;
use libc::uid_t;
use libkrimes::proto::KerberosCredentials;
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NssUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub homedir: String,
    pub shell: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NssGroup {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PamAuthResponse {
    Unknown,
    Success,
    Denied(String),
    Password {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        long_prompt: Option<String>,
    },
    /// PAM must prompt for a generic input value.
    #[serde(alias = "MFACode")]
    Input {
        msg: String,
        #[serde(default)]
        echo_on: bool,
    },
    /// PAM must prompt for a TOTP code
    HelloTOTP {
        msg: String,
    },
    /// PAM will poll for an external response
    MFAPoll {
        /// Initial message to display as the polling begins.
        msg: String,
        /// Seconds between polling attempts.
        polling_interval: u32,
        /// Whether PAM should append push-notification troubleshooting text.
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        show_push_hint: bool,
    },
    MFAPollWait,
    /// PAM must prompt for a new PIN and confirm that PIN input
    SetupPin {
        msg: String,
    },
    Pin,
    /// PAM must generate a Fido assertion
    Fido {
        fido_challenge: String,
        fido_allow_list: Vec<String>,
        has_physical_security_key: bool,
        has_cross_device: bool,
    },
    /// PAM must prompt for a new password and confirm that password input
    ChangePassword {
        msg: String,
    },
    /// PAM message indicating why auth init was denied
    InitDenied {
        msg: String,
    },
}

impl PamAuthResponse {
    pub fn translate_user_visible(self) -> Self {
        match self {
            PamAuthResponse::Denied(msg) => {
                PamAuthResponse::Denied(i18n::translate_external_message(&msg))
            }
            PamAuthResponse::Password {
                prompt,
                long_prompt,
            } => PamAuthResponse::Password {
                prompt: prompt.map(|msg| i18n::translate_external_message(&msg)),
                long_prompt: long_prompt.map(|msg| i18n::translate_external_message(&msg)),
            },
            PamAuthResponse::Input { msg, echo_on } => PamAuthResponse::Input {
                msg: i18n::translate_external_message(&msg),
                echo_on,
            },
            PamAuthResponse::HelloTOTP { msg } => PamAuthResponse::HelloTOTP {
                msg: i18n::translate_external_message(&msg),
            },
            PamAuthResponse::MFAPoll {
                msg,
                polling_interval,
                show_push_hint,
            } => PamAuthResponse::MFAPoll {
                msg: i18n::translate_external_message(&msg),
                polling_interval,
                show_push_hint,
            },
            PamAuthResponse::SetupPin { msg } => PamAuthResponse::SetupPin {
                msg: i18n::translate_external_message(&msg),
            },
            PamAuthResponse::ChangePassword { msg } => PamAuthResponse::ChangePassword {
                msg: i18n::translate_external_message(&msg),
            },
            PamAuthResponse::InitDenied { msg } => PamAuthResponse::InitDenied {
                msg: i18n::translate_external_message(&msg),
            },
            PamAuthResponse::Unknown
            | PamAuthResponse::Success
            | PamAuthResponse::MFAPollWait
            | PamAuthResponse::Pin
            | PamAuthResponse::Fido { .. } => self,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PamAuthRequest {
    Password {
        cred: String,
    },
    #[serde(alias = "MFACode")]
    Input {
        cred: String,
    },
    HelloTOTP {
        cred: String,
    },
    MFAPoll {
        poll_attempt: u32,
    },
    SetupPin {
        pin: String,
    },
    Pin {
        cred: String,
    },
    Fido {
        assertion: String,
    },
    /// FIDO hardware is unavailable (no USB key, no Bluetooth for cross-device).
    /// The daemon should fall back to password authentication.
    FidoUnavailable,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRequest {
    NssAccounts,
    NssAccountByUid(u32),
    NssAccountByName(String),
    NssGroups,
    NssGroupByGid(u32),
    NssGroupByName(String),
    NssInitgroups(String),
    PamAuthenticateInit(String, String, bool, bool),
    PamAuthenticateStep(PamAuthRequest),
    PamAccountAllowed(String),
    PamAccountBeginSession(String),
    PamChangeAuthToken(String, String, String, String),
    PamTryUnseal(String, String),
    InvalidateCache,
    ClearCache,
    OfflineBreakGlass(Option<u64>),
    Status,
    ComplianceCheck,
}

impl ClientRequest {
    /// Get a safe display version of the request, without credentials.
    pub fn as_safe_string(&self) -> String {
        match self {
            ClientRequest::NssAccounts => "NssAccounts".to_string(),
            ClientRequest::NssAccountByUid(id) => format!("NssAccountByUid({})", id),
            ClientRequest::NssAccountByName(id) => format!("NssAccountByName({})", id),
            ClientRequest::NssGroups => "NssGroups".to_string(),
            ClientRequest::NssGroupByGid(id) => format!("NssGroupByGid({})", id),
            ClientRequest::NssGroupByName(id) => format!("NssGroupByName({})", id),
            ClientRequest::NssInitgroups(id) => format!("NssInitgroups({})", id),
            ClientRequest::PamAuthenticateInit(id, service, no_hello_pin, force_reauth) => {
                format!(
                    "PamAuthenticateInit({}, {}, no_hello_pin: {}, force_reauth: {})",
                    id, service, no_hello_pin, force_reauth
                )
            }
            ClientRequest::PamAuthenticateStep(_) => "PamAuthenticateStep".to_string(),
            ClientRequest::PamAccountAllowed(id) => {
                format!("PamAccountAllowed({})", id)
            }
            ClientRequest::PamAccountBeginSession(_) => "PamAccountBeginSession".to_string(),
            ClientRequest::PamChangeAuthToken(id, _, _, _) => {
                format!("PamChangeAuthToken({}, ...)", id)
            }
            ClientRequest::PamTryUnseal(id, _) => {
                format!("PamTryUnseal({})", id)
            }
            ClientRequest::InvalidateCache => "InvalidateCache".to_string(),
            ClientRequest::ClearCache => "ClearCache".to_string(),
            ClientRequest::OfflineBreakGlass(ttl) => format!("OfflineBreakGlass({:?})", ttl),
            ClientRequest::Status => "Status".to_string(),
            ClientRequest::ComplianceCheck => "ComplianceCheck".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientResponse {
    NssAccounts(Vec<NssUser>),
    NssAccount(Option<NssUser>),
    NssGroups(Vec<NssGroup>),
    NssGroup(Option<NssGroup>),
    NssInitgroups(Option<Vec<u32>>),

    PamStatus(Option<bool>),
    PamAuthenticateStepResponse(PamAuthResponse),

    Ok,
    Error,
    NotAuthenticated,
    /// Non-compliant verdict with rule details passed through from Intune.
    NonCompliant(Vec<NoncompliantRule>),
}

impl From<PamAuthResponse> for ClientResponse {
    fn from(par: PamAuthResponse) -> Self {
        ClientResponse::PamAuthenticateStepResponse(par)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HomeDirectoryInfo {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub aliases: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum TaskRequest {
    HomeDirectory(HomeDirectoryInfo),
    LocalGroups(String, bool),
    LogonScript(String, String),
    KerberosConfig(Option<String>, Option<String>),
    KerberosTGTs(
        uid_t,
        uid_t,
        Option<Box<KerberosCredentials>>,
        Option<Box<KerberosCredentials>>,
    ),
    LoadProfilePhoto(String, String),
    ApplyPolicy(Option<String>, String, String, String, String),
    /// Set up subordinate UID/GID mappings for container support (podman, etc.)
    /// Parameters: (username, subid_start, subid_count)
    SubordinateIds(String, u32, u32),
}

impl TaskRequest {
    /// Get a safe display version of the request, without credentials.
    pub fn as_safe_string(&self) -> String {
        match self {
            TaskRequest::HomeDirectory(_) => "HomeDirectory(...)".to_string(),
            TaskRequest::LocalGroups(_, _) => "LocalGroups(...)".to_string(),
            TaskRequest::LogonScript(_, _) => "LogonScript(...)".to_string(),
            TaskRequest::KerberosConfig(..) => "KerberosConfig(...)".to_string(),
            TaskRequest::KerberosTGTs(uid, gid, _, _) => {
                format!("KerberosTGTs({}, {}, ...)", uid, gid)
            }
            TaskRequest::LoadProfilePhoto(_, _) => "LoadProfilePhoto(...)".to_string(),
            TaskRequest::ApplyPolicy(intune_device_id, _, _, _, _) => {
                format!("ApplyPolicy({:?}, ...)", intune_device_id)
            }
            TaskRequest::SubordinateIds(username, start, count) => {
                format!("SubordinateIds({}, {}, {})", username, start, count)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TaskResponse {
    Success(i32),
    Error(String),
    /// ApplyPolicy completed with a non-compliant verdict from Intune.
    NonCompliant(Vec<NoncompliantRule>),
}

#[test]
fn test_clientrequest_as_safe_string() {
    assert_eq!(
        ClientRequest::NssAccounts.as_safe_string(),
        "NssAccounts".to_string()
    );

    let safe =
        ClientRequest::PamTryUnseal("user@example.com".to_string(), "s3cret-pin".to_string())
            .as_safe_string();
    assert!(
        !safe.contains("s3cret-pin"),
        "as_safe_string() must not leak credentials: {}",
        safe
    );
}

#[test]
fn test_legacy_mfa_code_response_defaults_to_hidden_input() {
    let response: PamAuthResponse = serde_json::from_str(r#"{"MFACode":{"msg":"Code:"}}"#).unwrap();

    match response {
        PamAuthResponse::Input { msg, echo_on } => {
            assert_eq!(msg, "Code:");
            assert!(!echo_on);
        }
        other => panic!("expected Input response, got {:?}", other),
    }
}

#[test]
fn test_password_response_preserves_prompt() {
    let response = PamAuthResponse::Password {
        prompt: Some("New password".to_string()),
        long_prompt: Some("Your password has expired".to_string()),
    };
    let serialized = serde_json::to_string(&response).unwrap();
    let decoded: PamAuthResponse = serde_json::from_str(&serialized).unwrap();

    match decoded {
        PamAuthResponse::Password {
            prompt,
            long_prompt,
        } => {
            assert_eq!(prompt.as_deref(), Some("New password"));
            assert_eq!(long_prompt.as_deref(), Some("Your password has expired"));
        }
        other => panic!("expected Password response, got {:?}", other),
    }
}

#[test]
fn test_legacy_mfa_poll_response_defaults_to_push_hint() {
    let response: PamAuthResponse =
        serde_json::from_str(r#"{"MFAPoll":{"msg":"Approve","polling_interval":5}}"#).unwrap();

    match response {
        PamAuthResponse::MFAPoll {
            msg,
            polling_interval,
            show_push_hint,
        } => {
            assert_eq!(msg, "Approve");
            assert_eq!(polling_interval, 5);
            assert!(show_push_hint);
        }
        other => panic!("expected MFAPoll response, got {:?}", other),
    }
}

#[test]
fn test_mfa_poll_response_preserves_push_hint_opt_out() {
    let response = PamAuthResponse::MFAPoll {
        msg: "Waiting for browser authentication to complete...".to_string(),
        polling_interval: 2,
        show_push_hint: false,
    };
    let serialized = serde_json::to_string(&response).unwrap();
    let decoded: PamAuthResponse = serde_json::from_str(&serialized).unwrap();

    match decoded {
        PamAuthResponse::MFAPoll {
            msg,
            polling_interval,
            show_push_hint,
        } => {
            assert_eq!(msg, "Waiting for browser authentication to complete...");
            assert_eq!(polling_interval, 2);
            assert!(!show_push_hint);
        }
        other => panic!("expected MFAPoll response, got {:?}", other),
    }
}

#[test]
fn test_legacy_mfa_code_request_aliases_to_input() {
    let request: PamAuthRequest = serde_json::from_str(r#"{"MFACode":{"cred":"123456"}}"#).unwrap();

    match request {
        PamAuthRequest::Input { cred } => assert_eq!(cred, "123456"),
        other => panic!("expected Input request, got {:?}", other),
    }
}
