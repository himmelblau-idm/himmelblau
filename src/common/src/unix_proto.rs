/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use libc::uid_t;
use serde::{Deserialize, Serialize};

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
    Password,
    /// PAM must prompt for an authentication code
    MFACode {
        msg: String,
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

#[derive(Serialize, Deserialize, Debug)]
pub enum PamAuthRequest {
    Password { cred: String },
    MFACode { cred: String },
    HelloTOTP { cred: String },
    MFAPoll { poll_attempt: u32 },
    SetupPin { pin: String },
    Pin { cred: String },
    Fido { assertion: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRequest {
    NssAccounts,
    NssAccountByUid(u32),
    NssAccountByName(String),
    NssGroups,
    NssGroupByGid(u32),
    NssGroupByName(String),
    PamAuthenticateInit(String, String, bool),
    PamAuthenticateStep(PamAuthRequest),
    PamAccountAllowed(String),
    PamAccountBeginSession(String),
    PamChangeAuthToken(String, String, String, String),
    InvalidateCache,
    ClearCache,
    OfflineBreakGlass(Option<u64>),
    Status,
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
            ClientRequest::PamAuthenticateInit(id, service, no_hello_pin) => {
                format!(
                    "PamAuthenticateInit({}, {}, no_hello_pin: {})",
                    id, service, no_hello_pin
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
            ClientRequest::InvalidateCache => "InvalidateCache".to_string(),
            ClientRequest::ClearCache => "ClearCache".to_string(),
            ClientRequest::OfflineBreakGlass(ttl) => format!("OfflineBreakGlass({:?})", ttl),
            ClientRequest::Status => "Status".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientResponse {
    NssAccounts(Vec<NssUser>),
    NssAccount(Option<NssUser>),
    NssGroups(Vec<NssGroup>),
    NssGroup(Option<NssGroup>),

    PamStatus(Option<bool>),
    PamAuthenticateStepResponse(PamAuthResponse),

    Ok,
    Error,
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
    KerberosCCache(uid_t, uid_t, Vec<u8>, Vec<u8>),
    LoadProfilePhoto(String, String),
    ApplyPolicy(Option<String>, String, String, String, String),
}

impl TaskRequest {
    /// Get a safe display version of the request, without credentials.
    pub fn as_safe_string(&self) -> String {
        match self {
            TaskRequest::HomeDirectory(_) => "HomeDirectory(...)".to_string(),
            TaskRequest::LocalGroups(_, _) => "LocalGroups(...)".to_string(),
            TaskRequest::LogonScript(_, _) => "LogonScript(...)".to_string(),
            TaskRequest::KerberosCCache(uid, gid, _, _) => {
                format!("KerberosCCache({}, {}, ...)", uid, gid)
            }
            TaskRequest::LoadProfilePhoto(_, _) => "LoadProfilePhoto(...)".to_string(),
            TaskRequest::ApplyPolicy(intune_device_id, _, _, _, _) => {
                format!("ApplyPolicy({:?}, ...)", intune_device_id)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TaskResponse {
    Success(i32),
    Error(String),
}

// Embedded Browser Protocol Types
// These types are used for communication between the QR greeter extension
// and the himmelblau-embedded-browser daemon for in-GDM authentication.

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BrowserRequest {
    /// Check if embedded browser service is available
    Ping,
    /// Check if service is ready (container image built)
    IsReady,
    /// Start a browser session with the given URL
    StartSession { url: String, session_id: String },
    /// Stop an active session
    StopSession { session_id: String },
    /// Request VNC frame data for rendering
    GetVncFrame { session_id: String },
    /// Forward input event to the browser
    InputEvent {
        session_id: String,
        event: BrowserInputEvent,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BrowserResponse {
    /// Service is available
    Pong { version: String },
    /// Service is ready (container image available)
    Ready,
    /// Service is initializing (building container image)
    Initializing { message: String },
    /// Session started successfully
    SessionStarted {
        session_id: String,
        width: u32,
        height: u32,
    },
    /// Session stopped
    SessionStopped { session_id: String },
    /// VNC frame data for rendering (raw RGBA pixels)
    VncFrame {
        session_id: String,
        width: u32,
        height: u32,
        data: Vec<u8>,
    },
    /// Session completed (authentication successful)
    SessionCompleted { session_id: String },
    /// Session failed or timed out
    SessionFailed { session_id: String, reason: String },
    /// Input event acknowledged
    InputAck,
    /// Error response
    Error { message: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BrowserInputEvent {
    pub event_type: BrowserInputType,
    pub x: Option<i32>,
    pub y: Option<i32>,
    pub button: Option<u8>,
    pub key_code: Option<u32>,
    pub key_sym: Option<u32>,
    pub modifiers: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BrowserInputType {
    MouseMove,
    MouseDown,
    MouseUp,
    MouseScroll,
    KeyDown,
    KeyUp,
}

#[test]
fn test_clientrequest_as_safe_string() {
    assert_eq!(
        ClientRequest::NssAccounts.as_safe_string(),
        "NssAccounts".to_string()
    );
}
