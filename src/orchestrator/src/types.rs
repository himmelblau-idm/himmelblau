use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const ORCHESTRATOR_PROTOCOL_VERSION: &str = "0.2";

const MAX_SESSION_ID_LEN: usize = 128;
const MAX_USERNAME_LEN: usize = 320;
const MAX_ISSUER_URL_LEN: usize = 2048;
const MAX_DAG_AUTH_URL_LEN: usize = 4096;
const MAX_DAG_USER_CODE_LEN: usize = 128;
const MAX_INPUT_NAME_LEN: usize = 128;
const MAX_INPUT_VALUE_LEN: usize = 8192;
const MAX_PROVIDED_INPUTS: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    Username,
    Password,
    Otp,
    Text,
    Confirmation,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredInput {
    pub name: String,
    #[serde(rename = "type")]
    pub input_type: InputType,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub interaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvidedInput {
    pub name: String,
    pub value: String,
}

impl Drop for ProvidedInput {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    InProgress,
    WaitingForInput,
    WaitingForBrowser,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionLogEntry {
    pub timestamp_epoch_s: u64,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum FlowCommand {
    StartSession {
        session_id: String,
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
        interaction_id: Option<String>,
        #[serde(default)]
        provided_inputs: Vec<ProvidedInput>,
    },
    CompleteSession {
        session_id: String,
    },
    CancelSession {
        session_id: String,
    },
    GetSessionStatus {
        session_id: String,
    },
    Ping,
}

impl FlowCommand {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::StartSession {
                session_id,
                username,
                issuer_url,
                dag_auth_url,
                dag_user_code,
            } => {
                validate_required_text("session_id", session_id, MAX_SESSION_ID_LEN)?;
                if let Some(value) = username {
                    validate_optional_text("username", value, MAX_USERNAME_LEN)?;
                }
                if let Some(value) = issuer_url {
                    validate_optional_text("issuer_url", value, MAX_ISSUER_URL_LEN)?;
                }
                if let Some(value) = dag_auth_url {
                    validate_optional_text("dag_auth_url", value, MAX_DAG_AUTH_URL_LEN)?;
                }
                if let Some(value) = dag_user_code {
                    validate_optional_text("dag_user_code", value, MAX_DAG_USER_CODE_LEN)?;
                }
                Ok(())
            }
            Self::NextStep {
                session_id,
                interaction_id,
                provided_inputs,
            } => {
                validate_required_text("session_id", session_id, MAX_SESSION_ID_LEN)?;
                if let Some(value) = interaction_id {
                    validate_optional_text("interaction_id", value, MAX_SESSION_ID_LEN)?;
                }
                if provided_inputs.len() > MAX_PROVIDED_INPUTS {
                    return Err(format!(
                        "provided_inputs contains {} entries; max is {}",
                        provided_inputs.len(),
                        MAX_PROVIDED_INPUTS
                    ));
                }
                for input in provided_inputs {
                    validate_required_text("provided_input.name", &input.name, MAX_INPUT_NAME_LEN)?;
                    validate_text_max("provided_input.value", &input.value, MAX_INPUT_VALUE_LEN)?;
                }
                Ok(())
            }
            Self::CompleteSession { session_id }
            | Self::CancelSession { session_id }
            | Self::GetSessionStatus { session_id } => {
                validate_required_text("session_id", session_id, MAX_SESSION_ID_LEN)
            }
            Self::Ping => Ok(()),
        }
    }

    pub fn as_safe_string(&self) -> String {
        match self {
            Self::StartSession {
                session_id,
                username,
                issuer_url,
                dag_auth_url,
                dag_user_code,
            } => {
                format!(
                    "start_session(session_id={}, username_present={}, issuer_url_present={}, dag_auth_url_present={}, dag_user_code_present={})",
                    session_id,
                    username.as_ref().is_some_and(|entry| !entry.is_empty()),
                    issuer_url.as_ref().is_some_and(|entry| !entry.is_empty()),
                    dag_auth_url.as_ref().is_some_and(|entry| !entry.is_empty()),
                    dag_user_code.is_some()
                )
            }
            Self::NextStep {
                session_id,
                interaction_id,
                provided_inputs,
            } => {
                let names: Vec<&str> = provided_inputs
                    .iter()
                    .map(|entry| entry.name.as_str())
                    .collect();
                format!(
                    "next_step(session_id={}, interaction_id={:?}, inputs={:?})",
                    session_id, interaction_id, names
                )
            }
            Self::CompleteSession { session_id } => {
                format!("complete_session(session_id={})", session_id)
            }
            Self::CancelSession { session_id } => {
                format!("cancel_session(session_id={})", session_id)
            }
            Self::GetSessionStatus { session_id } => {
                format!("get_session_status(session_id={})", session_id)
            }
            Self::Ping => "ping".to_string(),
        }
    }
}

impl Drop for FlowCommand {
    fn drop(&mut self) {
        match self {
            Self::StartSession {
                dag_auth_url,
                dag_user_code,
                ..
            } => {
                if let Some(value) = dag_auth_url {
                    value.zeroize();
                }
                if let Some(value) = dag_user_code {
                    value.zeroize();
                }
            }
            Self::NextStep {
                provided_inputs, ..
            } => {
                for input in provided_inputs {
                    input.value.zeroize();
                }
            }
            Self::CompleteSession { .. }
            | Self::CancelSession { .. }
            | Self::GetSessionStatus { .. }
            | Self::Ping => {}
        }
    }
}

fn validate_required_text(field: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{} must not be empty", field));
    }
    validate_text_max(field, value, max_len)
}

fn validate_optional_text(field: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{} must not be empty when present", field));
    }
    validate_text_max(field, value, max_len)
}

fn validate_text_max(field: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.len() > max_len {
        return Err(format!(
            "{} exceeds max length {} (got {})",
            field,
            max_len,
            value.len()
        ));
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err(format!("{} contains control characters", field));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum FlowResponse {
    Ack {
        #[serde(default)]
        session_id: Option<String>,
        message: String,
    },
    NextStep {
        session_id: String,
        required_inputs: Vec<RequiredInput>,
        #[serde(default)]
        message: Option<String>,
    },
    Waiting {
        session_id: String,
        #[serde(default)]
        message: Option<String>,
    },
    SessionStatus {
        session_id: String,
        state: SessionState,
        #[serde(default)]
        detail: Option<String>,
        #[serde(default)]
        logs: Vec<SessionLogEntry>,
    },
    SessionError {
        session_id: String,
        error: String,
    },
    Error {
        error: String,
    },
    Pong {
        protocol_version: String,
    },
}

impl Drop for FlowResponse {
    fn drop(&mut self) {
        match self {
            Self::SessionError { error, .. } | Self::Error { error } => {
                error.zeroize();
            }
            Self::Ack { .. }
            | Self::NextStep { .. }
            | Self::Waiting { .. }
            | Self::SessionStatus { .. }
            | Self::Pong { .. } => {}
        }
    }
}
