use crate::podman::{ContainerInstance, PodmanClient};
use crate::provider_definitions::ProviderDefinition;
use crate::types::{FlowResponse, LogLevel, SessionLogEntry, SessionState, TokenBundle};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};

#[derive(Debug)]
pub(crate) struct SessionRuntime {
    pub state: SessionState,
    pub current_step_index: usize,
    pub last_activity: Instant,
    pub terminal_since: Option<Instant>,
    pub detail: Option<String>,
    pub collected_inputs: HashMap<String, String>,
    pub tokens: TokenBundle,
    pub metadata: HashMap<String, String>,
    pub logs: Vec<SessionLogEntry>,
}

impl Default for SessionRuntime {
    fn default() -> Self {
        Self {
            state: SessionState::InProgress,
            current_step_index: 0,
            last_activity: Instant::now(),
            terminal_since: None,
            detail: None,
            collected_inputs: HashMap::new(),
            tokens: TokenBundle::default(),
            metadata: HashMap::new(),
            logs: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct Session {
    pub session_id: String,
    pub provider: String,
    pub owner_uid: u32,
    pub container: ContainerInstance,
    pub definition: RwLock<Arc<ProviderDefinition>>,
    pub(crate) runtime: Mutex<SessionRuntime>,
}

impl Session {
    pub fn new(
        session_id: String,
        provider: String,
        owner_uid: u32,
        container: ContainerInstance,
        definition: Arc<ProviderDefinition>,
    ) -> Self {
        Self {
            session_id,
            provider,
            owner_uid,
            container,
            definition: RwLock::new(definition),
            runtime: Mutex::new(SessionRuntime::default()),
        }
    }

    pub fn owned_by(&self, uid: u32) -> bool {
        uid == 0 || self.owner_uid == uid
    }

    pub async fn log(&self, level: LogLevel, message: impl Into<String>) {
        let mut runtime = self.runtime.lock().await;
        runtime.last_activity = Instant::now();
        runtime.logs.push(SessionLogEntry {
            timestamp_epoch_s: now_epoch_s(),
            level,
            message: message.into(),
        });
    }

    pub async fn status_response(&self) -> FlowResponse {
        let runtime = self.runtime.lock().await;
        FlowResponse::SessionStatus {
            session_id: self.session_id.clone(),
            provider: self.provider.clone(),
            state: runtime.state.clone(),
            detail: runtime.detail.clone(),
            logs: runtime.logs.clone(),
        }
    }

    pub async fn is_stale(
        &self,
        idle_timeout: Duration,
        terminal_retention: Duration,
        now: Instant,
    ) -> bool {
        let runtime = self.runtime.lock().await;
        if now.duration_since(runtime.last_activity) >= idle_timeout {
            return true;
        }

        if let Some(terminal_since) = runtime.terminal_since {
            if now.duration_since(terminal_since) >= terminal_retention {
                return true;
            }
        }

        false
    }
}

pub struct SessionManager {
    sessions: RwLock<HashMap<String, Arc<Session>>>,
    podman: Arc<PodmanClient>,
    idle_timeout: Duration,
    terminal_retention: Duration,
}

impl SessionManager {
    pub fn new(
        podman: Arc<PodmanClient>,
        idle_timeout: Duration,
        terminal_retention: Duration,
    ) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            podman,
            idle_timeout,
            terminal_retention,
        }
    }

    pub async fn create_session(
        &self,
        session_id: String,
        provider: String,
        owner_uid: u32,
        username: Option<String>,
        issuer_url: Option<String>,
        dag_auth_url: Option<String>,
        dag_user_code: Option<String>,
        definition: Arc<ProviderDefinition>,
    ) -> Result<Arc<Session>> {
        if self.sessions.read().await.contains_key(&session_id) {
            return Err(anyhow!("session '{}' already exists", session_id));
        }

        let container = self
            .podman
            .create_session_container(&session_id)
            .await
            .map_err(|e| {
                anyhow!(
                    "failed to create session container for '{}': {e}",
                    session_id
                )
            })?;

        let session = Arc::new(Session::new(
            session_id.clone(),
            provider,
            owner_uid,
            container,
            definition,
        ));

        {
            let mut runtime = session.runtime.lock().await;
            if let Some(username) = username {
                runtime
                    .collected_inputs
                    .insert("username".to_string(), username);
            }
            if let Some(issuer_url) = issuer_url {
                runtime
                    .metadata
                    .insert("issuer_url".to_string(), issuer_url);
            }
            if let Some(dag_auth_url) = dag_auth_url {
                runtime
                    .metadata
                    .insert("dag_auth_url".to_string(), dag_auth_url);
            }
            if let Some(dag_user_code) = dag_user_code {
                runtime
                    .metadata
                    .insert("dag_user_code".to_string(), dag_user_code.clone());
                runtime
                    .collected_inputs
                    .insert("dag_user_code".to_string(), dag_user_code);
            }
        }

        {
            let mut guard = self.sessions.write().await;
            if guard.contains_key(&session_id) {
                let _ = self
                    .podman
                    .destroy_session_container(&session.container.id)
                    .await;
                return Err(anyhow!("session '{}' already exists", session_id));
            }
            guard.insert(session_id.clone(), Arc::clone(&session));
        }

        session
            .log(
                LogLevel::Info,
                format!(
                    "Session created with container '{}'",
                    session.container.name
                ),
            )
            .await;
        Ok(session)
    }

    pub async fn get_session(&self, session_id: &str) -> Option<Arc<Session>> {
        self.sessions.read().await.get(session_id).cloned()
    }

    pub async fn cancel_session(&self, session_id: &str) -> Result<bool> {
        let session = self.sessions.write().await.remove(session_id);
        if let Some(session) = session {
            {
                let mut runtime = session.runtime.lock().await;
                runtime.state = SessionState::Cancelled;
                runtime.detail = Some("Session cancelled by request".to_string());
                runtime.last_activity = Instant::now();
                runtime.terminal_since = Some(Instant::now());
            }
            session.log(LogLevel::Info, "Cancelling session").await;
            self.podman
                .destroy_session_container(&session.container.id)
                .await?;
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn cleanup_stale_sessions(&self) -> Result<usize> {
        let sessions: Vec<Arc<Session>> = self.sessions.read().await.values().cloned().collect();
        let now = Instant::now();

        let mut stale_ids = Vec::new();
        for session in sessions {
            if session
                .is_stale(self.idle_timeout, self.terminal_retention, now)
                .await
            {
                stale_ids.push(session.session_id.clone());
            }
        }

        let mut cleaned = 0_usize;
        for session_id in stale_ids {
            let session = self.sessions.write().await.remove(&session_id);
            if let Some(session) = session {
                let _ = self
                    .podman
                    .destroy_session_container(&session.container.id)
                    .await;
                cleaned += 1;
            }
        }

        Ok(cleaned)
    }

    pub async fn active_count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

fn now_epoch_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
