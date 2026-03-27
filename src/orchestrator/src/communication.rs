use crate::flow::FlowExecutor;
use crate::provider_definitions::ProviderRegistry;
use crate::session::SessionManager;
use crate::types::{FlowCommand, FlowResponse, ORCHESTRATOR_PROTOCOL_VERSION};
use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt};
use himmelblau_unix_common::config::HimmelblauConfig;
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio_util::bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::{debug, error, info};

const MAX_FLOW_FRAME_BYTES: usize = 64 * 1024;

#[derive(Default)]
struct FlowCodec;

impl Decoder for FlowCodec {
    type Error = io::Error;
    type Item = FlowCommand;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() > MAX_FLOW_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "flow command exceeds {} bytes (got {})",
                    MAX_FLOW_FRAME_BYTES,
                    src.len()
                ),
            ));
        }

        match serde_json::from_slice::<FlowCommand>(src) {
            Ok(message) => {
                src.clear();
                Ok(Some(message))
            }
            Err(err) if err.is_eof() => Ok(None),
            Err(err) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to decode flow command: {err}"),
            )),
        }
    }
}

impl Encoder<FlowResponse> for FlowCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: FlowResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = serde_json::to_vec(&msg).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed encoding response: {e}"),
            )
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

#[derive(Clone)]
pub struct CommunicationServer {
    session_manager: Arc<SessionManager>,
    provider_registry: Arc<ProviderRegistry>,
    config: Arc<HimmelblauConfig>,
    flow_executor: Arc<FlowExecutor>,
}

impl CommunicationServer {
    pub fn new(
        session_manager: Arc<SessionManager>,
        provider_registry: Arc<ProviderRegistry>,
        config: Arc<HimmelblauConfig>,
        flow_executor: Arc<FlowExecutor>,
    ) -> Self {
        Self {
            session_manager,
            provider_registry,
            config,
            flow_executor,
        }
    }

    pub async fn run(
        &self,
        socket_path: &Path,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        if socket_path.exists() {
            tokio::fs::remove_file(socket_path).await.with_context(|| {
                format!("failed to remove stale socket {}", socket_path.display())
            })?;
        }

        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create socket directory {}", parent.display())
            })?;
        }

        let listener = UnixListener::bind(socket_path).with_context(|| {
            format!(
                "failed to bind orchestration socket at {}",
                socket_path.display()
            )
        })?;

        info!(path = %socket_path.display(), "listening for himmelblaud orchestrator connections");

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("communication server received shutdown signal");
                    break;
                }
                accept_result = listener.accept() => {
                    let (stream, _) = accept_result.context("failed to accept orchestrator socket client")?;
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(error) = server.handle_client(stream).await {
                            error!(?error, "orchestrator client ended with error");
                        }
                    });
                }
            }
        }

        if socket_path.exists() {
            let _ = tokio::fs::remove_file(socket_path).await;
        }

        Ok(())
    }

    async fn handle_client(&self, stream: UnixStream) -> Result<()> {
        let peer_uid = peer_uid(&stream)?;
        let mut framed = Framed::new(stream, FlowCodec);

        while let Some(message) = framed.next().await {
            let request = message.context("failed to decode flow command")?;
            let request_safe = request.as_safe_string();
            debug!(request = %request_safe, "received flow command");

            let response = self.process_command(request, peer_uid).await;
            let response = match response {
                Ok(response) => response,
                Err(error) => FlowResponse::Error {
                    error: {
                        error!(request = %request_safe, ?error, "flow command failed");
                        error.to_string()
                    },
                },
            };

            debug!(request = %request_safe, response = %response_kind(&response), "sending flow response");

            framed
                .send(response)
                .await
                .context("failed sending flow response")?;
        }

        Ok(())
    }

    async fn process_command(&self, command: FlowCommand, peer_uid: u32) -> Result<FlowResponse> {
        command
            .validate()
            .map_err(|reason| anyhow!("invalid flow command: {}", reason))?;

        match command {
            FlowCommand::StartSession {
                session_id,
                provider,
                username,
                issuer_url,
                dag_auth_url,
                dag_user_code,
            } => {
                self.handle_start_session(
                    session_id,
                    provider,
                    peer_uid,
                    username,
                    issuer_url,
                    dag_auth_url,
                    dag_user_code,
                )
                .await
            }
            FlowCommand::NextStep {
                session_id,
                provided_inputs,
            } => self.handle_next_step(session_id, provided_inputs, peer_uid).await,
            FlowCommand::CancelSession { session_id } => {
                self.handle_cancel_session(session_id, peer_uid).await
            }
            FlowCommand::GetSessionStatus { session_id } => {
                self.handle_get_status(session_id, peer_uid).await
            }
            FlowCommand::Ping => Ok(FlowResponse::Pong {
                protocol_version: ORCHESTRATOR_PROTOCOL_VERSION.to_string(),
            }),
        }
    }

    async fn handle_start_session(
        &self,
        session_id: String,
        provider: Option<String>,
        owner_uid: u32,
        username: Option<String>,
        issuer_url: Option<String>,
        dag_auth_url: Option<String>,
        dag_user_code: Option<String>,
    ) -> Result<FlowResponse> {
        let provider_name = self.provider_registry.detect_provider(
            provider.as_deref(),
            username.as_deref(),
            issuer_url.as_deref(),
            self.config.as_ref(),
        );
        debug!(
            session_id = %session_id,
            requested_provider = ?provider,
            resolved_provider = %provider_name,
            username_present = username.as_ref().is_some_and(|entry| !entry.is_empty()),
            issuer_url = ?issuer_url,
            dag_auth_url_present = dag_auth_url.is_some(),
            dag_user_code_present = dag_user_code.is_some(),
            "resolved start_session provider"
        );

        let definition = self
            .provider_registry
            .get(&provider_name)
            .ok_or_else(|| anyhow!("unknown provider '{}'", provider_name))?;

        let step_summaries = definition
            .steps
            .iter()
            .map(|step| {
                let required_inputs = step
                    .required_inputs
                    .iter()
                    .map(|input| input.name.clone())
                    .collect::<Vec<_>>();
                format!(
                    "{}(required_inputs={:?}, actions={})",
                    step.name,
                    required_inputs,
                    step.actions.len()
                )
            })
            .collect::<Vec<_>>();
        debug!(
            session_id = %session_id,
            provider = %provider_name,
            step_count = definition.steps.len(),
            steps = ?step_summaries,
            "resolved provider definition for session"
        );

        let session = self
            .session_manager
            .create_session(
                session_id.clone(),
                provider_name,
                owner_uid,
                username,
                issuer_url,
                dag_auth_url,
                dag_user_code,
                definition,
            )
            .await?;

        self.flow_executor.start_session(Arc::clone(&session)).await
    }

    async fn handle_next_step(
        &self,
        session_id: String,
        provided_inputs: Vec<crate::types::ProvidedInput>,
        peer_uid: u32,
    ) -> Result<FlowResponse> {
        let provided_input_names = provided_inputs
            .iter()
            .map(|input| input.name.as_str())
            .collect::<Vec<_>>();
        debug!(
            session_id = %session_id,
            provided_inputs = ?provided_input_names,
            provided_count = provided_input_names.len(),
            "continuing session with next_step inputs"
        );

        let session = self
            .session_manager
            .get_session(&session_id)
            .await
            .ok_or_else(|| anyhow!("unknown session '{}'", session_id))?;

        if !session.owned_by(peer_uid) {
            return Err(anyhow!(
                "session '{}' is not owned by caller uid {}",
                session_id,
                peer_uid
            ));
        }

        self.flow_executor
            .continue_session(Arc::clone(&session), provided_inputs)
            .await
    }

    async fn handle_cancel_session(&self, session_id: String, peer_uid: u32) -> Result<FlowResponse> {
        if let Some(session) = self.session_manager.get_session(&session_id).await {
            if !session.owned_by(peer_uid) {
                return Err(anyhow!(
                    "session '{}' is not owned by caller uid {}",
                    session_id,
                    peer_uid
                ));
            }
        }

        let cancelled = self.session_manager.cancel_session(&session_id).await?;
        if cancelled {
            Ok(FlowResponse::Ack {
                session_id: Some(session_id),
                message: "session cancelled".to_string(),
            })
        } else {
            Ok(FlowResponse::SessionError {
                session_id,
                error: "session not found".to_string(),
            })
        }
    }

    async fn handle_get_status(&self, session_id: String, peer_uid: u32) -> Result<FlowResponse> {
        let Some(session) = self.session_manager.get_session(&session_id).await else {
            return Ok(FlowResponse::SessionError {
                session_id,
                error: "session not found".to_string(),
            });
        };

        if !session.owned_by(peer_uid) {
            return Err(anyhow!(
                "session '{}' is not owned by caller uid {}",
                session_id,
                peer_uid
            ));
        }

        Ok(session.status_response().await)
    }
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let creds = stream
        .peer_cred()
        .context("failed to read peer credentials for orchestrator socket")?;
    Ok(creds.uid())
}

fn response_kind(response: &FlowResponse) -> &'static str {
    match response {
        FlowResponse::Ack { .. } => "ack",
        FlowResponse::NextStep { .. } => "next_step",
        FlowResponse::SessionStatus { .. } => "session_status",
        FlowResponse::SessionComplete { .. } => "session_complete",
        FlowResponse::SessionError { .. } => "session_error",
        FlowResponse::Error { .. } => "error",
        FlowResponse::Pong { .. } => "pong",
    }
}
