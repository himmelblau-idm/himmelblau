use crate::flow::FlowExecutor;
use crate::session::SessionManager;
use crate::types::{FlowCommand, FlowResponse, ORCHESTRATOR_PROTOCOL_VERSION};
use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt};
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio_util::bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::{debug, error, info};
use zeroize::{Zeroize, Zeroizing};

// Protocol allows up to 32 provided inputs with values up to 8192 bytes each.
// Account for payload plus JSON overhead to avoid codec-level rejection.
const MAX_FLOW_FRAME_BYTES: usize = 384 * 1024;
const AUTHORIZED_CLIENT_USER: &str = "himmelblaud";

#[derive(Default)]
struct FlowCodec;

impl Decoder for FlowCodec {
    type Error = io::Error;
    type Item = FlowCommand;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() > MAX_FLOW_FRAME_BYTES {
            let frame_len = src.len();
            src.as_mut().zeroize();
            src.clear();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "flow command exceeds {} bytes (got {})",
                    MAX_FLOW_FRAME_BYTES, frame_len
                ),
            ));
        }

        match serde_json::from_slice::<FlowCommand>(src) {
            Ok(message) => {
                src.as_mut().zeroize();
                src.clear();
                Ok(Some(message))
            }
            Err(err) if err.is_eof() => Ok(None),
            Err(err) => {
                src.as_mut().zeroize();
                src.clear();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to decode flow command: {err}"),
                ))
            }
        }
    }
}

impl Encoder<FlowResponse> for FlowCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: FlowResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = Zeroizing::new(serde_json::to_vec(&msg).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed encoding response: {e}"),
            )
        })?);
        dst.put(data.as_slice());
        Ok(())
    }
}

#[derive(Clone)]
pub struct CommunicationServer {
    session_manager: Arc<SessionManager>,
    flow_executor: Arc<FlowExecutor>,
}

impl CommunicationServer {
    pub fn new(session_manager: Arc<SessionManager>, flow_executor: Arc<FlowExecutor>) -> Self {
        Self {
            session_manager,
            flow_executor,
        }
    }

    pub async fn run(
        &self,
        socket_path: &Path,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let authorized_client = resolve_user(AUTHORIZED_CLIENT_USER)
            .with_context(|| format!("failed to resolve user '{AUTHORIZED_CLIENT_USER}'"))?;

        if socket_path.exists() {
            tokio::fs::remove_file(socket_path).await.with_context(|| {
                format!("failed to remove stale socket {}", socket_path.display())
            })?;
        }

        if let Some(parent) = socket_path.parent() {
            let metadata = tokio::fs::metadata(parent).await.with_context(|| {
                format!(
                    "orchestrator socket directory {} is unavailable",
                    parent.display()
                )
            })?;
            if !metadata.is_dir() {
                return Err(anyhow!(
                    "orchestrator socket parent {} is not a directory",
                    parent.display()
                ));
            }
        }

        let listener = bind_private_socket(socket_path).with_context(|| {
            format!(
                "failed to bind orchestration socket at {}",
                socket_path.display()
            )
        })?;
        secure_socket(socket_path, authorized_client)
            .await
            .with_context(|| {
                format!(
                    "failed to secure orchestration socket at {}",
                    socket_path.display()
                )
            })?;

        info!(
            path = %socket_path.display(),
            authorized_uid = authorized_client.uid,
            "listening for himmelblaud orchestrator connections"
        );

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("communication server received shutdown signal");
                    break;
                }
                accept_result = listener.accept() => {
                    let (stream, _) = accept_result.context("failed to accept orchestrator socket client")?;
                    let server = self.clone();
                    let authorized_uid = authorized_client.uid;
                    tokio::spawn(async move {
                        if let Err(error) = server.handle_client(stream, authorized_uid).await {
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

    async fn handle_client(&self, stream: UnixStream, authorized_uid: u32) -> Result<()> {
        let peer_uid = peer_uid(&stream)?;
        if peer_uid != authorized_uid {
            return Err(anyhow!(
                "unauthorized orchestrator socket peer uid {}; expected uid {}",
                peer_uid,
                authorized_uid
            ));
        }

        let mut framed = Framed::new(stream, FlowCodec);

        let Some(message) = framed.next().await else {
            return Ok(());
        };

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

        Ok(())
    }

    async fn process_command(
        &self,
        mut command: FlowCommand,
        peer_uid: u32,
    ) -> Result<FlowResponse> {
        command
            .validate()
            .map_err(|reason| anyhow!("invalid flow command: {}", reason))?;

        match &mut command {
            FlowCommand::StartSession {
                session_id,
                username,
                issuer_url,
                dag_auth_url,
                dag_user_code,
                device_label,
            } => {
                self.handle_start_session(
                    std::mem::take(session_id),
                    peer_uid,
                    std::mem::take(username),
                    std::mem::take(issuer_url),
                    std::mem::take(dag_auth_url),
                    std::mem::take(dag_user_code),
                    std::mem::take(device_label),
                )
                .await
            }
            FlowCommand::NextStep {
                session_id,
                interaction_id,
                provided_inputs,
            } => {
                self.handle_next_step(
                    std::mem::take(session_id),
                    std::mem::take(interaction_id),
                    std::mem::take(provided_inputs),
                    peer_uid,
                )
                .await
            }
            FlowCommand::CompleteSession { session_id } => {
                self.handle_complete_session(std::mem::take(session_id), peer_uid)
                    .await
            }
            FlowCommand::CancelSession { session_id } => {
                self.handle_cancel_session(std::mem::take(session_id), peer_uid)
                    .await
            }
            FlowCommand::GetSessionStatus { session_id } => {
                self.handle_get_status(std::mem::take(session_id), peer_uid)
                    .await
            }
            FlowCommand::Ping => Ok(FlowResponse::Pong {
                protocol_version: ORCHESTRATOR_PROTOCOL_VERSION.to_string(),
            }),
        }
    }

    async fn handle_start_session(
        &self,
        session_id: String,
        owner_uid: u32,
        username: Option<String>,
        issuer_url: Option<String>,
        dag_auth_url: Option<String>,
        dag_user_code: Option<String>,
        device_label: Option<String>,
    ) -> Result<FlowResponse> {
        debug!(
            session_id = %session_id,
            username_present = username.as_ref().is_some_and(|entry| !entry.is_empty()),
            issuer_url = ?issuer_url,
            dag_auth_url_present = dag_auth_url.is_some(),
            dag_user_code_present = dag_user_code.is_some(),
            device_label_present = device_label.as_ref().is_some_and(|entry| !entry.is_empty()),
            "starting providerless orchestrator session"
        );

        let session = self
            .session_manager
            .create_session(
                session_id.clone(),
                owner_uid,
                username,
                issuer_url,
                dag_auth_url,
                dag_user_code,
                device_label,
            )
            .await?;

        self.flow_executor.start_session(Arc::clone(&session)).await
    }

    async fn handle_next_step(
        &self,
        session_id: String,
        interaction_id: Option<String>,
        provided_inputs: Vec<crate::types::ProvidedInput>,
        peer_uid: u32,
    ) -> Result<FlowResponse> {
        let provided_input_names = provided_inputs
            .iter()
            .map(|input| input.name.as_str())
            .collect::<Vec<_>>();
        debug!(
            session_id = %session_id,
            interaction_id = ?interaction_id,
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
            .continue_session(Arc::clone(&session), interaction_id, provided_inputs)
            .await
    }

    async fn handle_complete_session(
        &self,
        session_id: String,
        peer_uid: u32,
    ) -> Result<FlowResponse> {
        if let Some(session) = self.session_manager.get_session(&session_id).await {
            if !session.owned_by(peer_uid) {
                return Err(anyhow!(
                    "session '{}' is not owned by caller uid {}",
                    session_id,
                    peer_uid
                ));
            }
        }

        let completed = self.session_manager.complete_session(&session_id).await?;
        if completed {
            Ok(FlowResponse::Ack {
                session_id: Some(session_id),
                message: "session completed".to_string(),
            })
        } else {
            Ok(FlowResponse::SessionError {
                session_id,
                error: "session not found".to_string(),
            })
        }
    }

    async fn handle_cancel_session(
        &self,
        session_id: String,
        peer_uid: u32,
    ) -> Result<FlowResponse> {
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

#[derive(Clone, Copy)]
struct ResolvedUser {
    uid: u32,
    gid: u32,
}

fn resolve_user(name: &str) -> Result<ResolvedUser> {
    let name = CString::new(name).context("user name contains an interior NUL")?;
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];

    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            pwd.as_mut_ptr(),
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            buffer.len(),
            &mut result,
        )
    };

    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc)).context("getpwnam_r failed");
    }

    if result.is_null() {
        return Err(anyhow!("user not found"));
    }

    let pwd = unsafe { pwd.assume_init() };
    Ok(ResolvedUser {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
    })
}

fn bind_private_socket(socket_path: &Path) -> io::Result<UnixListener> {
    let before = unsafe { libc::umask(0o077) };
    let result = UnixListener::bind(socket_path);
    let _ = unsafe { libc::umask(before) };
    result
}

async fn secure_socket(socket_path: &Path, owner: ResolvedUser) -> Result<()> {
    let path = CString::new(socket_path.as_os_str().as_bytes())
        .context("socket path contains an interior NUL")?;
    let rc = unsafe { libc::chown(path.as_ptr(), owner.uid, owner.gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("failed to chown orchestrator socket");
    }

    let permissions = std::fs::Permissions::from_mode(0o600);
    tokio::fs::set_permissions(socket_path, permissions)
        .await
        .context("failed to chmod orchestrator socket")
}

fn response_kind(response: &FlowResponse) -> &'static str {
    match response {
        FlowResponse::Ack { .. } => "ack",
        FlowResponse::NextStep { .. } => "next_step",
        FlowResponse::Waiting { .. } => "waiting",
        FlowResponse::SessionStatus { .. } => "session_status",
        FlowResponse::SessionError { .. } => "session_error",
        FlowResponse::Error { .. } => "error",
        FlowResponse::Pong { .. } => "pong",
    }
}
