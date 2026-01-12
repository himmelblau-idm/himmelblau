/*
 * Himmelblau Embedded Browser Service
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

mod container;
mod session;
mod vnc;

use std::io;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use himmelblau_unix_common::unix_proto::{BrowserRequest, BrowserResponse};
use kanidm_utils_users::{get_effective_gid, get_effective_uid};
use sd_notify::NotifyState;
use sketching::tracing_forest::traits::*;
use sketching::tracing_forest::util::*;
use sketching::tracing_forest;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, RwLock};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::span;

use crate::container::ContainerManager;
use crate::session::{BrowserSession, SessionManager};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Service ready state
#[derive(Debug, Clone)]
enum ServiceState {
    Initializing(String),
    Ready,
    Failed(String),
}

struct BrowserCodec;

impl Decoder for BrowserCodec {
    type Error = io::Error;
    type Item = BrowserRequest;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        match serde_json::from_slice::<BrowserRequest>(src) {
            Ok(msg) => {
                src.clear();
                Ok(Some(msg))
            }
            Err(e) if e.is_eof() => Ok(None),
            Err(e) => {
                error!("Failed to decode browser request: {:?}", e);
                src.clear();
                Ok(None)
            }
        }
    }
}

impl Encoder<BrowserResponse> for BrowserCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: BrowserResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("Socket encoding error: {:?}", e);
            io::Error::new(io::ErrorKind::Other, "JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

impl BrowserCodec {
    fn new() -> Self {
        BrowserCodec
    }
}

async fn handle_client(
    stream: UnixStream,
    session_manager: Arc<RwLock<SessionManager>>,
    container_manager: Arc<ContainerManager>,
    service_state: Arc<RwLock<ServiceState>>,
    cfg: &HimmelblauConfig,
) {
    let mut reqs = Framed::new(stream, BrowserCodec::new());

    loop {
        match reqs.next().await {
            Some(Ok(BrowserRequest::Ping)) => {
                debug!("Received Ping request");
                let resp = BrowserResponse::Pong {
                    version: VERSION.to_string(),
                };
                // Write directly to the stream, bypassing the codec
                let data = match serde_json::to_vec(&resp) {
                    Ok(d) => d,
                    Err(e) => {
                        error!("Failed to serialize Pong response: {:?}", e);
                        return;
                    }
                };
                let stream = reqs.get_mut();
                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to write Pong response: {:?}", e);
                    return;
                }
                if let Err(e) = stream.flush().await {
                    error!("Failed to flush Pong response: {:?}", e);
                    return;
                }
                debug!("Sent Pong response, {} bytes", data.len());
                // Shutdown the write side to signal EOF to client
                if let Err(e) = stream.shutdown().await {
                    error!("Failed to shutdown stream: {:?}", e);
                }
                return;
            }
            Some(Ok(BrowserRequest::IsReady)) => {
                debug!("Received IsReady request");
                let state = service_state.read().await;
                let resp = match &*state {
                    ServiceState::Initializing(msg) => BrowserResponse::Initializing {
                        message: msg.clone(),
                    },
                    ServiceState::Ready => BrowserResponse::Ready,
                    ServiceState::Failed(msg) => BrowserResponse::Error {
                        message: msg.clone(),
                    },
                };
                // Write directly to the stream, bypassing the codec
                let data = match serde_json::to_vec(&resp) {
                    Ok(d) => d,
                    Err(e) => {
                        error!("Failed to serialize IsReady response: {:?}", e);
                        return;
                    }
                };
                let stream = reqs.get_mut();
                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to write IsReady response: {:?}", e);
                    return;
                }
                if let Err(e) = stream.flush().await {
                    error!("Failed to flush IsReady response: {:?}", e);
                    return;
                }
                debug!("Sent IsReady response, {} bytes", data.len());
                // Shutdown the write side to signal EOF to client
                if let Err(e) = stream.shutdown().await {
                    error!("Failed to shutdown stream: {:?}", e);
                }
                return;
            }
            Some(Ok(BrowserRequest::StartSession { url, session_id })) => {
                debug!("Received StartSession request for URL: {}", url);

                let (width, height) = cfg.get_embedded_browser_resolution();
                let timeout = cfg.get_embedded_browser_timeout();
                let container_image = cfg.get_embedded_browser_container_image();

                match container_manager
                    .start_browser(&session_id, &url, width, height, &container_image)
                    .await
                {
                    Ok(vnc_port) => {
                        let session = BrowserSession::new(
                            session_id.clone(),
                            url.clone(),
                            vnc_port,
                            width,
                            height,
                            timeout,
                        );

                        {
                            let mut sm = session_manager.write().await;
                            sm.add_session(session);
                        }

                        let resp = BrowserResponse::SessionStarted {
                            session_id,
                            width,
                            height,
                        };
                        if let Err(e) = reqs.send(resp).await {
                            error!("Failed to send SessionStarted response: {:?}", e);
                            return;
                        }
                        if let Err(e) = reqs.flush().await {
                            error!("Failed to flush SessionStarted response: {:?}", e);
                            return;
                        }
                    }
                    Err(e) => {
                        error!("Failed to start browser session: {:?}", e);
                        let resp = BrowserResponse::Error {
                            message: format!("Failed to start browser: {}", e),
                        };
                        if let Err(e) = reqs.send(resp).await {
                            error!("Failed to send error response: {:?}", e);
                            return;
                        }
                        if let Err(e) = reqs.flush().await {
                            error!("Failed to flush error response: {:?}", e);
                            return;
                        }
                    }
                }
            }
            Some(Ok(BrowserRequest::StopSession { session_id })) => {
                debug!("Received StopSession request for session: {}", session_id);

                {
                    let mut sm = session_manager.write().await;
                    sm.remove_session(&session_id);
                }

                if let Err(e) = container_manager.stop_browser(&session_id).await {
                    error!("Failed to stop container: {:?}", e);
                }

                let resp = BrowserResponse::SessionStopped { session_id };
                if let Err(e) = reqs.send(resp).await {
                    error!("Failed to send SessionStopped response: {:?}", e);
                    return;
                }
                if let Err(e) = reqs.flush().await {
                    error!("Failed to flush SessionStopped response: {:?}", e);
                    return;
                }
            }
            Some(Ok(BrowserRequest::GetVncFrame { session_id })) => {
                let sm = session_manager.read().await;
                if let Some(session) = sm.get_session(&session_id) {
                    match vnc::get_frame(session.vnc_port).await {
                        Ok(frame_data) => {
                            let resp = BrowserResponse::VncFrame {
                                session_id,
                                width: session.width,
                                height: session.height,
                                data: frame_data,
                            };
                            if let Err(e) = reqs.send(resp).await {
                                error!("Failed to send VncFrame response: {:?}", e);
                                return;
                            }
                            if let Err(e) = reqs.flush().await {
                                error!("Failed to flush VncFrame response: {:?}", e);
                                return;
                            }
                        }
                        Err(e) => {
                            error!("Failed to get VNC frame: {:?}", e);
                            let resp = BrowserResponse::Error {
                                message: format!("Failed to get VNC frame: {}", e),
                            };
                            if let Err(e) = reqs.send(resp).await {
                                error!("Failed to send error response: {:?}", e);
                                return;
                            }
                            if let Err(e) = reqs.flush().await {
                                error!("Failed to flush error response: {:?}", e);
                                return;
                            }
                        }
                    }
                } else {
                    let resp = BrowserResponse::Error {
                        message: format!("Session not found: {}", session_id),
                    };
                    if let Err(e) = reqs.send(resp).await {
                        error!("Failed to send error response: {:?}", e);
                        return;
                    }
                    if let Err(e) = reqs.flush().await {
                        error!("Failed to flush error response: {:?}", e);
                        return;
                    }
                }
            }
            Some(Ok(BrowserRequest::InputEvent { session_id, event })) => {
                let sm = session_manager.read().await;
                if let Some(session) = sm.get_session(&session_id) {
                    if let Err(e) = vnc::send_input(session.vnc_port, &event).await {
                        error!("Failed to send input event: {:?}", e);
                    }
                }
                let resp = BrowserResponse::InputAck;
                if let Err(e) = reqs.send(resp).await {
                    error!("Failed to send InputAck response: {:?}", e);
                    return;
                }
                if let Err(e) = reqs.flush().await {
                    error!("Failed to flush InputAck response: {:?}", e);
                    return;
                }
            }
            Some(Err(e)) => {
                error!("Error reading from client: {:?}", e);
                return;
            }
            None => {
                debug!("Client disconnected");
                return;
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let _ceuid = get_effective_uid();
    let _cegid = get_effective_gid();
    let systemd_booted = sd_notify::booted().unwrap_or(false);

    let config_path = Path::new(DEFAULT_CONFIG_PATH);
    let config_path_str = match config_path.to_str() {
        Some(cps) => cps,
        None => {
            eprintln!("Unable to turn config_path to str");
            return ExitCode::FAILURE;
        }
    };

    let cfg = match HimmelblauConfig::new(Some(config_path_str)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to parse {}: {}", config_path_str, e);
            return ExitCode::FAILURE;
        }
    };

    if cfg.get_debug() {
        std::env::set_var("RUST_LOG", "debug");
    }

    #[allow(clippy::expect_used)]
    tracing_forest::worker_task()
        .set_global(true)
        .map_sender(|sender| sender.or_stderr())
        .build_on(|subscriber| {
            subscriber.with(
                EnvFilter::try_from_default_env()
                    .or_else(|_| EnvFilter::try_new("info"))
                    .expect("Failed to init envfilter"),
            )
        })
        .on(async {
            let span = span!(Level::INFO, "Embedded browser daemon initialization");
            let _enter = span.enter();

            // Note: Unlike the tasks daemon, we don't require root since we use
            // rootless podman. However, we do need podman to be available.
            if !container::podman_available().await {
                error!("Podman is not available. Cannot start embedded browser service.");
                return ExitCode::FAILURE;
            }

            let socket_path = cfg.get_embedded_browser_socket_path();
            debug!("Using socket path: {}", socket_path);

            // Remove existing socket if present
            let sock_path = Path::new(&socket_path);
            if sock_path.exists() {
                if let Err(e) = std::fs::remove_file(sock_path) {
                    error!("Failed to remove existing socket: {:?}", e);
                    return ExitCode::FAILURE;
                }
            }

            // Create parent directory if needed
            if let Some(parent) = sock_path.parent() {
                if !parent.exists() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        error!("Failed to create socket directory: {:?}", e);
                        return ExitCode::FAILURE;
                    }
                }
            }

            let listener = match UnixListener::bind(&socket_path) {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind to socket {}: {:?}", socket_path, e);
                    return ExitCode::FAILURE;
                }
            };

            // Set socket permissions to allow other users (like gdm) to connect
            // Unix sockets require write permission to connect
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(
                &socket_path,
                std::fs::Permissions::from_mode(0o666),
            ) {
                error!("Failed to set socket permissions: {:?}", e);
                return ExitCode::FAILURE;
            }

            info!("Listening on {}", socket_path);

            let session_manager = Arc::new(RwLock::new(SessionManager::new()));
            let container_manager = Arc::new(ContainerManager::new());
            let service_state = Arc::new(RwLock::new(ServiceState::Initializing(
                "Building container image...".to_string(),
            )));

            let (broadcast_tx, _broadcast_rx) = broadcast::channel::<bool>(4);

            // Build container image in background so we can start accepting connections
            // and respond to IsReady queries while building
            let container_image = cfg.get_embedded_browser_container_image();
            let service_state_clone = Arc::clone(&service_state);
            tokio::spawn(async move {
                info!("Checking container image availability...");
                match container::ensure_container_image(&container_image).await {
                    Ok(was_present) => {
                        if was_present {
                            info!("Container image already available");
                        } else {
                            info!("Container image built successfully");
                        }
                        let mut state = service_state_clone.write().await;
                        *state = ServiceState::Ready;
                    }
                    Err(e) => {
                        error!("Failed to ensure container image: {}", e);
                        let mut state = service_state_clone.write().await;
                        *state = ServiceState::Failed(e);
                    }
                }
            });

            drop(_enter);

            if systemd_booted {
                if let Ok(monotonic_usec) = sd_notify::NotifyState::monotonic_usec_now() {
                    let _ = sd_notify::notify(true, &[NotifyState::Ready, monotonic_usec]);
                }
            }

            info!("Server started, waiting for connections...");

            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, _addr)) => {
                                let sm = Arc::clone(&session_manager);
                                let cm = Arc::clone(&container_manager);
                                let ss = Arc::clone(&service_state);
                                let cfg_clone = cfg.clone();
                                tokio::spawn(async move {
                                    handle_client(stream, sm, cm, ss, &cfg_clone).await;
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept connection: {:?}", e);
                            }
                        }
                    }
                    Ok(()) = tokio::signal::ctrl_c() => {
                        break;
                    }
                    Some(()) = async {
                        let sigterm = tokio::signal::unix::SignalKind::terminate();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        break;
                    }
                }
            }

            info!("Signal received, shutting down");
            if systemd_booted {
                if let Ok(monotonic_usec) = sd_notify::NotifyState::monotonic_usec_now() {
                    let _ = sd_notify::notify(true, &[NotifyState::Stopping, monotonic_usec]);
                }
            }

            // Clean up all active sessions
            {
                let sm = session_manager.read().await;
                for session_id in sm.get_session_ids() {
                    let _ = container_manager.stop_browser(&session_id).await;
                }
            }

            // Send shutdown signal
            let _ = broadcast_tx.send(true);

            // Note: We intentionally do NOT remove the socket on shutdown.
            // The new instance will remove any stale socket before binding.
            // This avoids a race condition where the old instance's cleanup
            // removes the new instance's freshly-created socket during restarts.

            ExitCode::SUCCESS
        })
        .await
}
