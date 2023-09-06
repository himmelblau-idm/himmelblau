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

use std::error::Error;
use std::fs::{set_permissions, Permissions};
use std::io;
use std::io::{Error as IoError, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::process::ExitCode;
use std::sync::Arc;

use bytes::{BufMut, BytesMut};
use clap::{Arg, ArgAction, Command};

use futures::{SinkExt, StreamExt};
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::{DEFAULT_CONFIG_PATH, DEFAULT_SOCK_PATH};
use himmelblau_unix_common::db::Db;
use himmelblau_unix_common::idprovider::himmelblau::HimmelblauMultiProvider;
use himmelblau_unix_common::resolver::Resolver;
use himmelblau_unix_common::unix_config::UidAttr;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse};

use std::path::Path;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::{Decoder, Encoder, Framed};

use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal::unix::{signal, SignalKind};

use tracing::{debug, error, info, warn};

/// Pass this a file path and it'll look for the file and remove it if it's there.
fn rm_if_exist(p: &str) {
    if Path::new(p).exists() {
        debug!("Removing requested file {:?}", p);
        let _ = std::fs::remove_file(p).map_err(|e| {
            error!(
                "Failure while attempting to attempting to remove {:?} -> {:?}",
                p, e
            );
        });
    } else {
        debug!("Path {:?} doesn't exist, not attempting to remove.", p);
    }
}

struct ClientCodec;

impl Decoder for ClientCodec {
    type Error = io::Error;
    type Item = ClientRequest;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match serde_json::from_slice::<ClientRequest>(src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<ClientResponse> for ClientCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: ClientResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("Attempting to send response -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

impl ClientCodec {
    fn new() -> Self {
        ClientCodec
    }
}

async fn handle_client(
    sock: UnixStream,
    cachelayer: Arc<Resolver<HimmelblauMultiProvider>>,
) -> Result<(), Box<dyn Error>> {
    debug!("Accepted connection");

    let Ok(ucred) = sock.peer_cred() else {
        return Err(Box::new(IoError::new(ErrorKind::Other, "Unable to verify peer credentials.")));
    };

    let mut reqs = Framed::new(sock, ClientCodec::new());
    let mut pam_auth_session_state = None;

    while let Some(Ok(req)) = reqs.next().await {
        let resp = match req {
            ClientRequest::PamAuthenticateInit(account_id) => {
                debug!("pam authenticate init");

                match &pam_auth_session_state {
                    Some(_auth_session) => {
                        // Invalid to init a request twice.
                        warn!("Attempt to init auth session while current session is active");
                        // Clean the former session, something is wrong.
                        pam_auth_session_state = None;
                        ClientResponse::Error
                    }
                    None => {
                        match cachelayer
                            .pam_account_authenticate_init(account_id.as_str())
                            .await
                        {
                            Ok((auth_session, pam_auth_response)) => {
                                pam_auth_session_state = Some(auth_session);
                                pam_auth_response.into()
                            }
                            Err(_) => ClientResponse::Error,
                        }
                    }
                }
            }
            ClientRequest::PamAuthenticateStep(pam_next_req) => {
                debug!("pam authenticate step");
                match &mut pam_auth_session_state {
                    Some(auth_session) => cachelayer
                        .pam_account_authenticate_step(auth_session, pam_next_req)
                        .await
                        .map(|pam_auth_response| pam_auth_response.into())
                        .unwrap_or(ClientResponse::Error),
                    None => {
                        warn!("Attempt to continue auth session while current session is inactive");
                        ClientResponse::Error
                    }
                }
            }
            ClientRequest::PamAccountAllowed(account_id) => {
                debug!("pam account allowed");
                cachelayer
                    .pam_account_allowed(account_id.as_str())
                    .await
                    .map(ClientResponse::PamStatus)
                    .unwrap_or(ClientResponse::Error)
            }
            ClientRequest::PamAccountBeginSession(_account_id) => {
                debug!("pam account begin session");
                // TODO: Implement session
                ClientResponse::PamStatus(Some(true))
            }
            ClientRequest::NssAccounts => {
                debug!("nssaccounts req");
                cachelayer
                    .get_nssaccounts()
                    .await
                    .map(ClientResponse::NssAccounts)
                    .unwrap_or_else(|_| {
                        error!("unable to enum accounts");
                        ClientResponse::NssAccounts(Vec::new())
                    })
            }
            ClientRequest::NssAccountByName(account_id) => {
                debug!("nssaccountbyname req");
                cachelayer
                    .get_nssaccount_name(account_id.as_str())
                    .await
                    .map(ClientResponse::NssAccount)
                    .unwrap_or_else(|_| {
                        error!("unable to load account, returning empty.");
                        ClientResponse::NssAccount(None)
                    })
            }
            ClientRequest::NssAccountByUid(uid) => {
                debug!("nssaccountbyuid req");
                cachelayer
                    .get_nssaccount_gid(uid)
                    .await
                    .map(ClientResponse::NssAccount)
                    .unwrap_or_else(|_| {
                        error!("unable to load account, returning empty.");
                        ClientResponse::NssAccount(None)
                    })
            }
            ClientRequest::NssGroups => {
                debug!("nssgroups req");
                cachelayer
                    .get_nssgroups()
                    .await
                    .map(ClientResponse::NssGroups)
                    .unwrap_or_else(|_| {
                        error!("unable to enum groups");
                        ClientResponse::NssGroups(Vec::new())
                    })
            }
            ClientRequest::NssGroupByName(grp_id) => {
                debug!("nssgroupbyname req");
                cachelayer
                    .get_nssgroup_name(grp_id.as_str())
                    .await
                    .map(ClientResponse::NssGroup)
                    .unwrap_or_else(|_| {
                        error!("unable to load group, returning empty.");
                        ClientResponse::NssGroup(None)
                    })
            }
            ClientRequest::NssGroupByGid(gid) => {
                debug!("nssgroupbygid req");
                cachelayer
                    .get_nssgroup_gid(gid)
                    .await
                    .map(ClientResponse::NssGroup)
                    .unwrap_or_else(|_| {
                        error!("unable to load group, returning empty.");
                        ClientResponse::NssGroup(None)
                    })
            }
            ClientRequest::InvalidateCache => {
                debug!("invalidate cache");
                cachelayer
                    .invalidate()
                    .await
                    .map(|_| ClientResponse::Ok)
                    .unwrap_or(ClientResponse::Error)
            }
            ClientRequest::ClearCache => {
                debug!("clear cache");
                if ucred.uid() == 0 {
                    cachelayer
                        .clear_cache()
                        .await
                        .map(|_| ClientResponse::Ok)
                        .unwrap_or(ClientResponse::Error)
                } else {
                    error!("Only root may clear the cache");
                    ClientResponse::Error
                }
            }
            ClientRequest::Status => {
                debug!("status check");
                if cachelayer.test_connection().await {
                    ClientResponse::Ok
                } else {
                    ClientResponse::Error
                }
            }
            ClientRequest::SshKey(_) => ClientResponse::Error,
        };
        reqs.send(resp).await?;
        reqs.flush().await?;
        debug!("flushed response!");
    }

    // Disconnect them
    debug!("Disconnecting client ...");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let clap_args = Command::new("himmelblaud")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Himmelblau Authentication Daemon")
        .arg(
            Arg::new("debug")
                .help("Show extra debug information")
                .short('d')
                .long("debug")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    if clap_args.get_flag("debug") {
        std::env::set_var("RUST_LOG", "debug");
    }
    tracing_subscriber::fmt::init();

    let stop_now = Arc::new(AtomicBool::new(false));
    let terminate_now = Arc::clone(&stop_now);
    let quit_now = Arc::clone(&stop_now);
    let interrupt_now = Arc::clone(&stop_now);

    async {
        // Read the configuration
        let config = match HimmelblauConfig::new(DEFAULT_CONFIG_PATH) {
            Ok(c) => c,
            Err(e) => {
                error!("{}", e);
                return ExitCode::FAILURE;
            }
        };

        let socket_path = match config.get("global", "socket_path") {
            Some(val) => val,
            None => {
                debug!("Using default socket path {}", DEFAULT_SOCK_PATH);
                String::from(DEFAULT_SOCK_PATH)
            }
        };
        debug!("🧹 Cleaning up socket from previous invocations");
        rm_if_exist(&socket_path);

        // Create the identify provider connection
        let idprovider = match HimmelblauMultiProvider::new() {
            Ok(idprovider) => idprovider,
            Err(e) => {
                error!("{}", e);
                return ExitCode::FAILURE;
            }
        };
        // Create the database
        let db = match Db::new(&config.get_db_path(), &config.get_tpm_policy()) {
            Ok(db) => db,
            Err(_e) => {
                error!("Failed to create database");
                return ExitCode::FAILURE;
            }
        };

        let cl_inner = match Resolver::new(
            db,
            idprovider,
            config.get_cache_timeout(),
            config.get_pam_allow_groups(),
            config.get_shell(None),
            config.get_home_prefix(None),
            config.get_home_attr(None),
            config.get_home_alias(None),
            UidAttr::Spn,
            UidAttr::Name,
            vec![], // TODO: Implement local account override
        )
        .await
        {
            Ok(c) => c,
            Err(_e) => {
                error!("Failed to build cache layer.");
                return ExitCode::FAILURE;
            }
        };

        let cachelayer = Arc::new(cl_inner);

        // Open the socket for all to read and write
        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(_e) => {
                error!("Failed to bind UNIX socket at {}", &socket_path);
                return ExitCode::FAILURE;
            }
        };
        match set_permissions(&socket_path, Permissions::from_mode(0o777)) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to set permissions for {}: {}", &socket_path, e);
                return ExitCode::FAILURE;
            }
        }

        let server = tokio::spawn(async move {
            while !stop_now.load(Ordering::Relaxed) {
                let cachelayer_ref = cachelayer.clone();
                match listener.accept().await {
                    Ok((socket, _addr)) => {
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(socket, cachelayer_ref.clone()).await {
                                error!("handle_client error occurred; error = {:?}", e);
                            }
                        });
                    }
                    Err(err) => {
                        error!("Error while handling connection -> {:?}", err);
                    }
                }
            }
        });

        let terminate_task = tokio::spawn(async move {
            match signal(SignalKind::terminate()) {
                Ok(mut stream) => {
                    stream.recv().await;
                    terminate_now.store(true, Ordering::Relaxed);
                }
                Err(e) => {
                    error!("Failed registering terminate signal: {}", e);
                }
            };
        });

        let quit_task = tokio::spawn(async move {
            match signal(SignalKind::quit()) {
                Ok(mut stream) => {
                    stream.recv().await;
                    quit_now.store(true, Ordering::Relaxed);
                }
                Err(e) => {
                    error!("Failed registering quit signal: {}", e);
                }
            };
        });

        let interrupt_task = tokio::spawn(async move {
            match signal(SignalKind::interrupt()) {
                Ok(mut stream) => {
                    stream.recv().await;
                    interrupt_now.store(true, Ordering::Relaxed);
                }
                Err(e) => {
                    error!("Failed registering interrupt signal: {}", e);
                }
            };
        });

        info!("Server started ...");

        tokio::select! {
            _ = server => {
                debug!("Main listener task is terminating");
            },
            _ = terminate_task => {
                debug!("Received signal to terminate");
            },
            _ = quit_task => {
                debug!("Received signal to quit");
            },
            _ = interrupt_task => {
                debug!("Received signal to interrupt");
            }
        }

        ExitCode::SUCCESS
    }
    .await
}
