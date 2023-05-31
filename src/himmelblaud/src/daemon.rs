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
use std::io;
use std::process::ExitCode;
use std::sync::Arc;

use bytes::{BufMut, BytesMut};
use clap::{Arg, ArgAction, Command};

use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use himmelblau_unix_common::constants::DEFAULT_SOCK_PATH;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse};
use msal::authentication::PublicClientApplication;
use futures::{SinkExt, StreamExt};

use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio_util::codec::{Decoder, Encoder, Framed};

use log::{error, debug, info};
use configparser::ini::Ini;

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
    capp: Arc<Mutex<PublicClientApplication>>,
) -> Result<(), Box<dyn Error>> {
    debug!("Accepted connection");

    let mut reqs = Framed::new(sock, ClientCodec::new());
    let app = capp.lock().await;

    while let Some(Ok(req)) = reqs.next().await {
        let resp = match req {
            ClientRequest::PamAuthenticate(account_id, cred) => {
                debug!("pam authenticate");
                let token = app.acquire_token_by_username_password(account_id.as_str(), cred.as_str(), vec![]);
                ClientResponse::PamStatus(token.contains_key("access_token").then(|| true))
            },
            _ => todo!()
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

    async {
        debug!("🧹 Cleaning up socket from previous invocations");
        rm_if_exist(DEFAULT_SOCK_PATH);

        // Read the configuration
        let mut config = Ini::new();
        let cfg_path: PathBuf = PathBuf::from(DEFAULT_CONFIG_PATH);
        if !cfg_path.exists() {
            // there's no point trying to start up if we can't read a usable config!
            error!("config missing from {} - cannot start up. Quitting.",
                   DEFAULT_CONFIG_PATH);
            return ExitCode::FAILURE
        } else {
            match config.load(DEFAULT_CONFIG_PATH) {
                Ok(c) => c,
                Err(_e) => {
                    error!("failed to read config from {} - cannot start up. Quitting.",
                           DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE
                }
            };
        }

        // Connect to the broker
        let authority_url = format!("https://login.microsoftonline.com/{}",
                                    config.get("global", "tenant_id").as_deref().unwrap());
        let app = Arc::new(Mutex::new(PublicClientApplication::new(
                    config.get("global", "app_id").as_deref().unwrap(),
                    authority_url.as_str())));

        let listener = match UnixListener::bind(DEFAULT_SOCK_PATH) {
            Ok(l) => l,
            Err(_e) => {
                error!("Failed to bind UNIX socket at {}", DEFAULT_SOCK_PATH);
                return ExitCode::FAILURE
            }
        };

        let server = async move {
            loop {
                let capp = app.clone();
                match listener.accept().await {
                    Ok((socket, _addr)) => {
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(socket, capp).await
                            {
                                error!("handle_client error occurred; error = {:?}", e);
                            }
                        });
                    }
                    Err(err) => {
                        error!("Error while handling connection -> {:?}", err);
                    }
                }
            }
        };

        info!("Server started ...");

        server.await;
        ExitCode::SUCCESS
    }
    .await
}
