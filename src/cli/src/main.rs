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

#[macro_use]
extern crate tracing;

use std::process::ExitCode;

use clap::Parser;
use himmelblau_unix_common::client::call_daemon;
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use himmelblau_unix_common::unix_proto::{
    ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse,
};
use rpassword::prompt_password;
use std::path::PathBuf;

include!("./opt/tool.rs");

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let opt = HimmelblauUnixParser::parse();

    let debug = match opt.commands {
        HimmelblauUnixOpt::AuthTest {
            debug,
            account_id: _,
        } => debug,
        HimmelblauUnixOpt::CacheClear { debug, really: _ } => debug,
        HimmelblauUnixOpt::CacheInvalidate { debug } => debug,
        HimmelblauUnixOpt::Status { debug } => debug,
        HimmelblauUnixOpt::Version { debug } => debug,
    };

    if debug {
        std::env::set_var("RUST_LOG", "debug");
    }
    sketching::tracing_subscriber::fmt::init();

    match opt.commands {
        HimmelblauUnixOpt::AuthTest {
            debug: _,
            account_id,
        } => {
            debug!("Starting PAM auth tester tool ...");

            let cfg = match HimmelblauConfig::new(DEFAULT_CONFIG_PATH) {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
                }
            };

            let mut req = ClientRequest::PamAuthenticateInit(account_id.clone());
            loop {
                match call_daemon(&cfg.get_socket_path(), req, cfg.get_unix_sock_timeout()).await {
                    Ok(r) => match r {
                        ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Success) => {
                            // ClientResponse::PamStatus(Some(true)) => {
                            println!("auth success!");
                            break;
                        }
                        ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Denied) => {
                            // ClientResponse::PamStatus(Some(false)) => {
                            println!("auth failed!");
                            break;
                        }
                        ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Unknown) => {
                            // ClientResponse::PamStatus(None) => {
                            println!("auth user unknown");
                            break;
                        }
                        ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Password) => {
                            // Prompt for and get the password
                            let cred = match prompt_password("Enter Unix password: ") {
                                Ok(p) => p,
                                Err(e) => {
                                    error!("Problem getting input: {}", e);
                                    return ExitCode::FAILURE;
                                }
                            };

                            // Setup the req for the next loop.
                            req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password {
                                cred,
                            });
                            continue;
                        }
                        _ => {
                            // unexpected response.
                            error!("Error: unexpected response -> {:?}", r);
                            break;
                        }
                    },
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        break;
                    }
                }
            }

            let sereq = ClientRequest::PamAccountAllowed(account_id);

            match call_daemon(&cfg.get_socket_path(), sereq, cfg.get_unix_sock_timeout()).await {
                Ok(r) => match r {
                    ClientResponse::PamStatus(Some(true)) => {
                        println!("account success!");
                    }
                    ClientResponse::PamStatus(Some(false)) => {
                        println!("account failed!");
                    }
                    ClientResponse::PamStatus(None) => {
                        println!("account user unknown");
                    }
                    _ => {
                        // unexpected response.
                        error!("Error: unexpected response -> {:?}", r);
                    }
                },
                Err(e) => {
                    error!("Error -> {:?}", e);
                }
            };
            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::CacheClear { debug: _, really } => {
            debug!("Starting cache clear tool ...");

            let cfg = match HimmelblauConfig::new(DEFAULT_CONFIG_PATH) {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
                }
            };

            if !really {
                error!("Are you sure you want to proceed? If so use --really");
                return ExitCode::SUCCESS;
            }

            let req = ClientRequest::ClearCache;

            match call_daemon(&cfg.get_socket_path(), req, cfg.get_unix_sock_timeout()).await {
                Ok(r) => match r {
                    ClientResponse::Ok => info!("success"),
                    _ => {
                        error!("Error: unexpected response -> {:?}", r);
                    }
                },
                Err(e) => {
                    error!("Error -> {:?}", e);
                }
            };
            println!("success");
            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::CacheInvalidate { debug: _ } => {
            debug!("Starting cache invalidate tool ...");

            let cfg = match HimmelblauConfig::new(DEFAULT_CONFIG_PATH) {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
                }
            };

            let req = ClientRequest::InvalidateCache;

            match call_daemon(&cfg.get_socket_path(), req, cfg.get_unix_sock_timeout()).await {
                Ok(r) => match r {
                    ClientResponse::Ok => info!("success"),
                    _ => {
                        error!("Error: unexpected response -> {:?}", r);
                    }
                },
                Err(e) => {
                    error!("Error -> {:?}", e);
                }
            };
            println!("success");
            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::Status { debug: _ } => {
            trace!("Starting cache status tool ...");

            let cfg = match HimmelblauConfig::new(DEFAULT_CONFIG_PATH) {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
                }
            };

            let req = ClientRequest::Status;

            let spath = PathBuf::from(cfg.get_socket_path());
            if !spath.exists() {
                error!(
                    "himmelblaud socket {} does not exist - is the service running?",
                    cfg.get_socket_path()
                )
            } else {
                match call_daemon(&cfg.get_socket_path(), req, cfg.get_unix_sock_timeout()).await {
                    Ok(r) => match r {
                        ClientResponse::Ok => println!("working!"),
                        _ => {
                            error!("Error: unexpected response -> {:?}", r);
                        }
                    },
                    Err(e) => {
                        error!("Error -> {:?}", e);
                    }
                }
            }
            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::Version { debug: _ } => {
            println!("himmelblau {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
    }
}
