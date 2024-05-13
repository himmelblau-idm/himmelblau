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
use himmelblau_unix_common::client_sync::DaemonClientBlocking;
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use himmelblau_unix_common::unix_proto::{
    ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse,
};
use rpassword::prompt_password;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

include!("./opt/tool.rs");

macro_rules! match_sm_auth_client_response {
    ($expr:expr, $opts:ident, $($pat:pat => $result:expr),*) => {
        match $expr {
            Ok(r) => match r {
                $($pat => $result),*
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Success) => {
                    println!("auth success!");
                    break;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Denied) => {
                    println!("auth failed!");
                    break;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Unknown) => {
                    println!("auth user unknown");
                    break;
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
}

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

            let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
                }
            };

            let mut timeout = cfg.get_unix_sock_timeout();
            let mut daemon_client = match DaemonClientBlocking::new(&cfg.get_socket_path()) {
                Ok(dc) => dc,
                Err(e) => {
                    error!(err = ?e, "Error DaemonClientBlocking::new()");
                    return ExitCode::FAILURE;
                }
            };

            let mut req = ClientRequest::PamAuthenticateInit(account_id.clone());
            loop {
                match_sm_auth_client_response!(daemon_client.call_and_wait(&req, timeout), opts,
                    ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Password) => {
                        // Prompt for and get the password
                        let cred = match prompt_password("Password: ") {
                            Ok(p) => p,
                            Err(e) => {
                                error!("Problem getting input: {}", e);
                                return ExitCode::FAILURE;
                            }
                        };

                        // Now setup the request for the next loop.
                        timeout = cfg.get_unix_sock_timeout();
                        req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password { cred });
                        continue;
                    },
                    ClientResponse::PamAuthenticateStepResponse(
                        PamAuthResponse::DeviceAuthorizationGrant { data },
                    ) => {
                        let msg = match &data.message {
                            Some(msg) => msg.clone(),
                            None => format!("Using a browser on another device, visit:\n{}\nAnd enter the code:\n{}",
                                            data.verification_uri, data.user_code)
                        };
                        println!("{}", msg);

                        timeout = u64::from(data.expires_in);
                        req = ClientRequest::PamAuthenticateStep(
                            PamAuthRequest::DeviceAuthorizationGrant { data },
                        );
                        continue;
                    },
                    ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFACode {
                        msg,
                    }) => {
                        // Prompt for and get the MFA code
                        println!("{}", msg);
                        let cred = match prompt_password("Code: ") {
                            Ok(p) => p,
                            Err(e) => {
                                error!("Problem getting input: {}", e);
                                return ExitCode::FAILURE;
                            }
                        };

                        // Now setup the request for the next loop.
                        timeout = cfg.get_unix_sock_timeout();
                        req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFACode {
                            cred,
                        });
                        continue;
                    },
                    ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFAPoll {
                        msg,
                        polling_interval,
                    }) => {
                        // Prompt the MFA message
                        println!("{}", msg);

                        loop {
                            thread::sleep(Duration::from_secs(polling_interval.into()));
                            timeout = cfg.get_unix_sock_timeout();
                            req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFAPoll);

                            // Counter intuitive, but we don't need a max poll attempts here because
                            // if the resolver goes away, then this will error on the sock and
                            // will shutdown. This allows the resolver to dynamically extend the
                            // timeout if needed, and removes logic from the front end.
                            match_sm_auth_client_response!(
                                daemon_client.call_and_wait(&req, timeout), opts,
                                ClientResponse::PamAuthenticateStepResponse(
                                        PamAuthResponse::MFAPollWait,
                                ) => {
                                    // Continue polling if the daemon says to wait
                                    continue;
                                }
                            );

                        }
                    },
                    ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::SetupPin {
                        msg,
                    }) => {
                        // Prompt for a new Hello PIN
                        println!("{}", msg);

                        let mut pin;
                        let mut confirm;
                        loop {
                            pin = match prompt_password("New PIN: ") {
                                Ok(p) => p,
                                Err(e) => {
                                    error!("Problem getting input: {}", e);
                                    return ExitCode::FAILURE;
                                }
                            };

                            confirm = match prompt_password("Confirm PIN: ") {
                                Ok(p) => p,
                                Err(e) => {
                                    error!("Problem getting input: {}", e);
                                    return ExitCode::FAILURE;
                                }
                            };

                            if pin == confirm {
                                break;
                            } else {
                                println!("Inputs did not match. Try again.");
                            }
                        }

                        // Now setup the request for the next loop.
                        timeout = cfg.get_unix_sock_timeout();
                        req = ClientRequest::PamAuthenticateStep(PamAuthRequest::SetupPin {
                            pin,
                        });
                        continue;
                    },
                    ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Pin) => {
                        // Prompt for and get the Hello PIN
                        let cred = match prompt_password("PIN: ") {
                            Ok(p) => p,
                            Err(e) => {
                                error!("Problem getting input: {}", e);
                                return ExitCode::FAILURE;
                            }
                        };

                        // Now setup the request for the next loop.
                        timeout = cfg.get_unix_sock_timeout();
                        req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Pin { cred });
                        continue;
                    }
                );
            }
            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::CacheClear { debug: _, really } => {
            debug!("Starting cache clear tool ...");

            let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
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

            let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
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

            let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
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
