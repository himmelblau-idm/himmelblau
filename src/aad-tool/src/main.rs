use clap::{App, Arg, SubCommand, ArgAction};
use tracing::{warn, debug, error, info};
use anyhow::{anyhow, Result};
use std::process::ExitCode;
use msal::authentication::PublicClientApplication;
use himmelblau_unix_common::constants::{DEFAULT_CONFIG_PATH, DEFAULT_APP_ID};
use himmelblau_unix_common::config::HimmelblauConfig;
use std::io;
use std::io::Write;
use himmelblau_unix_common::client_sync::call_daemon_blocking;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse};
use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};
use tokio;

async fn enroll(config: HimmelblauConfig, domain: &str, admin: &str) -> Result<()> {
    let (_tenant_id, authority_url, graph) = config.get_authority_url(domain).await;
    let app_id = config.get_app_id(domain);
    if app_id == DEFAULT_APP_ID {
        error!("Please specify an app_id in himmelblau.conf.");
        /* TODO: Figure out how to join via Intune Portal for Linux. Currently
         * it throws Access Denied errors. */
        return Err(anyhow!("Enrollment directly in the Intune Portal for Linux is not possible."));
    }
    let app = PublicClientApplication::new(&app_id, authority_url.as_str());
    let scopes = vec!["Directory.AccessAsUser.All"];
    info!("If you get error AADSTS500113 during authentication, you need to configure the Redirect URI of your \"Mobile and Desktop application\" as ``http://localhost`` for your Application in Azure.");
    let token = match app.acquire_token_interactive(scopes, "login", admin, domain) {
        Ok(token) => token,
        Err(e) => return Err(anyhow!("Failed enrolling the machine: {}", e))
    };
    match token.access_token {
        Some(access_token) => {
            debug!("Authentication successful");
            let req = ClientRequest::EnrollDevice(graph.to_string(), access_token.to_string());
            let socket_path = config.get_socket_path();
            match call_daemon_blocking(&socket_path, &req, 10) {
                Ok(r) => match r {
                    ClientResponse::Ok => {
                        Ok(())
                    },
                    _ => {
                        Err(anyhow!("Failed enrolling the machine. Invalid response!"))
                    },
                },
                Err(e) => {
                    Err(anyhow!("Failed enrolling the machine: {}", e))
                }
            }
        },
        None => {
            Err(anyhow!("{}: {}", token.error, token.error_description))
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cuid = get_current_uid();
    let ceuid = get_effective_uid();
    let cgid = get_current_gid();
    let cegid = get_effective_gid();

    let args = App::new("aad-tool")
        .arg(
            Arg::new("debug")
                .help("Show extra debug information")
                .short('d')
                .long("debug")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("skip-root-check")
                .help("Allow running as root. This should not be necessary!")
                .short('r')
                .long("skip-root-check")
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            SubCommand::with_name("enroll")
                .about("Enroll this device in Azure Active Directory")
                .arg(
                    Arg::with_name("domain")
                        .value_name("DOMAIN")
                        .help("Sets the Azure AD domain to enroll in")
                        .required(true)
                )
                .arg(
                    Arg::with_name("username")
                        .help("The calling user must be in one of the following Azure AD roles: Global Administrator, Intune Administrator, or Windows 365 Administrator.")
                        .short('U')
                        .long("username")
                        .takes_value(true)
                )
                .arg(
                    Arg::new("app-id")
                        .help("Sets the Application (client) ID")
                        .short('a')
                        .long("app-id")
                        .multiple_values(false)
                        .takes_value(true)
                )
        )
        .subcommand(
            SubCommand::with_name("cache")
                .about("Cache operations")
            .subcommand(
                SubCommand::with_name("clear")
                    .about("Cache clear tool")
            )
            .subcommand(
                SubCommand::with_name("invalidate")
                    .about("Cache invalidatation tool")
            )
            .subcommand(
                SubCommand::with_name("status")
                    .about("Cache status tool")
            )
        ).get_matches();

    if args.get_flag("debug") {
        std::env::set_var("RUST_LOG", "debug");
    }
    tracing_subscriber::fmt::init();

    if args.get_flag("skip-root-check") {
        warn!("Skipping root user check.")
    } else if cuid == 0 || ceuid == 0 || cgid == 0 || cegid == 0 {
        error!("Refusing to run - this process need not run as root.");
        return ExitCode::FAILURE
    };

    // Read the configuration
    let mut config = match HimmelblauConfig::new(DEFAULT_CONFIG_PATH) {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            return ExitCode::FAILURE
        }
    };

    match args.subcommand() {
        Some(("enroll", enroll_args)) => {
            let domain: &str = enroll_args.value_of("domain")
                .expect("Failed unwrapping the domain name");
            let admin: String = match enroll_args.value_of("username") {
                Some(username) => username.to_owned(),
                None => {
                    print!("Username: ");
                    io::stdout().flush()
                        .expect("Failed flushing prompt");
                    let mut buf = String::new();
                    io::stdin().read_line(&mut buf)
                        .expect("Failed reading username");
                    buf.to_owned()
                },
            };
            match enroll_args.value_of("app-id") {
                Some(app_id) => {
                    config.set("global", "app_id", app_id);
                },
                None => {},
            }
            match enroll(config, domain, &admin).await {
                Ok(()) => debug!("Success"),
                Err(e) => {
                    error!("{}", e);
                    return ExitCode::FAILURE;
                }
            };
        },
        Some(("invalidate", _args)) => {
            let req = ClientRequest::InvalidateCache;
            let socket_path = config.get_socket_path();
            match call_daemon_blocking(&socket_path, &req, 10) {
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
        },
        Some(("clear", _args)) => {
            let req = ClientRequest::ClearCache;
            let socket_path = config.get_socket_path();
            match call_daemon_blocking(&socket_path, &req, 10) {
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
        }
        Some(("status", _args)) => {
            let req = ClientRequest::Status;
            let socket_path = config.get_socket_path();
            match call_daemon_blocking(&socket_path, &req, 10) {
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
        _ => {
            error!("Invalid command. Use 'aad-tool --help' for more information");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
