use clap::{App, Arg, SubCommand, ArgAction};
use tracing::{warn, error, info};
use std::process::ExitCode;
use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::client::call_daemon;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse};
use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};
use tokio;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cuid = get_current_uid();
    let ceuid = get_effective_uid();
    let cgid = get_current_gid();
    let cegid = get_effective_gid();

    let parser = App::new("aad-tool")
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
        );

    // Read the configuration
    let config = match HimmelblauConfig::new(DEFAULT_CONFIG_PATH) {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            return ExitCode::FAILURE
        }
    };

    let args = parser.get_matches();

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

    match args.subcommand() {
        Some(("invalidate", _args)) => {
            let req = ClientRequest::InvalidateCache;
            let socket_path = config.get_socket_path();
            match call_daemon(&socket_path, req, 10).await {
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
            match call_daemon(&socket_path, req, 10).await {
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
            match call_daemon(&socket_path, req, 10).await {
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
