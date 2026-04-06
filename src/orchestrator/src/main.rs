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

mod communication;
mod flow;
mod podman;
mod provider_definitions;
mod session;
mod types;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use communication::CommunicationServer;
use flow::FlowExecutor;
use himmelblau_unix_common::config::HimmelblauConfig;
use podman::PodmanClient;
use provider_definitions::ProviderRegistry;
use session::SessionManager;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::broadcast;
use tokio::time::interval;
use tracing::{error, info, warn};

const DEFAULT_ORCHESTRATOR_SOCKET_PATH: &str = "/var/run/himmelblaud/orchestrator.sock";
const DEFAULT_ORCHESTRATOR_RUNTIME_DIR: &str = "/run/himmelblaud/orchestrator";
const DEFAULT_PROVIDER_OVERRIDE_PATH: &str = "/etc/himmelblau/orchestrator-providers.json";
const DEFAULT_PLAYWRIGHT_IMAGE: &str = "localhost/himmelblau/playwright-orchestrator:latest";
const DEFAULT_CONTAINER_NETWORK: &str = "host";

#[derive(Debug, Parser)]
#[command(name = "himmelblaud-orchestrator")]
#[command(about = "Containerized browser orchestration backend for OIDC interactive auth")]
struct OrchestratorArgs {
    #[arg(
        long,
        env = "HIMMELBLAU_CONFIG",
        default_value = "/etc/himmelblau/himmelblau.conf"
    )]
    config: String,

    #[arg(long, env = "HIMMELBLAU_ORCHESTRATOR_SOCKET", default_value = DEFAULT_ORCHESTRATOR_SOCKET_PATH)]
    socket: String,

    #[arg(long, env = "HIMMELBLAU_ORCHESTRATOR_PROVIDER_FILE", default_value = DEFAULT_PROVIDER_OVERRIDE_PATH)]
    provider_file: String,

    #[arg(long, env = "HIMMELBLAU_ORCHESTRATOR_PODMAN", default_value = "podman")]
    podman_binary: String,

    #[arg(long, env = "HIMMELBLAU_ORCHESTRATOR_IMAGE", default_value = DEFAULT_PLAYWRIGHT_IMAGE)]
    container_image: String,

    #[arg(long, env = "HIMMELBLAU_ORCHESTRATOR_NETWORK", default_value = DEFAULT_CONTAINER_NETWORK)]
    container_network: String,

    #[arg(
        long,
        env = "HIMMELBLAU_ORCHESTRATOR_RUNTIME_DIR",
        default_value = DEFAULT_ORCHESTRATOR_RUNTIME_DIR
    )]
    runtime_dir: String,

    #[arg(long, env = "HIMMELBLAU_ORCHESTRATOR_IDLE_SECS", default_value_t = 300)]
    idle_timeout_secs: u64,

    #[arg(
        long,
        env = "HIMMELBLAU_ORCHESTRATOR_TERMINAL_RETENTION_SECS",
        default_value_t = 60
    )]
    terminal_retention_secs: u64,

    #[arg(
        long,
        env = "HIMMELBLAU_ORCHESTRATOR_CLEANUP_INTERVAL_SECS",
        default_value_t = 30
    )]
    cleanup_interval_secs: u64,

    #[arg(
        long,
        env = "HIMMELBLAU_ORCHESTRATOR_ACTION_TIMEOUT_SECS",
        default_value_t = 45
    )]
    action_timeout_secs: u64,

    #[arg(
        long,
        env = "HIMMELBLAU_ORCHESTRATOR_NO_NEW_PRIVILEGES",
        default_value = "true"
    )]
    container_no_new_privileges: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = OrchestratorArgs::parse();

    let config = HimmelblauConfig::new(Some(&args.config))
        .map_err(anyhow::Error::msg)
        .context("failed to load himmelblau config")?;

    init_tracing(config.get_debug());
    let config = Arc::new(config);

    let provider_override_path = PathBuf::from(&args.provider_file);
    let provider_registry = Arc::new(if provider_override_path.exists() {
        ProviderRegistry::load(Some(provider_override_path.as_path())).await?
    } else {
        ProviderRegistry::load(None).await?
    });

    info!(providers = ?provider_registry.providers(), "loaded provider definitions");

    let container_no_new_privileges = parse_bool_flag(
        &args.container_no_new_privileges,
        "HIMMELBLAU_ORCHESTRATOR_NO_NEW_PRIVILEGES",
    )?;
    if !container_no_new_privileges {
        warn!(
            "orchestrator container security-opt no-new-privileges is DISABLED; use only for compatibility troubleshooting"
        );
    }

    let podman_client = Arc::new(PodmanClient::new(
        args.podman_binary,
        args.container_image,
        Some(args.container_network),
        PathBuf::from(args.runtime_dir),
        args.action_timeout_secs,
        container_no_new_privileges,
    ));

    let session_manager = Arc::new(SessionManager::new(
        Arc::clone(&podman_client),
        Duration::from_secs(args.idle_timeout_secs),
        Duration::from_secs(args.terminal_retention_secs),
    ));
    let flow_executor = Arc::new(FlowExecutor::new(Arc::clone(&podman_client)));

    let communication_server = CommunicationServer::new(
        Arc::clone(&session_manager),
        Arc::clone(&provider_registry),
        Arc::clone(&config),
        Arc::clone(&flow_executor),
    );

    let (shutdown_tx, _) = broadcast::channel::<()>(8);

    let cleanup_task = {
        let session_manager = Arc::clone(&session_manager);
        let mut shutdown_rx = shutdown_tx.subscribe();
        let cleanup_every = Duration::from_secs(args.cleanup_interval_secs);
        tokio::spawn(async move {
            let mut ticker = interval(cleanup_every);
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                    _ = ticker.tick() => {
                        match session_manager.cleanup_stale_sessions().await {
                            Ok(cleaned) if cleaned > 0 => {
                                info!(cleaned, "cleaned stale orchestrator sessions");
                            }
                            Ok(_) => {}
                            Err(error) => {
                                warn!(?error, "stale session cleanup failed");
                            }
                        }
                    }
                }
            }
        })
    };

    let server_task = {
        let shutdown_rx = shutdown_tx.subscribe();
        let socket_path = PathBuf::from(&args.socket);
        tokio::spawn(async move { communication_server.run(&socket_path, shutdown_rx).await })
    };

    wait_for_shutdown_signal().await?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(());

    if let Err(error) = cleanup_task.await {
        error!(?error, "cleanup task join error");
    }

    match server_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => error!(?error, "communication server exited with error"),
        Err(error) => error!(?error, "communication server join error"),
    }

    info!(
        active_sessions = session_manager.active_count().await,
        "orchestrator stopped"
    );
    Ok(())
}

fn parse_bool_flag(raw: &str, name: &str) -> Result<bool> {
    let normalized = raw.trim().to_ascii_lowercase();
    if ["1", "true", "yes", "on"].contains(&normalized.as_str()) {
        return Ok(true);
    }
    if ["0", "false", "no", "off"].contains(&normalized.as_str()) {
        return Ok(false);
    }

    Err(anyhow!(
        "invalid boolean for {}: '{}'; expected one of true/false/1/0/yes/no/on/off",
        name,
        raw
    ))
}

fn init_tracing(debug_enabled: bool) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if debug_enabled {
            tracing_subscriber::EnvFilter::new("debug")
        } else {
            tracing_subscriber::EnvFilter::new("info")
        }
    });

    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();
}

async fn wait_for_shutdown_signal() -> Result<()> {
    let mut sigterm =
        signal(SignalKind::terminate()).context("failed to register SIGTERM handler")?;
    let mut sigint =
        signal(SignalKind::interrupt()).context("failed to register SIGINT handler")?;

    tokio::select! {
        _ = sigterm.recv() => Ok(()),
        _ = sigint.recv() => Ok(()),
    }
}
