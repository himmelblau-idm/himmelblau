/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
use himmelblau_unix_common::config::HimmelblauConfig;
use identity_dbus_broker::{himmelblau_session_broker_serve, LogLevelCallbacks};
use std::process::ExitCode;
use std::sync::Arc;
use tracing::error;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{reload, EnvFilter};

fn syslog_level_from_level_filter(level: LevelFilter) -> &'static str {
    match level {
        LevelFilter::OFF | LevelFilter::ERROR => "err",
        LevelFilter::WARN => "warning",
        LevelFilter::INFO => "info",
        LevelFilter::DEBUG | LevelFilter::TRACE => "debug",
    }
}

fn env_filter_from_syslog_level(level: &str) -> Result<EnvFilter, String> {
    let tracing_level = match level {
        "emerg" | "alert" | "crit" | "err" => "error",
        "warning" | "notice" => "warn",
        "info" => "info",
        "debug" => "debug",
        other => return Err(format!("Invalid log level: {}", other)),
    };
    EnvFilter::try_new(tracing_level)
        .map_err(|e| format!("Failed to create filter: {}", e))
}

#[tokio::main]
async fn main() -> ExitCode {
    let initial_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let (filter_layer, reload_handle) = reload::Layer::new(initial_filter);

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let get_handle = reload_handle.clone();
    let log_callbacks = LogLevelCallbacks {
        get: Arc::new(move || {
            get_handle
                .with_current(|f| {
                    syslog_level_from_level_filter(
                        f.max_level_hint().unwrap_or(LevelFilter::TRACE),
                    )
                })
                .unwrap_or("info")
                .to_string()
        }),
        set: Arc::new(move |level: &str| {
            let new_filter = env_filter_from_syslog_level(level)?;
            reload_handle
                .reload(new_filter)
                .map_err(|e| format!("Failed to reload filter: {}", e))
        }),
    };

    // Read the configuration
    let cfg = match HimmelblauConfig::new(None) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let sock_path = cfg.get_broker_socket_path();
    let timeout = cfg.get_connection_timeout();

    match himmelblau_session_broker_serve(&sock_path, timeout, log_callbacks)
        .await
    {
        Ok(_) => return ExitCode::SUCCESS,
        Err(e) => {
            error!("Broker service failed: {}", e);
            return ExitCode::FAILURE;
        }
    }
}
