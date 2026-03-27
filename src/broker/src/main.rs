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
use std::fmt;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use tracing::error;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{reload, EnvFilter};

// Need to translate between syslog levels and tracing levels
#[derive(Clone, Copy)]
enum SyslogLevel {
    Emerg,
    Alert,
    Crit,
    Err,
    Warning,
    Notice,
    Info,
    Debug,
}

impl fmt::Display for SyslogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Emerg => "emerg",
            Self::Alert => "alert",
            Self::Crit => "crit",
            Self::Err => "err",
            Self::Warning => "warning",
            Self::Notice => "notice",
            Self::Info => "info",
            Self::Debug => "debug",
        })
    }
}

impl SyslogLevel {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "emerg" => Ok(Self::Emerg),
            "alert" => Ok(Self::Alert),
            "crit" => Ok(Self::Crit),
            "err" => Ok(Self::Err),
            "warning" => Ok(Self::Warning),
            "notice" => Ok(Self::Notice),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            other => Err(format!("Invalid log level: {}, allowed: emerg, alert, crit, err, warning, notice, info, debug", other)),
        }
    }

    fn from_level_filter(level: LevelFilter) -> Self {
        match level {
            LevelFilter::OFF => Self::Emerg,
            LevelFilter::ERROR => Self::Err,
            LevelFilter::WARN => Self::Warning,
            LevelFilter::INFO => Self::Info,
            LevelFilter::DEBUG | LevelFilter::TRACE => Self::Debug,
        }
    }

    fn to_env_filter(self) -> Result<EnvFilter, String> {
        let tracing_level = match self {
            Self::Emerg | Self::Alert | Self::Crit | Self::Err => "error",
            Self::Warning | Self::Notice => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        };
        EnvFilter::try_new(tracing_level).map_err(|e| format!("Failed to create filter: {}", e))
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let initial_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let (filter_layer, reload_handle) = reload::Layer::new(initial_filter);

    let initial_syslog_level =
        SyslogLevel::from_level_filter(filter_layer.max_level_hint().unwrap_or(LevelFilter::INFO));

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let syslog_level = Arc::new(Mutex::new(initial_syslog_level));

    let get_level = Arc::clone(&syslog_level);
    let set_level = Arc::clone(&syslog_level);
    let config_handle = reload_handle.clone();
    let config_level = Arc::clone(&syslog_level);
    let log_callbacks = LogLevelCallbacks {
        get: Arc::new(move || match get_level.lock() {
            Ok(level) => level.to_string(),
            Err(e) => e.into_inner().to_string(),
        }),
        set: Arc::new(move |level: &str| {
            let parsed = SyslogLevel::parse(level)?;
            let new_filter = parsed.to_env_filter()?;
            reload_handle
                .reload(new_filter)
                .map_err(|e| format!("Failed to reload filter: {}", e))?;
            let mut guard = match set_level.lock() {
                Ok(guard) => guard,
                Err(e) => e.into_inner(),
            };
            *guard = parsed;
            Ok(())
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

    // Apply config-driven debug level, overriding RUST_LOG if set
    if cfg.get_debug() {
        if let Ok(debug_filter) = EnvFilter::try_new("debug") {
            match config_handle.reload(debug_filter) {
                Ok(()) => match config_level.lock() {
                    Ok(mut level) => *level = SyslogLevel::Debug,
                    Err(e) => error!("Failed to update log level: {}", e),
                },
                Err(e) => error!("Failed to reload debug filter: {}", e),
            }
        }
    }

    let sock_path = cfg.get_broker_socket_path();
    let timeout = cfg.get_connection_timeout();

    match himmelblau_session_broker_serve(&sock_path, timeout, log_callbacks).await {
        Ok(_) => return ExitCode::SUCCESS,
        Err(e) => {
            error!("Broker service failed: {}", e);
            return ExitCode::FAILURE;
        }
    }
}
