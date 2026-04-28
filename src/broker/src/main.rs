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
use himmelblau_unix_common::auth::{authenticate, MessagePrinter};
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::pam::{Options, PamResultCode};
use identity_dbus_broker::{
    session_broker_serve, LogLevelCallbacks, SessionBroker,
};
use pinentry::PassphraseInput;
use sd_notify::NotifyState;
use secrecy::ExposeSecret;
use std::fmt;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time;
use tracing::{debug, error, info};
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

/// A `MessagePrinter` that uses `pinentry` for prompts and messages.
/// Used by `authenticate()` for the interactive auth flow.
struct PinentryMessagePrinter;

impl MessagePrinter for PinentryMessagePrinter {
    fn print_text(&self, msg: &str) {
        // Strip greeter protocol prefixes as these are meant for the
        // qr-greeter GNOME extension, not for end-user display.
        let clean = msg
            .trim_start_matches("[FIDO_INSERT] ")
            .trim_start_matches("[FIDO_TOUCH] ");
        debug!("message: {}", clean);
        if let Some(mut dialog) = pinentry::MessageDialog::with_default_binary() {
            let _ = dialog.with_ok("OK").show_message(clean);
        }
    }

    fn print_error(&self, msg: &str) {
        let clean = msg
            .trim_start_matches("[FIDO_INSERT] ")
            .trim_start_matches("[FIDO_TOUCH] ");
        error!("auth error: {}", clean);
        if let Some(mut dialog) = pinentry::MessageDialog::with_default_binary() {
            let _ = dialog.with_ok("OK").show_message(clean);
        }
    }

    fn prompt_echo_off(&self, prompt: &str) -> Option<String> {
        let mut input = PassphraseInput::with_default_binary()?;
        input
            .with_description("Entra ID Authentication")
            .with_prompt(prompt);
        match input.interact() {
            Ok(secret) => Some(secret.expose_secret().to_string()),
            Err(e) => {
                debug!("pinentry interaction failed: {:?}", e);
                None
            }
        }
    }
}

/// Session broker that forwards all D-Bus calls to the himmelblaud
/// broker socket, but overrides `acquireTokenInteractively` to
/// drive a full interactive auth (via `authenticate()` on the main
/// daemon socket with pinentry) when silent acquisition fails.
struct InteractiveSessionBroker {
    /// Path to the himmelblaud broker socket.
    broker_sock_path: String,
    /// Connection timeout in seconds.
    timeout: u64,
    /// Himmelblau configuration (for main socket path, FIDO config, etc.).
    cfg: Arc<HimmelblauConfig>,
}

impl InteractiveSessionBroker {
    /// Construct the serde JSON for a broker ClientRequest variant
    /// and forward it to the himmelblaud broker socket.
    fn forward(
        &self,
        method: &str,
        args: &[&str],
    ) -> Result<String, dbus::MethodErr> {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let request_json = serde_json::json!({ method: args });
        let serialized = serde_json::to_vec(&request_json)
            .map_err(|e| dbus::MethodErr::failed(&format!("JSON encode: {}", e)))?;

        let mut stream = UnixStream::connect(&self.broker_sock_path)
            .map_err(|e| dbus::MethodErr::failed(&format!("broker socket connect: {}", e)))?;

        stream
            .write_all(&serialized)
            .and_then(|_| stream.flush())
            .map_err(|e| dbus::MethodErr::failed(&format!("broker socket write: {}", e)))?;

        let timeout = Duration::from_secs(self.timeout);
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| dbus::MethodErr::failed(&format!("set_read_timeout: {}", e)))?;

        let mut data = Vec::with_capacity(4096);
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    data.extend_from_slice(&buf[..n]);
                    if serde_json::from_slice::<serde_json::Value>(&data).is_ok() {
                        break;
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if !data.is_empty()
                        && serde_json::from_slice::<serde_json::Value>(&data).is_ok()
                    {
                        break;
                    }
                    return Err(dbus::MethodErr::failed(&"broker socket read timeout"));
                }
                Err(e) => {
                    return Err(dbus::MethodErr::failed(&format!(
                        "broker socket read: {}",
                        e
                    )));
                }
            }
        }

        String::from_utf8(data)
            .map_err(|e| dbus::MethodErr::failed(&format!("invalid UTF-8: {}", e)))
    }
}

impl SessionBroker for InteractiveSessionBroker {
    fn acquire_token_interactively(
        &mut self,
        protocol_version: String,
        correlation_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr> {
        // Extract the username from the request for authenticate()
        let account_id = serde_json::from_str::<serde_json::Value>(&request_json)
            .ok()
            .and_then(|v| {
                v.get("account")
                    .or_else(|| v.get("authParameters").and_then(|ap| ap.get("account")))
                    .and_then(|a| a.get("username"))
                    .and_then(|u| u.as_str())
                    .map(String::from)
            })
            .ok_or_else(|| dbus::MethodErr::failed(&"Missing account username in request"))?;

        // Run authenticate() on a dedicated thread to avoid nested
        // tokio runtime issues (fido_auth creates its own Runtime).
        let cfg = (*self.cfg).clone();
        let msg_printer: Arc<dyn MessagePrinter> = Arc::new(PinentryMessagePrinter);
        let opts = Options {
            debug: false,
            use_first_pass: false,
            ignore_unknown_user: false,
            mfa_poll_prompt: false,
            no_hello_pin: true,
            set_authtok: false,
            try_unseal: false,
            force_reauth: true,
        };

        info!(
            "acquireTokenInteractively: starting interactive auth for {}",
            account_id
        );

        let account_id_clone = account_id.clone();
        let auth_result = std::thread::spawn(move || {
            authenticate(
                None,
                cfg,
                &account_id_clone,
                "broker-interactive",
                opts,
                msg_printer,
            )
        })
        .join()
        .map_err(|_| dbus::MethodErr::failed(&"Authentication thread panicked"))?;

        if auth_result != PamResultCode::PAM_SUCCESS {
            return Err(dbus::MethodErr::failed(&format!(
                "Interactive authentication failed: {:?}",
                auth_result
            )));
        }

        info!(
            "acquireTokenInteractively: auth succeeded for {}, acquiring token",
            account_id
        );

        // Auth succeeded — PRT is now refreshed. Acquire the token
        // silently via the broker socket.
        self.acquire_token_silently(protocol_version, correlation_id, request_json)
    }

    fn acquire_token_silently(
        &mut self,
        protocol_version: String,
        correlation_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr> {
        self.forward(
            "acquireTokenSilently",
            &[&protocol_version, &correlation_id, &request_json],
        )
    }

    fn get_accounts(
        &mut self,
        protocol_version: String,
        correlation_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr> {
        self.forward(
            "getAccounts",
            &[&protocol_version, &correlation_id, &request_json],
        )
    }

    fn remove_account(
        &mut self,
        protocol_version: String,
        correlation_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr> {
        self.forward(
            "removeAccount",
            &[&protocol_version, &correlation_id, &request_json],
        )
    }

    fn acquire_prt_sso_cookie(
        &mut self,
        protocol_version: String,
        correlation_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr> {
        self.forward(
            "acquirePrtSsoCookie",
            &[&protocol_version, &correlation_id, &request_json],
        )
    }

    fn generate_signed_http_request(
        &mut self,
        protocol_version: String,
        correlation_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr> {
        self.forward(
            "generateSignedHttpRequest",
            &[&protocol_version, &correlation_id, &request_json],
        )
    }

    fn cancel_interactive_flow(
        &mut self,
        protocol_version: String,
        correlation_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr> {
        self.forward(
            "cancelInteractiveFlow",
            &[&protocol_version, &correlation_id, &request_json],
        )
    }

    fn get_linux_broker_version(
        &mut self,
        protocol_version: String,
        correlation_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr> {
        self.forward(
            "getLinuxBrokerVersion",
            &[&protocol_version, &correlation_id, &request_json],
        )
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let initial_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,authenticator=warn"));
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
    let cfg = Arc::new(cfg);

    let systemd_booted = sd_notify::booted().unwrap_or(false);

    let broker_sock = sock_path.clone();
    let broker_cfg = Arc::clone(&cfg);
    let mut broker_handle = tokio::spawn(async move {
        session_broker_serve(
            InteractiveSessionBroker {
                broker_sock_path: broker_sock,
                timeout,
                cfg: broker_cfg,
            },
            "himmelblau_broker",
            log_callbacks,
        )
        .await
    });

    if systemd_booted {
        let _ = sd_notify::notify(&[NotifyState::Ready]);
    }

    // Ping the systemd watchdog at half the configured WatchdogSec interval.
    let mut watchdog_interval = if systemd_booted {
        std::env::var("WATCHDOG_USEC")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|usec| time::interval(Duration::from_micros(usec / 2)))
    } else {
        None
    };

    loop {
        tokio::select! {
            result = &mut broker_handle => {
                match result {
                    Ok(Ok(_)) => return ExitCode::SUCCESS,
                    Ok(Err(e)) => {
                        error!("Broker service failed: {}", e);
                        return ExitCode::FAILURE;
                    }
                    Err(e) => {
                        error!("Broker task panicked: {}", e);
                        return ExitCode::FAILURE;
                    }
                }
            }
            _ = async {
                match watchdog_interval.as_mut() {
                    Some(interval) => interval.tick().await,
                    None => std::future::pending().await,
                }
            } => {
                let _ = sd_notify::notify(&[NotifyState::Watchdog]);
            }
        }
    }
}
