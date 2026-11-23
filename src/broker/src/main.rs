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
use himmelblau_unix_common::i18n::{tr, translate_external_message};
use himmelblau_unix_common::pam::{Options, PamResultCode};
use identity_dbus_broker::{session_broker_serve, LogLevelCallbacks, SessionBroker};
use pinentry::PassphraseInput;
use sd_notify::NotifyState;
use secrecy::ExposeSecret;
use std::fmt;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time;
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info};
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

/// True when logind reports the user's graphical session as locked. A prompt
/// cannot be shown over the lock screen (pinentry-gnome3 falls back to curses,
/// which has no tty in a user service), so the attempt only blocks the broker.
/// Any lookup failure is treated as unlocked to keep the previous behavior.
fn graphical_session_locked() -> bool {
    use dbus::blocking::stdintf::org_freedesktop_dbus::Properties;
    use dbus::blocking::Connection;

    let locked_hint = || -> Result<bool, dbus::Error> {
        let conn = Connection::new_system()?;
        let timeout = Duration::from_secs(2);
        let user = conn.with_proxy(
            "org.freedesktop.login1",
            "/org/freedesktop/login1/user/self",
            timeout,
        );
        let (_, session): (String, dbus::Path<'static>) =
            user.get("org.freedesktop.login1.User", "Display")?;
        conn.with_proxy("org.freedesktop.login1", session, timeout)
            .get("org.freedesktop.login1.Session", "LockedHint")
    };
    match locked_hint() {
        Ok(locked) => locked,
        Err(e) => {
            debug!("Could not read the logind LockedHint: {}", e);
            false
        }
    }
}

/// True when we can prompt: an unlocked graphical session and a pinentry
/// binary exist.
fn interactive_session_available() -> bool {
    let has_display =
        std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();
    let has_pinentry = pinentry::PassphraseInput::with_default_binary().is_some();
    if !has_display {
        info!("No X11/Wayland session detected; cannot prompt interactively");
    }
    if !has_pinentry {
        info!("No pinentry binary found on PATH; cannot prompt interactively");
    }
    if !(has_display && has_pinentry) {
        return false;
    }
    if graphical_session_locked() {
        info!("Graphical session is locked; cannot prompt interactively");
        return false;
    }
    true
}

/// True when a broker SSO cookie response carries a usable cookie.
fn sso_cookie_response_is_valid(resp: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(resp)
        .ok()
        .and_then(|v| {
            v.get("cookieContent")
                .and_then(|c| c.as_str())
                .map(|c| !c.is_empty())
        })
        .unwrap_or(false)
}

/// True when a line is unicode/ASCII QR art (mostly block-drawing glyphs).
/// Those lines must not be sent through pinentry: the Assuan client panics on
/// long undivided SETDESC payloads (`splitting of long lines yet implemented`).
fn is_qr_art_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    let non_space = trimmed.chars().filter(|c| !c.is_whitespace()).count();
    if non_space == 0 {
        return false;
    }
    let blocks = trimmed
        .chars()
        .filter(|c| matches!(*c, '\u{2580}'..='\u{259F}'))
        .count();
    // QR rows are almost entirely half/full blocks + spaces.
    blocks * 2 >= non_space
}

// pinentry-rs caps encoded commands at 1000 bytes. Reserve room for command
// framing and its special handling of a trailing backslash.
const MAX_PINENTRY_TEXT_BYTES: usize = 900;

fn pinentry_char_bytes(ch: char) -> usize {
    match ch {
        '\n' | '\r' | '%' => 3,
        _ => ch.len_utf8(),
    }
}

fn limit_pinentry_text(msg: &str) -> String {
    const ELLIPSIS: &str = "\u{2026}";
    let mut encoded_bytes = 0;
    let mut prefix_end = 0;
    for (index, ch) in msg.char_indices() {
        encoded_bytes += pinentry_char_bytes(ch);
        if encoded_bytes <= MAX_PINENTRY_TEXT_BYTES - ELLIPSIS.len() {
            prefix_end = index + ch.len_utf8();
        }
        if encoded_bytes > MAX_PINENTRY_TEXT_BYTES {
            return format!("{}{ELLIPSIS}", &msg[..prefix_end]);
        }
    }
    msg.to_string()
}

/// Remove greeter prefixes and QR art while retaining full text for URL launch.
fn sanitize_for_pinentry(msg: &str) -> String {
    let clean = msg
        .trim_start_matches("[FIDO_INSERT] ")
        .trim_start_matches("[FIDO_TOUCH] ");

    clean
        .lines()
        .filter(|line| !is_qr_art_line(line))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

/// Pull https URLs out of MFA / device-code messages for browser launch.
fn extract_https_urls(msg: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut rest = msg;
    while let Some(start) = rest.find("https://") {
        let candidate = &rest[start..];
        let end = candidate
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '`' | '"' | '\'' | ')' | ']' | '>' | ',')
            })
            .unwrap_or(candidate.len());
        let url = candidate[..end]
            .trim_end_matches(['.', ';', ':'])
            .to_string();
        if !url.is_empty() {
            urls.push(url);
        }
        rest = &candidate[end.max(1)..];
    }
    urls
}

fn is_device_code_message(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("enter the code")
        || lower.contains("login.microsoft.com/device")
        || lower.contains("microsoft.com/devicelogin")
}

/// Open MFA / device-code URLs so the user is not stuck with a dead pinentry OK.
fn maybe_open_auth_urls(msg: &str) {
    for url in extract_https_urls(msg) {
        let lower = url.to_ascii_lowercase();
        if !(lower.contains("login.microsoft")
            || lower.contains("microsoftonline")
            || lower.contains("/device"))
        {
            continue;
        }
        match std::process::Command::new("xdg-open").arg(&url).spawn() {
            Ok(_) => info!("opened auth URL in browser: {}", url),
            Err(e) => debug!("could not open auth URL {}: {}", url, e),
        }
    }
}

fn show_pinentry_message(msg: &str) {
    maybe_open_auth_urls(msg);
    let ok_label = if is_device_code_message(msg) {
        "Continue after signing in"
    } else {
        "OK"
    };
    let msg = limit_pinentry_text(msg);
    let Some(mut dialog) = pinentry::MessageDialog::with_default_binary() else {
        error!("No pinentry binary found for authentication message");
        return;
    };
    if let Err(e) = dialog.with_ok(ok_label).show_message(&msg) {
        error!("pinentry message failed: {:?}", e);
    }
}

const PINENTRY_TITLE: &str = "Entra ID Authentication";

fn confirm_pinentry_retry(msg: &str) -> bool {
    let Some(mut dialog) = pinentry::ConfirmationDialog::with_default_binary() else {
        error!("No pinentry binary found for authentication retry confirmation");
        return false;
    };
    let msg = limit_pinentry_text(msg);
    let ok = tr("OK");
    let cancel = tr("Cancel");
    match dialog
        .with_title(PINENTRY_TITLE)
        .with_ok(&ok)
        .with_cancel(&cancel)
        .confirm(&msg)
    {
        Ok(retry) => retry,
        Err(e) => {
            error!("pinentry retry confirmation failed: {:?}", e);
            false
        }
    }
}

fn authenticate_with_retry(
    mut authenticate: impl FnMut(Arc<PinentryMessagePrinter>) -> Result<PamResultCode, dbus::MethodErr>,
    mut confirm_retry: impl FnMut(&str) -> bool,
) -> Result<(), dbus::MethodErr> {
    loop {
        let printer = Arc::new(PinentryMessagePrinter::default());
        let result = authenticate(Arc::clone(&printer))?;
        if result == PamResultCode::PAM_SUCCESS {
            return Ok(());
        }
        let message = printer
            .failure_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(message) = message {
            if confirm_retry(&message) {
                continue;
            }
        }
        return Err(dbus::MethodErr::failed(&format!(
            "Interactive authentication failed: {:?}",
            result
        )));
    }
}

/// Prompt and description shown in a pinentry passphrase dialog.
fn pinentry_prompt_fields(prompt: &str, message: Option<String>) -> (String, String) {
    let prompt = prompt.trim();
    // pinentry-gnome3 renders the prompt as the dialog heading.
    let prompt = if prompt == tr("PIN:").trim() {
        tr("Authorization Required")
    } else {
        prompt.to_string()
    };
    let description = message.unwrap_or_else(|| PINENTRY_TITLE.to_string());
    (
        limit_pinentry_text(&prompt),
        limit_pinentry_text(&description),
    )
}

fn pinentry_error_message(error: String, description: Option<String>) -> String {
    let Some(description) = description else {
        return error;
    };
    let combined = format!("{description}\n\n{error}");
    // Do not let optional prompt context displace the error when truncating.
    if combined.chars().map(pinentry_char_bytes).sum::<usize>() > MAX_PINENTRY_TEXT_BYTES {
        error
    } else {
        combined
    }
}

/// A `MessagePrinter` that uses `pinentry` for prompts and messages.
/// Used by `authenticate()` for the interactive auth flow.
#[derive(Default)]
struct PinentryMessagePrinter {
    pending_message: Mutex<Option<String>>,
    failure_message: Mutex<Option<String>>,
}

impl PinentryMessagePrinter {
    fn take_pending_message(&self) -> Option<String> {
        self.pending_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    fn show_text(&self, msg: &str, mut show: impl FnMut(&str)) {
        let clean = sanitize_for_pinentry(msg);
        if clean.is_empty() {
            return;
        }
        debug!("message: {}", clean);
        if let Some(pending) = self.take_pending_message() {
            show(&pending);
        }
        show(&clean);
    }
}

impl MessagePrinter for PinentryMessagePrinter {
    fn print_sensitive(&self, msg: &str) {
        let clean = sanitize_for_pinentry(msg);
        if !clean.is_empty() {
            if let Some(pending) = self.take_pending_message() {
                show_pinentry_message(&pending);
            }
            show_pinentry_message(&clean);
        }
    }

    fn print_text(&self, msg: &str) {
        self.show_text(msg, show_pinentry_message);
    }

    fn print_prompt_description(&self, msg: &str) {
        let clean = sanitize_for_pinentry(msg);
        if clean.is_empty() {
            return;
        }
        debug!("prompt description: {}", clean);
        let previous = self
            .pending_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .replace(clean);
        if let Some(previous) = previous {
            show_pinentry_message(&previous);
        }
    }

    fn print_auth_failure(&self, code: PamResultCode, msg: &str) {
        let clean = sanitize_for_pinentry(&translate_external_message(msg));
        error!("auth failure {:?}: {}", code, clean);
        let message = if clean.is_empty() {
            tr("Authentication failed.")
        } else {
            clean
        };
        *self
            .failure_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(message);
    }

    fn retry_after_denial(&self, msg: &str) -> bool {
        self.print_auth_failure(PamResultCode::PAM_AUTH_ERR, msg);
        false
    }

    fn print_error(&self, msg: &str) {
        let clean = sanitize_for_pinentry(msg);
        if clean.is_empty() {
            return;
        }
        error!("auth error: {}", clean);
        let message = pinentry_error_message(clean, self.take_pending_message());
        show_pinentry_message(&message);
    }

    fn prompt_echo_on(&self, prompt: &str) -> Option<String> {
        self.prompt_echo_off(prompt)
    }

    fn prompt_echo_off(&self, prompt: &str) -> Option<String> {
        let mut input = PassphraseInput::with_default_binary()?;
        let (prompt, description) = pinentry_prompt_fields(prompt, self.take_pending_message());
        input
            .with_title(PINENTRY_TITLE)
            .with_description(description.as_str())
            .with_prompt(prompt.as_str());
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
    fn forward(&self, method: &str, args: &[&str]) -> Result<String, dbus::MethodErr> {
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

    /// Resolve the caller's session account and reject any supplied username
    /// that does not match it before starting interactive authentication.
    fn resolve_account_id(
        request_json: &str,
        get_accounts: impl FnOnce() -> Result<String, dbus::MethodErr>,
    ) -> Result<String, dbus::MethodErr> {
        let request: serde_json::Value = serde_json::from_str(request_json)
            .map_err(|e| dbus::MethodErr::failed(&format!("Invalid broker request: {}", e)))?;
        let request = request.as_object().ok_or_else(|| {
            dbus::MethodErr::failed(&"Invalid broker request: expected an object")
        })?;
        let auth_parameters = match request.get("authParameters") {
            None | Some(serde_json::Value::Null) => None,
            Some(parameters) => Some(parameters.as_object().ok_or_else(|| {
                dbus::MethodErr::failed(&"Invalid broker request: authParameters must be an object")
            })?),
        };
        let mut requested_usernames = Vec::new();
        for account in [
            request.get("account"),
            auth_parameters.and_then(|parameters| parameters.get("account")),
        ]
        .into_iter()
        .flatten()
        .filter(|account| !account.is_null())
        {
            let account = account.as_object().ok_or_else(|| {
                dbus::MethodErr::failed(&"Invalid broker request: account must be an object")
            })?;
            match account.get("username") {
                None | Some(serde_json::Value::Null) => {}
                Some(serde_json::Value::String(username)) => {
                    requested_usernames.push(username);
                }
                Some(_) => {
                    return Err(dbus::MethodErr::failed(
                        &"Invalid broker request: account.username must be a string or null",
                    ));
                }
            }
        }
        // getAccounts is scoped by the daemon to the socket peer's UID.
        let response = get_accounts()?;
        let response: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| dbus::MethodErr::failed(&format!("Invalid accounts response: {}", e)))?;
        let account_id = response
            .get("accounts")
            .and_then(|accounts| accounts.as_array())
            .filter(|accounts| accounts.len() == 1)
            .and_then(|accounts| accounts.first())
            .and_then(|account| account.get("username"))
            .and_then(|username| username.as_str())
            .filter(|username| !username.trim().is_empty())
            .ok_or_else(|| {
                dbus::MethodErr::failed(&"Unable to resolve session account username")
            })?;
        let expected_username = account_id.to_lowercase();
        if requested_usernames
            .iter()
            .any(|username| username.to_lowercase() != expected_username)
        {
            return Err(dbus::MethodErr::failed(&"Invalid request for user!"));
        }
        Ok(account_id.to_string())
    }

    /// Drive an interactive auth via pinentry to re-prime the daemon cache.
    fn run_interactive_auth(&self, account_id: &str) -> Result<(), dbus::MethodErr> {
        authenticate_with_retry(
            |msg_printer| {
                if !interactive_session_available() {
                    return Err(dbus::MethodErr::failed(
                        &"No interactive prompt available: no unlocked graphical session or pinentry binary found",
                    ));
                }
                // Run authenticate() on a dedicated thread to avoid nested
                // tokio runtime issues (fido_auth creates its own Runtime).
                let cfg = (*self.cfg).clone();
                // Hello PIN provides the interactive step required by Edge.
                // force_reauth / no_hello_pin would skip it and fall back to MFA.
                let opts = Options::default();

                info!("starting interactive auth for {}", account_id);

                let account_id_clone = account_id.to_string();
                std::thread::spawn(move || {
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
                .map_err(|_| dbus::MethodErr::failed(&"Authentication thread panicked"))
            },
            confirm_pinentry_retry,
        )?;

        info!("interactive auth succeeded for {}", account_id);
        Ok(())
    }
}

impl SessionBroker for InteractiveSessionBroker {
    fn acquire_token_interactively(
        &mut self,
        protocol_version: String,
        correlation_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr> {
        let account_id = Self::resolve_account_id(&request_json, || {
            self.forward("getAccounts", &[&protocol_version, &correlation_id, "{}"])
        })?;

        self.run_interactive_auth(&account_id)?;

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
        // A daemon that cannot mint a cookie closes the connection without a
        // response, so forward() yields a payload with no cookieContent rather
        // than an Err; transport errors still propagate here.
        let resp = self.forward(
            "acquirePrtSsoCookie",
            &[&protocol_version, &correlation_id, &request_json],
        )?;
        if sso_cookie_response_is_valid(&resp) {
            return Ok(resp);
        }

        // No cookie: re-prime the PRT interactively, or surface the failure
        // (an empty response means no reply at all) when we cannot prompt.
        if !interactive_session_available() {
            if resp.is_empty() {
                return Err(dbus::MethodErr::failed(
                    &"PRT SSO cookie unavailable and no interactive session to re-authenticate",
                ));
            }
            return Ok(resp);
        }
        info!("Silent PRT SSO cookie unavailable; attempting interactive re-auth");
        let account_id = Self::resolve_account_id(&request_json, || {
            self.forward("getAccounts", &[&protocol_version, &correlation_id, "{}"])
        })?;
        self.run_interactive_auth(&account_id)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pinentry_request_bytes(command: &str, value: &str) -> usize {
        let mut escaped = value
            .replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A");
        if escaped.ends_with('\\') {
            escaped.pop();
            escaped.push_str("%5C");
        }
        format!("{command} {escaped}\n").len()
    }

    #[test]
    fn resolves_missing_username_from_session_account() {
        for request in [
            "{}",
            r#"{"account":null}"#,
            r#"{"account":{}}"#,
            r#"{"account":{"username":null}}"#,
            r#"{"authParameters":null}"#,
            r#"{"authParameters":{"account":{"username":null}}}"#,
        ] {
            let account_id = InteractiveSessionBroker::resolve_account_id(request, || {
                Ok(r#"{"accounts":[{"username":"user@example.com"}]}"#.to_string())
            })
            .unwrap();
            assert_eq!(account_id, "user@example.com");
        }
    }

    #[test]
    fn malformed_request_fails_before_account_lookup() {
        let mut queried = false;
        let error = InteractiveSessionBroker::resolve_account_id("{", || {
            queried = true;
            Ok(r#"{"accounts":[{"username":"user@example.com"}]}"#.to_string())
        })
        .unwrap_err();
        assert!(!queried);
        assert!(error.to_string().contains("Invalid broker request"));
    }

    #[test]
    fn invalid_account_fields_fail_before_account_lookup() {
        for invalid in [
            serde_json::json!(7),
            serde_json::json!(true),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            for request in [
                serde_json::json!({"account": {"username": invalid}}),
                serde_json::json!({"authParameters": {"account": {"username": invalid}}}),
                serde_json::json!({
                    "account": {"username": "user@example.com"},
                    "authParameters": {"account": {"username": invalid}}
                }),
                serde_json::json!({
                    "account": {"username": invalid},
                    "authParameters": {"account": {"username": "user@example.com"}}
                }),
            ] {
                let error =
                    InteractiveSessionBroker::resolve_account_id(&request.to_string(), || {
                        panic!("Invalid request must fail before account lookup")
                    })
                    .unwrap_err();
                assert!(error
                    .to_string()
                    .contains("account.username must be a string or null"));
            }
        }
        for request in [
            "null",
            "[]",
            "7",
            r#"{"account":true}"#,
            r#"{"account":"user@example.com"}"#,
            r#"{"authParameters":[]}"#,
            r#"{"authParameters":{"account":7}}"#,
            r#"{"account":{"username":"user@example.com"},"authParameters":true}"#,
            r#"{"account":{"username":"user@example.com"},"authParameters":{"account":[]}}"#,
        ] {
            let error = InteractiveSessionBroker::resolve_account_id(request, || {
                panic!("Invalid request must fail before account lookup")
            })
            .unwrap_err();
            assert!(error.to_string().contains("Invalid broker request"));
        }
    }

    #[test]
    fn explicit_usernames_must_match_session_account() {
        for request in [
            r#"{"account":{"username":"explicit@example.com"}}"#,
            r#"{"authParameters":{"account":{"username":"explicit@example.com"}}}"#,
            r#"{"account":null,"authParameters":{"account":{"username":"explicit@example.com"}}}"#,
            r#"{"account":{},"authParameters":{"account":{"username":"explicit@example.com"}}}"#,
            r#"{"account":{"username":null},"authParameters":{"account":{"username":"explicit@example.com"}}}"#,
            r#"{"account":{"username":"EXPLICIT@EXAMPLE.COM"}}"#,
            r#"{"account":{"username":"explicit@example.com"},"authParameters":{"account":{"username":"EXPLICIT@EXAMPLE.COM"}}}"#,
        ] {
            let account_id = InteractiveSessionBroker::resolve_account_id(request, || {
                Ok(r#"{"accounts":[{"username":"explicit@example.com"}]}"#.to_string())
            })
            .unwrap();
            assert_eq!(account_id, "explicit@example.com");
        }
    }

    #[test]
    fn mismatched_usernames_fail_before_interactive_authentication() {
        for username in ["other@another.org", "other@example.com", "", "  "] {
            for request in [
                serde_json::json!({"account": {"username": username}}),
                serde_json::json!({"authParameters": {"account": {"username": username}}}),
                serde_json::json!({
                    "account": {"username": "user@example.com"},
                    "authParameters": {"account": {"username": username}}
                }),
                serde_json::json!({
                    "account": {"username": username},
                    "authParameters": {"account": {"username": "user@example.com"}}
                }),
            ] {
                let error =
                    InteractiveSessionBroker::resolve_account_id(&request.to_string(), || {
                        Ok(r#"{"accounts":[{"username":"user@example.com"}]}"#.to_string())
                    })
                    .unwrap_err();
                assert!(error.to_string().contains("Invalid request for user!"));
            }
        }
    }

    #[test]
    fn requests_require_one_usable_session_account() {
        for request in ["{}", r#"{"account":{"username":"user@example.com"}}"#] {
            for response in [
                "not json",
                "{}",
                r#"{"accounts":[]}"#,
                r#"{"accounts":[{}]}"#,
                r#"{"accounts":[{"username":"  "}]}"#,
                r#"{"accounts":[{"username":"one@example.com"},{"username":"two@example.com"}]}"#,
            ] {
                assert!(InteractiveSessionBroker::resolve_account_id(request, || {
                    Ok(response.to_string())
                })
                .is_err());
            }
            assert!(InteractiveSessionBroker::resolve_account_id(request, || {
                Err(dbus::MethodErr::failed(&"Account lookup failed"))
            })
            .is_err());
        }
    }

    #[test]
    fn sso_cookie_valid_only_with_cookie_content() {
        assert!(sso_cookie_response_is_valid(
            r#"{"cookieContent":"abc","cookieName":"x"}"#
        ));
        assert!(!sso_cookie_response_is_valid(r#"{"cookieContent":""}"#));
        assert!(!sso_cookie_response_is_valid(r#"{"account":{}}"#));
        assert!(!sso_cookie_response_is_valid(""));
        assert!(!sso_cookie_response_is_valid("not json"));
    }

    #[test]
    fn sanitize_for_pinentry_strips_qr_art_keeps_prose() {
        let msg = "To sign in, visit https://login.microsoft.com/device and enter EH5PRW7RY.\n\
                   \u{2588}\u{2588}\u{2580}\u{2584}  \u{2588}\u{2580}\u{2588}\n\
                   \u{2580}\u{2584}\u{2588}\u{2580}\u{2584}\u{2588}\u{2580}\n\
                   Done.";
        let out = sanitize_for_pinentry(msg);
        assert!(out.contains("login.microsoft.com/device"));
        assert!(out.contains("EH5PRW7RY"));
        assert!(!out.contains('\u{2588}'));
        assert!(!out.contains('\u{2580}'));
        assert!(out.contains("Done."));
    }

    #[test]
    fn limit_pinentry_text_truncates_oversized_text() {
        let huge = "x".repeat(2000);
        let out = limit_pinentry_text(&huge);
        assert!(pinentry_request_bytes("SETDESC", &out) <= 1000);
        assert!(out.ends_with('\u{2026}'));
    }

    #[test]
    fn action_message_keeps_full_urls_until_display() {
        let url = format!(
            "https://login.microsoftonline.com/authorize?state={}",
            "%2F".repeat(400)
        );
        let printer = PinentryMessagePrinter::default();
        let mut shown = Vec::new();
        printer.show_text(&format!("Open {url}"), |message| {
            shown.push(message.to_string());
        });
        assert_eq!(shown.len(), 1);
        assert_eq!(extract_https_urls(&shown[0]), [url]);
    }

    #[test]
    fn pinentry_text_budget_handles_utf8_and_assuan_escaping() {
        for value in [
            "x",
            "\u{00e9}",
            "\u{4e2d}",
            "\u{1f600}",
            "%",
            "\r",
            "\n",
            "\\",
            "%\r\n\u{4e2d}\\",
        ] {
            for count in [0, 1, 299, 300, 301, 449, 450, 451, 899, 900, 901, 2000] {
                let input = value.repeat(count);
                let output = limit_pinentry_text(&input);
                for command in ["SETDESC", "SETPROMPT"] {
                    assert!(pinentry_request_bytes(command, &output) <= 1000);
                }
                if pinentry_request_bytes("SETPROMPT", &input) <= 900 {
                    assert_eq!(output, input);
                } else if pinentry_request_bytes("SETPROMPT", &input) > 1000 {
                    assert!(output.ends_with('\u{2026}'));
                    assert!(input.starts_with(output.strip_suffix('\u{2026}').unwrap()));
                }
            }
        }
        for input in ["x".repeat(900), "\u{4e2d}".repeat(300), "%".repeat(300)] {
            assert_eq!(limit_pinentry_text(&input), input);
        }
    }

    #[test]
    fn pinentry_prompt_fields_bound_final_prompt_and_description() {
        let (prompt, description) =
            pinentry_prompt_fields(&"%".repeat(1000), Some("\u{4e2d}".repeat(400)));
        assert!(pinentry_request_bytes("SETPROMPT", &prompt) <= 1000);
        assert!(pinentry_request_bytes("SETDESC", &description) <= 1000);
        assert!(prompt.ends_with('\u{2026}'));
        assert!(description.ends_with('\u{2026}'));
    }

    #[test]
    fn pinentry_error_message_keeps_errors_instead_of_oversized_context() {
        assert_eq!(
            pinentry_error_message("Failure".to_string(), Some("Context".to_string())),
            "Context\n\nFailure"
        );
        for (description, error) in [
            ("a".repeat(600), "b".repeat(600)),
            ("%".repeat(200), "b".repeat(400)),
            ("\u{4e2d}".repeat(200), "b".repeat(400)),
        ] {
            let message = pinentry_error_message(error.clone(), Some(description));
            assert_eq!(message, error);
            assert!(pinentry_request_bytes("SETDESC", &message) <= 1000);
        }
    }

    #[test]
    fn action_messages_are_shown_without_waiting_for_a_prompt() {
        for (msg, expected) in [
            (
                "Sign in at https://microsoft.com/devicelogin with code ABC123",
                "Sign in at https://microsoft.com/devicelogin with code ABC123",
            ),
            (
                "Approve sign-in on your phone",
                "Approve sign-in on your phone",
            ),
            ("[FIDO_INSERT] Insert your key", "Insert your key"),
            ("[FIDO_TOUCH] Touch your key", "Touch your key"),
        ] {
            let printer = PinentryMessagePrinter::default();
            let mut shown = Vec::new();
            printer.show_text(msg, |message| shown.push(message.to_string()));
            assert_eq!(shown, [expected]);
            assert!(printer.take_pending_message().is_none());
        }
    }

    #[test]
    fn credential_description_is_folded_into_the_next_prompt() {
        let printer = PinentryMessagePrinter::default();
        printer.print_prompt_description("Use your Hello PIN");
        assert_eq!(
            pinentry_prompt_fields("PIN: ", printer.take_pending_message()),
            (
                tr("Authorization Required"),
                "Use your Hello PIN".to_string()
            )
        );
        assert!(printer.take_pending_message().is_none());
    }

    #[test]
    fn action_message_flushes_an_unconsumed_description_first() {
        let printer = PinentryMessagePrinter::default();
        printer.print_prompt_description("Credential context");
        let mut shown = Vec::new();
        printer.show_text("Touch your key", |message| shown.push(message.to_string()));
        assert_eq!(shown, ["Credential context", "Touch your key"]);
        assert!(printer.take_pending_message().is_none());
    }

    #[test]
    fn confirmed_failure_retries_with_fresh_prompt_state() {
        let mut attempts = 0;
        let mut confirmations = 0;
        let failure = tr("No Entra Id Hello PIN was supplied.");
        let result = authenticate_with_retry(
            |printer| {
                attempts += 1;
                assert!(printer.take_pending_message().is_none());
                assert!(printer.failure_message.lock().unwrap().is_none());
                if attempts == 1 {
                    printer.print_prompt_description("Unconsumed description");
                    printer.print_auth_failure(
                        PamResultCode::PAM_CRED_INSUFFICIENT,
                        "No Entra Id Hello PIN was supplied.",
                    );
                    Ok(PamResultCode::PAM_ABORT)
                } else {
                    Ok(PamResultCode::PAM_SUCCESS)
                }
            },
            |message| {
                confirmations += 1;
                assert_eq!(message, failure);
                true
            },
        );
        assert!(result.is_ok());
        assert_eq!(attempts, 2);
        assert_eq!(confirmations, 1);
    }

    #[test]
    fn cancelled_failure_confirmation_ends_authentication() {
        for failure in ["Authentication failed.", ""] {
            let mut attempts = 0;
            let result = authenticate_with_retry(
                |printer| {
                    attempts += 1;
                    printer.print_auth_failure(PamResultCode::PAM_AUTH_ERR, failure);
                    Ok(PamResultCode::PAM_ABORT)
                },
                |message| {
                    assert_eq!(message, tr("Authentication failed."));
                    false
                },
            );
            assert!(result.is_err());
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn failures_without_recorded_messages_do_not_offer_retry() {
        for code in [
            PamResultCode::PAM_IGNORE,
            PamResultCode::PAM_SYSTEM_ERR,
            PamResultCode::PAM_USER_UNKNOWN,
        ] {
            let mut code = Some(code);
            let result = authenticate_with_retry(
                |_| Ok(code.take().expect("failure must not be retried")),
                |_| panic!("a failure without a recorded message must not show another dialog"),
            );
            assert!(result.is_err());
        }
    }

    #[test]
    fn daemon_denial_waits_for_confirmation_before_retrying() {
        use himmelblau_unix_common::auth::authenticate_with_client;
        use himmelblau_unix_common::client_sync::DaemonClientBlocking;
        use himmelblau_unix_common::unix_proto::{
            ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse,
        };
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        for retry in [false, true] {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("hb-broker-denied-{}-{nonce}", std::process::id()));
            let socket_path = path.with_extension("sock");
            let config_path = path.with_extension("conf");
            std::fs::write(&config_path, "[global]\n").unwrap();
            let listener = UnixListener::bind(&socket_path).unwrap();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut requests = Vec::new();
                for response in [
                    PamAuthResponse::Pin,
                    PamAuthResponse::Denied("Wrong Hello PIN".to_string()),
                ] {
                    let mut data = Vec::new();
                    let request = loop {
                        let mut buffer = [0; 4096];
                        let count = socket.read(&mut buffer).unwrap();
                        assert_ne!(count, 0);
                        data.extend_from_slice(&buffer[..count]);
                        if let Ok(request) = serde_json::from_slice::<ClientRequest>(&data) {
                            break request;
                        }
                    };
                    requests.push(request);
                    socket
                        .write_all(
                            &serde_json::to_vec(&ClientResponse::PamAuthenticateStepResponse(
                                response,
                            ))
                            .unwrap(),
                        )
                        .unwrap();
                }
                assert!(matches!(
                    requests.as_slice(),
                    [
                        ClientRequest::PamAuthenticateInit(..),
                        ClientRequest::PamAuthenticateStep(PamAuthRequest::Pin { .. }),
                    ]
                ));
                let mut buffer = [0];
                assert_eq!(socket.read(&mut buffer).unwrap(), 0);
            });
            let mut attempts = 0;
            let mut confirmations = 0;
            let result = authenticate_with_retry(
                |printer| {
                    attempts += 1;
                    if attempts > 1 {
                        return Ok(PamResultCode::PAM_SUCCESS);
                    }
                    let result = authenticate_with_client(
                        DaemonClientBlocking::new(socket_path.to_str().unwrap()).unwrap(),
                        Some("wrong-pin".to_string()),
                        HimmelblauConfig::new(Some(config_path.to_str().unwrap())).unwrap(),
                        "user@example.com",
                        "broker-interactive",
                        Options::default(),
                        printer,
                    );
                    assert_eq!(result, PamResultCode::PAM_AUTH_ERR);
                    Ok(result)
                },
                |message| {
                    confirmations += 1;
                    assert_eq!(message, "Wrong Hello PIN");
                    retry
                },
            );
            server.join().unwrap();
            std::fs::remove_file(socket_path).unwrap();
            std::fs::remove_file(config_path).unwrap();
            assert_eq!(result.is_ok(), retry);
            assert_eq!(attempts, if retry { 2 } else { 1 });
            assert_eq!(confirmations, 1);
        }
    }

    #[test]
    fn authentication_thread_error_is_not_retried() {
        let result = authenticate_with_retry(
            |_| Err(dbus::MethodErr::failed(&"Authentication thread panicked")),
            |_| panic!("a thread failure must not offer a retry"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn pinentry_prompt_fields_use_authorization_heading_for_hello_pin() {
        assert_eq!(
            pinentry_prompt_fields("PIN: ", Some("Use your Hello PIN".to_string())),
            (
                "Authorization Required".to_string(),
                "Use your Hello PIN".to_string()
            )
        );
        assert_eq!(
            pinentry_prompt_fields("Confirm PIN: ", None),
            (
                "Confirm PIN:".to_string(),
                "Entra ID Authentication".to_string()
            )
        );
    }

    #[test]
    fn extract_https_urls_from_device_code_message() {
        let msg = "To sign in, use a web browser to open the page `https://login.microsoft.com/device` and enter the code `BESBK78A2`.";
        let urls = extract_https_urls(msg);
        assert_eq!(urls, vec!["https://login.microsoft.com/device".to_string()]);
        assert!(is_device_code_message(msg));
    }
}
