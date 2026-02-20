/*
   MIT License

   Copyright (c) 2015 TOZNY
   Copyright (c) 2020 William Brown <william@blackhats.net.au>
   Copyright (c) 2024 David Mulder <dmulder@samba.org>

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/
//! Interface to the pluggable authentication module framework (PAM).
//!
//! The goal of this library is to provide a type-safe API that can be used to
//! interact with PAM.  The library is incomplete - currently it supports
//! a subset of functions for use in a pam authentication module.  A pam module
//! is a shared library that is invoked to authenticate a user, or to perform
//! other functions.
//!
//! For general information on writing pam modules, see
//! [The Linux-PAM Module Writers' Guide][module-guide]
//!
//! [module-guide]: http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_MWG.html
//!
//! A typical authentication module will define an external function called
//! `pam_sm_authenticate()`, which will use functions in this library to
//! interrogate the program that requested authentication for more information,
//! and to render a result.  For a working example that uses this library, see
//! [toznyauth-pam][].
//!
//! [toznyauth-pam]: https://github.com/tozny/toznyauth-pam
//!
//! Note that constants that are normally read from pam header files are
//! hard-coded in the `constants` module.  The values there are taken from
//! a Linux system.  That means that it might take some work to get this library
//! to work on other platforms.

pub mod constants;
pub mod conv;
pub mod items;
#[doc(hidden)]
pub mod macros;
pub mod module;

use std::convert::TryFrom;
use std::ffi::CStr;

use himmelblau_unix_common::client_sync::DaemonClientBlocking;
use himmelblau_unix_common::config::{split_username, HimmelblauConfig};
use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use himmelblau_unix_common::hello_pin_complexity::is_simple_pin;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse};
use himmelblau_unix_common::user_map::UserMap;

use crate::pam::constants::*;
use crate::pam::conv::PamConv;
use crate::pam::items::PamAuthTok;
use crate::pam::module::{PamHandle, PamHooks};
use crate::pam_hooks;
use constants::PamResultCode;

use tracing::instrument;
use tracing::{debug, error};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use std::thread;
use std::time::Duration;

use himmelblau_unix_common::auth::{authenticate, MessagePrinter};
use himmelblau_unix_common::pam::Options;
use std::sync::{Arc, Mutex};

pub fn get_cfg() -> Result<HimmelblauConfig, PamResultCode> {
    HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)).map_err(|_| PamResultCode::PAM_SERVICE_ERR)
}

/// Checks if the given host string represents a loopback address.
///
/// Handles various loopback representations:
/// - "localhost" (case-insensitive)
/// - IPv4 loopback: "127.0.0.1" and the entire 127.0.0.0/8 range
/// - IPv6 loopback: "::1"
/// - IPv6 with brackets: "[::1]"
/// - IPv6 with zone identifiers: "::1%lo", "::1%eth0", "[::1%lo]"
fn is_loopback_address(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }

    // Check for "localhost" (case-insensitive)
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    // Remove brackets if present (for IPv6 bracket notation)
    let host = host.trim_start_matches('[').trim_end_matches(']');

    // Remove zone identifier if present (e.g., "::1%lo" -> "::1")
    let host = match host.find('%') {
        Some(idx) => &host[..idx],
        None => host,
    };

    // Try to parse as an IP address
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ipv4)) => ipv4.is_loopback(),
        Ok(std::net::IpAddr::V6(ipv6)) => ipv6.is_loopback(),
        Err(_) => false,
    }
}

fn install_subscriber(debug: bool) {
    let fmt_layer = fmt::layer().with_target(false);

    let filter_layer = if debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::ERROR
    };

    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init();
}

pub struct PamKanidm;

pam_hooks!(PamKanidm);

pub struct PamConvMessagePrinter {
    conv: Arc<Mutex<PamConv>>,
}

impl PamConvMessagePrinter {
    pub fn new(conv: Arc<Mutex<PamConv>>) -> Self {
        Self { conv }
    }
}

impl MessagePrinter for PamConvMessagePrinter {
    fn print_text(&self, msg: &str) {
        if let Ok(conv) = self.conv.lock() {
            if let Err(e) = conv.send(PAM_TEXT_INFO, msg) {
                error!(?e, "Message prompt failed");
            }
        }
    }

    fn print_error(&self, msg: &str) {
        if let Ok(conv) = self.conv.lock() {
            if let Err(e) = conv.send(PAM_ERROR_MSG, msg) {
                error!(?e, "Message prompt failed");
            }
        }
    }

    fn prompt_echo_off(&self, prompt: &str) -> Option<String> {
        self.conv.lock().ok().and_then(|conv| {
            conv.send(PAM_PROMPT_ECHO_OFF, prompt)
                .map_err(|e| error!("PAM conversation failed: {:?}", e))
                .ok()
                .flatten()
        })
    }
}

fn should_capture_keyring_secret(prompt: &str) -> bool {
    let prompt = prompt.trim().to_lowercase();
    if prompt.contains("confirm") {
        return false;
    }

    prompt.contains("pin") || prompt.contains("password")
}

pub struct KeyringCaptureMessagePrinter {
    inner: Arc<dyn MessagePrinter>,
    captured: Arc<Mutex<Option<String>>>,
}

impl KeyringCaptureMessagePrinter {
    pub fn new(inner: Arc<dyn MessagePrinter>, captured: Arc<Mutex<Option<String>>>) -> Self {
        Self { inner, captured }
    }
}

impl MessagePrinter for KeyringCaptureMessagePrinter {
    fn print_text(&self, msg: &str) {
        self.inner.print_text(msg);
    }

    fn print_error(&self, msg: &str) {
        self.inner.print_error(msg);
    }

    fn prompt_echo_off(&self, prompt: &str) -> Option<String> {
        let result = self.inner.prompt_echo_off(prompt);
        if let Some(ref cred) = result {
            if should_capture_keyring_secret(prompt) {
                if let Ok(mut captured) = self.captured.lock() {
                    *captured = Some(cred.clone());
                }
            }
        }
        result
    }
}

impl PamHooks for PamKanidm {
    #[instrument(skip(pamh, args, _flags))]
    fn acct_mgmt(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        let tty = pamh.get_tty();
        let rhost = pamh.get_rhost();

        debug!(?args, ?opts, ?tty, ?rhost, "acct_mgmt");

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                error!(err = ?e, "get_user");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        let cfg = match get_cfg() {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };
        let user_map = UserMap::new(&cfg.get_user_map_file());
        let account_id = match user_map.get_upn_from_local(&account_id) {
            Some(account_id) => account_id,
            None => cfg.map_name_to_upn(&account_id),
        };
        let req = ClientRequest::PamAccountAllowed(account_id);
        // PamResultCode::PAM_IGNORE

        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(e) => {
                error!(err = ?e, "Error DaemonClientBlocking::new()");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        match daemon_client.call_and_wait(&req, cfg.get_unix_sock_timeout()) {
            Ok(r) => match r {
                ClientResponse::PamStatus(Some(true)) => {
                    debug!("PamResultCode::PAM_SUCCESS");
                    PamResultCode::PAM_SUCCESS
                }
                ClientResponse::PamStatus(Some(false)) => {
                    debug!("PamResultCode::PAM_AUTH_ERR");
                    PamResultCode::PAM_AUTH_ERR
                }
                ClientResponse::PamStatus(None) => {
                    if opts.ignore_unknown_user {
                        debug!("PamResultCode::PAM_IGNORE");
                        PamResultCode::PAM_IGNORE
                    } else {
                        debug!("PamResultCode::PAM_USER_UNKNOWN");
                        PamResultCode::PAM_USER_UNKNOWN
                    }
                }
                _ => {
                    // unexpected response.
                    error!(err = ?r, "PAM_IGNORE, unexpected resolver response");
                    PamResultCode::PAM_IGNORE
                }
            },
            Err(e) => {
                error!(err = ?e, "PamResultCode::PAM_IGNORE");
                PamResultCode::PAM_IGNORE
            }
        }
    }

    #[instrument(skip(pamh, args, _flags))]
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        // Gather all PAM context for service detection
        let pam_service = pamh.get_service();
        let pam_tty = pamh.get_tty();
        let pam_rhost = pamh.get_rhost();

        debug!(
            ?args,
            ?opts,
            ?pam_service,
            ?pam_tty,
            ?pam_rhost,
            "sm_authenticate PAM context"
        );

        // Use PAM_SERVICE as the primary service identifier (most reliable).
        // This is the service name passed by the application to pam_start().
        let service = match pam_service {
            Ok(Some(svc)) => svc,
            _ => match pam_tty {
                // Fall back to TTY if service is not available
                Ok(Some(tty)) => tty,
                _ => "unknown".to_string(),
            },
        };

        // Check if this is a remote connection based on PAM_RHOST.
        // If rhost is set to a non-localhost value, treat as remote.
        let is_remote = match &pam_rhost {
            Ok(Some(rhost)) => !rhost.is_empty() && !is_loopback_address(rhost),
            _ => false,
        };

        // For remote connections, prefix the service with "remote:" to signal
        // to the daemon that this is a remote auth attempt.
        let service = if is_remote {
            format!("remote:{}", service)
        } else {
            service
        };

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                error!(err = ?e, "get_user");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        let cfg = match get_cfg() {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };
        let user_map = UserMap::new(&cfg.get_user_map_file());
        let account_id = match user_map.get_upn_from_local(&account_id) {
            Some(account_id) => account_id,
            None => cfg.map_name_to_upn(&account_id),
        };

        let authtok = match pamh.get_authtok() {
            Ok(Some(v)) => Some(v),
            Ok(None) => {
                if opts.use_first_pass {
                    debug!("Don't have an authtok, returning PAM_AUTH_ERR");
                    return PamResultCode::PAM_AUTH_ERR;
                }
                None
            }
            Err(e) => {
                error!(err = ?e, "get_authtok");
                return e;
            }
        };

        let conv = match pamh.get_item::<PamConv>() {
            Ok(conv) => Arc::new(Mutex::new(conv.clone())),
            Err(err) => {
                error!(?err, "pam_conv");
                return err;
            }
        };

        let set_authtok = opts.set_authtok;
        let keyring_secret = Arc::new(Mutex::new(authtok.clone()));
        let base_printer: Arc<dyn MessagePrinter> = Arc::new(PamConvMessagePrinter::new(conv));
        let msg_printer: Arc<dyn MessagePrinter> = if set_authtok {
            Arc::new(KeyringCaptureMessagePrinter::new(
                base_printer.clone(),
                keyring_secret.clone(),
            ))
        } else {
            base_printer
        };

        let result = authenticate(authtok, &cfg, &account_id, &service, opts, msg_printer);

        if set_authtok && result == PamResultCode::PAM_SUCCESS {
            if let Ok(Some(secret)) = keyring_secret.lock().map(|s| s.clone()) {
                if let Err(err) = pamh.set_item_str::<PamAuthTok>(&secret) {
                    error!(?err, "Failed to set PAM_AUTHTOK for keyring");
                } else {
                    debug!("Set PAM_AUTHTOK for keyring unlock");
                }
            } else {
                debug!("No keyring secret captured; PAM_AUTHTOK not set");
            }
        }

        result
    }

    #[instrument(skip(pamh, args, flags))]
    fn sm_chauthtok(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        if flags & PAM_PRELIM_CHECK != 0 {
            return PamResultCode::PAM_SUCCESS;
        }

        if flags & PAM_UPDATE_AUTHTOK == 0 {
            // If this isn't a PAM_PRELIM_CHECK, and not a PAM_UPDATE_AUTHTOK,
            // what is it?
            return PamResultCode::PAM_SERVICE_ERR;
        }

        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_chauthtok");

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                error!(err = ?e, "get_user");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        let cfg = match get_cfg() {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };
        let user_map = UserMap::new(&cfg.get_user_map_file());
        let account_id = match user_map.get_upn_from_local(&account_id) {
            Some(account_id) => account_id,
            None => cfg.map_name_to_upn(&account_id),
        };

        // Local user (no UPN): not a Himmelblau/Entra account. Skip before touching the
        // daemon so local password changes (e.g. sudo passwd <local_user>) never depend
        // on himmelblaud and continue to pam_unix.
        let (_, _domain) = match split_username(&account_id) {
            Some(resp) => resp,
            None => {
                debug!(%account_id, "chauthtok: not a UPN, skipping (local user)");
                return PamResultCode::PAM_IGNORE;
            }
        };

        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(e) => {
                error!(err = ?e, "Error DaemonClientBlocking::new()");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        let conv = match pamh.get_item::<PamConv>() {
            Ok(conv) => conv,
            Err(err) => {
                error!(?err, "pam_conv");
                return err;
            }
        };
        match conv.send(
            PAM_TEXT_INFO,
            "This command changes your local Hello PIN, NOT your Entra Id password.",
        ) {
            Ok(_) => {}
            Err(err) => {
                if opts.debug {
                    println!("Message prompt failed");
                }
                return err;
            }
        }

        // Prompt for the current PIN to verify identity locally — no Entra
        // re-authentication required. The daemon re-keys the Hello key blob
        // directly using the old PIN, so this works offline too.
        let old_pin = match conv.send(PAM_PROMPT_ECHO_OFF, "Current PIN: ") {
            Ok(Some(cred)) => cred,
            Ok(None) => {
                debug!("no current pin");
                return PamResultCode::PAM_CRED_INSUFFICIENT;
            }
            Err(err) => {
                debug!("unable to get current pin");
                return err;
            }
        };

        let mut new_pin;
        loop {
            new_pin = match conv.send(PAM_PROMPT_ECHO_OFF, "New PIN: ") {
                Ok(password) => match password {
                    Some(cred) => {
                        if cred.len() < cfg.get_hello_pin_min_length() {
                            match conv.send(
                                PAM_TEXT_INFO,
                                &format!(
                                    "Chosen pin is too short! {} chars required.",
                                    cfg.get_hello_pin_min_length()
                                ),
                            ) {
                                Ok(_) => {}
                                Err(err) => {
                                    if opts.debug {
                                        println!("Message prompt failed");
                                    }
                                    return err;
                                }
                            }
                            continue;
                        } else if is_simple_pin(&cred) {
                            match conv
                                .send(PAM_TEXT_INFO, "PIN must not use repeating or predictable sequences. Avoid patterns like '111111', '123456', or '135791'.")
                            {
                                Ok(_) => {}
                                Err(err) => {
                                    if opts.debug {
                                        println!("Message prompt failed");
                                    }
                                    return err;
                                }
                            }
                            thread::sleep(Duration::from_secs(2));
                            continue;
                        }
                        cred
                    }
                    None => {
                        debug!("no pin");
                        return PamResultCode::PAM_CRED_INSUFFICIENT;
                    }
                },
                Err(err) => {
                    debug!("unable to get pin");
                    return err;
                }
            };

            let confirm = match conv.send(PAM_PROMPT_ECHO_OFF, "Confirm PIN: ") {
                Ok(password) => match password {
                    Some(cred) => cred,
                    None => {
                        debug!("no confirmation pin");
                        return PamResultCode::PAM_CRED_INSUFFICIENT;
                    }
                },
                Err(err) => {
                    debug!("unable to get confirmation pin");
                    return err;
                }
            };

            if new_pin == confirm {
                break;
            } else {
                match conv.send(PAM_TEXT_INFO, "Inputs did not match. Try again.") {
                    Ok(_) => {}
                    Err(err) => {
                        if opts.debug {
                            println!("Message prompt failed");
                        }
                        return err;
                    }
                }
            }
        }

        let req = ClientRequest::PamChangeAuthTokenLocal(account_id, old_pin, new_pin.clone());

        match daemon_client.call_and_wait(&req, cfg.get_unix_sock_timeout()) {
            Ok(ClientResponse::Ok) => {
                debug!("PamResultCode::PAM_SUCCESS");
                // Publish the new PIN as PAM_AUTHTOK so downstream modules
                // (e.g. pam_gnome_keyring) can update the keyring password.
                if opts.set_authtok {
                    if let Err(err) = pamh.set_item_str::<PamAuthTok>(&new_pin) {
                        error!(?err, "Failed to set PAM_AUTHTOK after PIN change");
                    } else {
                        debug!("Set PAM_AUTHTOK to new PIN for keyring update");
                    }
                }
                PamResultCode::PAM_SUCCESS
            }
            Ok(ClientResponse::Error) => {
                debug!("PamResultCode::PAM_AUTH_ERR (PIN change denied by daemon)");
                match conv.send(PAM_TEXT_INFO, "PIN change failed. Check that a Hello PIN is enrolled and the current PIN is correct.") {
                    Ok(_) => {}
                    Err(_) => {}
                }
                PamResultCode::PAM_AUTH_ERR
            }
            other => {
                debug!(err = ?other, "PamResultCode::PAM_AUTH_ERR");
                PamResultCode::PAM_AUTH_ERR
            }
        }
    }

    #[instrument(skip(_pamh, args, _flags))]
    fn sm_close_session(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_close_session");

        PamResultCode::PAM_SUCCESS
    }

    #[instrument(skip(pamh, args, _flags))]
    fn sm_open_session(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_open_session");

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(err) => {
                error!(?err, "get_user");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        let cfg = match get_cfg() {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };
        let user_map = UserMap::new(&cfg.get_user_map_file());
        let account_id = match user_map.get_upn_from_local(&account_id) {
            Some(account_id) => account_id,
            None => cfg.map_name_to_upn(&account_id),
        };

        let req = ClientRequest::PamAccountBeginSession(account_id);

        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(e) => {
                error!(err = ?e, "Error DaemonClientBlocking::new()");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        match daemon_client.call_and_wait(&req, cfg.get_unix_sock_timeout()) {
            Ok(ClientResponse::Ok) => {
                // println!("PAM_SUCCESS");
                PamResultCode::PAM_SUCCESS
            }
            other => {
                debug!(err = ?other, "PAM_IGNORE");
                PamResultCode::PAM_IGNORE
            }
        }
    }

    #[instrument(skip(_pamh, args, _flags))]
    fn sm_setcred(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_setcred");

        PamResultCode::PAM_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_capture_keyring_secret_pin_prompts() {
        // capture
        assert!(should_capture_keyring_secret("PIN: "));
        assert!(should_capture_keyring_secret(" New PIN: "));
        assert!(should_capture_keyring_secret("Fido PIN: "));
        assert!(should_capture_keyring_secret("   pIn   "));

        // do not capture confirmations
        assert!(!should_capture_keyring_secret("Confirm PIN: "));
        assert!(!should_capture_keyring_secret("confirm new pin: "));
    }

    #[test]
    fn test_is_loopback_address_empty() {
        assert!(!is_loopback_address(""));
    }

    #[test]
    fn test_is_loopback_address_localhost() {
        assert!(is_loopback_address("localhost"));
        assert!(is_loopback_address("LOCALHOST"));
        assert!(is_loopback_address("LocalHost"));
    }

    #[test]
    fn test_is_loopback_address_ipv4() {
        assert!(is_loopback_address("127.0.0.1"));
        assert!(is_loopback_address("127.0.0.2"));
        assert!(is_loopback_address("127.255.255.255"));
        assert!(!is_loopback_address("192.168.1.1"));
        assert!(!is_loopback_address("10.0.0.1"));
    }

    #[test]
    fn test_is_loopback_address_ipv6() {
        assert!(is_loopback_address("::1"));
        assert!(!is_loopback_address("::2"));
        assert!(!is_loopback_address("fe80::1"));
        assert!(!is_loopback_address("2001:db8::1"));
    }

    #[test]
    fn test_is_loopback_address_ipv6_brackets() {
        assert!(is_loopback_address("[::1]"));
        assert!(!is_loopback_address("[::2]"));
        assert!(!is_loopback_address("[fe80::1]"));
    }

    #[test]
    fn test_is_loopback_address_ipv6_zone_identifier() {
        assert!(is_loopback_address("::1%lo"));
        assert!(is_loopback_address("::1%eth0"));
        assert!(is_loopback_address("[::1%lo]"));
        assert!(!is_loopback_address("fe80::1%eth0"));
    }

    #[test]
    fn test_is_loopback_address_non_ip() {
        assert!(!is_loopback_address("example.com"));
        assert!(!is_loopback_address("remotehost"));
        assert!(!is_loopback_address("192.168.1.invalid"));
    }
}
