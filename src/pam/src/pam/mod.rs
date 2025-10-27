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

use himmelblau::error::MsalError;
use himmelblau::{AuthOption, PublicClientApplication};
use himmelblau_unix_common::client_sync::DaemonClientBlocking;
use himmelblau_unix_common::config::{split_username, HimmelblauConfig};
use himmelblau_unix_common::constants::BROKER_APP_ID;
use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use himmelblau_unix_common::hello_pin_complexity::is_simple_pin;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse};
use himmelblau_unix_common::{auth_handle_mfa_resp, pam_fail};
#[cfg(feature = "interactive")]
use std::env;
use std::thread::sleep;

use crate::pam::constants::*;
use crate::pam::conv::PamConv;
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

use himmelblau_unix_common::auth::{authenticate, fido_auth, MessagePrinter};
use himmelblau_unix_common::pam::Options;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

pub fn get_cfg() -> Result<HimmelblauConfig, PamResultCode> {
    HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)).map_err(|_| PamResultCode::PAM_SERVICE_ERR)
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
        let account_id = cfg.map_name_to_upn(&account_id);
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

        // This will == "Ok(Some("ssh"))" on remote auth.
        let tty = pamh.get_tty();
        let rhost = pamh.get_rhost();

        debug!(?args, ?opts, ?tty, ?rhost, "sm_authenticate");

        let service = match tty {
            Ok(Some(service)) => service,
            _ => "unknown".to_string(),
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
        let account_id = cfg.map_name_to_upn(&account_id);

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

        authenticate(
            authtok,
            &cfg,
            &account_id,
            &service,
            opts,
            Arc::new(PamConvMessagePrinter::new(conv)),
        )
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
        let account_id = cfg.map_name_to_upn(&account_id);

        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(e) => {
                error!(err = ?e, "Error DaemonClientBlocking::new()");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        let (_, domain) = match split_username(&account_id) {
            Some(resp) => resp,
            None => {
                error!("split_username");
                return PamResultCode::PAM_AUTH_ERR;
            }
        };
        let tenant_id = match cfg.get_tenant_id(domain) {
            Some(tenant_id) => tenant_id,
            None => "common".to_string(),
        };
        let authority = format!("https://{}/{}", cfg.get_authority_host(domain), tenant_id);
        let app = match PublicClientApplication::new(BROKER_APP_ID, Some(&authority)) {
            Ok(app) => app,
            Err(e) => {
                error!(err = ?e, "PublicClientApplication");
                return PamResultCode::PAM_AUTH_ERR;
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

        let mut pin;
        loop {
            pin = match conv.send(PAM_PROMPT_ECHO_OFF, "New PIN: ") {
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

            if pin == confirm {
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

        let rt = match Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                error!("{:?}", e);
                return PamResultCode::PAM_AUTH_ERR;
            }
        };
        let interactive;
        #[cfg(feature = "interactive")]
        {
            interactive = !cfg.get_enable_experimental_mfa()
                || env::var("INTERACTIVE")
                    .map(|value| value.to_lowercase() == "true")
                    .unwrap_or(false);
        }
        #[cfg(not(feature = "interactive"))]
        {
            interactive = false;
        }
        let token = if !interactive {
            #[cfg(feature = "interactive")]
            match conv.send(
                PAM_TEXT_INFO,
                "If necessary, you can authenticate via a browser by setting the environment variable INTERACTIVE=true"
            ) {
                Ok(_) => {}
                Err(err) => {
                    if opts.debug {
                        println!("Message prompt failed");
                    }
                    return err;
                }
            }

            let auth_options = vec![AuthOption::Fido, AuthOption::Passwordless];
            let auth_init = match rt.block_on(async {
                app.check_user_exists(&account_id, None, &auth_options)
                    .await
            }) {
                Ok(auth_init) => auth_init,
                Err(e) => {
                    error!("{:?}", e);
                    return PamResultCode::PAM_AUTH_ERR;
                }
            };

            let password = if !auth_init.passwordless() {
                match conv.send(PAM_PROMPT_ECHO_OFF, "Entra Id Password: ") {
                    Ok(password) => match password {
                        Some(cred) => Some(cred),
                        None => {
                            debug!("no password");
                            return PamResultCode::PAM_CRED_INSUFFICIENT;
                        }
                    },
                    Err(err) => {
                        debug!("unable to get password");
                        return err;
                    }
                }
            } else {
                None
            };

            let mut mfa_req = match rt.block_on(async {
                app.initiate_acquire_token_by_mfa_flow(
                    &account_id,
                    password.as_deref(),
                    vec![],
                    None,
                    &auth_options,
                    Some(auth_init),
                )
                .await
            }) {
                Ok(mfa) => mfa,
                Err(e) => {
                    error!("{:?}", e);
                    return PamResultCode::PAM_AUTH_ERR;
                }
            };

            auth_handle_mfa_resp!(
                mfa_req,
                // FIDO
                {
                    let conv = Arc::new(Mutex::new(conv.clone()));
                    let fido_challenge = match mfa_req.fido_challenge {
                        Some(ref fido_challenge) => fido_challenge.clone(),
                        None => {
                            debug!("no Fido challenge");
                            return PamResultCode::PAM_CRED_INSUFFICIENT;
                        }
                    };

                    let fido_allow_list = match mfa_req.fido_allow_list {
                        Some(ref fido_allow_list) => fido_allow_list.clone(),
                        None => {
                            debug!("no Fido allow list");
                            return PamResultCode::PAM_CRED_INSUFFICIENT;
                        }
                    };

                    let msg_printer = Arc::new(PamConvMessagePrinter::new(conv));
                    let assertion =
                        match fido_auth(msg_printer.clone(), fido_challenge, fido_allow_list) {
                            Ok(assertion) => assertion,
                            Err(e) => {
                                pam_fail!(msg_printer, "Entra Id Fido authentication failed.", e);
                            }
                        };
                    match rt.block_on(async {
                        app.acquire_token_by_mfa_flow(
                            &account_id,
                            Some(&assertion),
                            None,
                            &mut mfa_req,
                        )
                        .await
                    }) {
                        Ok(token) => token,
                        Err(e) => {
                            error!("MFA FAIL: {:?}", e);
                            return PamResultCode::PAM_AUTH_ERR;
                        }
                    }
                },
                // PROMPT
                {
                    let input = match conv.send(PAM_PROMPT_ECHO_OFF, &mfa_req.msg) {
                        Ok(password) => match password {
                            Some(cred) => cred,
                            None => {
                                debug!("no password");
                                return PamResultCode::PAM_CRED_INSUFFICIENT;
                            }
                        },
                        Err(err) => {
                            debug!("unable to get password");
                            return err;
                        }
                    };
                    match rt.block_on(async {
                        app.acquire_token_by_mfa_flow(&account_id, Some(&input), None, &mut mfa_req)
                            .await
                    }) {
                        Ok(token) => token,
                        Err(e) => {
                            error!("MFA FAIL: {:?}", e);
                            return PamResultCode::PAM_AUTH_ERR;
                        }
                    }
                },
                // POLL
                {
                    match conv.send(PAM_TEXT_INFO, &mfa_req.msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }
                    let mut poll_attempt = 1;
                    let polling_interval = mfa_req.polling_interval.unwrap_or(5000);
                    loop {
                        match rt.block_on(async {
                            app.acquire_token_by_mfa_flow(
                                &account_id,
                                None,
                                Some(poll_attempt),
                                &mut mfa_req,
                            )
                            .await
                        }) {
                            Ok(token) => break token,
                            Err(e) => match e {
                                MsalError::MFAPollContinue => {
                                    poll_attempt += 1;
                                    sleep(Duration::from_millis(polling_interval.into()));
                                    continue;
                                }
                                e => {
                                    error!("MFA FAIL: {:?}", e);
                                    return PamResultCode::PAM_AUTH_ERR;
                                }
                            },
                        }
                    }
                }
            )
        } else {
            #[cfg(feature = "interactive")]
            match rt.block_on(async { app.acquire_token_interactive(&account_id, None).await }) {
                Ok(token) => token,
                Err(e) => {
                    error!(err = ?e, "acquire_token");
                    return PamResultCode::PAM_AUTH_ERR;
                }
            }
            #[cfg(not(feature = "interactive"))]
            {
                error!("Himmelblau was built without interactive support");
                return PamResultCode::PAM_AUTH_ERR;
            }
        };

        let req = ClientRequest::PamChangeAuthToken(
            account_id,
            match token.access_token.clone() {
                Some(access_token) => access_token,
                None => {
                    error!("Failed fetching access token for pin change");
                    return PamResultCode::PAM_AUTH_ERR;
                }
            },
            token.refresh_token.clone(),
            pin,
        );

        match daemon_client.call_and_wait(&req, cfg.get_unix_sock_timeout()) {
            Ok(ClientResponse::Ok) => {
                debug!("PamResultCode::PAM_SUCCESS");
                PamResultCode::PAM_SUCCESS
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
        let account_id = cfg.map_name_to_upn(&account_id);
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
