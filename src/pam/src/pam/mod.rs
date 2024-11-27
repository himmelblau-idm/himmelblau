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

use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::ffi::CStr;

use kanidm_unix_common::client_sync::DaemonClientBlocking;
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{
    ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse,
};

use crate::pam::constants::*;
use crate::pam::conv::PamConv;
use crate::pam::module::{PamHandle, PamHooks};
use crate::pam_hooks;
use constants::PamResultCode;

use tracing::{debug, error};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use std::thread;
use std::time::Duration;

use authenticator::{
    authenticatorservice::{AuthenticatorService, SignArgs},
    ctap2::server::{
        AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
    },
    statecallback::StateCallback,
    Pin, StatusPinUv, StatusUpdate,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, to_string as json_to_string};
use sha2::{Digest, Sha256};
use std::sync::mpsc::{channel, RecvError};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

pub fn get_cfg() -> Result<KanidmUnixdConfig, PamResultCode> {
    KanidmUnixdConfig::new()
        .read_options_from_optional_config(DEFAULT_CONFIG_PATH)
        .map_err(|_| PamResultCode::PAM_SERVICE_ERR)
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

#[derive(Debug)]
struct Options {
    debug: bool,
    use_first_pass: bool,
    ignore_unknown_user: bool,
    mfa_poll_prompt: bool,
}

impl TryFrom<&Vec<&CStr>> for Options {
    type Error = ();

    fn try_from(args: &Vec<&CStr>) -> Result<Self, Self::Error> {
        let opts: Result<BTreeSet<&str>, _> = args.iter().map(|cs| cs.to_str()).collect();
        let gopts = match opts {
            Ok(o) => o,
            Err(e) => {
                println!("Error in module args -> {:?}", e);
                return Err(());
            }
        };

        Ok(Options {
            debug: gopts.contains("debug"),
            use_first_pass: gopts.contains("use_first_pass"),
            ignore_unknown_user: gopts.contains("ignore_unknown_user"),
            mfa_poll_prompt: gopts.contains("mfa_poll_prompt"),
        })
    }
}

#[derive(Clone)]
enum FailReason {
    None,
    PinRequired,
    ErrorMsg(String),
}

async fn fido_auth(
    conv: &PamConv,
    fido_challenge: String,
    fido_allow_list: Vec<String>,
) -> Result<String, PamResultCode> {
    // Initialize AuthenticatorService
    let mut manager = AuthenticatorService::new().map_err(|e| {
        error!("{:?}", e);
        PamResultCode::PAM_CRED_INSUFFICIENT
    })?;
    manager.add_u2f_usb_hid_platform_transports();

    let challenge_str = json_to_string(&json!({
        "type": "webauthn.get",
        "challenge": URL_SAFE_NO_PAD.encode(fido_challenge.clone()),
        "origin": "https://login.microsoft.com"
    }))
    .map_err(|e| {
        error!("{:?}", e);
        PamResultCode::PAM_CRED_INSUFFICIENT
    })?;

    let shared_flag = Arc::new(Mutex::new(FailReason::None));
    let shared_pin: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    // Create a channel for status updates
    macro_rules! fido_attempt {
        () => {{
            let (status_tx, status_rx) = channel::<StatusUpdate>();
            let shared_flag = shared_flag.clone();
            let shared_pin = shared_pin.clone();
            thread::spawn(move || {
                // Reset the flag
                if let Ok(mut flag) = shared_flag.lock() {
                    *flag = FailReason::None;
                }
                loop {
                    match status_rx.recv() {
                        Ok(StatusUpdate::InteractiveManagement(..)) => {
                            if let Ok(mut flag) = shared_flag.lock() {
                                *flag = FailReason::ErrorMsg(
                                    "InteractiveManagement request impossible".to_string(),
                                );
                            }
                            break;
                        }
                        Ok(StatusUpdate::SelectDeviceNotice) => {
                            if let Ok(mut flag) = shared_flag.lock() {
                                *flag = FailReason::ErrorMsg(
                                    "Please only connect a single Fido device.".to_string(),
                                );
                            }
                            break;
                        }
                        Ok(StatusUpdate::PresenceRequired) => {
                            continue;
                        }
                        Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender))) => {
                            if let Ok(guard) = shared_pin.lock() {
                                if let Some(raw_pin) = &*guard {
                                    if let Err(e) = sender.send(Pin::new(&raw_pin)) {
                                        error!("{:?}", e);
                                        break;
                                    }
                                } else {
                                    if let Ok(mut flag) = shared_flag.lock() {
                                        *flag = FailReason::PinRequired;
                                    }
                                    break;
                                }
                            } else {
                                if let Ok(mut flag) = shared_flag.lock() {
                                    *flag = FailReason::PinRequired;
                                }
                                break;
                            }
                        }
                        Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(
                            _sender,
                            _attempts,
                        ))) => {
                            if let Ok(mut flag) = shared_flag.lock() {
                                *flag = FailReason::PinRequired;
                            }
                            break;
                        }
                        Ok(StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked)) => {
                            if let Ok(mut flag) = shared_flag.lock() {
                                *flag = FailReason::ErrorMsg("Too many failed attempts in one row. Your device has been temporarily blocked. Please unplug it and plug in again.".to_string());
                            }
                            break;
                        }
                        Ok(StatusUpdate::PinUvError(StatusPinUv::PinBlocked)) => {
                            if let Ok(mut flag) = shared_flag.lock() {
                                *flag = FailReason::ErrorMsg("Too many failed attempts. Your device has been blocked. Reset it.".to_string());
                            }
                            break;
                        }
                        Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidUv(_attempts))) => {
                            if let Ok(mut flag) = shared_flag.lock() {
                                *flag = FailReason::ErrorMsg("Wrong UV! Try again.".to_string());
                            }
                            break;
                        }
                        Ok(StatusUpdate::PinUvError(StatusPinUv::UvBlocked)) => {
                            if let Ok(mut flag) = shared_flag.lock() {
                                *flag = FailReason::ErrorMsg(
                                    "Too many failed UV-attempts.".to_string(),
                                );
                            }
                            break;
                        }
                        Ok(StatusUpdate::PinUvError(e)) => {
                            if let Ok(mut flag) = shared_flag.lock() {
                                *flag = FailReason::ErrorMsg(format!("Unexpected error: {:?}", e));
                            }
                            break;
                        }
                        Ok(StatusUpdate::SelectResultNotice(_, _)) => {
                            if let Ok(mut flag) = shared_flag.lock() {
                                *flag = FailReason::ErrorMsg(
                                    "Unexpected select device notice".to_string(),
                                );
                            }
                            break;
                        }
                        Err(RecvError) => {
                            break;
                        }
                    }
                }
            });
            status_tx
        }}
    }
    let mut status_tx = fido_attempt!();

    let allow_list: Vec<PublicKeyCredentialDescriptor> = fido_allow_list
        .into_iter()
        .filter_map(|id| match URL_SAFE_NO_PAD.decode(id) {
            Ok(decoded_id) => Some(PublicKeyCredentialDescriptor {
                id: decoded_id,
                transports: vec![],
            }),
            Err(e) => {
                error!("Failed decoding allow list id: {:?}", e);
                None
            }
        })
        .collect();

    // Prepare SignArgs
    let chall_bytes = Sha256::digest(challenge_str.clone()).into();
    let ctap_args = SignArgs {
        client_data_hash: chall_bytes,
        origin: "https://login.microsoft.com".to_string(),
        relying_party_id: "login.microsoft.com".to_string(),
        allow_list,
        user_verification_req: UserVerificationRequirement::Preferred,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: false,
    };

    let mut sign_rx;
    loop {
        // Perform authentication
        let (sign_tx, inner_sign_rx) = channel();
        sign_rx = inner_sign_rx;
        let callback = StateCallback::new(Box::new(move |rv| {
            let _ = sign_tx.send(rv);
        }));
        if let Err(e) = manager.sign(25000, ctap_args.clone(), status_tx.clone(), callback) {
            let shared_flag_value = match shared_flag.lock() {
                Ok(shared_flag) => {
                    let cloned_value = (*shared_flag).clone();
                    drop(shared_flag);
                    cloned_value
                }
                Err(_) => return Err(PamResultCode::PAM_CRED_INSUFFICIENT),
            };
            match shared_flag_value {
                FailReason::ErrorMsg(msg) => {
                    error!("Couldn't sign: {:?}", e);
                    if let Err(e) = conv.send(PAM_TEXT_INFO, &msg) {
                        error!("{:?}", e);
                    }
                    return Err(PamResultCode::PAM_CRED_INSUFFICIENT);
                }
                FailReason::PinRequired => {
                    let raw_pin = match conv.send(PAM_PROMPT_ECHO_OFF, "Enter Fido PIN: ") {
                        Ok(Some(raw_pin)) => raw_pin,
                        Err(e) => {
                            error!("{:?}", e);
                            return Err(PamResultCode::PAM_CRED_INSUFFICIENT);
                        }
                        _ => return Err(PamResultCode::PAM_CRED_INSUFFICIENT),
                    };
                    if let Ok(mut pin) = shared_pin.lock() {
                        *pin = Some(raw_pin);
                    } else {
                        error!("Couldn't set the Fido pin");
                        return Err(PamResultCode::PAM_CRED_INSUFFICIENT);
                    }
                    status_tx = fido_attempt!();
                }
                FailReason::None => {
                    error!("Couldn't sign: {:?}", e);
                    return Err(PamResultCode::PAM_CRED_INSUFFICIENT);
                }
            }
        } else {
            break;
        }
    }

    let assertion_result = sign_rx
        .recv()
        .map_err(|e| {
            error!("{:?}", e);
            PamResultCode::PAM_CRED_INSUFFICIENT
        })?
        .map_err(|e| {
            error!("{:?}", e);
            PamResultCode::PAM_CRED_INSUFFICIENT
        })?;

    let credential_id = assertion_result
        .assertion
        .credentials
        .as_ref()
        .map(|cred| cred.id.clone())
        .unwrap_or_default();
    let auth_data = assertion_result.assertion.auth_data;
    let signature = assertion_result.assertion.signature;
    let user_handle = assertion_result
        .assertion
        .user
        .as_ref()
        .map(|user| user.id.clone())
        .unwrap_or_default();
    let json_response = json!({
        "id": URL_SAFE_NO_PAD.encode(credential_id),
        "clientDataJSON": URL_SAFE_NO_PAD.encode(challenge_str),
        "authenticatorData": URL_SAFE_NO_PAD.encode(auth_data.to_vec()),
        "signature": URL_SAFE_NO_PAD.encode(signature),
        "userHandle": URL_SAFE_NO_PAD.encode(user_handle),
    });

    // Convert the JSON response to a string
    json_to_string(&json_response).map_err(|e| {
        error!("{:?}", e);
        PamResultCode::PAM_CRED_INSUFFICIENT
    })
}

pub struct PamKanidm;

pam_hooks!(PamKanidm);

macro_rules! match_sm_auth_client_response {
    ($expr:expr, $opts:ident, $conv:ident, $req:ident, $authtok:ident, $cfg:ident, $($pat:pat => $result:expr),*) => {
        match $expr {
            Ok(r) => match r {
                $($pat => $result),*
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Success) => {
                    return PamResultCode::PAM_SUCCESS;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Denied) => {
                    return PamResultCode::PAM_AUTH_ERR;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Unknown) => {
                    if $opts.ignore_unknown_user {
                        return PamResultCode::PAM_IGNORE;
                    } else {
                        return PamResultCode::PAM_USER_UNKNOWN;
                    }
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::SetupPin {
                    msg,
                }) => {
                    match $conv.send(PAM_TEXT_INFO, &msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if $opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }

                    let mut pin;
                    let mut confirm;
                    loop {
                        pin = match $conv.send(PAM_PROMPT_ECHO_OFF, "New PIN: ") {
                            Ok(password) => match password {
                                Some(cred) => {
                                    if cred.len() < $cfg.hello_pin_min_length {
                                        match $conv.send(PAM_TEXT_INFO, &format!("Chosen pin is too short! {} chars required.", $cfg.hello_pin_min_length)) {
                                            Ok(_) => {}
                                            Err(err) => {
                                                if $opts.debug {
                                                    println!("Message prompt failed");
                                                }
                                                return err;
                                            }
                                        }
                                        continue;
                                    }
                                    cred
                                },
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

                        confirm = match $conv.send(PAM_PROMPT_ECHO_OFF, "Confirm PIN: ") {
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
                            match $conv.send(PAM_TEXT_INFO, "Inputs did not match. Try again.") {
                                Ok(_) => {}
                                Err(err) => {
                                    if $opts.debug {
                                        println!("Message prompt failed");
                                    }
                                    return err;
                                }
                            }
                        }
                    }

                    // Now setup the request for the next loop.
                    $req = ClientRequest::PamAuthenticateStep(PamAuthRequest::SetupPin {
                        pin,
                    });
                    continue;
                },
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Pin) => {
                    let mut consume_authtok = None;
                    // Swap the authtok out with a None, so it can only be consumed once.
                    // If it's already been swapped, we are just swapping two null pointers
                    // here effectively.
                    std::mem::swap(&mut $authtok, &mut consume_authtok);
                    let cred = if let Some(cred) = consume_authtok {
                        cred
                    } else {
                        match $conv.send(PAM_PROMPT_ECHO_OFF, "PIN: ") {
                            Ok(password) => match password {
                                Some(cred) => cred,
                                None => {
                                    debug!("no pin");
                                    return PamResultCode::PAM_CRED_INSUFFICIENT;
                                }
                            },
                            Err(err) => {
                                debug!("unable to get pin");
                                return err;
                            }
                        }
                    };

                    // Now setup the request for the next loop.
                    $req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Pin { cred });
                    continue;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Fido {
                    fido_challenge,
                    fido_allow_list,
                }) => {
                    let rt = Runtime::new().unwrap();

                    // Block on the async function
                    let result = match rt.block_on(async {
                        fido_auth($conv, fido_challenge, fido_allow_list).await
                    }) {
                        Ok(assertion) => assertion,
                        Err(e) => return e,
                    };

                    // Now setup the request for the next loop.
                    $req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Fido { assertion: result });
                    continue;
                }
                _ => {
                    // unexpected response.
                    error!(err = ?r, "PAM_IGNORE, unexpected resolver response");
                    return PamResultCode::PAM_IGNORE;
                }
            },
            Err(err) => {
                error!(?err, "PAM_IGNORE");
                return PamResultCode::PAM_IGNORE;
            }
        }
    }
}

impl PamHooks for PamKanidm {
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
        let account_id = cfg.map_cn_name(&account_id);
        let req = ClientRequest::PamAccountAllowed(account_id);
        // PamResultCode::PAM_IGNORE

        let mut daemon_client = match DaemonClientBlocking::new(cfg.sock_path.as_str()) {
            Ok(dc) => dc,
            Err(e) => {
                error!(err = ?e, "Error DaemonClientBlocking::new()");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        match daemon_client.call_and_wait(&req, cfg.unix_sock_timeout) {
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
        let account_id = cfg.map_cn_name(&account_id);

        let mut timeout = cfg.unix_sock_timeout;
        let mut daemon_client = match DaemonClientBlocking::new(cfg.sock_path.as_str()) {
            Ok(dc) => dc,
            Err(e) => {
                error!(err = ?e, "Error DaemonClientBlocking::new()");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        // Later we may need to move this to a function and call it as a oneshot for auth methods
        // that don't require any authtoks at all. For example, imagine a user authed and they
        // needed to follow a URL to continue. In that case, they would fail here because they
        // didn't enter an authtok that they didn't need!
        let mut authtok = match pamh.get_authtok() {
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
            Ok(conv) => conv,
            Err(err) => {
                error!(?err, "pam_conv");
                return err;
            }
        };

        let mut req = ClientRequest::PamAuthenticateInit(account_id);

        loop {
            match_sm_auth_client_response!(daemon_client.call_and_wait(&req, timeout), opts, conv, req, authtok, cfg,
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Password) => {
                    let mut consume_authtok = None;
                    // Swap the authtok out with a None, so it can only be consumed once.
                    // If it's already been swapped, we are just swapping two null pointers
                    // here effectively.
                    std::mem::swap(&mut authtok, &mut consume_authtok);
                    let cred = if let Some(cred) = consume_authtok {
                        cred
                    } else {
                        match conv.send(PAM_PROMPT_ECHO_OFF, "Password: ") {
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
                        }
                    };

                    // Now setup the request for the next loop.
                    timeout = cfg.unix_sock_timeout;
                    req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password { cred });
                    continue;
                },
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFACode {
                    msg,
                }) => {
                    match conv.send(PAM_TEXT_INFO, &msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }
                    let cred = match conv.send(PAM_PROMPT_ECHO_OFF, "Code: ") {
                        Ok(password) => match password {
                            Some(cred) => cred,
                            None => {
                                debug!("no mfa code");
                                return PamResultCode::PAM_CRED_INSUFFICIENT;
                            }
                        },
                        Err(err) => {
                            debug!("unable to get mfa code");
                            return err;
                        }
                    };

                    // Now setup the request for the next loop.
                    timeout = cfg.unix_sock_timeout;
                    req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFACode {
                        cred,
                    });
                    continue;
                },
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFAPoll {
                    msg,
                    polling_interval,
                }) => {
                    match conv.send(PAM_TEXT_INFO, &msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }

                    // Necessary because of OpenSSH bug
                    // https://bugzilla.mindrot.org/show_bug.cgi?id=2876 -
                    // PAM_TEXT_INFO and PAM_ERROR_MSG conversation not
                    // honoured during PAM authentication
                    if opts.mfa_poll_prompt {
                        let _ = conv.send(PAM_PROMPT_ECHO_OFF, "Press enter to continue");
                    }

                    let mut poll_attempt = 0;
                    req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFAPoll { poll_attempt });
                    loop {
                        thread::sleep(Duration::from_secs(polling_interval.into()));

                        // Counter intuitive, but we don't need a max poll attempts here because
                        // if the resolver goes away, then this will error on the sock and
                        // will shutdown. This allows the resolver to dynamically extend the
                        // timeout if needed, and removes logic from the front end.
                        match_sm_auth_client_response!(
                            daemon_client.call_and_wait(&req, timeout), opts, conv, req, authtok, cfg,
                            ClientResponse::PamAuthenticateStepResponse(
                                    PamAuthResponse::MFAPollWait,
                            ) => {
                                // Continue polling if the daemon says to wait
                                poll_attempt += 1;
                                req = ClientRequest::PamAuthenticateStep(
                                    PamAuthRequest::MFAPoll { poll_attempt }
                                );
                                continue;
                            }
                        );
                    }
                }
            );
        } // while true, continue calling PamAuthenticateStep until we get a decision.
    }

    fn sm_chauthtok(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_chauthtok");

        PamResultCode::PAM_IGNORE
    }

    fn sm_close_session(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_close_session");

        PamResultCode::PAM_SUCCESS
    }

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
        let account_id = cfg.map_cn_name(&account_id);
        let req = ClientRequest::PamAccountBeginSession(account_id);

        let mut daemon_client = match DaemonClientBlocking::new(cfg.sock_path.as_str()) {
            Ok(dc) => dc,
            Err(e) => {
                error!(err = ?e, "Error DaemonClientBlocking::new()");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        match daemon_client.call_and_wait(&req, cfg.unix_sock_timeout) {
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
