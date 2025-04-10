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

use himmelblau::error::MsalError;
use himmelblau::{AuthOption, PublicClientApplication};
use himmelblau_unix_common::client_sync::DaemonClientBlocking;
use himmelblau_unix_common::config::{split_username, HimmelblauConfig};
use himmelblau_unix_common::constants::BROKER_APP_ID;
use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use himmelblau_unix_common::unix_proto::{
    ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse,
};
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

use authenticator::{
    authenticatorservice::{AuthenticatorService, SignArgs},
    ctap2::server::{
        AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
    },
    statecallback::StateCallback,
    Pin, StatusPinUv, StatusUpdate,
};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, to_string as json_to_string};
use sha2::{Digest, Sha256};
use std::sync::mpsc::{channel, RecvError, Sender};
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

async fn fido_status_check(conv: Arc<Mutex<PamConv>>) -> Sender<StatusUpdate> {
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::InteractiveManagement(..)) => {
                error!("Fido STATUS: InteractiveManagement: This can't happen when doing non-interactive usage");
                break;
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                let conv = conv.lock().unwrap();
                conv.send(
                    PAM_TEXT_INFO,
                    "Please select a device by touching one of them.",
                )
                .unwrap();
            }
            Ok(StatusUpdate::PresenceRequired) => {
                let conv = conv.lock().unwrap();
                conv.send(PAM_TEXT_INFO, "Waiting for user presence")
                    .unwrap();
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender))) => {
                let conv = conv.lock().unwrap();
                match conv.send(PAM_PROMPT_ECHO_OFF, "Fido PIN: ") {
                    Ok(Some(pin)) => {
                        sender.send(Pin::new(&pin)).expect("Failed to send PIN");
                        continue;
                    }
                    _ => {
                        break;
                    }
                }
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts))) => {
                let conv = conv.lock().unwrap();
                let msg = format!(
                    "Wrong PIN! {}",
                    attempts.map_or("Try again.".to_string(), |a| format!(
                        "You have {a} attempts left."
                    ))
                );
                conv.send(PAM_ERROR_MSG, &msg).unwrap();
                match conv.send(PAM_PROMPT_ECHO_OFF, "Fido PIN: ") {
                    Ok(Some(pin)) => {
                        sender.send(Pin::new(&pin)).expect("Failed to send PIN");
                        continue;
                    }
                    _ => {
                        break;
                    }
                }
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked)) => {
                let conv = conv.lock().unwrap();
                let msg = "Too many failed attempts in one row. Your device has been temporarily blocked. Please unplug it and plug in again.";
                conv.send(PAM_ERROR_MSG, msg).unwrap();
                break;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinBlocked)) => {
                let conv = conv.lock().unwrap();
                let msg = "Too many failed attempts. Your device has been blocked. Reset it.";
                conv.send(PAM_ERROR_MSG, msg).unwrap();
                break;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidUv(attempts))) => {
                let msg = format!(
                    "Wrong UV! {}",
                    attempts.map_or("Try again.".to_string(), |a| format!(
                        "You have {a} attempts left."
                    ))
                );
                let conv = conv.lock().unwrap();
                conv.send(PAM_ERROR_MSG, &msg).unwrap();
                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::UvBlocked)) => {
                let conv = conv.lock().unwrap();
                conv.send(PAM_ERROR_MSG, "Too many failed UV-attempts.")
                    .unwrap();
                break;
            }
            Ok(StatusUpdate::PinUvError(e)) => {
                let conv = conv.lock().unwrap();
                let msg = format!("Unexpected error: {:?}", e);
                conv.send(PAM_ERROR_MSG, &msg).unwrap();
                break;
            }
            Ok(StatusUpdate::SelectResultNotice(_, _)) => {
                let conv = conv.lock().unwrap();
                conv.send(PAM_ERROR_MSG, "Unexpected select device notice")
                    .unwrap();
                break;
            }
            Err(RecvError) => {
                debug!("Fido STATUS: end");
                return;
            }
        }
    });
    status_tx
}

fn fido_auth(
    conv: Arc<Mutex<PamConv>>,
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
        "challenge": URL_SAFE_NO_PAD.encode(fido_challenge),
        "origin": "https://login.microsoft.com"
    }))
    .map_err(|e| {
        error!("{:?}", e);
        PamResultCode::PAM_CRED_INSUFFICIENT
    })?;

    // Create a channel for status updates
    let rt = Runtime::new().map_err(|e| {
        error!("{:?}", e);
        PamResultCode::PAM_AUTH_ERR
    })?;
    let status_tx = rt.block_on(async { fido_status_check(conv).await });

    let allow_list: Vec<PublicKeyCredentialDescriptor> = fido_allow_list
        .into_iter()
        .filter_map(|id| match STANDARD.decode(id) {
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

    // Perform authentication
    let (sign_tx, sign_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        sign_tx.send(rv).unwrap();
    }));

    manager
        .sign(25000, ctap_args, status_tx.clone(), callback)
        .map_err(|e| {
            error!("{:?}", e);
            PamResultCode::PAM_CRED_INSUFFICIENT
        })?;

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

macro_rules! pam_fail {
    ($conv:expr, $msg:expr, $ret:expr) => {{
        let _ = $conv.send(PAM_TEXT_INFO,
            &format!(
                "{} If you are now prompted for a password from pam_unix, please disregard the prompt, exit and try again.",
                 $msg
            )
        );
        return $ret;
    }}
}

macro_rules! match_sm_auth_client_response {
    ($daemon_client:expr, $opts:ident, $conv:ident, $req:ident, $authtok:ident, $cfg:ident, $($pat:pat => $result:expr),*) => {{
        let timeout = $cfg.get_unix_sock_timeout();
        match $daemon_client.call_and_wait(&$req, timeout) {
            Ok(r) => match r {
                $($pat => $result),*
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Success) => {
                    return PamResultCode::PAM_SUCCESS;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Denied) => {
                    pam_fail!(
                        $conv.lock().unwrap(),
                        "Entra Id authentication denied.",
                        PamResultCode::PAM_AUTH_ERR
                    );
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
                    let conv = $conv.lock().unwrap();
                    match conv.send(PAM_TEXT_INFO, &msg) {
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
                        pin = match conv.send(PAM_PROMPT_ECHO_OFF, "New PIN: ") {
                            Ok(password) => match password {
                                Some(cred) => {
                                    if cred.len() < $cfg.get_hello_pin_min_length() {
                                        match conv.send(PAM_TEXT_INFO, &format!("Chosen pin is too short! {} chars required.", $cfg.get_hello_pin_min_length())) {
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
                                    pam_fail!(
                                        conv,
                                        "No Entra Id Hello PIN was supplied.",
                                        PamResultCode::PAM_CRED_INSUFFICIENT
                                    );
                                }
                            },
                            Err(err) => {
                                debug!("unable to get pin");
                                pam_fail!(
                                    conv,
                                    "No Entra Id Hello PIN was found.",
                                    err
                                );
                            }
                        };

                        match conv.send(PAM_TEXT_INFO, &msg) {
                            Ok(_) => {}
                            Err(err) => {
                                if $opts.debug {
                                    println!("Message prompt failed");
                                }
                                return err;
                            }
                        }

                        confirm = match conv.send(PAM_PROMPT_ECHO_OFF, "Confirm PIN: ") {
                            Ok(password) => match password {
                                Some(cred) => cred,
                                None => {
                                    debug!("no confirmation pin");
                                    pam_fail!(
                                        conv,
                                        "No Entra Id Hello confirmation PIN was supplied.",
                                        PamResultCode::PAM_CRED_INSUFFICIENT
                                    );
                                }
                            },
                            Err(err) => {
                                debug!("unable to get confirmation pin");
                                pam_fail!(
                                    conv,
                                    "No Entra Id Hello confirmation PIN was found.",
                                    err
                                );
                            }
                        };

                        if pin == confirm {
                            break;
                        } else {
                            match conv.send(PAM_TEXT_INFO, "Inputs did not match. Try again.") {
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
                        let conv = $conv.lock().unwrap();
                        match conv.send(PAM_PROMPT_ECHO_OFF, "PIN: ") {
                            Ok(password) => match password {
                                Some(cred) => cred,
                                None => {
                                    debug!("no pin");
                                    pam_fail!(
                                        conv,
                                        "No Entra Id Hello PIN was supplied.",
                                        PamResultCode::PAM_CRED_INSUFFICIENT
                                    );
                                }
                            },
                            Err(err) => {
                                debug!("unable to get pin");
                                pam_fail!(
                                    conv,
                                    "No Entra Id Hello PIN was found.",
                                    err
                                );
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
                    let result = match fido_auth($conv.clone(), fido_challenge, fido_allow_list) {
                        Ok(assertion) => assertion,
                        Err(e) => {
                            pam_fail!(
                                $conv.lock().unwrap(),
                                "Entra Id Fido authentication failed.",
                                e
                            );
                        },
                    };

                    // Now setup the request for the next loop.
                    $req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Fido { assertion: result });
                    continue;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::ChangePassword {
                    msg,
                }) => {
                    let conv = $conv.lock().unwrap();
                    match conv.send(PAM_TEXT_INFO, &msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if $opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }

                    let mut password;
                    let mut confirm;
                    loop {
                        password = match conv.send(PAM_PROMPT_ECHO_OFF, "New password: ") {
                            Ok(password) => match password {
                                Some(cred) => {
                                    // Entra Id requires a minimum password length of 8 characters
                                    if cred.len() < 8 {
                                        match conv.send(PAM_TEXT_INFO, "Chosen password is too short! 8 chars required.") {
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
                                    debug!("no password");
                                    pam_fail!(
                                        conv,
                                        "No Entra Id password was supplied.",
                                        PamResultCode::PAM_CRED_INSUFFICIENT
                                    );
                                }
                            },
                            Err(err) => {
                                debug!("unable to get password");
                                pam_fail!(
                                    conv,
                                    "No Entra Id password was found.",
                                    err
                                );
                            }
                        };

                        match conv.send(PAM_TEXT_INFO, &msg) {
                            Ok(_) => {}
                            Err(err) => {
                                if $opts.debug {
                                    println!("Message prompt failed");
                                }
                                return err;
                            }
                        }

                        confirm = match conv.send(PAM_PROMPT_ECHO_OFF, "Confirm password: ") {
                            Ok(password) => match password {
                                Some(cred) => cred,
                                None => {
                                    debug!("no confirmation password");
                                    pam_fail!(
                                        conv,
                                        "No Entra Id confirmation password was supplied.",
                                        PamResultCode::PAM_CRED_INSUFFICIENT
                                    );
                                }
                            },
                            Err(err) => {
                                debug!("unable to get confirmation password");
                                pam_fail!(
                                    conv,
                                    "No Entra Id confirmation password was found.",
                                    err
                                );
                            }
                        };

                        if password == confirm {
                            break;
                        } else {
                            match conv.send(PAM_TEXT_INFO, "Inputs did not match. Try again.") {
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
                    $req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password {
                        cred: password,
                    });
                    continue;
                },
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Password) => {
                    let mut consume_authtok = None;
                    // Swap the authtok out with a None, so it can only be consumed once.
                    // If it's already been swapped, we are just swapping two null pointers
                    // here effectively.
                    std::mem::swap(&mut $authtok, &mut consume_authtok);
                    let cred = if let Some(cred) = consume_authtok {
                        cred
                    } else {
                        let lconv = $conv.lock().unwrap();
                        match lconv.send(PAM_PROMPT_ECHO_OFF, "Entra Id Password: ") {
                            Ok(password) => match password {
                                Some(cred) => cred,
                                None => {
                                    debug!("no password");
                                    pam_fail!(
                                        lconv,
                                        "No Entra Id password was supplied.",
                                        PamResultCode::PAM_CRED_INSUFFICIENT
                                    );
                                }
                            },
                            Err(err) => {
                                debug!("unable to get password");
                                pam_fail!(
                                    lconv,
                                    "No Entra Id password was found.",
                                    err
                                );
                            }
                        }
                    };

                    // Now setup the request for the next loop.
                    $req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password { cred });
                    continue;
                },
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFACode {
                    msg,
                }) => {
                    let lconv = $conv.lock().unwrap();
                    match lconv.send(PAM_TEXT_INFO, &msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if $opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }
                    let cred = match lconv.send(PAM_PROMPT_ECHO_OFF, "Code: ") {
                        Ok(password) => match password {
                            Some(cred) => cred,
                            None => {
                                debug!("no mfa code");
                                pam_fail!(
                                    lconv,
                                    "No Entra Id auth code was supplied.",
                                    PamResultCode::PAM_CRED_INSUFFICIENT
                                );
                            }
                        },
                        Err(err) => {
                            debug!("unable to get mfa code");
                            pam_fail!(
                                lconv,
                                "No Entra Id auth code was found.",
                                err
                            );
                        }
                    };

                    // Now setup the request for the next loop.
                    $req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFACode {
                        cred,
                    });
                    continue;
                },
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFAPoll {
                    msg,
                    polling_interval,
                }) => {
                    return mfa_poll($daemon_client, $authtok, $conv, $opts, $cfg, &msg, polling_interval);
                }
                _ => {
                    // unexpected response.
                    error!(err = ?r, "PAM_IGNORE, unexpected resolver response");
                    pam_fail!(
                        $conv.lock().unwrap(),
                        "An unexpected error occurred.",
                        PamResultCode::PAM_IGNORE
                    );
                }
            },
            Err(err) => {
                error!(?err, "PAM_IGNORE");
                pam_fail!(
                    $conv.lock().unwrap(),
                    "An unexpected error occured.",
                    PamResultCode::PAM_IGNORE
                );
            }
        }
    }}
}

/// This function exists to prevent infinite build-time recursion to the
/// match_sm_auth_client_response macro. Instead we have run-time recursion.
fn mfa_poll(
    mut daemon_client: DaemonClientBlocking,
    mut authtok: Option<String>,
    conv: Arc<Mutex<PamConv>>,
    opts: Options,
    cfg: HimmelblauConfig,
    msg: &str,
    polling_interval: u32,
) -> PamResultCode {
    // This conversation is intentionally nested within a block
    // to ensure the lconv lock is dropped before calling the
    // nested `match_sm_auth_client_response`, otherwise we
    // deadlock here.
    {
        let lconv = conv.lock().unwrap();
        match lconv.send(PAM_TEXT_INFO, msg) {
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
            let _ = lconv.send(PAM_PROMPT_ECHO_OFF, "Press enter to continue");
        }
    }

    let mut poll_attempt = 0;
    let mut req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFAPoll { poll_attempt });
    loop {
        thread::sleep(Duration::from_secs(polling_interval.into()));

        // Counter intuitive, but we don't need a max poll attempts here because
        // if the resolver goes away, then this will error on the sock and
        // will shutdown. This allows the resolver to dynamically extend the
        // timeout if needed, and removes logic from the front end.
        match_sm_auth_client_response!(
            daemon_client, opts, conv, req, authtok, cfg,
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

        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
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
            Ok(conv) => Arc::new(Mutex::new(conv.clone())),
            Err(err) => {
                error!(?err, "pam_conv");
                return err;
            }
        };

        let mut req = ClientRequest::PamAuthenticateInit(account_id, service);

        loop {
            match_sm_auth_client_response!(daemon_client, opts, conv, req, authtok, cfg,);
        } // while true, continue calling PamAuthenticateStep until we get a decision.
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

            match mfa_req.mfa_method.as_str() {
                "PhoneAppOTP" | "OneWaySMS" | "ConsolidatedTelephony" => {
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
                }
                _ => {
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
            }
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
