/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2025

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
use crate::client_sync::DaemonClientBlocking;
use crate::config::HimmelblauConfig;
use crate::hello_pin_complexity::is_simple_pin;
use crate::unix_proto::{ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse};
use std::sync::Arc;

use tracing::{debug, error};

use std::thread;
use std::time::Duration;

use crate::pam::{Options, PamResultCode};
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
use rpassword::prompt_password;
use serde_json::{json, to_string as json_to_string};
use sha2::{Digest, Sha256};
use std::sync::mpsc::{channel, RecvError, Sender};
use tokio::runtime::Runtime;

#[macro_export]
macro_rules! auth_handle_mfa_resp {
    ($resp:ident, $on_fido:expr, $on_prompt:expr, $on_poll:expr) => {
        match $resp.mfa_method.as_str() {
            "FidoKey" => $on_fido,
            "AccessPass" | "PhoneAppOTP" | "OneWaySMS" | "ConsolidatedTelephony" => $on_prompt,
            _ => $on_poll,
        }
    };
}

pub trait MessagePrinter: Send + Sync {
    fn print_text(&self, msg: &str);
    fn print_error(&self, msg: &str);
    fn prompt_echo_off(&self, prompt: &str) -> Option<String>;
}

#[derive(Default)]
pub struct SimpleMessagePrinter {}

impl MessagePrinter for SimpleMessagePrinter {
    fn print_text(&self, msg: &str) {
        println!("{}", msg);
    }

    fn print_error(&self, msg: &str) {
        eprintln!("{}", msg);
    }

    fn prompt_echo_off(&self, prompt: &str) -> Option<String> {
        prompt_password(prompt).ok()
    }
}

#[allow(clippy::expect_used)]
async fn fido_status_check(msg_printer: Arc<dyn MessagePrinter>) -> Sender<StatusUpdate> {
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::InteractiveManagement(..)) => {
                error!("Fido STATUS: InteractiveManagement: This can't happen when doing non-interactive usage");
                break;
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                msg_printer.print_text("Please select a device by touching one of them.");
            }
            Ok(StatusUpdate::PresenceRequired) => {
                msg_printer.print_text("Waiting for user presence");
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender))) => {
                match msg_printer.prompt_echo_off("Fido PIN: ") {
                    Some(pin) => {
                        sender.send(Pin::new(&pin)).expect("Failed to send PIN");
                        continue;
                    }
                    None => {
                        break;
                    }
                }
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts))) => {
                let msg = format!(
                    "Wrong PIN! {}",
                    attempts.map_or("Try again.".to_string(), |a| format!(
                        "You have {a} attempts left."
                    ))
                );
                msg_printer.print_text(&msg);
                match msg_printer.prompt_echo_off("Fido PIN: ") {
                    Some(pin) => {
                        sender.send(Pin::new(&pin)).expect("Failed to send PIN");
                        continue;
                    }
                    None => {
                        break;
                    }
                }
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked)) => {
                let msg = "Too many failed attempts in one row. Your device has been temporarily blocked. Please unplug it and plug in again.";
                msg_printer.print_error(msg);
                break;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinBlocked)) => {
                let msg = "Too many failed attempts. Your device has been blocked. Reset it.";
                msg_printer.print_error(msg);
                break;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidUv(attempts))) => {
                let msg = format!(
                    "Wrong UV! {}",
                    attempts.map_or("Try again.".to_string(), |a| format!(
                        "You have {a} attempts left."
                    ))
                );
                msg_printer.print_error(&msg);
                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::UvBlocked)) => {
                msg_printer.print_error("Too many failed UV-attempts.");
                break;
            }
            Ok(StatusUpdate::PinUvError(e)) => {
                let msg = format!("Unexpected error: {:?}", e);
                msg_printer.print_error(&msg);
                break;
            }
            Ok(StatusUpdate::SelectResultNotice(_, _)) => {
                msg_printer.print_error("Unexpected select device notice");
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

#[allow(clippy::unwrap_used)]
pub fn fido_auth(
    msg_printer: Arc<dyn MessagePrinter>,
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
    let status_tx = rt.block_on(async { fido_status_check(msg_printer).await });

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

#[macro_export]
macro_rules! pam_fail {
    ($msg_printer:expr, $msg:expr, $ret:expr) => {{
        $msg_printer.print_text(&format!(
            "{:?}: {} \nIf you are now prompted for a password from pam_unix, please disregard the prompt, go back and try again.",
            $ret,
            $msg
        ));

        thread::sleep(Duration::from_secs(2));
        // Abort the auth attempt, and don't continue executing the stack
        return PamResultCode::PAM_ABORT;
    }};
}

macro_rules! match_sm_auth_client_response {
    ($daemon_client:expr, $req:ident, $authtok:expr, $cfg:ident, $account_id:ident, $service:ident, $msg_printer:ident, $opts:ident, $($pat:pat => $result:expr),*) => {{
        let timeout = $cfg.get_unix_sock_timeout();
        match $daemon_client.call_and_wait(&$req, timeout) {
            Ok(r) => match r {
                $($pat => $result),*
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Success) => {
                    return PamResultCode::PAM_SUCCESS;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Denied(msg)) => {
                    $msg_printer.print_text(&msg);
                    thread::sleep(Duration::from_secs(2));
                    $req = ClientRequest::PamAuthenticateInit($account_id.to_string(), $service.to_string(), $opts.no_hello_pin);
                    continue;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::InitDenied {
                    msg,
                }) => {
                    pam_fail!($msg_printer, msg, PamResultCode::PAM_ABORT)
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
                    let msg = format!("{}\nThe minimum PIN length is {} characters.", msg, $cfg.get_hello_pin_min_length());

                    let mut pin;
                    let mut confirm;
                    loop {
                        $msg_printer.print_text(&msg);
                        pin = match $msg_printer.prompt_echo_off("New PIN: ") {
                            Some(cred) => {
                                if cred.len() < $cfg.get_hello_pin_min_length() {
                                    $msg_printer.print_text(&format!("Chosen pin is too short! {} chars required.", $cfg.get_hello_pin_min_length()));
                                    thread::sleep(Duration::from_secs(2));
                                    continue;
                                } else if is_simple_pin(&cred) {
                                    $msg_printer.print_text("PIN must not use repeating or predictable sequences. Avoid patterns like '111111', '123456', or '135791'.");
                                    thread::sleep(Duration::from_secs(2));
                                    continue;
                                }
                                cred
                            },
                            None => {
                                debug!("no pin");
                                pam_fail!(
                                    $msg_printer,
                                    "No Entra Id Hello PIN was supplied.",
                                    PamResultCode::PAM_CRED_INSUFFICIENT
                                );
                            }
                        };

                        $msg_printer.print_text(&msg);

                        confirm = match $msg_printer.prompt_echo_off("Confirm PIN: ") {
                            Some(cred) => cred,
                            None => {
                                debug!("no confirmation pin");
                                pam_fail!(
                                    $msg_printer,
                                    "No Entra Id Hello confirmation PIN was supplied.",
                                    PamResultCode::PAM_CRED_INSUFFICIENT
                                );
                            }
                        };

                        if pin == confirm {
                            break;
                        } else {
                            $msg_printer.print_text("Inputs did not match. Try again.");
                            thread::sleep(Duration::from_secs(2));
                        }
                    }

                    $msg_printer.print_text("Enrolling the Hello PIN. Please wait...");

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
                        $msg_printer.print_text(&$cfg.get_hello_pin_prompt());
                        match $msg_printer.prompt_echo_off("PIN: ") {
                            Some(cred) => cred,
                            None => {
                                debug!("no pin");
                                pam_fail!(
                                    $msg_printer,
                                    "No Entra Id Hello PIN was supplied.",
                                    PamResultCode::PAM_CRED_INSUFFICIENT
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
                    let result = match fido_auth($msg_printer.clone(), fido_challenge, fido_allow_list) {
                        Ok(assertion) => assertion,
                        Err(e) => {
                            pam_fail!(
                                $msg_printer,
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
                    let mut password;
                    let mut confirm;
                    loop {
                        $msg_printer.print_text(&msg);
                        password = match $msg_printer.prompt_echo_off("New password: ") {
                            Some(cred) => {
                                // Entra Id requires a minimum password length of 8 characters
                                if cred.len() < 8 {
                                    $msg_printer.print_text("Chosen password is too short! 8 chars required.");
                                    continue;
                                }
                                cred
                            },
                            None => {
                                debug!("no password");
                                pam_fail!(
                                    $msg_printer,
                                    "No Entra Id password was supplied.",
                                    PamResultCode::PAM_CRED_INSUFFICIENT
                                );
                            }
                        };

                        $msg_printer.print_text(&msg);

                        confirm = match $msg_printer.prompt_echo_off("Confirm password: ") {
                            Some(cred) => cred,
                            None => {
                                debug!("no confirmation password");
                                pam_fail!(
                                    $msg_printer,
                                    "No Entra Id confirmation password was supplied.",
                                    PamResultCode::PAM_CRED_INSUFFICIENT
                                );
                            }
                        };

                        if password == confirm {
                            break;
                        } else {
                            $msg_printer.print_text("Inputs did not match. Try again.");
                            thread::sleep(Duration::from_secs(2));
                        }
                    }

                    $msg_printer.print_text("Changing the password. Please wait...");

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
                        $msg_printer.print_text(&$cfg.get_entra_id_password_prompt());
                        match $msg_printer.prompt_echo_off("Entra Id Password: ") {
                            Some(cred) => cred,
                            None => {
                                debug!("no password");
                                pam_fail!(
                                    $msg_printer,
                                    "No Entra Id password was supplied.",
                                    PamResultCode::PAM_CRED_INSUFFICIENT
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
                    $msg_printer.print_text(&msg);
                    let cred = match $msg_printer.prompt_echo_off("Code: ") {
                        Some(cred) => cred,
                        None => {
                            debug!("no mfa code");
                            pam_fail!(
                                $msg_printer,
                                "No Entra Id auth code was supplied.",
                                PamResultCode::PAM_CRED_INSUFFICIENT
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
                    return mfa_poll($daemon_client, $authtok, $msg_printer, $opts, $cfg, &$account_id, &$service, &msg, polling_interval);
                }
                _ => {
                    // unexpected response.
                    error!(err = ?r, "PAM_IGNORE, unexpected resolver response");
                    pam_fail!(
                        $msg_printer,
                        "An unexpected error occurred.",
                        PamResultCode::PAM_IGNORE
                    );
                }
            },
            Err(err) => {
                error!(?err, "PAM_IGNORE");
                pam_fail!(
                    $msg_printer,
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
    msg_printer: Arc<dyn MessagePrinter>,
    opts: Options,
    cfg: &HimmelblauConfig,
    account_id: &str,
    service: &str,
    msg: &str,
    polling_interval: u32,
) -> PamResultCode {
    // Suggest users connect mobile devices to the internet, except when
    // polling a DAG.
    let msg = if !msg.contains("https://microsoft.com/devicelogin") {
        format!(
            "{}\nNo push? Check your mobile device's internet connection.",
            msg
        )
    } else {
        msg.to_string()
    };
    msg_printer.print_text(&msg);

    // Necessary because of OpenSSH bug
    // https://bugzilla.mindrot.org/show_bug.cgi?id=2876 -
    // PAM_TEXT_INFO and PAM_ERROR_MSG conversation not
    // honoured during PAM authentication
    if opts.mfa_poll_prompt {
        msg_printer.prompt_echo_off("Press enter to continue");
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
            daemon_client, req, authtok, cfg, account_id, service, msg_printer, opts,
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

pub fn authenticate(
    mut authtok: Option<String>,
    cfg: &HimmelblauConfig,
    account_id: &str,
    service: &str,
    opts: Options,
    msg_printer: Arc<dyn MessagePrinter>,
) -> PamResultCode {
    let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
        Ok(dc) => dc,
        Err(e) => {
            error!(err = ?e, "Error DaemonClientBlocking::new()");
            return PamResultCode::PAM_SERVICE_ERR;
        }
    };

    let mut req = ClientRequest::PamAuthenticateInit(
        account_id.to_string(),
        service.to_string(),
        opts.no_hello_pin,
    );

    loop {
        match_sm_auth_client_response!(
            daemon_client,
            req,
            authtok,
            cfg,
            account_id,
            service,
            msg_printer,
            opts,
        );
    }
}

pub async fn authenticate_async(
    authtok: Option<String>,
    cfg: HimmelblauConfig,
    account_id: String,
    service: String,
    opts: Options,
    msg_printer: Arc<dyn MessagePrinter>,
) -> PamResultCode {
    match tokio::task::spawn_blocking(move || {
        authenticate(authtok, &cfg, &account_id, &service, opts, msg_printer)
    })
    .await
    {
        Err(e) => {
            error!(err = ?e, "Error authenticate_async failed spawning task");
            PamResultCode::PAM_SERVICE_ERR
        }
        Ok(r) => r,
    }
}
