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
use crate::hello_pin_complexity::{is_simple_pin, meets_intune_pin_policy};
use crate::unix_proto::{ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse};
use regex::{Match, Regex};
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
        match $resp.get_default_mfa_method_details() {
            Some(value) => match value.auth_method_id.as_str() {
                "FidoKey" => $on_fido,
                "AccessPass" | "PhoneAppOTP" | "OneWaySMS" | "ConsolidatedTelephony" => $on_prompt,
                _ => $on_poll,
            },
            None => $on_poll,
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
        return PamWhatNext::Finish(PamResultCode::PAM_ABORT);
    }};
}

fn hello_totp_urldecode_match(m: Option<Match>) -> Result<String, String> {
    match m.map(|c| urlencoding::decode(c.as_str())) {
        Some(c) => match c {
            Ok(c) => Ok(c.to_string()),
            Err(ref e) => {
                debug!("Failed to decode parameter {:?}: {:?}", c, e);
                Err("Failed to generate QR code".to_string())
            }
        },
        None => {
            debug!("Failed to capture parameter from TOTP url");
            Err("Failed to generate QR code".to_string())
        }
    }
}

fn hello_totp_enroll_fallback_msg(url: &str) -> Result<String, String> {
    let totp_regex = Regex::new(r"otpauth://([ht]otp)/([^:?]+):?([^\?]+)\?secret=([0-9A-Za-z]+)(?:.*(?:<?counter=)([0-9]+))?").map_err(|e| {
        debug!(?e, "Failed to build regex");
        format!("Failed to build regex: {}", e)
    })?;

    match totp_regex.captures(url) {
        Some(cap) => {
            let secret = match cap.get(4) {
                Some(c) => Ok(c.as_str().to_string()),
                None => {
                    debug!("Failed to capture secret from TOTP url {}", url);
                    Err("Failed to generate QR code".to_string())
                }
            }?;
            let issuer = hello_totp_urldecode_match(cap.get(2))?;
            let acct = hello_totp_urldecode_match(cap.get(3))?;
            let fallback_msg = format!(
                "Enter the setup key '{}' to enroll a TOTP Authenticator app. Use '{}' for the code name and '{}' as the label/name.",
                secret, issuer, acct);
            Ok(fallback_msg)
        }
        None => {
            debug!("Failed to parse TOTP url {}", url);
            Err("Failed to generate QR code".to_string())
        }
    }
}

fn handle_pam_auth_response_mfapoll(
    state: &mut AuthenticateState,
    msg: &str,
    polling_interval: u32,
) -> PamWhatNext {
    // Suggest users connect mobile devices to the internet, except when
    // polling a DAG.
    let msg = if !msg.contains("https://microsoft.com/devicelogin") && !msg.trim().is_empty() {
        format!(
            "{}\nNo push? Check your mobile device's internet connection.",
            msg
        )
    } else {
        msg.to_string()
    };
    if !msg.trim().is_empty() {
        state.msg_printer.print_text(&msg);
    }

    // Necessary because of OpenSSH bug
    // https://bugzilla.mindrot.org/show_bug.cgi?id=2876 -
    // PAM_TEXT_INFO and PAM_ERROR_MSG conversation not
    // honoured during PAM authentication. Only prompt if
    // this is the ssh service and a message was sent.
    if state.opts.mfa_poll_prompt && state.service.contains("ssh") && !msg.trim().is_empty() {
        state.msg_printer.prompt_echo_off("Press enter to continue");
    }

    // Do not allow concurrent MFA polling
    if state.poll_attempt >= 0 {
        error!("MFA poll already in progress");
        pam_fail!(
            state.msg_printer,
            "Unexpected error occurred.",
            PamResultCode::PAM_SYSTEM_ERR
        );
    }
    state.poll_attempt = 0;

    // Daemon tell us the polling_interval
    state.polling_interval = polling_interval;
    thread::sleep(Duration::from_secs(state.polling_interval.into()));

    // Counter intuitive, but we don't need a max poll attempts here because
    // if the resolver goes away, then this will error on the sock and
    // will shutdown. This allows the resolver to dynamically extend the
    // timeout if needed, and removes logic from the front end.
    let next = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFAPoll {
        poll_attempt: state.poll_attempt as u32,
    });
    PamWhatNext::Next(next)
}

fn handle_pam_auth_response_mfapollwait(state: &mut AuthenticateState) -> PamWhatNext {
    if state.poll_attempt < 0 {
        // No MFA poll was initiated yet.
        error!("MFAPollWait before MFAPoll");
        pam_fail!(
            state.msg_printer,
            "An unexpected error occurred.",
            PamResultCode::PAM_IGNORE
        );
    }

    // Continue polling if the daemon says to wait
    thread::sleep(Duration::from_secs(state.polling_interval.into()));

    state.poll_attempt += 1;
    let req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFAPoll {
        poll_attempt: state.poll_attempt as u32,
    });
    PamWhatNext::Next(req)
}

enum PamWhatNext {
    Next(ClientRequest),
    Finish(PamResultCode),
}

fn handle_pam_auth_response_unknown(state: &AuthenticateState) -> PamWhatNext {
    let code = if state.opts.ignore_unknown_user {
        PamResultCode::PAM_IGNORE
    } else {
        PamResultCode::PAM_USER_UNKNOWN
    };
    PamWhatNext::Finish(code)
}

fn handle_pam_auth_response_success() -> PamWhatNext {
    let code = PamResultCode::PAM_SUCCESS;
    PamWhatNext::Finish(code)
}

fn handle_pam_auth_response_denied(state: &AuthenticateState, msg: &str) -> PamWhatNext {
    state.msg_printer.print_text(msg);
    thread::sleep(Duration::from_secs(2));
    let req = ClientRequest::PamAuthenticateInit(
        state.account_id.to_string(),
        state.service.to_string(),
        state.opts.no_hello_pin,
    );
    PamWhatNext::Next(req)
}

fn handle_pam_auth_response_password(state: &mut AuthenticateState) -> PamWhatNext {
    let mut consume_authtok = None;
    // Swap the authtok out with a None, so it can only be consumed once.
    // If it's already been swapped, we are just swapping two null pointers
    // here effectively.
    std::mem::swap(&mut state.authtok, &mut consume_authtok);
    let cred = if let Some(cred) = consume_authtok {
        cred
    } else {
        state
            .msg_printer
            .print_text(&state.cfg.get_entra_id_password_prompt());
        match state.msg_printer.prompt_echo_off("Entra Id Password: ") {
            Some(cred) => cred,
            None => {
                debug!("no password");
                pam_fail!(
                    state.msg_printer,
                    "No Entra Id password was supplied.",
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
        }
    };

    // Now setup the request for the next loop.
    let req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password { cred });
    PamWhatNext::Next(req)
}

fn handle_pam_auth_response_mfacode(state: &AuthenticateState, msg: &str) -> PamWhatNext {
    state.msg_printer.print_text(msg);
    let cred = match state.msg_printer.prompt_echo_off("Code: ") {
        Some(cred) => cred,
        None => {
            debug!("no mfa code");
            pam_fail!(
                state.msg_printer,
                "No Entra Id auth code was supplied.",
                PamResultCode::PAM_CRED_INSUFFICIENT
            );
        }
    };

    // Now setup the request for the next loop.
    let req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFACode { cred });
    PamWhatNext::Next(req)
}

fn generate_unicode_qr(content: &str) -> Result<String, String> {
    match qrcodegen::QrCode::encode_text(content, qrcodegen::QrCodeEcc::Low) {
        Ok(qr) => {
            let mut buf = String::new();
            let border: i32 = 4;
            let full_block: char = '\u{2588}';
            let half_upper_block: char = '\u{2580}';
            let half_lower_block: char = '\u{2584}';
            let white_block: char = '\u{0020}';

            for y in (-border..qr.size() + border).step_by(2) {
                for x in -border..qr.size() + border {
                    let upper = qr.get_module(x, y);
                    let lower = qr.get_module(x, y + 1);
                    let c = match (upper, lower) {
                        (true, true) => full_block,
                        (true, false) => half_upper_block,
                        (false, true) => half_lower_block,
                        (false, false) => white_block,
                    };
                    buf.push(c);
                }
                buf.push('\n');
            }
            Ok(buf)
        }
        Err(e) => Err(e.to_string()),
    }
}

fn handle_pam_auth_response_hellototp(state: &AuthenticateState, msg: &str) -> PamWhatNext {
    // GDM will render its own QR code if qr-greeter is installed.
    // Otherwise render with unicode chars.
    if msg.starts_with("otpauth://") && state.service != "gdm-password" {
        match generate_unicode_qr(msg) {
            Ok(qr) => {
                let msg = format!("Open your authenticator app and scan this QR code to enroll. Then enter the generated code.\n{}", &qr);
                state.msg_printer.print_text(&msg);
            }
            Err(e) => {
                debug!("failed to generate QR code: {:?}", e);
                // Fallback to manual setup
                match hello_totp_enroll_fallback_msg(msg) {
                    Ok(msg) => state.msg_printer.print_text(&msg),
                    Err(msg) => {
                        pam_fail!(state.msg_printer, msg, PamResultCode::PAM_SYSTEM_ERR);
                    }
                }
            }
        };
    } else {
        state.msg_printer.print_text(msg);
    };

    let cred = match state.msg_printer.prompt_echo_off("TOTP Code: ") {
        Some(cred) => cred,
        None => {
            debug!("no hello totp code");
            pam_fail!(
                state.msg_printer,
                "No Hello TOTP code was supplied.",
                PamResultCode::PAM_CRED_INSUFFICIENT
            );
        }
    };

    // Now setup the request for the next loop.
    let req = ClientRequest::PamAuthenticateStep(PamAuthRequest::HelloTOTP { cred });
    PamWhatNext::Next(req)
}

fn handle_pam_auth_response_setup_pin(state: &AuthenticateState, msg: &str) -> PamWhatNext {
    let msg = format!(
        "{}\nThe minimum PIN length is {} characters.",
        msg,
        state.cfg.get_hello_pin_min_length()
    );

    let mut pin;
    let mut confirm;
    loop {
        state.msg_printer.print_text(&msg);
        pin = match state.msg_printer.prompt_echo_off("New PIN: ") {
            Some(cred) => {
                if cred.len() < state.cfg.get_hello_pin_min_length() {
                    state.msg_printer.print_text(&format!(
                        "Chosen pin is too short! {} chars required.",
                        state.cfg.get_hello_pin_min_length()
                    ));
                    thread::sleep(Duration::from_secs(2));
                    continue;
                } else if is_simple_pin(&cred) {
                    state.msg_printer.print_text("PIN must not use repeating or predictable sequences. Avoid patterns like '111111', '123456', or '135791'.");
                    thread::sleep(Duration::from_secs(2));
                    continue;
                } else if let Err(msg) = meets_intune_pin_policy(&cred) {
                    state.msg_printer.print_text(&msg);
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
                cred
            }
            None => {
                debug!("no pin");
                pam_fail!(
                    state.msg_printer,
                    "No Entra Id Hello PIN was supplied.",
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
        };

        state.msg_printer.print_text(&msg);

        confirm = match state.msg_printer.prompt_echo_off("Confirm PIN: ") {
            Some(cred) => cred,
            None => {
                debug!("no confirmation pin");
                pam_fail!(
                    state.msg_printer,
                    "No Entra Id Hello confirmation PIN was supplied.",
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
        };

        if pin == confirm {
            break;
        } else {
            state
                .msg_printer
                .print_text("Inputs did not match. Try again.");
            thread::sleep(Duration::from_secs(2));
        }
    }

    state
        .msg_printer
        .print_text("Enrolling the Hello PIN. Please wait...");

    // Now setup the request for the next loop.
    let req = ClientRequest::PamAuthenticateStep(PamAuthRequest::SetupPin { pin });
    PamWhatNext::Next(req)
}

fn handle_pam_auth_response_pin(state: &mut AuthenticateState) -> PamWhatNext {
    let mut consume_authtok = None;
    // Swap the authtok out with a None, so it can only be consumed once.
    // If it's already been swapped, we are just swapping two null pointers
    // here effectively.
    std::mem::swap(&mut state.authtok, &mut consume_authtok);
    let cred = if let Some(cred) = consume_authtok {
        cred
    } else {
        state
            .msg_printer
            .print_text(&state.cfg.get_hello_pin_prompt());
        match state.msg_printer.prompt_echo_off("PIN: ") {
            Some(cred) => cred,
            None => {
                debug!("no pin");
                pam_fail!(
                    state.msg_printer,
                    "No Entra Id Hello PIN was supplied.",
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
        }
    };

    // Now setup the request for the next loop.
    let req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Pin { cred });
    PamWhatNext::Next(req)
}

fn handle_pam_auth_response_fido(
    state: &AuthenticateState,
    fido_challenge: String,
    fido_allow_list: Vec<String>,
) -> PamWhatNext {
    let result = match fido_auth(state.msg_printer.clone(), fido_challenge, fido_allow_list) {
        Ok(assertion) => assertion,
        Err(e) => {
            pam_fail!(state.msg_printer, "Entra Id Fido authentication failed.", e);
        }
    };

    // Now setup the request for the next loop.
    let req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Fido { assertion: result });
    PamWhatNext::Next(req)
}

fn handle_pam_auth_response_change_password(state: &AuthenticateState, msg: &str) -> PamWhatNext {
    let mut password;
    let mut confirm;
    loop {
        state.msg_printer.print_text(msg);
        password = match state.msg_printer.prompt_echo_off("New password: ") {
            Some(cred) => {
                // Entra Id requires a minimum password length of 8 characters
                if cred.len() < 8 {
                    state
                        .msg_printer
                        .print_text("Chosen password is too short! 8 chars required.");
                    continue;
                }
                cred
            }
            None => {
                debug!("no password");
                pam_fail!(
                    state.msg_printer,
                    "No Entra Id password was supplied.",
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
        };

        state.msg_printer.print_text(msg);

        confirm = match state.msg_printer.prompt_echo_off("Confirm password: ") {
            Some(cred) => cred,
            None => {
                debug!("no confirmation password");
                pam_fail!(
                    state.msg_printer,
                    "No Entra Id confirmation password was supplied.",
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
        };

        if password == confirm {
            break;
        } else {
            state
                .msg_printer
                .print_text("Inputs did not match. Try again.");
            thread::sleep(Duration::from_secs(2));
        }
    }

    state
        .msg_printer
        .print_text("Changing the password. Please wait...");

    // Now setup the request for the next loop.
    let next = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password { cred: password });
    PamWhatNext::Next(next)
}

fn handle_pam_auth_init_denied(state: &AuthenticateState, msg: &str) -> PamWhatNext {
    pam_fail!(state.msg_printer, msg, PamResultCode::PAM_ABORT)
}

fn authenticate_request_response(
    state: &mut AuthenticateState,
    req: &ClientRequest,
) -> PamWhatNext {
    let cli_res = match state
        .daemon_client
        .call_and_wait(req, state.cfg.get_unix_sock_timeout())
    {
        Ok(res) => res,
        Err(err) => {
            error!(?err, "PAM_IGNORE");
            pam_fail!(
                state.msg_printer,
                "An unexpected error occurred.",
                PamResultCode::PAM_IGNORE
            );
        }
    };

    let response = match cli_res {
        ClientResponse::PamAuthenticateStepResponse(res) => res,
        _ => {
            // unexpected response.
            error!(err = ?cli_res, "PAM_IGNORE, unexpected resolver response");
            pam_fail!(
                state.msg_printer,
                "An unexpected error occurred.",
                PamResultCode::PAM_IGNORE
            );
        }
    };

    match response {
        PamAuthResponse::Unknown => handle_pam_auth_response_unknown(state),
        PamAuthResponse::Success => handle_pam_auth_response_success(),
        PamAuthResponse::Denied(msg) => handle_pam_auth_response_denied(state, &msg),
        PamAuthResponse::InitDenied { msg } => handle_pam_auth_init_denied(state, &msg),
        PamAuthResponse::Password => handle_pam_auth_response_password(state),
        PamAuthResponse::MFACode { msg } => handle_pam_auth_response_mfacode(state, &msg),
        PamAuthResponse::HelloTOTP { msg } => handle_pam_auth_response_hellototp(state, &msg),
        PamAuthResponse::MFAPoll {
            msg,
            polling_interval,
        } => handle_pam_auth_response_mfapoll(state, &msg, polling_interval),
        PamAuthResponse::MFAPollWait => handle_pam_auth_response_mfapollwait(state),
        PamAuthResponse::SetupPin { msg } => handle_pam_auth_response_setup_pin(state, &msg),
        PamAuthResponse::Pin => handle_pam_auth_response_pin(state),
        PamAuthResponse::Fido {
            fido_challenge,
            fido_allow_list,
        } => handle_pam_auth_response_fido(state, fido_challenge, fido_allow_list),
        PamAuthResponse::ChangePassword { msg } => {
            handle_pam_auth_response_change_password(state, &msg)
        }
    }
}

struct AuthenticateState {
    daemon_client: DaemonClientBlocking,
    authtok: Option<String>,
    cfg: HimmelblauConfig,
    account_id: String,
    service: String,
    opts: Options,
    msg_printer: Arc<dyn MessagePrinter>,
    poll_attempt: i32,
    polling_interval: u32,
}

pub fn authenticate(
    authtok: Option<String>,
    cfg: HimmelblauConfig,
    account_id: &str,
    service: &str,
    opts: Options,
    msg_printer: Arc<dyn MessagePrinter>,
) -> PamResultCode {
    let daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
        Ok(dc) => dc,
        Err(e) => {
            debug!(err = ?e, "himmelblaud not available, ignoring");
            return PamResultCode::PAM_IGNORE;
        }
    };

    let mut state = AuthenticateState {
        daemon_client,
        authtok,
        cfg,
        account_id: account_id.to_owned(),
        service: service.to_owned(),
        opts,
        msg_printer,
        poll_attempt: -1,
        polling_interval: 2,
    };

    // This is the initial request to the daemon
    let mut req = ClientRequest::PamAuthenticateInit(
        state.account_id.to_owned(),
        state.service.to_owned(),
        state.opts.no_hello_pin,
    );

    loop {
        let res = authenticate_request_response(&mut state, &req);
        match res {
            PamWhatNext::Next(next_request) => req = next_request,
            PamWhatNext::Finish(pam_result_code) => return pam_result_code,
        }
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
        authenticate(authtok, cfg, &account_id, &service, opts, msg_printer)
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
