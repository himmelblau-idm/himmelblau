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
use crate::i18n::{self, tr, tr_fmt, trn_fmt};
use crate::unix_proto::{ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse};
use regex::{Match, Regex};
use std::future::Future;
use std::io::{self, ErrorKind, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use lazy_static::lazy_static;
use tracing::{debug, error};

use std::thread;
use std::time::{Duration, Instant};

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
use libwebauthn::ops::webauthn::{GetAssertionRequest, UserVerificationRequirement as CableUvReq};
use libwebauthn::transport::cable::qr_code_device::{
    CableQrCodeDevice, CableTransports, QrCodeOperationHint,
};
use libwebauthn::transport::{ChannelSettings, Device};
use libwebauthn::webauthn::WebAuthn;
use rpassword::prompt_password;
use serde_json::{json, to_string as json_to_string};
use sha2::{Digest, Sha256};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender, TryRecvError};
use tokio::runtime::Runtime;

const FIDO_INTERRUPT_POLL_INTERVAL: Duration = Duration::from_millis(100);

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
    /// Whether this output can render a Unicode QR code with ANSI colors.
    fn supports_terminal_qr(&self) -> bool {
        false
    }
    fn print_text(&self, msg: &str);
    /// Show authentication secrets without recording their contents in logs.
    fn print_sensitive(&self, msg: &str) {
        self.print_text(msg);
    }
    fn print_error(&self, msg: &str);
    fn prompt_echo_on(&self, prompt: &str) -> Option<String>;
    fn prompt_echo_off(&self, prompt: &str) -> Option<String>;
}

pub const DAEMON_START_WAIT_MESSAGE: &str = "Himmelblau authentication is starting, please wait...";
pub const DAEMON_START_WAIT_TIMEOUT: Duration = Duration::from_secs(1);
pub const DAEMON_START_WAIT_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Default)]
pub struct SimpleMessagePrinter {}

impl MessagePrinter for SimpleMessagePrinter {
    fn supports_terminal_qr(&self) -> bool {
        true
    }

    fn print_text(&self, msg: &str) {
        println!("{}", msg);
    }

    fn print_error(&self, msg: &str) {
        eprintln!("{}", msg);
    }

    fn prompt_echo_on(&self, prompt: &str) -> Option<String> {
        print!("{}", prompt);
        io::stdout().flush().ok()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input).ok()?;
        Some(input.trim_end_matches(['\r', '\n']).to_string())
    }

    fn prompt_echo_off(&self, prompt: &str) -> Option<String> {
        prompt_password(prompt).ok()
    }
}

pub(crate) fn fido_status_check(
    msg_printer: Arc<dyn MessagePrinter>,
    presence_prompt: String,
) -> Sender<StatusUpdate> {
    spawn_fido_status_check(
        msg_printer,
        presence_prompt,
        Arc::new(AtomicBool::new(false)),
    )
    .0
}

fn spawn_fido_status_check(
    msg_printer: Arc<dyn MessagePrinter>,
    presence_prompt: String,
    cancelled: Arc<AtomicBool>,
) -> (Sender<StatusUpdate>, thread::JoinHandle<()>) {
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    let worker = thread::spawn(move || loop {
        if cancelled.load(Ordering::Acquire) {
            return;
        }
        match status_rx.recv_timeout(FIDO_INTERRUPT_POLL_INTERVAL) {
            Ok(StatusUpdate::InteractiveManagement(..)) => {
                error!("Fido STATUS: InteractiveManagement: This can't happen when doing non-interactive usage");
                break;
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                msg_printer.print_text(&tr("Please select a device by touching one of them."));
            }
            Ok(StatusUpdate::PresenceRequired) => {
                // "[FIDO_TOUCH] " prefix must match FIDO_TOUCH_PREFIX in qr-greeter extension.js
                msg_printer.print_text(&format!("[FIDO_TOUCH] {}", presence_prompt));
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender))) => {
                match msg_printer.prompt_echo_off(&(tr("Fido PIN:") + " ")) {
                    Some(pin) => {
                        if cancelled.load(Ordering::Acquire) {
                            break;
                        }
                        if let Err(e) = sender.send(Pin::new(&pin)) {
                            error!("Failed to send FIDO PIN: {:?}", e);
                            break;
                        }
                        continue;
                    }
                    None => {
                        break;
                    }
                }
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts))) => {
                let detail = attempts.map_or(tr("Try again."), |a| {
                    trn_fmt(
                        "You have {attempts} attempt left.",
                        "You have {attempts} attempts left.",
                        u32::from(a),
                        &[("attempts", a.to_string())],
                    )
                });
                let msg = tr_fmt("Wrong PIN! {message}", &[("message", detail)]);
                msg_printer.print_text(&msg);
                match msg_printer.prompt_echo_off(&(tr("Fido PIN:") + " ")) {
                    Some(pin) => {
                        if cancelled.load(Ordering::Acquire) {
                            break;
                        }
                        if let Err(e) = sender.send(Pin::new(&pin)) {
                            error!("Failed to send FIDO PIN: {:?}", e);
                            break;
                        }
                        continue;
                    }
                    None => {
                        break;
                    }
                }
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked)) => {
                msg_printer.print_error(&tr("Too many failed attempts in one row. Your device has been temporarily blocked. Please unplug it and plug in again."));
                break;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinBlocked)) => {
                msg_printer.print_error(&tr(
                    "Too many failed attempts. Your device has been blocked. Reset it.",
                ));
                break;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidUv(attempts))) => {
                let detail = attempts.map_or(tr("Try again."), |a| {
                    trn_fmt(
                        "You have {attempts} attempt left.",
                        "You have {attempts} attempts left.",
                        u32::from(a),
                        &[("attempts", a.to_string())],
                    )
                });
                let msg = tr_fmt("Wrong user verification! {message}", &[("message", detail)]);
                msg_printer.print_error(&msg);
                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::UvBlocked)) => {
                msg_printer.print_error(&tr("Too many failed user verification attempts."));
                break;
            }
            Ok(StatusUpdate::PinUvError(e)) => {
                let msg = tr_fmt(
                    "Unexpected error: {error}",
                    &[("error", format!("{:?}", e))],
                );
                msg_printer.print_error(&msg);
                break;
            }
            Ok(StatusUpdate::SelectResultNotice(_, _)) => {
                msg_printer.print_error(&tr("Unexpected select device notice"));
                break;
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                debug!("Fido STATUS: end");
                return;
            }
        }
    });
    (status_tx, worker)
}

struct FidoUsbSession {
    manager: AuthenticatorService,
    status: Sender<StatusUpdate>,
    worker: Option<thread::JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
    started: bool,
}

impl FidoUsbSession {
    fn new(
        manager: AuthenticatorService,
        msg_printer: Arc<dyn MessagePrinter>,
        presence_prompt: String,
    ) -> Self {
        let cancelled = Arc::new(AtomicBool::new(false));
        let (status, worker) =
            spawn_fido_status_check(msg_printer, presence_prompt, cancelled.clone());
        Self {
            manager,
            status,
            worker: Some(worker),
            cancelled,
            started: false,
        }
    }

    async fn sign(
        &mut self,
        timeout_ms: u64,
        args: SignArgs,
    ) -> Result<authenticator::SignResult, PamResultCode> {
        let (sign_tx, sign_rx) = channel();
        let cancelled = self.cancelled.clone();
        let callback = StateCallback::new(Box::new(move |rv| {
            if let Err(e) = sign_tx.send(rv) {
                if cancelled.load(Ordering::Acquire) {
                    debug!("Discarding cancelled FIDO assertion result");
                } else {
                    error!("Failed sending FIDO assertion result: {:?}", e);
                }
            }
        }));
        self.manager
            .sign(timeout_ms, args, self.status.clone(), callback)
            .map_err(|e| {
                error!("Failed to start USB FIDO authentication: {:?}", e);
                PamResultCode::PAM_CRED_INSUFFICIENT
            })?;
        self.started = true;
        receive_fido_result(sign_rx).await?.map_err(|e| {
            error!("USB FIDO authentication failed: {:?}", e);
            PamResultCode::PAM_CRED_INSUFFICIENT
        })
    }
}

impl Drop for FidoUsbSession {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if self.started {
            if let Err(e) = self.manager.cancel() {
                error!("Failed to cancel USB FIDO authentication: {:?}", e);
            }
        }
        // Finish all PAM callbacks before returning control to the PAM caller.
        if let Some(worker) = self.worker.take() {
            if let Err(e) = worker.join() {
                error!("FIDO status worker panicked: {:?}", e);
            }
        }
    }
}

async fn receive_fido_result<T>(receiver: Receiver<T>) -> Result<T, PamResultCode> {
    loop {
        match receiver.try_recv() {
            Ok(result) => return Ok(result),
            Err(TryRecvError::Empty) => {
                tokio::time::sleep(FIDO_INTERRUPT_POLL_INTERVAL).await;
            }
            Err(TryRecvError::Disconnected) => {
                error!("FIDO assertion result channel disconnected");
                return Err(PamResultCode::PAM_CRED_INSUFFICIENT);
            }
        }
    }
}

pub fn fido_auth(
    msg_printer: Arc<dyn MessagePrinter>,
    fido_challenge: String,
    fido_allow_list: Vec<String>,
    timeout_ms: u64,
    prompt: &str,
    presence_prompt: &str,
) -> Result<String, PamResultCode> {
    let rt = Runtime::new().map_err(|e| {
        error!("Failed to create FIDO runtime: {:?}", e);
        PamResultCode::PAM_AUTH_ERR
    })?;
    rt.block_on(wait_for_fido(
        fido_auth_inner(
            msg_printer,
            fido_challenge,
            fido_allow_list,
            timeout_ms,
            prompt,
            presence_prompt,
            None,
        ),
        timeout_ms,
    ))
}

async fn fido_auth_inner(
    msg_printer: Arc<dyn MessagePrinter>,
    fido_challenge: String,
    fido_allow_list: Vec<String>,
    timeout_ms: u64,
    prompt: &str,
    presence_prompt: &str,
    qr_suffix: Option<&str>,
) -> Result<String, PamResultCode> {
    // Send FIDO_INSERT prompt, optionally with QR data appended to avoid
    // multiple PAM conversation round-trips (GDM adds ~2.5s per call).
    let msg = match qr_suffix {
        Some(suffix) => format!("[FIDO_INSERT] {}\n{}", prompt, suffix),
        None => format!("[FIDO_INSERT] {}", prompt),
    };
    if qr_suffix.is_some() {
        msg_printer.print_sensitive(&msg);
    } else {
        msg_printer.print_text(&msg);
    }

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
    let mut session = FidoUsbSession::new(manager, msg_printer, presence_prompt.to_string());

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

    let assertion_result = session.sign(timeout_ms, ctap_args).await?;

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
    let result_str = json_to_string(&json_response).map_err(|e| {
        error!("{:?}", e);
        PamResultCode::PAM_CRED_INSUFFICIENT
    })?;
    Ok(result_str)
}

enum BluetoothState {
    PoweredOn,
    PoweredOff,
    NoAdapter,
}

fn check_fido_interrupt() -> Result<(), PamResultCode> {
    let mut pending = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // Observe, but do not consume, signals blocked by the PAM host (e.g. sudo).
    if unsafe { libc::sigpending(pending.as_mut_ptr()) } != 0 {
        error!(
            "Failed to inspect pending authentication signals: {}",
            io::Error::last_os_error()
        );
        return Err(PamResultCode::PAM_SYSTEM_ERR);
    }
    let pending = unsafe { pending.assume_init() };
    for signal in [libc::SIGINT, libc::SIGQUIT] {
        match unsafe { libc::sigismember(&pending, signal) } {
            1 => {
                debug!(
                    "FIDO authentication interrupted by pending signal {}",
                    signal
                );
                return Err(PamResultCode::PAM_ABORT);
            }
            0 => {}
            _ => {
                error!(
                    "Failed to inspect pending authentication signal: {}",
                    io::Error::last_os_error()
                );
                return Err(PamResultCode::PAM_SYSTEM_ERR);
            }
        }
    }
    Ok(())
}

// Poll directly on the PAM caller thread, where thread-directed signals are pending.
async fn wait_for_fido<T>(
    operation: impl Future<Output = Result<T, PamResultCode>>,
    timeout_ms: u64,
) -> Result<T, PamResultCode> {
    let mut poll = tokio::time::interval(FIDO_INTERRUPT_POLL_INTERVAL);
    let deadline = tokio::time::sleep(Duration::from_millis(timeout_ms));
    tokio::pin!(operation, deadline);
    loop {
        tokio::select! {
            biased;
            _ = poll.tick() => check_fido_interrupt()?,
            _ = &mut deadline => {
                error!("FIDO authentication timed out after {} ms", timeout_ms);
                return Err(PamResultCode::PAM_CRED_INSUFFICIENT);
            }
            result = &mut operation => {
                check_fido_interrupt()?;
                return result;
            }
        }
    }
}

async fn race_fido_transports<T>(
    usb: impl Future<Output = Result<T, PamResultCode>>,
    qr: impl Future<Output = Result<T, PamResultCode>>,
) -> Result<T, PamResultCode> {
    tokio::pin!(usb, qr);
    tokio::select! {
        result = &mut usb => match result {
            Ok(assertion) => Ok(assertion),
            Err(e) => {
                debug!("USB FIDO failed ({:?}), waiting for QR/Bluetooth", e);
                qr.await
            }
        },
        result = &mut qr => match result {
            Ok(assertion) => Ok(assertion),
            Err(e) => {
                debug!("QR/Bluetooth failed ({:?}), waiting for USB", e);
                usb.await
            }
        },
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FidoAuthMethod {
    Unavailable,
    SecurityKey,
    QrBluetooth,
    SecurityKeyAndQrBluetooth,
}

fn can_display_qr_bluetooth(service: &str, printer: &dyn MessagePrinter) -> bool {
    service.contains("gdm") || printer.supports_terminal_qr()
}

fn select_fido_auth_method(
    has_physical_security_key: bool,
    has_cross_device: bool,
    bluetooth: &BluetoothState,
    can_display_qr: bool,
) -> FidoAuthMethod {
    let can_qr =
        has_cross_device && matches!(bluetooth, BluetoothState::PoweredOn) && can_display_qr;
    match (has_physical_security_key, can_qr) {
        (true, true) => FidoAuthMethod::SecurityKeyAndQrBluetooth,
        (true, false) => FidoAuthMethod::SecurityKey,
        (false, true) => FidoAuthMethod::QrBluetooth,
        (false, false) => FidoAuthMethod::Unavailable,
    }
}

fn qr_bluetooth_message(
    printer: &dyn MessagePrinter,
    prompt: &str,
    qr_url: &str,
) -> Result<String, PamResultCode> {
    if !printer.supports_terminal_qr() {
        return Ok(format!("[QR_BT_LABEL] {}\n[QR_BT] {}", prompt, qr_url));
    }

    let qr = generate_unicode_qr(qr_url).map_err(|e| {
        error!("Failed to render QR/Bluetooth code: {}", e);
        printer.print_error(&tr("The QR/Bluetooth code could not be displayed."));
        PamResultCode::PAM_SYSTEM_ERR
    })?;
    let mut message = format!("{}\n", prompt);
    // Set both colors so the quiet zone stays white on dark terminal themes.
    for line in qr.lines() {
        message.push_str("\x1b[30;47m");
        message.push_str(line);
        message.push_str("\x1b[0m\n");
    }
    Ok(message)
}

fn check_bluetooth() -> BluetoothState {
    let conn = match zbus::blocking::Connection::system() {
        Ok(c) => c,
        Err(e) => {
            debug!("D-Bus system connection failed: {:?}", e);
            return BluetoothState::NoAdapter;
        }
    };

    let proxy = match zbus::blocking::fdo::ObjectManagerProxy::builder(&conn)
        .destination("org.bluez")
        .and_then(|b| b.path("/"))
        .and_then(|b| b.build())
    {
        Ok(p) => p,
        Err(e) => {
            debug!("BlueZ not available on D-Bus: {:?}", e);
            return BluetoothState::NoAdapter;
        }
    };

    let objects = match proxy.get_managed_objects() {
        Ok(o) => o,
        Err(e) => {
            debug!("BlueZ GetManagedObjects failed: {:?}", e);
            return BluetoothState::NoAdapter;
        }
    };

    let mut has_adapter = false;
    for (path, interfaces) in &objects {
        if let Some(props) = interfaces.get("org.bluez.Adapter1") {
            has_adapter = true;
            if let Some(powered) = props.get("Powered") {
                if bool::try_from(powered) == Ok(true) {
                    debug!("Bluetooth adapter {} is powered on", path);
                    return BluetoothState::PoweredOn;
                }
            }
        }
    }

    if has_adapter {
        debug!("All Bluetooth adapters are powered off");
        BluetoothState::PoweredOff
    } else {
        debug!("No Bluetooth adapters found");
        BluetoothState::NoAdapter
    }
}

/// Caller must verify Bluetooth is powered on before calling this.
async fn qr_bluetooth_fido_auth(
    msg_printer: Arc<dyn MessagePrinter>,
    fido_challenge: String,
    _fido_allow_list: Vec<String>,
    qr_prompt: &str,
    device: Option<CableQrCodeDevice>,
) -> Result<String, PamResultCode> {
    let mut device = match device {
        Some(d) => d,
        None => {
            let d = CableQrCodeDevice::new_transient(
                QrCodeOperationHint::GetAssertionRequest,
                CableTransports::CloudAssistedOnly,
            )
            .map_err(|e| {
                error!("Failed to create QR/Bluetooth device: {:?}", e);
                PamResultCode::PAM_CRED_INSUFFICIENT
            })?;
            let qr_url = d.qr_code.to_string();
            // Combine into one message to avoid GDM per-message delay.
            let message = qr_bluetooth_message(msg_printer.as_ref(), qr_prompt, &qr_url)?;
            msg_printer.print_sensitive(&message);
            d
        }
    };

    // Channel creation starts the connection task; the caller bounds the
    // scan/handshake and assertion together with wait_for_fido.
    let mut channel = device
        .channel(ChannelSettings::default())
        .await
        .map_err(|e| {
            error!("QR/Bluetooth channel establishment failed: {:?}", e);
            PamResultCode::PAM_CRED_INSUFFICIENT
        })?;

    // Empty allowList forces the phone to use a discoverable credential,
    // which includes userHandle (required by Entra to identify the user).
    let request = GetAssertionRequest {
        relying_party_id: "login.microsoft.com".to_string(),
        challenge: fido_challenge.as_bytes().to_vec(),
        origin: "https://login.microsoft.com".to_string(),
        top_origin: None,
        allow: vec![],
        extensions: None,
        user_verification: CableUvReq::Preferred,
        timeout: Duration::from_secs(120),
    };

    // Send the challenge to the phone over the BLE tunnel; the phone
    // prompts for biometrics/PIN, signs, and returns the assertion.
    let response = channel
        .webauthn_get_assertion(&request)
        .await
        .map_err(|e| {
            error!("QR/Bluetooth assertion failed: {:?}", e);
            PamResultCode::PAM_CRED_INSUFFICIENT
        })?;

    let assertion = response
        .assertions
        .first()
        .ok_or(PamResultCode::PAM_CRED_INSUFFICIENT)?;

    // Package the assertion into the same base64url JSON format that
    // a local USB security key would produce, so Entra can verify it.
    let credential_id = assertion
        .credential_id
        .as_ref()
        .map(|c| c.id.to_vec())
        .unwrap_or_default();
    let auth_data = assertion
        .authenticator_data
        .to_response_bytes()
        .map_err(|e| {
            error!("Failed to serialize authenticator data: {:?}", e);
            PamResultCode::PAM_CRED_INSUFFICIENT
        })?;
    let signature = &assertion.signature;
    let user_handle = assertion
        .user
        .as_ref()
        .map(|u| u.id.to_vec())
        .unwrap_or_default();

    let json_response = json!({
        "id": URL_SAFE_NO_PAD.encode(&credential_id),
        "clientDataJSON": URL_SAFE_NO_PAD.encode(request.client_data_json()),
        "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
        "signature": URL_SAFE_NO_PAD.encode(signature),
        "userHandle": URL_SAFE_NO_PAD.encode(&user_handle),
    });

    let result_str = json_to_string(&json_response).map_err(|e| {
        error!("{:?}", e);
        PamResultCode::PAM_CRED_INSUFFICIENT
    })?;
    Ok(result_str)
}

/// Race USB security key and QR/Bluetooth auth; cancel the losing transport.
pub fn fido_auth_with_qr_bluetooth(
    msg_printer: &Arc<dyn MessagePrinter>,
    fido_challenge: String,
    fido_allow_list: Vec<String>,
    timeout_ms: u64,
    prompt: &str,
    presence_prompt: &str,
    qr_prompt: &str,
) -> Result<String, PamResultCode> {
    let rt = Runtime::new().map_err(|e| {
        error!("{:?}", e);
        PamResultCode::PAM_AUTH_ERR
    })?;

    // Create caBLE device upfront so we can send all PAM messages
    // (FIDO_INSERT + QR_BT_LABEL + QR_BT) in a single print_text call
    // from within fido_auth. This avoids concurrent PAM conversation
    // calls that block each other for ~2.5s each in GDM.
    let cable_device = CableQrCodeDevice::new_transient(
        QrCodeOperationHint::GetAssertionRequest,
        CableTransports::CloudAssistedOnly,
    )
    .map_err(|e| {
        error!("Failed to create QR/Bluetooth device: {:?}", e);
        PamResultCode::PAM_CRED_INSUFFICIENT
    })?;
    let qr_url = cable_device.qr_code.to_string();
    let qr_suffix = qr_bluetooth_message(msg_printer.as_ref(), qr_prompt, &qr_url)?;

    rt.block_on(wait_for_fido(
        race_fido_transports(
            fido_auth_inner(
                msg_printer.clone(),
                fido_challenge.clone(),
                fido_allow_list.clone(),
                timeout_ms,
                prompt,
                presence_prompt,
                Some(&qr_suffix),
            ),
            qr_bluetooth_fido_auth(
                msg_printer.clone(),
                fido_challenge,
                fido_allow_list,
                "",
                Some(cable_device),
            ),
        ),
        timeout_ms,
    ))
}

#[macro_export]
macro_rules! pam_fail {
    ($msg_printer:expr, $msg:expr, $ret:expr) => {{
        $msg_printer.print_text(&$crate::i18n::tr_fmt(
            "{code}: {message}\nIf you are now prompted for a password from pam_unix, please disregard the prompt, go back and try again.",
            &[
                ("code", format!("{:?}", $ret)),
                ("message", $crate::i18n::translate_external_message(&$msg)),
            ],
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
                Err(tr("Failed to generate QR code"))
            }
        },
        None => {
            debug!("Failed to capture parameter from TOTP url");
            Err(tr("Failed to generate QR code"))
        }
    }
}

fn hello_totp_enroll_fallback_msg(url: &str) -> Result<String, String> {
    let totp_regex = Regex::new(r"otpauth://([ht]otp)/([^:?]+):?([^\?]+)\?secret=([0-9A-Za-z]+)(?:.*(?:<?counter=)([0-9]+))?").map_err(|e| {
        debug!(?e, "Failed to build regex");
        tr_fmt("Failed to build regex: {error}", &[("error", e.to_string())])
    })?;

    match totp_regex.captures(url) {
        Some(cap) => {
            let secret = match cap.get(4) {
                Some(c) => Ok(c.as_str().to_string()),
                None => {
                    debug!("Failed to capture secret from TOTP url {}", url);
                    Err(tr("Failed to generate QR code"))
                }
            }?;
            let issuer = hello_totp_urldecode_match(cap.get(2))?;
            let acct = hello_totp_urldecode_match(cap.get(3))?;
            let fallback_msg = tr_fmt(
                "Enter the setup key '{secret}' to enroll a TOTP Authenticator app. Use '{issuer}' for the code name and '{account}' as the label/name.",
                &[
                    ("secret", secret),
                    ("issuer", issuer),
                    ("account", acct),
                ],
            );
            Ok(fallback_msg)
        }
        None => {
            debug!("Failed to parse TOTP url {}", url);
            Err(tr("Failed to generate QR code"))
        }
    }
}

fn hello_totp_enroll_qr_msg(url: &str, qr: &str) -> Result<String, String> {
    let fallback_msg = hello_totp_enroll_fallback_msg(url)?;
    Ok(tr_fmt(
        "Open your authenticator app and scan this QR code to enroll. Then enter the generated code.\n{qr}",
        &[("qr", format!("{qr}\n{fallback_msg}"))],
    ))
}

fn handle_pam_auth_response_mfapoll(
    state: &mut AuthenticateState,
    msg: &str,
    polling_interval: u32,
    show_push_hint: bool,
) -> PamWhatNext {
    let msg = format_mfa_poll_message(msg, &state.service, show_push_hint);
    if !msg.trim().is_empty() {
        state.msg_printer.print_text(&msg);
    }

    // Necessary because of OpenSSH bug
    // https://bugzilla.mindrot.org/show_bug.cgi?id=2876 -
    // PAM_TEXT_INFO and PAM_ERROR_MSG conversation not
    // honoured during PAM authentication. Some other PAM consumers, such as
    // Cockpit, also need an input prompt before they display the message.
    if should_prompt_mfa_poll(&state.service, &state.opts, &state.cfg, &msg) {
        state
            .msg_printer
            .prompt_echo_off(&tr("Press enter to continue"));
    }

    // Do not allow concurrent MFA polling
    if state.poll_attempt >= 0 {
        error!("MFA poll already in progress");
        pam_fail!(
            state.msg_printer,
            tr("Unexpected error occurred."),
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

fn format_mfa_poll_message(msg: &str, service: &str, show_push_hint: bool) -> String {
    if show_push_hint && !msg.trim().is_empty() {
        tr_fmt(
            "{message}\nNo push? Check your mobile device's internet connection.",
            &[("message", i18n::translate_external_message(msg))],
        )
    } else if service != "gdm-password" && service != "broker-interactive" {
        // GDM renders its own QR; broker-interactive uses pinentry, which
        // panics on long Assuan payloads if we append unicode QR art.
        lazy_static! {
            // Avoid compiling a new Regex every time with a lazy_static ref
            static ref RE: Option<Regex> =
                Regex::new(r#"(?i)\bhttps?://[^\s<>"']+[^\s<>"'\]\[)\(\}\{.,;:!?]"#).ok();
        }
        // In case of any failure matching for URLs or generating the QR the
        // plain message will be returned
        if let Some(qr) = RE
            .as_ref()
            .and_then(|re| {
                re.captures(msg)
                    .and_then(|cap| cap.get(0).map(|x| x.as_str()))
            })
            .and_then(|url| generate_unicode_qr(url).ok())
        {
            format!("{}\n{}", i18n::translate_external_message(msg), qr)
        } else {
            i18n::translate_external_message(msg)
        }
    } else {
        i18n::translate_external_message(msg)
    }
}

fn handle_pam_auth_response_mfapollwait(state: &mut AuthenticateState) -> PamWhatNext {
    let next_poll_attempt = if state.poll_attempt < 0 {
        debug!("MFAPollWait received before MFAPoll; starting polling loop from attempt 0");
        0
    } else {
        state.poll_attempt + 1
    };

    // Continue polling if the daemon says to wait
    thread::sleep(Duration::from_secs(state.polling_interval.into()));

    state.poll_attempt = next_poll_attempt;
    let req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFAPoll {
        poll_attempt: state.poll_attempt as u32,
    });
    PamWhatNext::Next(req)
}

fn should_prompt_mfa_poll(
    service: &str,
    opts: &Options,
    cfg: &HimmelblauConfig,
    msg: &str,
) -> bool {
    opts.mfa_poll_prompt
        && !msg.trim().is_empty()
        && cfg
            .get_mfa_poll_prompt_services()
            .iter()
            .any(|s| service.contains(s))
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
        state.opts.force_reauth,
    );
    PamWhatNext::Next(req)
}

fn handle_pam_auth_response_password(
    state: &mut AuthenticateState,
    prompt: Option<&str>,
    long_prompt: Option<&str>,
) -> PamWhatNext {
    let mut consume_authtok = None;
    // Swap the authtok out with a None, so it can only be consumed once.
    // If it's already been swapped, we are just swapping two null pointers
    // here effectively.
    std::mem::swap(&mut state.authtok, &mut consume_authtok);
    let cred = if let Some(cred) = consume_authtok {
        cred
    } else {
        let fold = state.opts.no_info_prompt;
        let long_prompt = long_prompt.filter(|prompt| !prompt.trim().is_empty());

        // The info text is normally sent as a standalone PAM_TEXT_INFO before the
        // prompt. With no_info_prompt it is folded into the single password prompt
        // instead, for PAM clients that cannot carry a separate info message during
        // authentication (e.g. MariaDB's auth_pam dialog).
        if !fold {
            if let Some(long_prompt) = long_prompt {
                state.msg_printer.print_text(long_prompt);
            }
        }

        let prompt = match prompt.filter(|prompt| !prompt.trim().is_empty()) {
            Some(prompt) => i18n::translate_external_message(prompt),
            None if state.cfg.get_oidc_issuer_url().is_some() => tr("Cloud Password:"),
            None => {
                let info =
                    i18n::translate_external_message(&state.cfg.get_entra_id_password_prompt());
                if fold {
                    format!("{}\n{}", info, tr("Entra Id Password:"))
                } else {
                    state.msg_printer.print_text(&info);
                    tr("Entra Id Password:")
                }
            }
        };
        let prompt = match (fold, long_prompt) {
            (true, Some(long_prompt)) => format!("{}\n{}", long_prompt, prompt),
            _ => prompt,
        };
        match state.msg_printer.prompt_echo_off(&prompt) {
            Some(cred) => cred,
            None => {
                debug!("no password");
                pam_fail!(
                    state.msg_printer,
                    tr("No Entra Id password was supplied."),
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
        }
    };

    // Now setup the request for the next loop.
    let req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password { cred });
    PamWhatNext::Next(req)
}

fn handle_pam_auth_response_input(
    state: &AuthenticateState,
    msg: &str,
    echo_on: bool,
) -> PamWhatNext {
    state
        .msg_printer
        .print_text(&i18n::translate_external_message(msg));
    let cred = match if echo_on {
        state.msg_printer.prompt_echo_on(&(tr("Value:") + " "))
    } else {
        state.msg_printer.prompt_echo_off(&(tr("Code:") + " "))
    } {
        Some(cred) => cred,
        None => {
            debug!("no input");
            pam_fail!(
                state.msg_printer,
                tr("No input was supplied."),
                PamResultCode::PAM_CRED_INSUFFICIENT
            );
        }
    };

    // Now setup the request for the next loop.
    let req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Input { cred });
    PamWhatNext::Next(req)
}

pub(crate) fn generate_unicode_qr(content: &str) -> Result<String, String> {
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
    // Broker pinentry cannot display unicode QR art (Assuan line-length panic).
    // Otherwise render with unicode chars.
    if msg.starts_with("otpauth://")
        && state.service != "gdm-password"
        && state.service != "broker-interactive"
    {
        match generate_unicode_qr(msg) {
            Ok(qr) => match hello_totp_enroll_qr_msg(msg, &qr) {
                Ok(msg) => state.msg_printer.print_text(&msg),
                Err(msg) => {
                    pam_fail!(state.msg_printer, msg, PamResultCode::PAM_SYSTEM_ERR);
                }
            },
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
        state
            .msg_printer
            .print_text(&i18n::translate_external_message(msg));
    };

    let cred = match state.msg_printer.prompt_echo_off(&(tr("TOTP Code:") + " ")) {
        Some(cred) => cred,
        None => {
            debug!("no hello totp code");
            pam_fail!(
                state.msg_printer,
                tr("No Hello TOTP code was supplied."),
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
        "{}\n{}",
        i18n::translate_external_message(msg),
        tr_fmt(
            "The minimum PIN length is {length} characters.",
            &[("length", state.cfg.get_hello_pin_min_length().to_string())]
        )
    );

    let mut pin;
    let mut confirm;
    loop {
        state.msg_printer.print_text(&msg);
        pin = match state.msg_printer.prompt_echo_off(&(tr("New PIN:") + " ")) {
            Some(cred) => {
                if cred.len() < state.cfg.get_hello_pin_min_length() {
                    state.msg_printer.print_text(&tr_fmt(
                        "Chosen pin is too short! {length} chars required.",
                        &[("length", state.cfg.get_hello_pin_min_length().to_string())],
                    ));
                    thread::sleep(Duration::from_secs(2));
                    continue;
                } else if is_simple_pin(&cred) {
                    state.msg_printer.print_text(&tr("PIN must not use repeating or predictable sequences. Avoid patterns like '111111', '123456', or '135791'."));
                    thread::sleep(Duration::from_secs(2));
                    continue;
                } else if let Err(msg) = meets_intune_pin_policy(&cred) {
                    state
                        .msg_printer
                        .print_text(&i18n::translate_external_message(&msg));
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
                cred
            }
            None => {
                debug!("no pin");
                pam_fail!(
                    state.msg_printer,
                    tr("No Entra Id Hello PIN was supplied."),
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
        };

        state.msg_printer.print_text(&msg);

        confirm = match state
            .msg_printer
            .prompt_echo_off(&(tr("Confirm PIN:") + " "))
        {
            Some(cred) => cred,
            None => {
                debug!("no confirmation pin");
                pam_fail!(
                    state.msg_printer,
                    tr("No Entra Id Hello confirmation PIN was supplied."),
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
        };

        if pin == confirm {
            break;
        } else {
            state
                .msg_printer
                .print_text(&tr("Inputs did not match. Try again."));
            thread::sleep(Duration::from_secs(2));
        }
    }

    state
        .msg_printer
        .print_text(&tr("Enrolling the Hello PIN. Please wait..."));

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
            .print_text(&i18n::translate_external_message(
                &state.cfg.get_hello_pin_prompt(),
            ));
        match state.msg_printer.prompt_echo_off(&(tr("PIN:") + " ")) {
            Some(cred) if !cred.is_empty() => cred,
            None => {
                debug!("no pin");
                pam_fail!(
                    state.msg_printer,
                    tr("No Entra Id Hello PIN was supplied."),
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
            Some(_) => {
                debug!("empty pin");
                pam_fail!(
                    state.msg_printer,
                    tr("No Entra Id Hello PIN was supplied."),
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
        }
    };

    // Now setup the request for the next loop.
    let req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Pin { cred });
    PamWhatNext::Next(req)
}

fn fido_auth_qr_bluetooth_only(
    msg_printer: Arc<dyn MessagePrinter>,
    fido_challenge: String,
    fido_allow_list: Vec<String>,
    qr_prompt: &str,
    timeout_ms: u64,
) -> Result<String, PamResultCode> {
    let rt = Runtime::new().map_err(|e| {
        error!("{:?}", e);
        PamResultCode::PAM_AUTH_ERR
    })?;
    rt.block_on(wait_for_fido(
        qr_bluetooth_fido_auth(
            msg_printer,
            fido_challenge,
            fido_allow_list,
            qr_prompt,
            None,
        ),
        timeout_ms,
    ))
}

fn handle_pam_auth_response_fido(
    state: &AuthenticateState,
    fido_challenge: String,
    fido_allow_list: Vec<String>,
    has_physical_security_key: bool,
    has_cross_device: bool,
) -> PamWhatNext {
    let timeout_ms = state.cfg.get_fido_timeout().saturating_mul(1000);
    let fido_prompt = state.cfg.get_fido_prompt();
    let fido_presence_prompt = state.cfg.get_fido_presence_prompt();
    let qr_prompt = state.cfg.get_qr_bluetooth_prompt();
    let can_display_qr = can_display_qr_bluetooth(&state.service, state.msg_printer.as_ref());
    let mut bt_state = check_bluetooth();
    debug!(
        "FIDO auth: has_physical_security_key={}, has_cross_device={}, can_display_qr={}, has_bluetooth={}",
        has_physical_security_key,
        has_cross_device,
        can_display_qr,
        matches!(bt_state, BluetoothState::PoweredOn)
    );

    if !has_physical_security_key
        && has_cross_device
        && can_display_qr
        && matches!(bt_state, BluetoothState::PoweredOff)
    {
        state
            .msg_printer
            .print_text(&tr("Enable Bluetooth to sign in with your phone."));
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            bt_state = check_bluetooth();
            if matches!(bt_state, BluetoothState::PoweredOn) {
                break;
            }
        }
    }

    let result = match select_fido_auth_method(
        has_physical_security_key,
        has_cross_device,
        &bt_state,
        can_display_qr,
    ) {
        FidoAuthMethod::Unavailable => {
            debug!("FIDO auth: no usable FIDO transport, requesting fallback to password");
            return PamWhatNext::Next(ClientRequest::PamAuthenticateStep(
                PamAuthRequest::FidoUnavailable,
            ));
        }
        FidoAuthMethod::SecurityKeyAndQrBluetooth => {
            debug!("FIDO auth: attempting both security key and QR/Bluetooth");
            match fido_auth_with_qr_bluetooth(
                &state.msg_printer,
                fido_challenge,
                fido_allow_list,
                timeout_ms,
                &fido_prompt,
                &fido_presence_prompt,
                &qr_prompt,
            ) {
                Ok(assertion) => assertion,
                Err(PamResultCode::PAM_ABORT) => {
                    return PamWhatNext::Finish(PamResultCode::PAM_ABORT);
                }
                Err(e) => {
                    pam_fail!(
                        state.msg_printer,
                        tr("Security key and QR/Bluetooth authentication failed."),
                        e
                    );
                }
            }
        }
        FidoAuthMethod::QrBluetooth => {
            debug!("FIDO auth: attempting QR/Bluetooth");
            match fido_auth_qr_bluetooth_only(
                state.msg_printer.clone(),
                fido_challenge,
                fido_allow_list,
                &qr_prompt,
                timeout_ms,
            ) {
                Ok(assertion) => assertion,
                Err(PamResultCode::PAM_ABORT) => {
                    return PamWhatNext::Finish(PamResultCode::PAM_ABORT);
                }
                Err(e) => {
                    pam_fail!(
                        state.msg_printer,
                        tr("QR/Bluetooth authentication failed."),
                        e
                    );
                }
            }
        }
        FidoAuthMethod::SecurityKey => {
            debug!("FIDO auth: attempting security key");
            match fido_auth(
                state.msg_printer.clone(),
                fido_challenge,
                fido_allow_list,
                timeout_ms,
                &fido_prompt,
                &fido_presence_prompt,
            ) {
                Ok(assertion) => assertion,
                Err(PamResultCode::PAM_ABORT) => {
                    return PamWhatNext::Finish(PamResultCode::PAM_ABORT);
                }
                Err(e) => {
                    pam_fail!(
                        state.msg_printer,
                        tr("Security key authentication failed."),
                        e
                    );
                }
            }
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
        state
            .msg_printer
            .print_text(&i18n::translate_external_message(msg));
        password = match state
            .msg_printer
            .prompt_echo_off(&(tr("New password:") + " "))
        {
            Some(cred) => {
                // Entra Id requires a minimum password length of 8 characters
                if cred.len() < 8 {
                    state
                        .msg_printer
                        .print_text(&tr("Chosen password is too short! 8 chars required."));
                    continue;
                }
                cred
            }
            None => {
                debug!("no password");
                pam_fail!(
                    state.msg_printer,
                    tr("No Entra Id password was supplied."),
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
        };

        state
            .msg_printer
            .print_text(&i18n::translate_external_message(msg));

        confirm = match state
            .msg_printer
            .prompt_echo_off(&(tr("Confirm password:") + " "))
        {
            Some(cred) => cred,
            None => {
                debug!("no confirmation password");
                pam_fail!(
                    state.msg_printer,
                    tr("No Entra Id confirmation password was supplied."),
                    PamResultCode::PAM_CRED_INSUFFICIENT
                );
            }
        };

        if password == confirm {
            break;
        } else {
            state
                .msg_printer
                .print_text(&tr("Inputs did not match. Try again."));
            thread::sleep(Duration::from_secs(2));
        }
    }

    state
        .msg_printer
        .print_text(&tr("Changing the password. Please wait..."));

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
                tr("An unexpected error occurred."),
                PamResultCode::PAM_IGNORE
            );
        }
    };

    let response = match cli_res {
        ClientResponse::PamAuthenticateStepResponse(res) => res.translate_user_visible(),
        _ => {
            // unexpected response.
            error!(err = ?cli_res, "PAM_IGNORE, unexpected resolver response");
            pam_fail!(
                state.msg_printer,
                tr("An unexpected error occurred."),
                PamResultCode::PAM_IGNORE
            );
        }
    };

    let enrollment = match &response {
        PamAuthResponse::Input { enrollment, .. }
        | PamAuthResponse::MFAPoll { enrollment, .. }
        | PamAuthResponse::WebAuthn { enrollment, .. } => enrollment.as_ref(),
        _ => None,
    };
    if !matches!(response, PamAuthResponse::MFAPollWait) {
        let qr_emitted = if let Some(enrollment) = enrollment {
            match crate::enrollment::present(state.msg_printer.as_ref(), &state.service, enrollment)
            {
                Ok(active) => active,
                Err(message) => {
                    state.clear_enrollment_qr();
                    pam_fail!(state.msg_printer, message, PamResultCode::PAM_AUTH_ERR);
                }
            }
        } else {
            false
        };
        if qr_emitted {
            state.enrollment_qr_active = true;
        } else {
            state.clear_enrollment_qr();
        }
    }
    if !matches!(
        response,
        PamAuthResponse::MFAPoll { .. } | PamAuthResponse::MFAPollWait
    ) {
        state.poll_attempt = -1;
    }
    match response {
        PamAuthResponse::Unknown => handle_pam_auth_response_unknown(state),
        PamAuthResponse::Success => handle_pam_auth_response_success(),
        PamAuthResponse::Denied(msg) => handle_pam_auth_response_denied(state, &msg),
        PamAuthResponse::InitDenied { msg } => handle_pam_auth_init_denied(state, &msg),
        PamAuthResponse::Password {
            prompt,
            long_prompt,
        } => handle_pam_auth_response_password(state, prompt.as_deref(), long_prompt.as_deref()),
        PamAuthResponse::Input {
            enrollment: _,
            msg,
            echo_on,
        } => handle_pam_auth_response_input(state, &msg, echo_on),
        PamAuthResponse::HelloTOTP { msg } => handle_pam_auth_response_hellototp(state, &msg),
        PamAuthResponse::MFAPoll {
            enrollment: _,
            msg,
            polling_interval,
            show_push_hint,
        } => handle_pam_auth_response_mfapoll(state, &msg, polling_interval, show_push_hint),
        PamAuthResponse::MFAPollWait => handle_pam_auth_response_mfapollwait(state),
        PamAuthResponse::SetupPin { msg } => handle_pam_auth_response_setup_pin(state, &msg),
        PamAuthResponse::Pin => handle_pam_auth_response_pin(state),
        PamAuthResponse::WebAuthn {
            enrollment: _,
            operation,
            origin,
            options,
        } => {
            let result = crate::webauthn::perform(
                state.msg_printer.clone(),
                operation,
                &origin,
                &options,
                state.cfg.get_fido_timeout().saturating_mul(1000),
            );
            let request = match result {
                Ok(response) => PamAuthRequest::WebAuthn { response },
                Err(()) => {
                    state.msg_printer.print_error(&tr(
                        "Security key operation unavailable. Choose another method or try again.",
                    ));
                    PamAuthRequest::WebAuthnUnavailable
                }
            };
            PamWhatNext::Next(ClientRequest::PamAuthenticateStep(request))
        }
        PamAuthResponse::Fido {
            fido_challenge,
            fido_allow_list,
            has_physical_security_key,
            has_cross_device,
        } => handle_pam_auth_response_fido(
            state,
            fido_challenge,
            fido_allow_list,
            has_physical_security_key,
            has_cross_device,
        ),
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
    enrollment_qr_active: bool,
}

impl AuthenticateState {
    fn clear_enrollment_qr(&mut self) {
        // The empty marker is a greeter command, not a user-facing message.
        // Ordinary logins (including local-user fallthrough) never need it.
        if self.enrollment_qr_active {
            self.msg_printer.print_sensitive("[OIDC_ENROLL_QR]");
            self.enrollment_qr_active = false;
        }
    }
}

fn daemon_connect_error_is_retryable(err: &io::Error) -> bool {
    if matches!(
        err.kind(),
        ErrorKind::NotFound
            | ErrorKind::ConnectionRefused
            | ErrorKind::TimedOut
            | ErrorKind::WouldBlock
            | ErrorKind::Interrupted
    ) {
        return true;
    }

    matches!(
        err.raw_os_error(),
        Some(libc::ENOENT | libc::ECONNREFUSED | libc::ETIMEDOUT | libc::EAGAIN | libc::EINTR)
    )
}

fn wait_for_daemon_client_with<T, F, S>(
    path: &str,
    msg_printer: &dyn MessagePrinter,
    timeout: Duration,
    interval: Duration,
    mut connect: F,
    mut sleep: S,
) -> Result<T, PamResultCode>
where
    F: FnMut(&str) -> io::Result<T>,
    S: FnMut(Duration),
{
    let started = Instant::now();
    let mut announced = false;

    loop {
        match connect(path) {
            Ok(client) => return Ok(client),
            Err(err) => {
                if !daemon_connect_error_is_retryable(&err) {
                    error!(?err, "himmelblaud socket connection failed");
                    msg_printer
                        .print_error(&tr("Himmelblau authentication service is unavailable."));
                    return Err(PamResultCode::PAM_IGNORE);
                }

                if !announced {
                    msg_printer
                        .print_text(&tr("Himmelblau authentication is starting, please wait..."));
                    announced = true;
                }

                let elapsed = started.elapsed();
                if elapsed >= timeout {
                    error!(?err, "timed out waiting for himmelblaud socket");
                    msg_printer.print_error(&tr(
                        "Himmelblau authentication service did not become available in time.",
                    ));
                    return Err(PamResultCode::PAM_IGNORE);
                }

                let remaining = timeout.saturating_sub(elapsed);
                sleep(std::cmp::min(interval, remaining));
            }
        }
    }
}

pub fn wait_for_daemon_client(
    path: &str,
    msg_printer: &Arc<dyn MessagePrinter>,
) -> Result<DaemonClientBlocking, PamResultCode> {
    wait_for_daemon_client_with(
        path,
        msg_printer.as_ref(),
        DAEMON_START_WAIT_TIMEOUT,
        DAEMON_START_WAIT_INTERVAL,
        DaemonClientBlocking::new,
        thread::sleep,
    )
}

pub fn authenticate_with_client(
    daemon_client: DaemonClientBlocking,
    authtok: Option<String>,
    cfg: HimmelblauConfig,
    account_id: &str,
    service: &str,
    opts: Options,
    msg_printer: Arc<dyn MessagePrinter>,
) -> PamResultCode {
    i18n::init();
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
        enrollment_qr_active: false,
    };

    // This is the initial request to the daemon
    let mut req = ClientRequest::PamAuthenticateInit(
        state.account_id.to_owned(),
        state.service.to_owned(),
        state.opts.no_hello_pin,
        state.opts.force_reauth,
    );

    loop {
        let res = authenticate_request_response(&mut state, &req);
        match res {
            PamWhatNext::Next(next_request) => req = next_request,
            PamWhatNext::Finish(pam_result_code) => {
                state.clear_enrollment_qr();
                return pam_result_code;
            }
        }
    }
}

pub fn authenticate(
    authtok: Option<String>,
    cfg: HimmelblauConfig,
    account_id: &str,
    service: &str,
    opts: Options,
    msg_printer: Arc<dyn MessagePrinter>,
) -> PamResultCode {
    i18n::init();
    let daemon_client = match wait_for_daemon_client(cfg.get_socket_path().as_str(), &msg_printer) {
        Ok(dc) => dc,
        Err(code) => return code,
    };

    authenticate_with_client(
        daemon_client,
        authtok,
        cfg,
        account_id,
        service,
        opts,
        msg_printer,
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Error as IoError;
    use std::sync::Mutex;

    fn create_temp_config(contents: &str) -> String {
        let file_path = format!(
            "/tmp/himmelblau_auth_test_config_{}.ini",
            uuid::Uuid::new_v4()
        );
        fs::write(&file_path, contents).expect("Failed to write temporary config file");
        file_path
    }

    fn test_config(contents: &str) -> HimmelblauConfig {
        let temp_file = create_temp_config(contents);
        HimmelblauConfig::new(Some(&temp_file)).unwrap()
    }

    fn test_options(mfa_poll_prompt: bool) -> Options {
        Options {
            mfa_poll_prompt,
            ..Default::default()
        }
    }

    #[derive(Default)]
    struct RecordingPrinter {
        text: Mutex<Vec<String>>,
        error: Mutex<Vec<String>>,
        prompts: Mutex<Vec<String>>,
    }

    impl MessagePrinter for RecordingPrinter {
        fn print_text(&self, msg: &str) {
            self.text.lock().unwrap().push(msg.to_string());
        }

        fn print_error(&self, msg: &str) {
            self.error.lock().unwrap().push(msg.to_string());
        }

        fn prompt_echo_on(&self, prompt: &str) -> Option<String> {
            self.prompts.lock().unwrap().push(prompt.to_string());
            None
        }

        fn prompt_echo_off(&self, prompt: &str) -> Option<String> {
            self.prompts.lock().unwrap().push(prompt.to_string());
            Some("hunter2".to_string())
        }
    }

    #[test]
    fn qr_bluetooth_gdm_message_is_unchanged() -> Result<(), PamResultCode> {
        let message = qr_bluetooth_message(
            &RecordingPrinter::default(),
            "Scan with your phone",
            "FIDO:/1234567890",
        )?;
        assert_eq!(
            message,
            "[QR_BT_LABEL] Scan with your phone\n[QR_BT] FIDO:/1234567890"
        );
        Ok(())
    }

    #[test]
    fn qr_bluetooth_terminal_message_round_trips_real_cable_payload(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let device = CableQrCodeDevice::new_transient(
            QrCodeOperationHint::GetAssertionRequest,
            CableTransports::CloudAssistedOnly,
        )?;
        let payload = device.qr_code.to_string();
        assert!(payload.starts_with("FIDO:/"));
        let message = qr_bluetooth_message(
            &SimpleMessagePrinter::default(),
            "Scan with your phone",
            &payload,
        )
        .map_err(|e| format!("QR presentation failed: {e:?}"))?;
        assert!(!message.contains("[QR_BT"));
        assert!(!message.contains(&payload));
        let qr = message
            .strip_prefix("Scan with your phone\n")
            .ok_or("missing QR prompt")?;
        let lines: Vec<Vec<char>> = qr
            .lines()
            .map(|line| {
                line.strip_prefix("\x1b[30;47m")
                    .and_then(|line| line.strip_suffix("\x1b[0m"))
                    .map(|line| line.chars().collect())
                    .ok_or("missing explicit black-on-white colors")
            })
            .collect::<Result<_, _>>()?;
        let width = lines.first().ok_or("missing QR pixels")?.len();
        assert!(lines.iter().all(|line| line.len() == width));
        assert!(lines.iter().all(|line| line
            .iter()
            .all(|ch| matches!(ch, ' ' | '\u{2588}' | '\u{2580}' | '\u{2584}'))));
        assert!(lines[..2].iter().flatten().all(|ch| *ch == ' '));
        assert!(lines.iter().all(|line| line[..4]
            .iter()
            .chain(&line[width - 4..])
            .all(|ch| *ch == ' ')));
        let image = image::GrayImage::from_fn(width as u32 * 4, lines.len() as u32 * 8, |x, y| {
            let dark = match lines[y as usize / 8][x as usize / 4] {
                '\u{2588}' => true,
                '\u{2580}' => y % 8 < 4,
                '\u{2584}' => y % 8 >= 4,
                _ => false,
            };
            image::Luma([if dark { 0 } else { 255 }])
        });
        let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(
            image.width() as usize,
            image.height() as usize,
            |x, y| image.get_pixel(x as u32, y as u32).0[0],
        );
        let grids = prepared.detect_grids();
        assert_eq!(grids.len(), 1);
        assert_eq!(grids[0].decode()?.1, payload);
        Ok(())
    }

    fn retryable_connect_error() -> io::Error {
        IoError::new(ErrorKind::NotFound, "missing socket")
    }

    #[test]
    fn test_wait_for_daemon_client_immediate_success_has_no_message() {
        let printer = RecordingPrinter::default();
        let mut attempts = 0;

        let result = wait_for_daemon_client_with(
            "/run/himmelblaud/socket",
            &printer,
            Duration::from_secs(20),
            Duration::from_millis(250),
            |_| {
                attempts += 1;
                Ok("connected")
            },
            |_| panic!("sleep should not be called"),
        );

        assert_eq!(result.unwrap(), "connected");
        assert_eq!(attempts, 1);
        assert!(printer.text.lock().unwrap().is_empty());
        assert!(printer.error.lock().unwrap().is_empty());
    }

    #[test]
    fn test_wait_for_daemon_client_retries_transient_errors() {
        let printer = RecordingPrinter::default();
        let mut attempts = 0;
        let mut sleeps = Vec::new();

        let result = wait_for_daemon_client_with(
            "/run/himmelblaud/socket",
            &printer,
            Duration::from_secs(20),
            Duration::from_millis(250),
            |_| {
                attempts += 1;
                if attempts < 3 {
                    Err(retryable_connect_error())
                } else {
                    Ok("connected")
                }
            },
            |duration| sleeps.push(duration),
        );

        assert_eq!(result.unwrap(), "connected");
        assert_eq!(attempts, 3);
        assert_eq!(sleeps, vec![Duration::from_millis(250); 2]);
        assert_eq!(
            printer.text.lock().unwrap().as_slice(),
            &[DAEMON_START_WAIT_MESSAGE.to_string()]
        );
        assert!(printer.error.lock().unwrap().is_empty());
    }

    #[test]
    fn test_wait_for_daemon_client_times_out() {
        let printer = RecordingPrinter::default();

        let result: Result<(), PamResultCode> = wait_for_daemon_client_with(
            "/run/himmelblaud/socket",
            &printer,
            Duration::ZERO,
            Duration::from_millis(250),
            |_| Err(retryable_connect_error()),
            |_| panic!("sleep should not be called after timeout"),
        );

        assert_eq!(result.err(), Some(PamResultCode::PAM_IGNORE));
        assert_eq!(
            printer.text.lock().unwrap().as_slice(),
            &[DAEMON_START_WAIT_MESSAGE.to_string()]
        );
        assert_eq!(
            printer.error.lock().unwrap().as_slice(),
            &["Himmelblau authentication service did not become available in time.".to_string()]
        );
    }

    #[test]
    fn test_wait_for_daemon_client_retries_missing_socket_os_error() {
        let printer = RecordingPrinter::default();
        let connect_error = IoError::from_raw_os_error(libc::ENOENT);
        assert!(
            daemon_connect_error_is_retryable(&connect_error),
            "missing socket error should be retryable: kind={:?} raw_os_error={:?} err={:?}",
            connect_error.kind(),
            connect_error.raw_os_error(),
            connect_error
        );
        let mut connect_error = Some(connect_error);

        let result: Result<(), PamResultCode> = wait_for_daemon_client_with(
            "/run/himmelblaud/socket",
            &printer,
            Duration::ZERO,
            Duration::from_millis(250),
            |_| Err(connect_error.take().unwrap()),
            |_| panic!("sleep should not be called after timeout"),
        );

        assert_eq!(result.err(), Some(PamResultCode::PAM_IGNORE));
        assert_eq!(
            printer.text.lock().unwrap().as_slice(),
            &[DAEMON_START_WAIT_MESSAGE.to_string()]
        );
        assert_eq!(
            printer.error.lock().unwrap().as_slice(),
            &["Himmelblau authentication service did not become available in time.".to_string()]
        );
    }

    #[test]
    fn test_wait_for_daemon_client_stops_on_non_retryable_error() {
        let printer = RecordingPrinter::default();

        let result: Result<(), PamResultCode> = wait_for_daemon_client_with(
            "/run/himmelblaud/socket",
            &printer,
            Duration::from_secs(20),
            Duration::from_millis(250),
            |_| {
                Err(IoError::new(
                    ErrorKind::PermissionDenied,
                    "permission denied",
                ))
            },
            |_| panic!("sleep should not be called for non-retryable errors"),
        );

        assert_eq!(result.unwrap_err(), PamResultCode::PAM_IGNORE);
        assert!(printer.text.lock().unwrap().is_empty());
        assert_eq!(
            printer.error.lock().unwrap().as_slice(),
            &["Himmelblau authentication service is unavailable.".to_string()]
        );
    }

    #[test]
    fn test_should_prompt_mfa_poll_for_ssh_default() {
        let cfg = test_config("");
        let opts = test_options(true);

        assert!(should_prompt_mfa_poll(
            "sshd",
            &opts,
            &cfg,
            "Approve sign-in"
        ));
    }

    #[test]
    fn test_should_prompt_mfa_poll_for_cockpit_default() {
        let cfg = test_config("");
        let opts = test_options(true);

        assert!(should_prompt_mfa_poll(
            "cockpit",
            &opts,
            &cfg,
            "Approve sign-in"
        ));
    }

    #[test]
    fn test_should_prompt_mfa_poll_for_remote_cockpit_default() {
        let cfg = test_config("");
        let opts = test_options(true);

        assert!(should_prompt_mfa_poll(
            "remote:cockpit",
            &opts,
            &cfg,
            "Approve sign-in"
        ));
    }

    #[test]
    fn test_should_not_prompt_mfa_poll_for_unmatched_service() {
        let cfg = test_config("");
        let opts = test_options(true);

        assert!(!should_prompt_mfa_poll(
            "login",
            &opts,
            &cfg,
            "Approve sign-in"
        ));
    }

    #[test]
    fn test_should_not_prompt_mfa_poll_when_option_disabled() {
        let cfg = test_config("");
        let opts = test_options(false);

        assert!(!should_prompt_mfa_poll(
            "cockpit",
            &opts,
            &cfg,
            "Approve sign-in"
        ));
    }

    #[test]
    fn test_should_not_prompt_mfa_poll_for_empty_message() {
        let cfg = test_config("");
        let opts = test_options(true);

        assert!(!should_prompt_mfa_poll("cockpit", &opts, &cfg, "   "));
    }

    #[test]
    fn test_should_prompt_mfa_poll_for_configured_service() {
        let cfg = test_config(
            r#"
            [global]
            mfa_poll_prompt_services = login
            "#,
        );
        let opts = test_options(true);

        assert!(should_prompt_mfa_poll(
            "login",
            &opts,
            &cfg,
            "Approve sign-in"
        ));
        assert!(!should_prompt_mfa_poll(
            "cockpit",
            &opts,
            &cfg,
            "Approve sign-in"
        ));
    }

    #[test]
    fn test_format_mfa_poll_message_adds_push_hint_when_enabled() {
        let msg = format_mfa_poll_message("Approve sign-in", "login", true);

        assert!(msg.contains("Approve sign-in"));
        assert!(msg.contains("No push? Check your mobile device's internet connection."));
    }

    #[test]
    fn test_format_mfa_poll_message_suppresses_push_hint_when_disabled() {
        let msg = format_mfa_poll_message(
            "Waiting for browser authentication to complete...",
            "login",
            false,
        );

        assert_eq!(msg, "Waiting for browser authentication to complete...");
        assert!(!msg.contains("No push?"));
    }

    #[test]
    fn test_format_mfa_poll_message_does_not_add_push_hint_to_empty_message() {
        let msg = format_mfa_poll_message("   ", "login", true);

        assert_eq!(msg, "   ");
        assert!(!msg.contains("No push?"));
    }

    #[test]
    fn test_format_mfa_poll_message_omits_qr_for_broker_interactive() {
        let input = "Using a browser on another device, visit:\nhttps://microsoft.com/devicelogin\nAnd enter the code:\nABC123";
        let msg = format_mfa_poll_message(input, "broker-interactive", false);

        assert_eq!(
            msg, input,
            "pinentry panics on long Assuan payloads, so no QR art may be appended"
        );
    }

    #[test]
    fn test_format_mfa_poll_message_keeps_dag_qr_when_push_hint_disabled() {
        let input = "Using a browser on another device, visit:\nhttps://microsoft.com/devicelogin\nAnd enter the code:\nABC123";
        let msg = format_mfa_poll_message(input, "login", false);

        assert!(msg.contains(input));
        assert!(!msg.contains("No push?"));
        assert!(
            msg.len() > input.len(),
            "DAG message should still include generated QR content"
        );
    }

    fn test_password_state(
        printer: Arc<RecordingPrinter>,
    ) -> (AuthenticateState, std::os::unix::net::UnixListener) {
        fs::create_dir_all("target").expect("Failed to create target directory");
        let socket_path = format!("target/himmelblau_auth_test_sock_{}", uuid::Uuid::new_v4());
        let listener = std::os::unix::net::UnixListener::bind(&socket_path)
            .expect("Failed to bind test socket");
        let daemon_client =
            DaemonClientBlocking::new(&socket_path).expect("Failed to connect test socket");
        (
            AuthenticateState {
                daemon_client,
                authtok: None,
                cfg: test_config(""),
                account_id: "user@example.com".to_string(),
                service: "mariadb".to_string(),
                opts: Options::default(),
                msg_printer: printer,
                poll_attempt: 0,
                polling_interval: 0,
                enrollment_qr_active: false,
            },
            listener,
        )
    }

    #[test]
    fn local_user_fallthrough_has_no_conversation() {
        for (ignore_unknown_user, expected) in [
            (true, PamResultCode::PAM_IGNORE),
            (false, PamResultCode::PAM_USER_UNKNOWN),
        ] {
            let printer = Arc::new(RecordingPrinter::default());
            let (state, listener) = test_password_state(printer.clone());
            let (socket, _) = listener.accept().unwrap();
            serde_json::to_writer(
                &socket,
                &ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Unknown),
            )
            .unwrap();

            let result = authenticate_with_client(
                state.daemon_client,
                None,
                state.cfg,
                "localuser",
                "gdm-password",
                Options {
                    ignore_unknown_user,
                    ..Default::default()
                },
                printer.clone(),
            );

            assert_eq!(result, expected);
            assert!(printer.text.lock().unwrap().is_empty());
            assert!(printer.error.lock().unwrap().is_empty());
            assert!(printer.prompts.lock().unwrap().is_empty());
            fs::remove_file(listener.local_addr().unwrap().as_pathname().unwrap()).unwrap();
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn enrollment_qr_replacement_and_cleanup_messages() {
        use crate::unix_proto::EnrollmentPresentation;
        use base64::Engine;
        let payload = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP";
        let qr = qrcodegen::QrCode::encode_text(payload, qrcodegen::QrCodeEcc::Low).unwrap();
        let size = (qr.size() + 8) as u32 * 4;
        let image = image::GrayImage::from_fn(size, size, |x, y| {
            image::Luma([if qr.get_module(x as i32 / 4 - 4, y as i32 / 4 - 4) {
                0
            } else {
                255
            }])
        });
        let mut png = io::Cursor::new(Vec::new());
        image.write_to(&mut png, image::ImageFormat::Png).unwrap();
        let source = format!(
            "data:image/png;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(png.into_inner())
        );
        let input = |qr, setup_key| PamAuthResponse::Input {
            msg: "Enter code".into(),
            echo_on: false,
            enrollment: Some(EnrollmentPresentation { qr, setup_key }),
        };
        for (response, active_after, clear_count, payload_count, fails) in [
            (input(Some(source), None), true, 0, 1, false),
            (input(None, Some("FIXTUREKEY".into())), false, 1, 0, false),
            (
                input(Some("invalid".into()), Some("FIXTUREKEY".into())),
                false,
                1,
                0,
                false,
            ),
            (input(Some("invalid".into()), None), false, 1, 0, true),
            (PamAuthResponse::MFAPollWait, true, 0, 0, false),
            (PamAuthResponse::Success, false, 1, 0, false),
        ] {
            let printer = Arc::new(RecordingPrinter::default());
            let (mut state, listener) = test_password_state(printer.clone());
            state.service = "gdm-password".into();
            state.enrollment_qr_active = true;
            let (socket, _) = listener.accept().unwrap();
            serde_json::to_writer(
                &socket,
                &ClientResponse::PamAuthenticateStepResponse(response),
            )
            .unwrap();
            let result = authenticate_request_response(
                &mut state,
                &ClientRequest::PamAuthenticateStep(PamAuthRequest::MFAPoll { poll_attempt: 0 }),
            );
            assert_eq!(
                matches!(result, PamWhatNext::Finish(PamResultCode::PAM_ABORT)),
                fails
            );
            assert_eq!(state.enrollment_qr_active, active_after);
            let messages = printer.text.lock().unwrap();
            assert_eq!(
                messages
                    .iter()
                    .filter(|m| m.as_str() == "[OIDC_ENROLL_QR]")
                    .count(),
                clear_count
            );
            assert_eq!(
                messages
                    .iter()
                    .filter(|m| m.starts_with("[OIDC_ENROLL_QR] "))
                    .count(),
                payload_count
            );
            fs::remove_file(listener.local_addr().unwrap().as_pathname().unwrap()).unwrap();
        }
    }

    #[test]
    fn completed_poll_can_be_followed_by_another_poll_after_input() {
        use std::io::{Read, Write};

        let printer = Arc::new(RecordingPrinter::default());
        let (mut state, listener) = test_password_state(printer.clone());
        state.poll_attempt = 3;
        let socket_path = listener
            .local_addr()
            .unwrap()
            .as_pathname()
            .unwrap()
            .to_owned();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut data = Vec::new();
            let mut buffer = [0; 1024];
            loop {
                let count = socket.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                data.extend_from_slice(&buffer[..count]);
                if serde_json::from_slice::<ClientRequest>(&data).is_ok() {
                    break;
                }
            }
            let response = ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Input {
                msg: "Enter verification code".into(),
                echo_on: false,
                enrollment: None,
            });
            socket
                .write_all(&serde_json::to_vec(&response).unwrap())
                .unwrap();
        });
        let next = authenticate_request_response(
            &mut state,
            &ClientRequest::PamAuthenticateStep(PamAuthRequest::MFAPoll { poll_attempt: 3 }),
        );
        assert!(matches!(
            next,
            PamWhatNext::Next(ClientRequest::PamAuthenticateStep(
                PamAuthRequest::Input { .. }
            ))
        ));
        let next = handle_pam_auth_response_mfapoll(&mut state, "Approve enrollment", 0, false);
        assert!(matches!(
            next,
            PamWhatNext::Next(ClientRequest::PamAuthenticateStep(
                PamAuthRequest::MFAPoll { poll_attempt: 0 }
            ))
        ));
        assert!(printer.error.lock().unwrap().is_empty());
        server.join().unwrap();
        fs::remove_file(socket_path).unwrap();
    }

    #[test]
    fn test_hello_totp_enrollment_prints_qr_and_setup_key() {
        let uri = "otpauth://totp/Himmelblau%20testhost:user%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Himmelblau%20testhost&algorithm=SHA1&digits=6&period=30";
        let qr = generate_unicode_qr(uri).expect("QR generation should succeed");

        let msg = hello_totp_enroll_qr_msg(uri, &qr).expect("QR enrollment message should format");

        assert!(msg.contains(
            "Open your authenticator app and scan this QR code to enroll. Then enter the generated code."
        ));
        assert!(msg.contains("Enter the setup key"));
        assert!(msg.contains("JBSWY3DPEHPK3PXP"));
        assert!(msg.contains("Himmelblau testhost"));
        assert!(msg.contains("user@example.com"));
        assert!(
            msg.len() > uri.len(),
            "enrollment text should include generated QR content"
        );
    }

    // no_info_prompt folds the info text into a single PAM_PROMPT_ECHO_OFF.
    #[test]
    fn test_no_info_prompt_folds_info_into_single_prompt() {
        let printer = Arc::new(RecordingPrinter::default());
        let (mut state, _listener) = test_password_state(printer.clone());
        state.opts.no_info_prompt = true;

        let next = handle_pam_auth_response_password(&mut state, None, Some("MFA required"));

        assert!(
            printer.text.lock().unwrap().is_empty(),
            "no standalone info text should be emitted when folding"
        );
        let prompts = printer.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1, "folding must produce a single prompt");
        assert!(prompts[0].starts_with("MFA required"));
        assert!(prompts[0].contains(&state.cfg.get_entra_id_password_prompt()));
        assert!(prompts[0].contains("Entra Id Password:"));
        match next {
            PamWhatNext::Next(ClientRequest::PamAuthenticateStep(PamAuthRequest::Password {
                cred,
            })) => assert_eq!(cred, "hunter2"),
            _ => panic!("expected a password step request"),
        }
    }

    // Default (no_info_prompt unset) keeps the upstream behavior: info as separate text.
    #[test]
    fn test_default_sends_info_as_separate_text() {
        let printer = Arc::new(RecordingPrinter::default());
        let (mut state, _listener) = test_password_state(printer.clone());

        let _ = handle_pam_auth_response_password(&mut state, None, Some("MFA required"));

        let text = printer.text.lock().unwrap();
        assert!(text.iter().any(|t| t.contains("MFA required")));
        assert!(text
            .iter()
            .any(|t| t.contains(&state.cfg.get_entra_id_password_prompt())));
        let prompts = printer.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert!(prompts[0].contains("Entra Id Password:"));
        assert!(
            !prompts[0].contains("MFA required"),
            "info must not be folded into the prompt by default"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod fido_cancellation_tests {
    use super::*;
    use authenticator::authenticatorservice::{AuthenticatorTransport, RegisterArgs};
    use authenticator::errors::AuthenticatorError;
    use std::sync::atomic::AtomicUsize;

    struct WaitingUsbTransport {
        cancellations: Arc<AtomicUsize>,
        callback: Option<StateCallback<authenticator::Result<authenticator::SignResult>>>,
    }

    impl AuthenticatorTransport for WaitingUsbTransport {
        fn register(
            &mut self,
            _timeout: u64,
            _args: RegisterArgs,
            _status: Sender<StatusUpdate>,
            _callback: StateCallback<authenticator::Result<authenticator::RegisterResult>>,
        ) -> authenticator::Result<()> {
            Err(AuthenticatorError::NoConfiguredTransports)
        }

        fn sign(
            &mut self,
            _timeout: u64,
            _args: SignArgs,
            _status: Sender<StatusUpdate>,
            callback: StateCallback<authenticator::Result<authenticator::SignResult>>,
        ) -> authenticator::Result<()> {
            self.callback = Some(callback);
            Ok(())
        }

        fn cancel(&mut self) -> authenticator::Result<()> {
            self.cancellations.fetch_add(1, Ordering::Relaxed);
            self.callback.take();
            Ok(())
        }

        fn reset(
            &mut self,
            _timeout: u64,
            _status: Sender<StatusUpdate>,
            _callback: StateCallback<authenticator::Result<authenticator::ResetResult>>,
        ) -> authenticator::Result<()> {
            Err(AuthenticatorError::NoConfiguredTransports)
        }

        fn set_pin(
            &mut self,
            _timeout: u64,
            _pin: Pin,
            _status: Sender<StatusUpdate>,
            _callback: StateCallback<authenticator::Result<authenticator::ResetResult>>,
        ) -> authenticator::Result<()> {
            Err(AuthenticatorError::NoConfiguredTransports)
        }

        fn manage(
            &mut self,
            _timeout: u64,
            _status: Sender<StatusUpdate>,
            _callback: StateCallback<authenticator::Result<authenticator::ManageResult>>,
        ) -> authenticator::Result<()> {
            Err(AuthenticatorError::NoConfiguredTransports)
        }
    }

    async fn waiting_usb(
        cancellations: Arc<AtomicUsize>,
        printer: Arc<dyn MessagePrinter>,
    ) -> Result<(), PamResultCode> {
        let mut manager = AuthenticatorService::new().unwrap();
        manager.add_transport(Box::new(WaitingUsbTransport {
            cancellations,
            callback: None,
        }));
        let mut session = FidoUsbSession::new(manager, printer, "Touch the test key".into());
        session
            .sign(
                60_000,
                SignArgs {
                    client_data_hash: [0; 32],
                    origin: "https://login.microsoft.com".into(),
                    relying_party_id: "login.microsoft.com".into(),
                    allow_list: vec![],
                    user_verification_req: UserVerificationRequirement::Preferred,
                    user_presence_req: true,
                    extensions: AuthenticationExtensionsClientInputs::default(),
                    pin: None,
                    use_ctap1_fallback: false,
                },
            )
            .await
            .map(|_| ())
    }

    #[tokio::test]
    async fn fido_qr_success_cancels_usb_and_releases_printer() {
        let cancellations = Arc::new(AtomicUsize::new(0));
        let printer = Arc::new(SimpleMessagePrinter::default());
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_fido(
                race_fido_transports(waiting_usb(cancellations.clone(), printer.clone()), async {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok(())
                }),
                60_000,
            ),
        )
        .await
        .unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(cancellations.load(Ordering::Relaxed), 1);
        assert_eq!(
            Arc::strong_count(&printer),
            1,
            "status worker retained the PAM printer"
        );
    }

    #[tokio::test]
    async fn fido_shared_deadline_cancels_remaining_usb_after_qr_failure() {
        let cancellations = Arc::new(AtomicUsize::new(0));
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_fido(
                race_fido_transports(
                    waiting_usb(
                        cancellations.clone(),
                        Arc::new(SimpleMessagePrinter::default()),
                    ),
                    async { Err(PamResultCode::PAM_AUTH_ERR) },
                ),
                20,
            ),
        )
        .await
        .unwrap();
        assert_eq!(result, Err(PamResultCode::PAM_CRED_INSUFFICIENT));
        assert_eq!(cancellations.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn fido_race_keeps_the_other_transport_after_a_failure() {
        for usb_fails in [true, false] {
            let result = wait_for_fido(
                race_fido_transports(
                    async {
                        if usb_fails {
                            Err(PamResultCode::PAM_AUTH_ERR)
                        } else {
                            Ok("usb")
                        }
                    },
                    async {
                        if usb_fails {
                            Ok("phone")
                        } else {
                            Err(PamResultCode::PAM_AUTH_ERR)
                        }
                    },
                ),
                1000,
            )
            .await;
            assert_eq!(result, Ok(if usb_fails { "phone" } else { "usb" }));
        }
    }

    #[tokio::test]
    async fn fido_usb_success_drops_qr_wait() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let (started, ready) = tokio::sync::oneshot::channel();
        let result = wait_for_fido(
            race_fido_transports(
                async {
                    ready.await.unwrap();
                    Ok::<_, PamResultCode>(())
                },
                async {
                    let _guard = Dropped(dropped.clone());
                    started.send(()).unwrap();
                    std::future::pending::<Result<(), PamResultCode>>().await
                },
            ),
            1000,
        )
        .await;
        assert_eq!(result, Ok(()));
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn fido_wait_includes_connection_in_timeout() {
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_fido(std::future::pending::<Result<(), PamResultCode>>(), 20),
        )
        .await
        .expect("FIDO wait did not enforce its deadline");
        assert_eq!(result, Err(PamResultCode::PAM_CRED_INSUFFICIENT));
    }

    #[tokio::test]
    async fn fido_wait_preserves_success_and_failure() {
        assert_eq!(
            wait_for_fido(async { Ok("assertion") }, 1000).await,
            Ok("assertion")
        );
        assert_eq!(
            wait_for_fido(async { Err::<(), _>(PamResultCode::PAM_AUTH_ERR) }, 1000).await,
            Err(PamResultCode::PAM_AUTH_ERR),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fido_wait_does_not_replace_default_sigint_handling() {
        use std::os::unix::process::ExitStatusExt;

        const CHILD: &str = "HIMMELBLAU_FIDO_DEFAULT_SIGNAL_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "auth::fido_cancellation_tests::fido_wait_does_not_replace_default_sigint_handling",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert_eq!(
                output.status.signal(),
                Some(libc::SIGINT),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            return;
        }

        unsafe {
            assert_ne!(libc::signal(libc::SIGINT, libc::SIG_DFL), libc::SIG_ERR);
            let caller = libc::pthread_self();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(20));
                assert_eq!(libc::pthread_kill(caller, libc::SIGINT), 0);
            });
        }
        Runtime::new().unwrap().block_on(async {
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                wait_for_fido(std::future::pending::<Result<(), PamResultCode>>(), 60_000),
            )
            .await;
            assert!(
                result.is_ok(),
                "default SIGINT did not terminate the subprocess"
            );
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fido_wait_observes_blocked_interrupt_on_caller_thread() {
        const CHILD: &str = "HIMMELBLAU_FIDO_SIGNAL_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "auth::fido_cancellation_tests::fido_wait_observes_blocked_interrupt_on_caller_thread",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            return;
        }

        // Real signals are confined to this subprocess's test thread.
        unsafe {
            let mut blocked = std::mem::zeroed::<libc::sigset_t>();
            let mut original = std::mem::zeroed::<libc::sigset_t>();
            assert_eq!(libc::sigemptyset(&mut blocked), 0);
            assert_eq!(libc::sigaddset(&mut blocked, libc::SIGINT), 0);
            assert_eq!(libc::sigaddset(&mut blocked, libc::SIGQUIT), 0);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut original),
                0
            );
            let caller = libc::pthread_self();
            let rt = Runtime::new().unwrap();

            for (signal, with_usb) in [
                (libc::SIGINT, false),
                (libc::SIGQUIT, false),
                (libc::SIGINT, true),
                (libc::SIGQUIT, true),
            ] {
                let cancellations = Arc::new(AtomicUsize::new(0));
                let sender = thread::spawn(move || {
                    thread::sleep(Duration::from_millis(20));
                    assert_eq!(libc::pthread_kill(caller, signal), 0);
                });
                let started = Instant::now();
                let result = rt
                    .block_on(async {
                        tokio::time::timeout(
                            Duration::from_secs(1),
                            wait_for_fido(
                                async {
                                    if with_usb {
                                        race_fido_transports(
                                            waiting_usb(
                                                cancellations.clone(),
                                                Arc::new(SimpleMessagePrinter::default()),
                                            ),
                                            std::future::pending::<Result<(), PamResultCode>>(),
                                        )
                                        .await
                                    } else {
                                        std::future::pending::<Result<(), PamResultCode>>().await
                                    }
                                },
                                60_000,
                            ),
                        )
                        .await
                    })
                    .expect("blocked interrupt did not cancel the FIDO wait");
                sender.join().unwrap();
                assert_eq!(result, Err(PamResultCode::PAM_ABORT));
                assert!(started.elapsed() < Duration::from_millis(500));
                assert_eq!(cancellations.load(Ordering::Relaxed), usize::from(with_usb));

                let mut pending = std::mem::zeroed::<libc::sigset_t>();
                let mut mask = std::mem::zeroed::<libc::sigset_t>();
                assert_eq!(libc::sigpending(&mut pending), 0);
                assert_eq!(
                    libc::sigismember(&pending, signal),
                    1,
                    "host signal was consumed"
                );
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask),
                    0
                );
                assert_eq!(
                    libc::sigismember(&mask, signal),
                    1,
                    "host signal was unblocked"
                );

                let mut consume = std::mem::zeroed::<libc::sigset_t>();
                assert_eq!(libc::sigemptyset(&mut consume), 0);
                assert_eq!(libc::sigaddset(&mut consume, signal), 0);
                let mut received = 0;
                assert_eq!(libc::sigwait(&consume, &mut received), 0);
                assert_eq!(received, signal);
            }
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, &original, std::ptr::null_mut()),
                0
            );
        }
    }
}

#[cfg(test)]
mod fido_status_tests {
    use super::*;
    use std::error::Error;
    use std::sync::mpsc::Receiver;

    type TestResult = Result<(), Box<dyn Error>>;
    const WAIT: Duration = Duration::from_secs(5);

    #[derive(Debug, PartialEq)]
    enum Event {
        Text(String),
        Prompt(String),
        Error(String),
        Dropped,
    }

    struct StatusPrinter(Sender<Event>);

    impl MessagePrinter for StatusPrinter {
        fn print_text(&self, msg: &str) {
            let _ = self.0.send(Event::Text(msg.into()));
        }

        fn print_error(&self, msg: &str) {
            let _ = self.0.send(Event::Error(msg.into()));
        }

        fn prompt_echo_on(&self, _prompt: &str) -> Option<String> {
            None
        }

        fn prompt_echo_off(&self, prompt: &str) -> Option<String> {
            let _ = self.0.send(Event::Prompt(prompt.into()));
            Some("123456".into())
        }
    }

    impl Drop for StatusPrinter {
        fn drop(&mut self) {
            let _ = self.0.send(Event::Dropped);
        }
    }

    fn start_status_worker() -> (Sender<StatusUpdate>, Receiver<Event>) {
        let (events, receiver) = channel();
        let status =
            fido_status_check(Arc::new(StatusPrinter(events)), "Touch the test key".into());
        (status, receiver)
    }

    fn check_presence_delivery() -> TestResult {
        let (status, events) = start_status_worker();
        status.send(StatusUpdate::PresenceRequired)?;
        assert_eq!(
            events.recv_timeout(WAIT)?,
            Event::Text("[FIDO_TOUCH] Touch the test key".into())
        );
        drop(status);
        assert_eq!(events.recv_timeout(WAIT)?, Event::Dropped);
        Ok(())
    }

    #[test]
    fn presence_updates_work_without_a_tokio_runtime() -> TestResult {
        check_presence_delivery()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn presence_updates_work_inside_an_existing_runtime() -> TestResult {
        // Call directly on the runtime thread to catch a nested block_on bridge.
        check_presence_delivery()
    }

    #[test]
    fn pin_requests_deliver_the_prompted_pin() -> TestResult {
        let (status, events) = start_status_worker();
        let (pin_sender, pin_receiver) = channel();
        status.send(StatusUpdate::PinUvError(StatusPinUv::PinRequired(
            pin_sender,
        )))?;
        assert_eq!(
            events.recv_timeout(WAIT)?,
            Event::Prompt(tr("Fido PIN:") + " ")
        );
        assert_eq!(pin_receiver.recv_timeout(WAIT)?.as_bytes(), b"123456");
        drop(status);
        assert_eq!(events.recv_timeout(WAIT)?, Event::Dropped);
        Ok(())
    }

    #[test]
    fn dropping_status_senders_releases_the_worker_printer() -> TestResult {
        let (status, events) = start_status_worker();
        drop(status);
        assert_eq!(events.recv_timeout(WAIT)?, Event::Dropped);
        Ok(())
    }
}
