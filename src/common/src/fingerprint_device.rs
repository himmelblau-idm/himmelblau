//! Local biometric FIDO2 transport. PIN verification is deliberately forbidden here.
use crate::secret_memory::SecretBuffer;
use authenticator::{
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
    crypto::COSEAlgorithm,
    ctap2::{
        attestation::AuthenticatorDataFlags,
        server::{
            AuthenticationExtensionsClientInputs, CredentialProtectionPolicy, HMACGetSecretInput,
            PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
            PublicKeyCredentialUserEntity, RelyingParty, ResidentKeyRequirement, Transport,
            UserVerificationRequirement,
        },
    },
    statecallback::StateCallback,
    StatusPinUv, StatusUpdate,
};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Verifier};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{channel, Receiver},
        Mutex, TryLockError,
    },
    time::{Duration, Instant},
};

pub const RP_ID: &str = "hello.himmelblau.local";
const TIMEOUT_MS: u64 = 60_000;
static DEVICE_OWNER: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceCredential {
    pub credential_id: Vec<u8>,
    pub public_key_der: Vec<u8>,
    pub salt: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceProgress {
    TouchRequired,
    SelectDevice,
    InvalidFingerprint { remaining: u8 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceError {
    Unavailable,
    Cancelled,
    Timeout,
    PinRequired,
    Locked,
    InvalidAssertion,
    Transport,
    Busy,
    Ineligible,
}
impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DeviceError {}

pub struct FingerprintDevice;
impl Default for FingerprintDevice {
    fn default() -> Self {
        Self::new()
    }
}
impl FingerprintDevice {
    pub fn new() -> Self {
        Self
    }
    pub fn available() -> bool {
        !authenticator::local_biometric_devices().is_empty()
    }
    fn service() -> Result<AuthenticatorService, DeviceError> {
        let mut service = AuthenticatorService::new().map_err(|_| DeviceError::Unavailable)?;
        service.add_u2f_usb_hid_platform_transports();
        Ok(service)
    }
    pub fn enroll(
        &self,
        account_id: &str,
        cancel: &AtomicBool,
        mut progress: impl FnMut(DeviceProgress),
    ) -> Result<(DeviceCredential, SecretBuffer), DeviceError> {
        if cancel.load(Ordering::Acquire) {
            return Err(DeviceError::Cancelled);
        }
        let paths = authenticator::local_biometric_devices();
        if paths.len() != 1 {
            return Err(if paths.is_empty() {
                DeviceError::Unavailable
            } else {
                DeviceError::Busy
            });
        }
        self.enroll_on(&paths[0], account_id, cancel, &mut progress)
    }
    pub fn enroll_on(
        &self,
        path: &str,
        account_id: &str,
        cancel: &AtomicBool,
        mut progress: impl FnMut(DeviceProgress),
    ) -> Result<(DeviceCredential, SecretBuffer), DeviceError> {
        if cancel.load(Ordering::Acquire) {
            return Err(DeviceError::Cancelled);
        }
        let _guard = DEVICE_OWNER.try_lock().map_err(|_| DeviceError::Busy)?;
        let paths = [path.to_owned()];
        let cred_protect = Self::credential_protection_supported(path)?;
        let mut service = Self::service()?;
        let mut challenge = [0u8; 32];
        openssl::rand::rand_bytes(&mut challenge).map_err(|_| DeviceError::Transport)?;
        let (status_tx, status_rx) = channel();
        let (tx, rx) = channel();
        let args = RegisterArgs {
            client_data_hash: challenge,
            relying_party: RelyingParty {
                id: RP_ID.into(),
                name: None,
            },
            origin: format!("https://{RP_ID}"),
            user: PublicKeyCredentialUserEntity {
                id: openssl::sha::sha256(account_id.as_bytes()).to_vec(),
                name: Some(account_id.into()),
                display_name: None,
            },
            pub_cred_params: vec![PublicKeyCredentialParameters {
                alg: COSEAlgorithm::ES256,
            }],
            exclude_list: vec![],
            user_verification_req: UserVerificationRequirement::Required,
            resident_key_req: ResidentKeyRequirement::Discouraged,
            extensions: AuthenticationExtensionsClientInputs {
                local_device_path: Some(paths[0].clone()),
                hmac_create_secret: Some(true),
                credential_protection_policy: cred_protect
                    .then_some(CredentialProtectionPolicy::UserVerificationRequired),
                enforce_credential_protection_policy: Some(cred_protect),
                ..Default::default()
            },
            pin: None,
            use_ctap1_fallback: false,
            internal_uv_only: true,
        };
        service
            .register(
                TIMEOUT_MS,
                args,
                status_tx,
                StateCallback::new(Box::new(move |r| {
                    let _ = tx.send(r);
                })),
            )
            .map_err(|_| DeviceError::Transport)?;
        let result = wait(&mut service, &rx, &status_rx, cancel, &mut progress)?;
        let data = result.att_obj.auth_data;
        if !data
            .flags
            .contains(AuthenticatorDataFlags::USER_PRESENT | AuthenticatorDataFlags::USER_VERIFIED)
            || data.rp_id_hash != RelyingParty::from(RP_ID).hash()
        {
            return Err(DeviceError::InvalidAssertion);
        }
        let cred = data.credential_data.ok_or(DeviceError::InvalidAssertion)?;
        let mut salt = [0; 32];
        openssl::rand::rand_bytes(&mut salt).map_err(|_| DeviceError::Transport)?;
        let credential = DeviceCredential {
            credential_id: cred.credential_id,
            public_key_der: cred
                .credential_public_key
                .der_spki()
                .map_err(|_| DeviceError::InvalidAssertion)?,
            salt,
        };
        // A fresh assertion proves both the credential and hmac-secret work before saving.
        let secret = self.verify_owned(&credential, Some(path), 3, cancel, &mut progress)?;
        Ok((credential, secret))
    }
    pub fn verify(
        &self,
        credential: &DeviceCredential,
        cancel: &AtomicBool,
        mut progress: impl FnMut(DeviceProgress),
    ) -> Result<SecretBuffer, DeviceError> {
        if cancel.load(Ordering::Acquire) {
            return Err(DeviceError::Cancelled);
        }
        let _guard = DEVICE_OWNER.try_lock().map_err(|e| match e {
            TryLockError::WouldBlock => DeviceError::Busy,
            _ => DeviceError::Unavailable,
        })?;
        self.verify_owned(credential, None, 3, cancel, &mut progress)
    }
    pub fn verify_with_budget(
        &self,
        credential: &DeviceCredential,
        remaining: u8,
        cancel: &AtomicBool,
        mut progress: impl FnMut(DeviceProgress),
    ) -> Result<SecretBuffer, DeviceError> {
        if remaining == 0 {
            return Err(DeviceError::Locked);
        }
        if cancel.load(Ordering::Acquire) {
            return Err(DeviceError::Cancelled);
        }
        let _guard = DEVICE_OWNER.try_lock().map_err(|_| DeviceError::Busy)?;
        self.verify_owned(credential, None, remaining, cancel, &mut progress)
    }
    pub fn verify_on(
        &self,
        path: &str,
        credential: &DeviceCredential,
        cancel: &AtomicBool,
        mut progress: impl FnMut(DeviceProgress),
    ) -> Result<SecretBuffer, DeviceError> {
        if cancel.load(Ordering::Acquire) {
            return Err(DeviceError::Cancelled);
        }
        let _guard = DEVICE_OWNER.try_lock().map_err(|_| DeviceError::Busy)?;
        self.verify_owned(credential, Some(path), 3, cancel, &mut progress)
    }
    fn verify_owned(
        &self,
        credential: &DeviceCredential,
        path: Option<&str>,
        remaining: u8,
        cancel: &AtomicBool,
        progress: &mut impl FnMut(DeviceProgress),
    ) -> Result<SecretBuffer, DeviceError> {
        if remaining == 0 {
            return Err(DeviceError::Locked);
        }
        let mut service = Self::service()?;
        let mut challenge = [0; 32];
        openssl::rand::rand_bytes(&mut challenge).map_err(|_| DeviceError::Transport)?;
        let (status_tx, status_rx) = channel();
        let (tx, rx) = channel();
        let args = SignArgs {
            client_data_hash: challenge,
            origin: format!("https://{RP_ID}"),
            relying_party_id: RP_ID.into(),
            allow_list: vec![PublicKeyCredentialDescriptor {
                id: credential.credential_id.clone(),
                transports: vec![Transport::USB],
            }],
            user_verification_req: UserVerificationRequirement::Required,
            user_presence_req: true,
            extensions: AuthenticationExtensionsClientInputs {
                local_device_path: path.map(str::to_owned),
                local_uv_attempt_limit: Some(remaining.min(3)),
                hmac_get_secret: Some(HMACGetSecretInput {
                    salt1: credential.salt,
                    salt2: None,
                }),
                ..Default::default()
            },
            pin: None,
            use_ctap1_fallback: false,
            internal_uv_only: true,
        };
        service
            .sign(
                TIMEOUT_MS,
                args,
                status_tx,
                StateCallback::new(Box::new(move |r| {
                    let _ = tx.send(r);
                })),
            )
            .map_err(|_| DeviceError::Transport)?;
        let result = wait(&mut service, &rx, &status_rx, cancel, progress)?;
        verify_assertion(credential, &result, &challenge)
    }
}
fn verify_assertion(
    credential: &DeviceCredential,
    result: &authenticator::SignResult,
    challenge: &[u8; 32],
) -> Result<SecretBuffer, DeviceError> {
    let assertion = &result.assertion;
    if !matches!(assertion.auth_data.extensions.hmac_secret, Some(authenticator::ctap2::attestation::HmacSecretResponse::Secret(ref ciphertext)) if [32,48].contains(&ciphertext.len()))
    {
        return Err(DeviceError::InvalidAssertion);
    }
    if !assertion
        .auth_data
        .flags
        .contains(AuthenticatorDataFlags::EXTENSION_DATA)
    {
        return Err(DeviceError::InvalidAssertion);
    }
    verify_identity(credential, result, challenge)?;
    let output = result
        .extensions
        .hmac_get_secret
        .as_ref()
        .ok_or(DeviceError::InvalidAssertion)?;
    if output.output2.is_some() {
        return Err(DeviceError::InvalidAssertion);
    }
    SecretBuffer::from_slice(&output.output1).map_err(|_| DeviceError::Unavailable)
}
fn verify_identity(
    credential: &DeviceCredential,
    result: &authenticator::SignResult,
    challenge: &[u8; 32],
) -> Result<(), DeviceError> {
    let assertion = &result.assertion;
    if !assertion
        .auth_data
        .flags
        .contains(AuthenticatorDataFlags::USER_PRESENT | AuthenticatorDataFlags::USER_VERIFIED)
        || assertion.auth_data.rp_id_hash != RelyingParty::from(RP_ID).hash()
        || assertion
            .credentials
            .as_ref()
            .is_some_and(|c| c.id != credential.credential_id)
    {
        return Err(DeviceError::InvalidAssertion);
    }
    let key = PKey::public_key_from_der(&credential.public_key_der)
        .map_err(|_| DeviceError::InvalidAssertion)?;
    let mut verifier =
        Verifier::new(MessageDigest::sha256(), &key).map_err(|_| DeviceError::InvalidAssertion)?;
    verifier
        .update(&assertion.auth_data.to_vec())
        .map_err(|_| DeviceError::InvalidAssertion)?;
    verifier
        .update(challenge)
        .map_err(|_| DeviceError::InvalidAssertion)?;
    if !verifier
        .verify(&assertion.signature)
        .map_err(|_| DeviceError::InvalidAssertion)?
    {
        return Err(DeviceError::InvalidAssertion);
    }
    Ok(())
}
fn process_status(
    event: &StatusUpdate,
    failures: &mut u8,
    progress: &mut impl FnMut(DeviceProgress),
) -> Option<DeviceError> {
    match event {
        StatusUpdate::PresenceRequired => {
            progress(DeviceProgress::TouchRequired);
            None
        }
        StatusUpdate::SelectDeviceNotice => {
            progress(DeviceProgress::SelectDevice);
            None
        }
        StatusUpdate::PinUvError(StatusPinUv::InvalidUv(_)) => {
            *failures = failures.saturating_add(1);
            progress(DeviceProgress::InvalidFingerprint {
                remaining: 3u8.saturating_sub(*failures),
            });
            (*failures >= 3).then_some(DeviceError::Locked)
        }
        StatusUpdate::PinUvError(StatusPinUv::PinRequired(_) | StatusPinUv::InvalidPin(_, _)) => {
            Some(DeviceError::PinRequired)
        }
        StatusUpdate::PinUvError(_) => Some(DeviceError::Locked),
        _ => None,
    }
}
fn wait<T>(
    service: &mut AuthenticatorService,
    result: &Receiver<Result<T, authenticator::errors::AuthenticatorError>>,
    status: &Receiver<StatusUpdate>,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(DeviceProgress),
) -> Result<T, DeviceError> {
    let start = Instant::now();
    let mut failures = 0;
    loop {
        if cancel.load(Ordering::Acquire) {
            let _ = service.cancel();
            return Err(DeviceError::Cancelled);
        }
        if start.elapsed() >= Duration::from_millis(TIMEOUT_MS) {
            let _ = service.cancel();
            return Err(DeviceError::Timeout);
        }
        while let Ok(event) = status.try_recv() {
            let failure = process_status(&event, &mut failures, progress);
            if let Some(error) = failure {
                let _ = service.cancel();
                return Err(error);
            }
        }
        match result.recv_timeout(Duration::from_millis(25)) {
            Ok(r) => {
                // The callback can race the status receiver. Drain events emitted before
                // completion so the final failed scan is persisted and PIN fallback stays exact.
                while let Ok(event) = status.try_recv() {
                    if let Some(error) = process_status(&event, &mut failures, progress) {
                        let _ = service.cancel();
                        return Err(error);
                    }
                }
                if cancel.load(Ordering::Acquire) {
                    let _ = service.cancel();
                    return Err(DeviceError::Cancelled);
                }
                return r.map_err(|_| DeviceError::Transport);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return Err(DeviceError::Transport),
        }
    }
}

impl FingerprintDevice {
    /// Public transport paths are selection handles, never account identity or key material.
    pub fn discover() -> Vec<String> {
        authenticator::local_biometric_devices()
    }
    /// Prepare an explicitly selected personal authenticator. PIN changes require prior consent.
    pub fn prepare(
        &self,
        path: &str,
        hello_pin: &SecretBuffer,
        current_token_pin: Option<&SecretBuffer>,
        initialize_pin: bool,
        synchronize_pin: bool,
        cancel: &AtomicBool,
        mut progress: impl FnMut(DeviceProgress) + Send,
    ) -> Result<Vec<u8>, DeviceError> {
        if cancel.load(Ordering::Acquire) {
            return Err(DeviceError::Cancelled);
        }
        use authenticator::{
            local_biometric_transport::{Device, FidoDevice, HIDDevice},
            BioEnrollmentCmd, BioEnrollmentResult, InteractiveUpdate, Pin,
        };
        let _guard = DEVICE_OWNER.try_lock().map_err(|_| DeviceError::Busy)?;
        if !Self::discover().iter().any(|p| p == path) {
            return Err(DeviceError::Ineligible);
        }
        let mut dev = Device::new(path.into()).map_err(|_| DeviceError::Unavailable)?;
        dev.set_local_read_timeout(Some(1_000));
        dev.init().map_err(|_| DeviceError::Transport)?;
        let info = dev
            .get_authenticator_info()
            .ok_or(DeviceError::Ineligible)?;
        let configured = info.options.client_pin == Some(true);
        if !configured && !initialize_pin {
            return Err(DeviceError::PinRequired);
        }
        let hello =
            std::str::from_utf8(hello_pin.as_slice()).map_err(|_| DeviceError::PinRequired)?;
        let current = current_token_pin
            .map(|p| std::str::from_utf8(p.as_slice()).map_err(|_| DeviceError::PinRequired))
            .transpose()?;
        if configured && current.is_none() {
            return Err(DeviceError::PinRequired);
        }
        let pin_start = Instant::now();
        let alive = || {
            !cancel.load(Ordering::Acquire)
                && pin_start.elapsed() < Duration::from_millis(TIMEOUT_MS)
        };
        if !configured || synchronize_pin {
            let (tx, rx) = channel();
            let (status_tx, status_rx) = channel();
            drop(status_rx);
            authenticator::ctap2::set_or_change_pin_helper::<()>(
                &mut dev,
                current.map(Pin::new),
                Pin::new(hello),
                status_tx,
                StateCallback::new(Box::new(move |r| {
                    let _ = tx.send(r);
                })),
                &alive,
            );
            rx.recv()
                .map_err(|_| DeviceError::Transport)?
                .map_err(|_| DeviceError::PinRequired)?;
        }
        let management_pin = if !configured || synchronize_pin {
            hello
        } else {
            current.ok_or(DeviceError::PinRequired)?
        };
        let (status_tx, status_rx) = channel();
        let (tx, _rx) = channel();
        // Enrollment runs on this open device. The responder supplies a PIN once; failed PINs
        // are never automatically retried, avoiding accidental token lockout.
        let pin = Pin::new(management_pin);
        let (event_tx, event_rx) = channel();
        progress(DeviceProgress::TouchRequired);
        let name = format!("Himmelblau {}", uuid::Uuid::new_v4());
        let start = Instant::now();
        let alive = || {
            !cancel.load(Ordering::Acquire) && start.elapsed() < Duration::from_millis(TIMEOUT_MS)
        };
        std::thread::scope(|scope| {
            let progress = &mut progress;
            let responder = scope.spawn(move || {
                let mut pin = Some(pin);
                while let Ok(event) = status_rx.recv() {
                    match event {
                        StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                            if let Some(p) = pin.take() {
                                let _ = sender.send(p);
                            }
                        }
                        StatusUpdate::PinUvError(StatusPinUv::InvalidPin(_, _)) => {
                            // Drop the retry sender immediately. Retaining it would block CTAP.
                            let _ =
                                event_tx.send(StatusUpdate::PinUvError(StatusPinUv::PinBlocked));
                        }
                        StatusUpdate::InteractiveManagement(
                            InteractiveUpdate::BioEnrollmentUpdate((
                                BioEnrollmentResult::SampleStatus(_, _),
                                _,
                            )),
                        ) => {
                            progress(DeviceProgress::TouchRequired);
                        }
                        event => {
                            let _ = event_tx.send(event);
                        }
                    }
                }
            });
            authenticator::ctap2::bio_enrollment(
                &mut dev,
                None,
                BioEnrollmentCmd::StartNewEnrollment(Some(name.clone())),
                status_tx,
                StateCallback::new(Box::new(move |r| {
                    let _ = tx.send(r);
                })),
                &alive,
            );
            let _ = responder.join();
        });
        let mut complete = false;
        for event in event_rx.try_iter() {
            match event {
                StatusUpdate::InteractiveManagement(InteractiveUpdate::BioEnrollmentUpdate((
                    BioEnrollmentResult::AddSuccess(_),
                    _,
                ))) => complete = true,
                StatusUpdate::InteractiveManagement(InteractiveUpdate::BioEnrollmentUpdate((
                    BioEnrollmentResult::SampleStatus(_, _),
                    _,
                ))) => progress(DeviceProgress::TouchRequired),
                StatusUpdate::PinUvError(_) => return Err(DeviceError::PinRequired),
                _ => {}
            }
        }
        if !complete {
            return Err(if cancel.load(Ordering::Acquire) {
                DeviceError::Cancelled
            } else {
                DeviceError::Transport
            });
        }
        // Enumerate after enrollment to obtain the exact managed template ID. A fresh token
        // PIN authorization is intentional; no cached PIN/UV token crosses operations.
        let result = self.list_owned(&mut dev, management_pin, &alive)?;
        result
            .into_iter()
            .find(|(_, n)| n.as_deref() == Some(&name))
            .map(|(id, _)| id)
            .ok_or(DeviceError::InvalidAssertion)
    }
    fn list_owned(
        &self,
        dev: &mut authenticator::local_biometric_transport::Device,
        pin: &str,
        alive: &dyn Fn() -> bool,
    ) -> Result<Vec<(Vec<u8>, Option<String>)>, DeviceError> {
        use authenticator::{BioEnrollmentCmd, BioEnrollmentResult, InteractiveUpdate, Pin};
        let (status_tx, status_rx) = channel();
        let (tx, _rx) = channel();
        let pin = Pin::new(pin);
        let responder = std::thread::spawn(move || {
            let mut pin = Some(pin);
            let mut entries = None;
            while let Ok(event) = status_rx.recv() {
                match event {
                    StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                        if let Some(p) = pin.take() {
                            let _ = sender.send(p);
                        }
                    }
                    StatusUpdate::InteractiveManagement(
                        InteractiveUpdate::BioEnrollmentUpdate((
                            BioEnrollmentResult::EnrollmentList(list),
                            _,
                        )),
                    ) => {
                        entries = Some(
                            list.into_iter()
                                .map(|i| (i.template_id, i.template_friendly_name))
                                .collect(),
                        );
                        break;
                    }
                    StatusUpdate::PinUvError(_) => break,
                    _ => {}
                }
            }
            entries
        });
        authenticator::ctap2::bio_enrollment(
            dev,
            None,
            BioEnrollmentCmd::GetEnrollments,
            status_tx,
            StateCallback::new(Box::new(move |r| {
                let _ = tx.send(r);
            })),
            alive,
        );
        responder
            .join()
            .map_err(|_| DeviceError::Transport)?
            .ok_or(DeviceError::Transport)
    }
}

impl FingerprintDevice {
    fn credential_protection_supported(path: &str) -> Result<bool, DeviceError> {
        use authenticator::local_biometric_transport::{Device, FidoDevice, HIDDevice};
        let mut dev = Device::new(path.into()).map_err(|_| DeviceError::Unavailable)?;
        dev.set_local_read_timeout(Some(1_000));
        dev.init().map_err(|_| DeviceError::Transport)?;
        dev.get_authenticator_info()
            .map(|i| i.supports_cred_protect())
            .ok_or(DeviceError::Ineligible)
    }
    pub fn token_pin_configured(path: &str) -> Result<bool, DeviceError> {
        use authenticator::local_biometric_transport::{Device, FidoDevice, HIDDevice};
        let _guard = DEVICE_OWNER.try_lock().map_err(|_| DeviceError::Busy)?;
        if !Self::discover().iter().any(|p| p == path) {
            return Err(DeviceError::Ineligible);
        }
        let mut dev = Device::new(path.into()).map_err(|_| DeviceError::Unavailable)?;
        dev.set_local_read_timeout(Some(1_000));
        dev.init().map_err(|_| DeviceError::Transport)?;
        dev.get_authenticator_info()
            .map(|i| i.options.client_pin == Some(true))
            .ok_or(DeviceError::Ineligible)
    }
    /// Remove only a selected template created by Himmelblau. Unrelated templates and
    /// discoverable credentials are never deleted and the authenticator is never reset.
    pub fn remove_managed(
        &self,
        path: &str,
        template_id: &[u8],
        current_token_pin: &SecretBuffer,
        cancel: &AtomicBool,
    ) -> Result<(), DeviceError> {
        if cancel.load(Ordering::Acquire) {
            return Err(DeviceError::Cancelled);
        }
        use authenticator::{
            local_biometric_transport::{Device, FidoDevice, HIDDevice},
            BioEnrollmentCmd, BioEnrollmentResult, InteractiveUpdate, Pin,
        };
        let _guard = DEVICE_OWNER.try_lock().map_err(|_| DeviceError::Busy)?;
        if !Self::discover().iter().any(|p| p == path) {
            return Err(DeviceError::Ineligible);
        }
        let mut dev = Device::new(path.into()).map_err(|_| DeviceError::Unavailable)?;
        dev.set_local_read_timeout(Some(1_000));
        dev.init().map_err(|_| DeviceError::Transport)?;
        let start = Instant::now();
        let alive = || {
            !cancel.load(Ordering::Acquire) && start.elapsed() < Duration::from_millis(TIMEOUT_MS)
        };
        let pin = std::str::from_utf8(current_token_pin.as_slice())
            .map_err(|_| DeviceError::PinRequired)?;
        let list = self.list_owned(&mut dev, pin, &alive)?;
        if !list.iter().any(|(id, name)| {
            id == template_id && name.as_ref().is_some_and(|n| n.starts_with("Himmelblau "))
        }) {
            return Err(DeviceError::Ineligible);
        }
        let (status_tx, status_rx) = channel();
        let (tx, _rx) = channel();
        let pin = Pin::new(pin);
        let responder = std::thread::spawn(move || {
            let mut pin = Some(pin);
            while let Ok(event) = status_rx.recv() {
                match event {
                    StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                        if let Some(p) = pin.take() {
                            let _ = sender.send(p);
                        }
                    }
                    StatusUpdate::InteractiveManagement(
                        InteractiveUpdate::BioEnrollmentUpdate((
                            BioEnrollmentResult::DeleteSuccess(_),
                            _,
                        )),
                    ) => return true,
                    StatusUpdate::PinUvError(_) => return false,
                    _ => {}
                }
            }
            false
        });
        authenticator::ctap2::bio_enrollment(
            &mut dev,
            None,
            BioEnrollmentCmd::DeleteEnrollment(template_id.into()),
            status_tx,
            StateCallback::new(Box::new(move |r| {
                let _ = tx.send(r);
            })),
            &alive,
        );
        if responder.join().map_err(|_| DeviceError::Transport)? {
            Ok(())
        } else {
            Err(DeviceError::Transport)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticator::ctap2::{
        attestation::{AuthenticatorData, Extension},
        commands::get_assertion::{Assertion, GetAssertionResult},
        server::{
            AuthenticationExtensionsClientOutputs, AuthenticatorAttachment, HMACGetSecretOutput,
        },
    };
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        sign::Signer,
    };
    fn fixture() -> (DeviceCredential, GetAssertionResult, [u8; 32]) {
        fixture_with_hmac(true)
    }
    fn fixture_with_hmac(hmac: bool) -> (DeviceCredential, GetAssertionResult, [u8; 32]) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let challenge = [23; 32];
        let credential = DeviceCredential {
            credential_id: vec![1, 2, 3],
            public_key_der: key.public_key_to_der().unwrap(),
            salt: [19; 32],
        };
        let auth_data = AuthenticatorData {
            rp_id_hash: RelyingParty::from(RP_ID).hash(),
            flags: AuthenticatorDataFlags::USER_PRESENT
                | AuthenticatorDataFlags::USER_VERIFIED
                | if hmac {
                    AuthenticatorDataFlags::EXTENSION_DATA
                } else {
                    AuthenticatorDataFlags::empty()
                },
            counter: 1,
            credential_data: None,
            extensions: Extension {
                hmac_secret: hmac.then_some(
                    authenticator::ctap2::attestation::HmacSecretResponse::Secret(vec![7; 48]),
                ),
                ..Default::default()
            },
        };
        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer.update(&auth_data.to_vec()).unwrap();
        signer.update(&challenge).unwrap();
        let signature = signer.sign_to_vec().unwrap();
        let result = GetAssertionResult {
            assertion: Assertion {
                credentials: Some(PublicKeyCredentialDescriptor {
                    id: credential.credential_id.clone(),
                    transports: vec![Transport::USB],
                }),
                auth_data,
                signature,
                user: None,
            },
            attachment: AuthenticatorAttachment::CrossPlatform,
            extensions: AuthenticationExtensionsClientOutputs {
                hmac_get_secret: hmac.then_some(HMACGetSecretOutput {
                    output1: [42; 32],
                    output2: None,
                }),
                ..Default::default()
            },
        };
        (credential, result, challenge)
    }
    #[test]
    fn exhausted_budget_is_rejected_without_touching_hardware() {
        let (c, _, _) = fixture();
        assert!(matches!(
            FingerprintDevice::new().verify_with_budget(&c, 0, &AtomicBool::new(false), |_| {}),
            Err(DeviceError::Locked)
        ));
    }
    #[test]
    fn management_pin_assertion_proves_key_but_cannot_release_unlock_secret() {
        let (c, r, n) = fixture_with_hmac(false);
        assert!(verify_identity(&c, &r, &n).is_ok());
        assert!(verify_assertion(&c, &r, &n).is_err());
        let (other, _, _) = fixture();
        assert!(verify_identity(&other, &r, &n).is_err());
    }
    #[test]
    fn reported_failures_have_a_three_scan_budget_and_pin_requests_are_rejected() {
        let mut failures = 0;
        let mut remaining = Vec::new();
        let mut progress = |event| {
            if let DeviceProgress::InvalidFingerprint { remaining: n } = event {
                remaining.push(n);
            }
        };
        for i in 0..3 {
            assert_eq!(
                process_status(
                    &StatusUpdate::PinUvError(StatusPinUv::InvalidUv(None)),
                    &mut failures,
                    &mut progress
                ),
                if i == 2 {
                    Some(DeviceError::Locked)
                } else {
                    None
                }
            );
        }
        assert_eq!(remaining, vec![2, 1, 0]);
        let (tx, rx) = channel();
        assert_eq!(
            process_status(
                &StatusUpdate::PinUvError(StatusPinUv::PinRequired(tx)),
                &mut failures,
                &mut |_| {}
            ),
            Some(DeviceError::PinRequired)
        );
        assert!(
            rx.recv().is_err(),
            "PIN substitution channel must be dropped"
        );
    }
    #[test]
    fn verified_assertion_releases_hmac_output() {
        let (c, r, n) = fixture();
        assert_eq!(verify_assertion(&c, &r, &n).unwrap().as_slice(), &[42; 32]);
    }
    #[test]
    fn assertion_replay_on_fresh_challenge_is_rejected() {
        let (c, r, mut n) = fixture();
        n[0] ^= 1;
        assert!(matches!(
            verify_assertion(&c, &r, &n),
            Err(DeviceError::InvalidAssertion)
        ));
    }
    #[test]
    fn altered_rp_and_flags_are_rejected() {
        let (c, mut r, n) = fixture();
        r.assertion.auth_data.rp_id_hash = RelyingParty::from("attacker.local").hash();
        assert!(verify_assertion(&c, &r, &n).is_err());
        for flags in [
            AuthenticatorDataFlags::USER_PRESENT,
            AuthenticatorDataFlags::USER_VERIFIED,
            AuthenticatorDataFlags::empty(),
        ] {
            let (c, mut r, n) = fixture();
            r.assertion.auth_data.flags = flags;
            assert!(verify_assertion(&c, &r, &n).is_err());
        }
    }
    #[test]
    fn wrong_credential_key_and_signature_are_rejected() {
        let (c, mut r, n) = fixture();
        r.assertion.credentials.as_mut().unwrap().id.push(9);
        assert!(verify_assertion(&c, &r, &n).is_err());
        let (c, mut r, n) = fixture();
        r.assertion.signature[0] ^= 1;
        assert!(verify_assertion(&c, &r, &n).is_err());
        let (c, r, n) = fixture();
        let (mut other, _, _) = fixture();
        other.credential_id = c.credential_id;
        assert!(verify_assertion(&other, &r, &n).is_err());
    }
    #[test]
    fn missing_or_unrequested_secret_output_is_rejected() {
        let (c, mut r, n) = fixture();
        r.assertion.auth_data.extensions.hmac_secret = None;
        assert!(verify_assertion(&c, &r, &n).is_err());
        let (c, mut r, n) = fixture();
        r.extensions.hmac_get_secret = None;
        assert!(verify_assertion(&c, &r, &n).is_err());
        let (c, mut r, n) = fixture();
        r.extensions.hmac_get_secret.as_mut().unwrap().output2 = Some([1; 32]);
        assert!(verify_assertion(&c, &r, &n).is_err());
    }
    #[test]
    fn cancellation_never_starts_a_hardware_operation() {
        // Cancellation can be checked before touching the transport and must not become
        // successful verification simply because a callback result races with cancellation.
        let cancelled = AtomicBool::new(true);
        let mut service = AuthenticatorService::new().unwrap();
        let (_tx, rx) = channel::<Result<(), authenticator::errors::AuthenticatorError>>();
        let (_st, sr) = channel();
        assert_eq!(
            wait(&mut service, &rx, &sr, &cancelled, &mut |_| {}),
            Err(DeviceError::Cancelled)
        );
    }
}

impl FingerprintDevice {
    /// Best-effort CTAP 2.1 UV retry recovery after a successful typed Hello PIN.
    /// The caller must know this personal token's PIN was synchronized to Hello.
    /// This does not request an assertion or hmac-secret and never unlocks Hello.
    pub fn unblock_on(
        &self,
        path: &str,
        hello_pin: &SecretBuffer,
        cancel: &AtomicBool,
    ) -> Result<(), DeviceError> {
        use authenticator::{
            ctap2::commands::client_pin::PinUvAuthTokenPermission,
            local_biometric_transport::{Device, FidoDevice, HIDDevice},
            Pin,
        };
        if cancel.load(Ordering::Acquire) {
            return Err(DeviceError::Cancelled);
        }
        let _guard = DEVICE_OWNER.try_lock().map_err(|_| DeviceError::Busy)?;
        if !Self::discover().iter().any(|p| p == path) {
            return Err(DeviceError::Unavailable);
        }
        let mut dev = Device::new(path.into()).map_err(|_| DeviceError::Unavailable)?;
        dev.set_local_read_timeout(Some(1_000));
        dev.init().map_err(|_| DeviceError::Transport)?;
        if dev
            .get_authenticator_info()
            .is_none_or(|i| i.options.pin_uv_auth_token != Some(true))
        {
            return Err(DeviceError::Ineligible);
        }
        let text =
            std::str::from_utf8(hello_pin.as_slice()).map_err(|_| DeviceError::PinRequired)?;
        let pin = Some(Pin::new(text));
        let start = Instant::now();
        let alive = || {
            !cancel.load(Ordering::Acquire) && start.elapsed() < Duration::from_millis(TIMEOUT_MS)
        };
        let rp = RP_ID.to_owned();
        let token = dev
            .get_pin_uv_auth_token_using_pin_with_permissions(
                &pin,
                PinUvAuthTokenPermission::GetAssertion,
                Some(&rp),
                &alive,
            )
            .map_err(|_| DeviceError::PinRequired)?;
        // Dropping the patched upstream token immediately wipes its secret bytes.
        drop(token);
        drop(pin);
        drop(dev);
        Ok(())
    }
}

impl FingerprintDevice {
    /// Prove the selected physical key owns an existing account credential during
    /// PIN-authorized management. No HMAC output is requested or released here.
    pub fn prove_credential_on(
        &self,
        path: &str,
        credential: &DeviceCredential,
        current_token_pin: &SecretBuffer,
        cancel: &AtomicBool,
    ) -> Result<(), DeviceError> {
        if cancel.load(Ordering::Acquire) {
            return Err(DeviceError::Cancelled);
        }
        let _guard = DEVICE_OWNER.try_lock().map_err(|_| DeviceError::Busy)?;
        let mut service = Self::service()?;
        let mut challenge = [0; 32];
        openssl::rand::rand_bytes(&mut challenge).map_err(|_| DeviceError::Transport)?;
        let pin = std::str::from_utf8(current_token_pin.as_slice())
            .map_err(|_| DeviceError::PinRequired)?;
        let (status_tx, status_rx) = channel();
        let (tx, rx) = channel();
        let args = SignArgs {
            client_data_hash: challenge,
            origin: format!("https://{RP_ID}"),
            relying_party_id: RP_ID.into(),
            allow_list: vec![PublicKeyCredentialDescriptor {
                id: credential.credential_id.clone(),
                transports: vec![Transport::USB],
            }],
            user_verification_req: UserVerificationRequirement::Required,
            user_presence_req: true,
            extensions: AuthenticationExtensionsClientInputs {
                local_device_path: Some(path.into()),
                local_pin_only: true,
                ..Default::default()
            },
            pin: Some(authenticator::Pin::new(pin)),
            internal_uv_only: false,
            use_ctap1_fallback: false,
        };
        service
            .sign(
                TIMEOUT_MS,
                args,
                status_tx,
                StateCallback::new(Box::new(move |r| {
                    let _ = tx.send(r);
                })),
            )
            .map_err(|_| DeviceError::Transport)?;
        let result = wait(&mut service, &rx, &status_rx, cancel, &mut |_| {})?;
        if result.extensions.hmac_get_secret.is_some() {
            return Err(DeviceError::InvalidAssertion);
        }
        verify_identity(credential, &result, &challenge)
    }
}
