//! Local Hello adapter: biometric secrets never cross the daemon protocol.
use super::*;
use crate::{
    db::KeyStoreTxn,
    fingerprint::{FingerprintBinding, FingerprintEnvelope},
    fingerprint_device::{DeviceCredential, DeviceError, DeviceProgress, FingerprintDevice},
    secret_memory::SecretBuffer,
    unix_proto::{FingerprintAction, FingerprintStatus, SecretPin},
};
use kanidm_hsm_crypto::structures::SealedData;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{atomic::AtomicBool, Arc};
use std::time::Instant;

#[derive(Serialize, Deserialize)]
struct Enrollment {
    credential: DeviceCredential,
    sealed: SealedData,
    binding: FingerprintBinding,
    #[serde(default)]
    template_id: Option<Vec<u8>>,
    #[serde(default)]
    template_ids: Vec<Vec<u8>>,
    #[serde(default)]
    device_path: String,
}
#[derive(Clone, Copy, PartialEq)]
enum Action {
    Authenticate,
    Enroll,
    Continue,
}
struct Retirement {
    credential: DeviceCredential,
    path: String,
    template_id: Vec<u8>,
    pin: SecretBuffer,
}
enum DeviceResult {
    Recovered,
    Fallback(u8),
    Pin(SecretBuffer, u8),
    Removed(Vec<u8>),
    Enrollment(Box<EnrollmentResult>),
}
struct EnrollmentResult {
    credential: DeviceCredential,
    envelope: FingerprintEnvelope,
    binding: FingerprintBinding,
    template_id: Vec<u8>,
    device_path: String,
    retirement: Option<Retirement>,
}
struct DeviceWorker {
    handle: tokio::task::JoinHandle<ResolverResult<DeviceResult>>,
    cancel: Arc<AtomicBool>,
    progress: Arc<std::sync::Mutex<String>>,
}
impl Drop for DeviceWorker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}
enum Preparation {
    TemplateChoice(String, Vec<Vec<u8>>),
    Choose(Vec<String>),
    Initialize(String),
    CurrentPin(String),
    Synchronize(String, SecretBuffer),
}
pub struct LocalHelloSession {
    inner: AuthSession,
    account_id: String,
    pin: Option<SecretBuffer>,
    typed: bool,
    action: Action,
    preparation: Option<Preparation>,
    management: Option<FingerprintAction>,
    worker: Option<DeviceWorker>,
    management_authorization: bool,
    selected_template: Option<Vec<u8>>,
    expires: Instant,
    pin_created: Option<Instant>,
    reservation: Option<String>,
    operation_binding: Option<FingerprintBinding>,
    authenticated_generation: Option<String>,
}
impl AuthSession {
    pub fn expire_fingerprint_secrets(&mut self) {
        if let Self::LocalHello(context) = self {
            if context.action == Action::Enroll
                && context.management.is_none()
                && context.inner.successful_account().is_some()
            {
                context.pin.take();
                context.worker.take();
                context.preparation.take();
                context.pin_created = None;
                context.expires = Instant::now();
                return;
            }
        }
        *self = Self::Denied;
    }
    pub fn fingerprint_secret_remaining(&self) -> Option<Duration> {
        let created = match self {
            Self::LocalHello(c) if c.pin.is_some() => c.pin_created,
            Self::HelloSuccess { created, .. } => Some(*created),
            _ => None,
        }?;
        Some(Duration::from_secs(60).saturating_sub(created.elapsed()))
    }
    pub fn secret_expired(&self) -> bool {
        match self {
            Self::LocalHello(c) => Instant::now() >= c.expires,
            Self::HelloSuccess { created, .. } => created.elapsed() > Duration::from_secs(60),
            _ => false,
        }
    }
    pub fn successful_account(&self) -> Option<&str> {
        match self {
            Self::Success(a) | Self::HelloSuccess { account_id: a, .. } => Some(a),
            _ => None,
        }
    }
    pub fn authentication_account(&self) -> Option<&str> {
        match self {
            Self::InProgress { account_id, .. }
            | Self::HelloSuccess { account_id, .. }
            | Self::Success(account_id) => Some(account_id),
            Self::LocalHello(c) => Some(&c.account_id),
            _ => None,
        }
    }
}
impl<I: IdProvider + Sync> Resolver<I> {
    pub fn fingerprint_force_pin(
        &self,
        session: &mut AuthSession,
        response: PamAuthResponse,
    ) -> PamAuthResponse {
        if let AuthSession::LocalHello(context) = session {
            context.management_authorization = true;
            if context.action == Action::Authenticate {
                context.action = Action::Continue;
                return PamAuthResponse::Pin;
            }
        }
        response
    }
    pub fn set_fingerprint_remote_services(&self, services: Vec<String>) {
        if let Ok(mut current) = self.fingerprint_remote_services.write() {
            *current = services;
        }
    }
    pub fn set_enable_hello_fingerprint(&self, enabled: bool) {
        self.fingerprint_enabled.store(enabled, Ordering::Release);
    }
    pub async fn fingerprint_status(&self, account: &str) -> ResolverResult<FingerprintStatus> {
        let mut txn = self.db.write().await;
        let enrollment: Option<Enrollment> = txn
            .get_tagged_hsm_key(&format!("{}/hello_fingerprint", account.to_lowercase()))
            .map_err(|_| ResolverError)?;
        let failures: u8 = txn
            .get_tagged_hsm_key(&format!("{}/fingerprint_failures", account.to_lowercase()))
            .map_err(|_| ResolverError)?
            .unwrap_or(0);
        let installed: Option<String> = txn
            .get_tagged_hsm_key("fingerprint_installation")
            .map_err(|_| ResolverError)?;
        let generation = Self::hello_generation(&mut txn, account)?;
        let enrolled = enrollment.is_some_and(|e| {
            Some(e.binding.installation_id) == installed
                && Some(e.binding.hello_generation) == generation
        });
        Ok(FingerprintStatus {
            enrolled,
            failures,
            pending: !enrolled,
        })
    }
    fn hello_generation<D: CacheTxn + KeyStoreTxn>(
        txn: &mut D,
        account: &str,
    ) -> ResolverResult<Option<String>> {
        let key: Option<serde_json::Value> = txn
            .get_tagged_hsm_key(&format!("{}/hello", account.to_lowercase()))
            .map_err(|_| ResolverError)?;
        let key = match key {
            Some(key) => Some(key),
            None => txn
                .get_tagged_hsm_key::<serde_json::Value>(&format!(
                    "{}/hello_decoupled",
                    account.to_lowercase()
                ))
                .map_err(|_| ResolverError)?,
        };
        let identity = txn
            .get_account(&Id::Name(account.to_owned()))
            .map_err(|_| ResolverError)?;
        let Some((key, (identity, _))) = key.zip(identity) else {
            return Ok(None);
        };
        let bytes = serde_json::to_vec(&(key, identity.uuid, identity.tenant_id))
            .map_err(|_| ResolverError)?;
        Ok(Some(
            Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        ))
    }
    async fn fingerprint_binding(
        &self,
        account: &str,
        credential_id: Vec<u8>,
    ) -> ResolverResult<FingerprintBinding> {
        let mut txn = self.db.write().await;
        // Hash the actual loadable Hello key. Replacing it invalidates old envelopes,
        // including a replacement performed outside this adapter.
        let generation = Self::hello_generation(&mut txn, account)?.ok_or(ResolverError)?;
        let installation: Option<String> = txn
            .get_tagged_hsm_key("fingerprint_installation")
            .map_err(|_| ResolverError)?;
        let installation_id = installation.unwrap_or_else(|| Uuid::new_v4().to_string());
        txn.insert_tagged_hsm_key("fingerprint_installation", &installation_id)
            .map_err(|_| ResolverError)?;
        txn.commit().map_err(|_| ResolverError)?;
        Ok(FingerprintBinding {
            account_id: account.to_lowercase(),
            credential_id,
            installation_id,
            hello_generation: generation,
        })
    }
    async fn fingerprint_failures(&self, account: &str, value: u8) -> ResolverResult<()> {
        let mut txn = self.db.write().await;
        txn.insert_tagged_hsm_key(
            &format!("{}/fingerprint_failures", account.to_lowercase()),
            &value,
        )
        .map_err(|_| ResolverError)?;
        if value == 0 {
            txn.delete_tagged_hsm_key(&format!(
                "{}/fingerprint_reservation",
                account.to_lowercase()
            ))
            .map_err(|_| ResolverError)?;
        }
        txn.commit().map_err(|_| ResolverError)
    }
    async fn finish_fingerprint_budget(
        &self,
        context: &mut LocalHelloSession,
        value: u8,
    ) -> ResolverResult<bool> {
        let Some(reservation) = context.reservation.take() else {
            return Ok(false);
        };
        let mut txn = self.db.write().await;
        let tag = format!(
            "{}/fingerprint_reservation",
            context.account_id.to_lowercase()
        );
        let current: Option<String> = txn.get_tagged_hsm_key(&tag).map_err(|_| ResolverError)?;
        if current.as_deref() != Some(reservation.as_str()) {
            return Ok(false);
        }
        txn.insert_tagged_hsm_key(
            &format!("{}/fingerprint_failures", context.account_id.to_lowercase()),
            &value,
        )
        .map_err(|_| ResolverError)?;
        txn.delete_tagged_hsm_key(&tag).map_err(|_| ResolverError)?;
        txn.commit().map_err(|_| ResolverError)?;
        Ok(true)
    }
    fn device_poll(msg: String) -> PamAuthResponse {
        PamAuthResponse::FingerprintWait { msg }
    }
    async fn start_enrollment(
        &self,
        context: &mut LocalHelloSession,
        path: String,
        current: Option<SecretBuffer>,
        initialize: bool,
        synchronize: bool,
    ) -> ResolverResult<PamAuthResponse> {
        let pin = SecretBuffer::from_slice(context.pin.as_ref().ok_or(ResolverError)?.as_slice())
            .map_err(|_| ResolverError)?;
        let binding = self
            .fingerprint_binding(&context.account_id, vec![0])
            .await?;
        if context.authenticated_generation.as_ref() != Some(&binding.hello_generation) {
            return Err(ResolverError);
        }
        let existing_credential = if matches!(
            context.management,
            Some(FingerprintAction::Add | FingerprintAction::Replace)
        ) {
            let mut txn = self.db.write().await;
            txn.get_tagged_hsm_key::<Enrollment>(&format!(
                "{}/hello_fingerprint",
                context.account_id.to_lowercase()
            ))
            .map_err(|_| ResolverError)?
            .map(|e| e.credential)
        } else {
            None
        };
        let account = context.account_id.clone();
        let retire = context
            .selected_template
            .clone()
            .filter(|_| matches!(context.management, Some(FingerprintAction::Replace)));
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let progress = Arc::new(std::sync::Mutex::new(
            "Touch the fingerprint sensor repeatedly to enroll your fingerprint.".to_owned(),
        ));
        let worker_progress = progress.clone();
        let handle = tokio::task::spawn_blocking(move || {
            let update = |event: DeviceProgress| {
                if let Ok(mut msg) = worker_progress.lock() {
                    *msg = match event {
                        DeviceProgress::TouchRequired => "Touch the fingerprint sensor.".into(),
                        DeviceProgress::SelectDevice => {
                            "Select your biometric security key.".into()
                        }
                        DeviceProgress::InvalidFingerprint { remaining } => {
                            format!("Fingerprint did not match. {remaining} attempts remain.")
                        }
                    };
                }
            };
            let device = FingerprintDevice::new();
            if let Some(credential) = existing_credential.as_ref() {
                device
                    .prove_credential_on(
                        &path,
                        credential,
                        current.as_ref().ok_or(ResolverError)?,
                        &worker_cancel,
                    )
                    .map_err(|_| ResolverError)?;
            }
            let retirement = if let Some(template_id) = retire {
                let cleanup_pin = if synchronize || initialize {
                    SecretBuffer::from_slice(pin.as_slice())
                } else {
                    SecretBuffer::from_slice(current.as_ref().ok_or(ResolverError)?.as_slice())
                }
                .map_err(|_| ResolverError)?;
                Some(Retirement {
                    credential: existing_credential.clone().ok_or(ResolverError)?,
                    path: path.clone(),
                    template_id,
                    pin: cleanup_pin,
                })
            } else {
                None
            };
            let template_id = device
                .prepare(
                    &path,
                    &pin,
                    current.as_ref(),
                    initialize,
                    synchronize,
                    &worker_cancel,
                    update,
                )
                .map_err(|_| ResolverError)?;
            let (credential, secret) = device
                .enroll_on(&path, &account, &worker_cancel, &update)
                .map_err(|_| ResolverError)?;
            let mut binding = binding;
            binding.credential_id = credential.credential_id.clone();
            let envelope =
                FingerprintEnvelope::encrypt(pin.as_slice(), secret.as_slice(), &binding)
                    .map_err(|_| ResolverError)?;
            drop(secret);
            if let Ok(mut msg) = worker_progress.lock() {
                *msg = "Verify the new fingerprint once more to complete enrollment.".into();
            }
            let verified = device
                .verify_on(&path, &credential, &worker_cancel, &update)
                .map_err(|_| ResolverError)?;
            let check = envelope
                .decrypt(verified.as_slice(), &binding)
                .map_err(|_| ResolverError)?;
            if check.as_slice() != pin.as_slice() {
                return Err(ResolverError);
            }
            Ok(DeviceResult::Enrollment(Box::new(EnrollmentResult {
                credential,
                envelope,
                binding,
                template_id,
                device_path: path,
                retirement,
            })))
        });
        context.worker = Some(DeviceWorker {
            handle,
            cancel,
            progress,
        });
        Ok(Self::device_poll(
            "Touch the fingerprint sensor repeatedly to enroll your fingerprint.".into(),
        ))
    }
    async fn start_unlock(
        &self,
        context: &mut LocalHelloSession,
    ) -> ResolverResult<PamAuthResponse> {
        let account = &context.account_id;
        let (enrollment, previous_failures) = {
            let mut txn = self.db.write().await;
            let failures: u8 = txn
                .get_tagged_hsm_key(&format!("{}/fingerprint_failures", account.to_lowercase()))
                .map_err(|_| ResolverError)?
                .unwrap_or(0);
            if failures >= 3 {
                return Err(ResolverError);
            }
            let enrollment: Enrollment = txn
                .get_tagged_hsm_key(&format!("{}/hello_fingerprint", account.to_lowercase()))
                .map_err(|_| ResolverError)?
                .ok_or(ResolverError)?;
            txn.insert_tagged_hsm_key(
                &format!("{}/fingerprint_failures", account.to_lowercase()),
                &3u8,
            )
            .map_err(|_| ResolverError)?;
            let reservation = Uuid::new_v4().to_string();
            txn.insert_tagged_hsm_key(
                &format!("{}/fingerprint_reservation", account.to_lowercase()),
                &reservation,
            )
            .map_err(|_| ResolverError)?;
            context.reservation = Some(reservation);
            txn.commit().map_err(|_| ResolverError)?;
            (enrollment, failures)
        };
        let expected = self
            .fingerprint_binding(account, enrollment.credential.credential_id.clone())
            .await?;
        if expected != enrollment.binding {
            return Err(ResolverError);
        }
        context.operation_binding = Some(expected.clone());
        let envelope = {
            let mut hsm = self.hsm.lock().await;
            let serialized = hsm
                .unseal_data(&self.machine_key, &enrollment.sealed)
                .map_err(|_| ResolverError)?;
            serde_json::from_slice::<FingerprintEnvelope>(&serialized).map_err(|_| ResolverError)?
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let progress = Arc::new(std::sync::Mutex::new(
            "Touch the fingerprint sensor on your security key.".to_owned(),
        ));
        let worker_progress = progress.clone();
        let credential = enrollment.credential;
        let handle = tokio::task::spawn_blocking(move || {
            let mut failures = previous_failures;
            let result = FingerprintDevice::new().verify_with_budget(
                &credential,
                3u8.saturating_sub(previous_failures),
                &worker_cancel,
                |event| {
                    if let DeviceProgress::InvalidFingerprint { .. } = event {
                        failures = failures.saturating_add(1);
                        if failures >= 3 {
                            worker_cancel.store(true, Ordering::Release);
                        }
                        if let Ok(mut msg) = worker_progress.lock() {
                            *msg = format!(
                                "Fingerprint did not match. {} attempts remain.",
                                3u8.saturating_sub(failures)
                            );
                        }
                    }
                },
            );
            let secret = match result {
                Ok(secret) => secret,
                Err(DeviceError::Locked | DeviceError::InvalidAssertion) => {
                    return Ok(DeviceResult::Fallback(3))
                }
                Err(_) => return Ok(DeviceResult::Fallback(failures.min(3))),
            };
            let pin = envelope
                .decrypt(secret.as_slice(), &expected)
                .map_err(|_| ResolverError)?;
            Ok(DeviceResult::Pin(pin, failures))
        });
        context.worker = Some(DeviceWorker {
            handle,
            cancel,
            progress,
        });
        Ok(Self::device_poll(
            "Touch the fingerprint sensor on your security key.".into(),
        ))
    }
    async fn save_enrollment(
        &self,
        account: &str,
        credential: DeviceCredential,
        envelope: FingerprintEnvelope,
        binding: FingerprintBinding,
        template_id: Vec<u8>,
        device_path: String,
    ) -> ResolverResult<()> {
        // Reject Hello-key changes while the user interacted with hardware.
        if self
            .fingerprint_binding(account, credential.credential_id.clone())
            .await?
            != binding
        {
            return Err(ResolverError);
        }
        let serialized = Zeroizing::new(serde_json::to_vec(&envelope).map_err(|_| ResolverError)?);
        let mut hsm = self.hsm.lock().await;
        let sealed = hsm
            .seal_data(&self.machine_key, serialized)
            .map_err(|_| ResolverError)?;
        let mut txn = self.db.write().await;
        let previous = txn
            .get_tagged_hsm_key::<Enrollment>(&format!(
                "{}/hello_fingerprint",
                account.to_lowercase()
            ))
            .map_err(|_| ResolverError)?;
        let mut template_ids = previous
            .map(|e| {
                let mut ids = e.template_ids;
                if let Some(id) = e.template_id {
                    if !ids.contains(&id) {
                        ids.push(id);
                    }
                }
                ids
            })
            .unwrap_or_default();
        if !template_ids.contains(&template_id) {
            template_ids.push(template_id.clone());
        }
        txn.insert_tagged_hsm_key(
            &format!("{}/hello_fingerprint", account.to_lowercase()),
            &Enrollment {
                credential,
                sealed,
                binding,
                template_id: Some(template_id),
                template_ids,
                device_path,
            },
        )
        .map_err(|_| ResolverError)?;
        txn.commit().map_err(|_| ResolverError)
    }
    pub async fn pam_account_authenticate_init(
        &self,
        account: &str,
        service: &str,
        no_hello_pin: bool,
        force_reauth: bool,
        shutdown: broadcast::Receiver<()>,
    ) -> ResolverResult<(AuthSession, PamAuthResponse)> {
        let (inner, mut response) = self
            .pam_account_authenticate_init_inner(
                account,
                service,
                no_hello_pin,
                force_reauth,
                shutdown,
            )
            .await?;
        let remote = service.starts_with("remote:")
            || self
                .fingerprint_remote_services
                .read()
                .map(|services| services.iter().any(|entry| service.contains(entry)))
                .unwrap_or(true);
        if remote
            || !self.fingerprint_enabled.load(Ordering::Acquire)
            || !matches!(inner, AuthSession::InProgress { .. })
        {
            return Ok((inner, response));
        }
        let action = if matches!(response, PamAuthResponse::Pin)
            && self
                .fingerprint_status(account)
                .await
                .is_ok_and(|s| s.enrolled && s.failures < 3)
        {
            response = PamAuthResponse::Fingerprint { enrollment: false };
            Action::Authenticate
        } else {
            Action::Continue
        };
        Ok((
            AuthSession::LocalHello(Box::new(LocalHelloSession {
                inner,
                account_id: account.to_owned(),
                pin: None,
                typed: false,
                action,
                preparation: None,
                management: None,
                worker: None,
                management_authorization: false,
                selected_template: None,
                expires: Instant::now() + Duration::from_secs(300),
                pin_created: None,
                reservation: None,
                operation_binding: None,
                authenticated_generation: None,
            })),
            response,
        ))
    }
    pub async fn pam_account_authenticate_step(
        &self,
        session: &mut AuthSession,
        request: PamAuthRequest,
    ) -> ResolverResult<PamAuthResponse> {
        let current = std::mem::replace(session, AuthSession::Denied);
        let AuthSession::LocalHello(mut context) = current else {
            *session = current;
            return self
                .pam_account_authenticate_step_inner(session, request)
                .await;
        };
        if Instant::now() >= context.expires
            || context
                .pin_created
                .is_some_and(|created| created.elapsed() > Duration::from_secs(60))
        {
            if context.action == Action::Enroll
                && context.management.is_none()
                && context.inner.successful_account().is_some()
            {
                context.pin.take();
                context.worker.take();
                context.preparation.take();
                return Ok(Self::finish_hello(session, *context));
            }
            return Ok(PamAuthResponse::Denied(
                "Authentication timed out. Sign in again.".into(),
            ));
        }
        if context.management.is_some() {
            let current = {
                let mut txn = self.db.write().await;
                Self::hello_generation(&mut txn, &context.account_id)?
            };
            if context.authenticated_generation.is_none()
                || current != context.authenticated_generation
            {
                return Ok(PamAuthResponse::Denied(
                    "Hello credentials changed. Authenticate again before managing fingerprints."
                        .into(),
                ));
            }
        }
        let mut recovered = false;
        let request = if context.worker.is_some() {
            if matches!(request, PamAuthRequest::FingerprintCancel) {
                context.worker.take();
                if context.action == Action::Authenticate {
                    context.action = Action::Continue;
                    *session = AuthSession::LocalHello(context);
                    return Ok(PamAuthResponse::Pin);
                }
                if context.management.is_some() {
                    return Ok(PamAuthResponse::Denied(
                        "Fingerprint management cancelled.".into(),
                    ));
                }
                return Ok(Self::finish_hello(session, *context));
            }
            if !matches!(request, PamAuthRequest::MFAPoll { .. }) {
                *session = AuthSession::LocalHello(context);
                return Err(ResolverError);
            }
            let worker = context.worker.as_ref().ok_or(ResolverError)?;
            if !worker.handle.is_finished() {
                let msg = worker
                    .progress
                    .lock()
                    .map(|m| m.clone())
                    .unwrap_or_else(|_| "Waiting for fingerprint verification.".into());
                *session = AuthSession::LocalHello(context);
                return Ok(Self::device_poll(msg));
            }
            let mut worker = context.worker.take().ok_or(ResolverError)?;
            let result = (&mut worker.handle).await.unwrap_or(Err(ResolverError));
            match result {
                Ok(DeviceResult::Fallback(failures)) => {
                    self.finish_fingerprint_budget(&mut context, failures)
                        .await?;
                    context.action = Action::Continue;
                    *session = AuthSession::LocalHello(context);
                    return Ok(PamAuthResponse::Pin);
                }
                Ok(DeviceResult::Pin(pin, failures)) => {
                    let budget_valid = self
                        .finish_fingerprint_budget(&mut context, failures.min(3))
                        .await?;
                    let binding_valid = if let Some(binding) = context.operation_binding.take() {
                        self.fingerprint_binding(&context.account_id, binding.credential_id.clone())
                            .await
                            .is_ok_and(|current| current == binding)
                    } else {
                        false
                    };
                    if !budget_valid || !binding_valid {
                        context.action = Action::Continue;
                        *session = AuthSession::LocalHello(context);
                        return Ok(PamAuthResponse::Pin);
                    }
                    context.action = Action::Continue;
                    recovered = true;
                    let cred = std::str::from_utf8(pin.as_slice())
                        .map_err(|_| ResolverError)?
                        .to_owned();
                    context.pin = Some(pin);
                    context.pin_created = Some(Instant::now());
                    PamAuthRequest::Pin { cred }
                }
                Ok(DeviceResult::Enrollment(enrollment)) => {
                    let EnrollmentResult {
                        credential,
                        envelope,
                        binding,
                        template_id,
                        device_path,
                        retirement,
                    } = *enrollment;
                    let result = self
                        .save_enrollment(
                            &context.account_id,
                            credential,
                            envelope,
                            binding,
                            template_id,
                            device_path,
                        )
                        .await;
                    if result.is_err() && context.management.is_some() {
                        return Ok(PamAuthResponse::Denied(
                            "Fingerprint enrollment could not be saved.".into(),
                        ));
                    }
                    if result.is_ok() {
                        if let Some(retirement) = retirement {
                            let response = self.start_template_removal(&mut context, retirement);
                            *session = AuthSession::LocalHello(context);
                            return Ok(response);
                        }
                    }
                    return Ok(Self::finish_hello(session, *context));
                }
                Ok(DeviceResult::Recovered) => return Ok(Self::finish_hello(session, *context)),
                Ok(DeviceResult::Removed(template_id)) => {
                    self.forget_template(&context.account_id, &template_id)
                        .await?;
                    return Ok(Self::finish_hello(session, *context));
                }
                Err(_) if context.action == Action::Authenticate => {
                    context.action = Action::Continue;
                    *session = AuthSession::LocalHello(context);
                    return Ok(PamAuthResponse::Pin);
                }
                Err(_) if context.management.is_some() => {
                    return Ok(PamAuthResponse::Denied(
                        "Fingerprint management failed.".into(),
                    ))
                }
                Err(_) => return Ok(Self::finish_hello(session, *context)),
            }
        } else if context.action == Action::Enroll {
            let response = self
                .fingerprint_enrollment_step(&mut context, request)
                .await;
            match response {
                Ok(Some(response)) => {
                    *session = AuthSession::LocalHello(context);
                    return Ok(response);
                }
                Err(_) if context.management.is_some() => {
                    return Ok(PamAuthResponse::Denied(
                        "Fingerprint management failed.".into(),
                    ))
                }
                Ok(None) if context.management.is_some() => {
                    *session = AuthSession::Success(context.account_id);
                    return Ok(PamAuthResponse::Success);
                }
                _ => return Ok(Self::finish_hello(session, *context)),
            }
        } else if context.action == Action::Authenticate {
            match request {
                PamAuthRequest::Fingerprint => match self.start_unlock(&mut context).await {
                    Ok(response) => {
                        *session = AuthSession::LocalHello(context);
                        return Ok(response);
                    }
                    Err(_) => {
                        context.action = Action::Continue;
                        *session = AuthSession::LocalHello(context);
                        return Ok(PamAuthResponse::Pin);
                    }
                },
                PamAuthRequest::FingerprintCancel => {
                    context.action = Action::Continue;
                    *session = AuthSession::LocalHello(context);
                    return Ok(PamAuthResponse::Pin);
                }
                other => {
                    context.action = Action::Continue;
                    other
                }
            }
        } else {
            request
        };
        if let PamAuthRequest::Pin { cred } | PamAuthRequest::SetupPin { pin: cred } = &request {
            if !recovered {
                context.pin = SecretBuffer::from_slice(cred.as_bytes()).ok();
                context.pin_created = Some(Instant::now());
                context.typed = true;
            }
        }
        let response = self
            .pam_account_authenticate_step_inner(&mut context.inner, request)
            .await?;
        if matches!(
            response,
            PamAuthResponse::Denied(_)
                | PamAuthResponse::Unknown
                | PamAuthResponse::InitDenied { .. }
        ) {
            *session = context.inner;
            return Ok(response);
        }
        if matches!(response, PamAuthResponse::Success) {
            if context.typed {
                let mut txn = self.db.write().await;
                context.authenticated_generation =
                    Self::hello_generation(&mut txn, &context.account_id)?;
            }
            if context.typed {
                self.fingerprint_failures(&context.account_id, 0).await?;
            }
            if !context.management_authorization
                && context.pin.is_some()
                && context.typed
                && self
                    .fingerprint_status(&context.account_id)
                    .await
                    .is_ok_and(|s| !s.enrolled)
                && tokio::task::spawn_blocking(FingerprintDevice::available)
                    .await
                    .unwrap_or(false)
            {
                context.action = Action::Enroll;
                *session = AuthSession::LocalHello(context);
                return Ok(PamAuthResponse::Fingerprint { enrollment: true });
            }
            return Ok(Self::finish_hello(session, *context));
        }
        *session = AuthSession::LocalHello(context);
        Ok(response)
    }
    fn finish_hello(session: &mut AuthSession, mut context: LocalHelloSession) -> PamAuthResponse {
        if context.management.is_some() {
            *session = AuthSession::Success(context.account_id);
            return PamAuthResponse::Success;
        }
        if let Some(pin) = context.pin.take() {
            let response = if !context.typed {
                match std::str::from_utf8(pin.as_slice()) {
                    Ok(s) => PamAuthResponse::SuccessWithPin {
                        pin: SecretPin::new(s.to_owned()),
                    },
                    Err(_) => {
                        *session = AuthSession::Denied;
                        return PamAuthResponse::Denied(
                            "Fingerprint credential is invalid.".into(),
                        );
                    }
                }
            } else {
                PamAuthResponse::Success
            };
            if context.management_authorization && context.typed {
                *session = AuthSession::HelloSuccess {
                    account_id: context.account_id,
                    pin,
                    typed: true,
                    created: context.pin_created.unwrap_or_else(Instant::now),
                    generation: context.authenticated_generation,
                };
            } else {
                *session = AuthSession::Success(context.account_id);
            }
            response
        } else {
            *session = context.inner;
            PamAuthResponse::Success
        }
    }
    async fn fingerprint_enrollment_step(
        &self,
        context: &mut LocalHelloSession,
        request: PamAuthRequest,
    ) -> ResolverResult<Option<PamAuthResponse>> {
        fn input(msg: String, echo_on: bool) -> Option<PamAuthResponse> {
            Some(PamAuthResponse::FingerprintInput { msg, echo_on })
        }
        if matches!(request, PamAuthRequest::FingerprintCancel) {
            return if context.management.is_some() {
                Err(ResolverError)
            } else {
                Ok(None)
            };
        }
        let preparation = context.preparation.take();
        let (path, current, initialize, synchronize) = match preparation {
            None => {
                if !matches!(request, PamAuthRequest::Fingerprint) {
                    return Err(ResolverError);
                }
                let paths = tokio::task::spawn_blocking(FingerprintDevice::discover)
                    .await
                    .map_err(|_| ResolverError)?;
                if paths.is_empty() {
                    return Ok(None);
                }
                if paths.len() > 1 || matches!(context.management, Some(FingerprintAction::Recover))
                {
                    let msg = format!(
                        "Select a biometric security key by number (or cancel):\n{}",
                        paths
                            .iter()
                            .enumerate()
                            .map(|(i, p)| format!("{}: {}", i + 1, p))
                            .collect::<Vec<_>>()
                            .join("\n")
                    );
                    context.preparation = Some(Preparation::Choose(paths));
                    return Ok(input(msg, true));
                }
                return self
                    .fingerprint_prepare_prompt(context, paths[0].clone())
                    .await;
            }
            Some(Preparation::TemplateChoice(path, templates)) => {
                let PamAuthRequest::Input { cred } = request else {
                    return Err(ResolverError);
                };
                let Some(template) = cred
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|i| templates.get(i))
                    .cloned()
                else {
                    return Err(ResolverError);
                };
                context.selected_template = Some(template);
                return self.fingerprint_prepare_prompt(context, path).await;
            }
            Some(Preparation::Choose(paths)) => {
                let PamAuthRequest::Input { cred } = request else {
                    return Err(ResolverError);
                };
                let Some(path) = cred
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|i| paths.get(i))
                    .cloned()
                else {
                    return Err(ResolverError);
                };
                return self.fingerprint_prepare_prompt(context, path).await;
            }
            Some(Preparation::Initialize(path)) => {
                let PamAuthRequest::Input { cred } = request else {
                    return Err(ResolverError);
                };
                if !cred.trim().eq_ignore_ascii_case("yes") {
                    return if context.management.is_some() {
                        Err(ResolverError)
                    } else {
                        Ok(None)
                    };
                }
                (path, None, true, false)
            }
            Some(Preparation::CurrentPin(path)) => {
                let PamAuthRequest::Input { mut cred } = request else {
                    return Err(ResolverError);
                };
                let cred = Zeroizing::new(std::mem::take(&mut cred));
                let pin = SecretBuffer::from_slice(cred.as_bytes()).map_err(|_| ResolverError)?;
                if matches!(context.management, Some(FingerprintAction::Recover)) {
                    let cancel = Arc::new(AtomicBool::new(false));
                    let worker_cancel = cancel.clone();
                    let progress = Arc::new(std::sync::Mutex::new(
                        "Recovering the selected biometric security key.".into(),
                    ));
                    let handle = tokio::task::spawn_blocking(move || {
                        FingerprintDevice::new()
                            .unblock_on(&path, &pin, &worker_cancel)
                            .map_err(|_| ResolverError)?;
                        Ok(DeviceResult::Recovered)
                    });
                    context.worker = Some(DeviceWorker {
                        handle,
                        cancel,
                        progress,
                    });
                    return Ok(Some(Self::device_poll(
                        "Recovering the selected biometric security key.".into(),
                    )));
                }
                if matches!(context.management, Some(FingerprintAction::Remove)) {
                    let template_id = context.selected_template.clone().ok_or(ResolverError)?;
                    let credential = {
                        let mut txn = self.db.write().await;
                        txn.get_tagged_hsm_key::<Enrollment>(&format!(
                            "{}/hello_fingerprint",
                            context.account_id.to_lowercase()
                        ))
                        .map_err(|_| ResolverError)?
                        .ok_or(ResolverError)?
                        .credential
                    };
                    return Ok(Some(self.start_template_removal(
                        context,
                        Retirement {
                            credential,
                            path,
                            template_id,
                            pin,
                        },
                    )));
                }
                context.preparation = Some(Preparation::Synchronize(path, pin));
                return Ok(input("Synchronize this security key's PIN to your Hello PIN? This changes the PIN for its other uses. Type yes to synchronize, or no to keep its current PIN.".into(),true));
            }
            Some(Preparation::Synchronize(path, pin)) => {
                let PamAuthRequest::Input { cred } = request else {
                    return Err(ResolverError);
                };
                if !cred.trim().eq_ignore_ascii_case("yes")
                    && !cred.trim().eq_ignore_ascii_case("no")
                {
                    return Ok(None);
                }
                (
                    path,
                    Some(pin),
                    false,
                    cred.trim().eq_ignore_ascii_case("yes"),
                )
            }
        };
        let pin = context.pin.as_ref().ok_or(ResolverError)?;
        let _ = pin;
        Ok(Some(
            self.start_enrollment(context, path, current, initialize, synchronize)
                .await?,
        ))
    }
    async fn fingerprint_prepare_prompt(
        &self,
        context: &mut LocalHelloSession,
        path: String,
    ) -> ResolverResult<Option<PamAuthResponse>> {
        if context.selected_template.is_none()
            && matches!(
                context.management,
                Some(FingerprintAction::Replace | FingerprintAction::Remove)
            )
        {
            let enrollment = {
                let mut txn = self.db.write().await;
                txn.get_tagged_hsm_key::<Enrollment>(&format!(
                    "{}/hello_fingerprint",
                    context.account_id.to_lowercase()
                ))
                .map_err(|_| ResolverError)?
                .ok_or(ResolverError)?
            };
            let mut templates = enrollment.template_ids;
            if let Some(id) = enrollment.template_id {
                if !templates.contains(&id) {
                    templates.push(id);
                }
            }
            if templates.is_empty() {
                return Err(ResolverError);
            }
            if templates.len() > 1 {
                let count = templates.len();
                context.preparation = Some(Preparation::TemplateChoice(path, templates));
                return Ok(Some(PamAuthResponse::FingerprintInput {msg:format!("Choose the enrolled fingerprint to replace or remove (1-{count}, in enrollment order)."),echo_on:true}));
            }
            context.selected_template = templates.into_iter().next();
        }
        let probe_path = path.clone();
        let configured = tokio::task::spawn_blocking(move || {
            FingerprintDevice::token_pin_configured(&probe_path)
        })
        .await
        .map_err(|_| ResolverError)?
        .map_err(|_| ResolverError)?;
        if !configured
            && matches!(
                context.management,
                Some(FingerprintAction::Recover | FingerprintAction::Remove)
            )
        {
            return Err(ResolverError);
        }
        let msg = if configured {
            context.preparation = Some(Preparation::CurrentPin(path));
            "Use a personal security key. Any fingerprint enrolled on this key can unlock this account. Enter its current PIN (use your Hello PIN if synchronized)."
        } else {
            context.preparation = Some(Preparation::Initialize(path));
            "Use a personal security key. Any fingerprint enrolled on this key can unlock this account. Initialize it using your Hello PIN? This configures its PIN for other uses too. Type yes to continue or no to postpone."
        };
        Ok(Some(PamAuthResponse::FingerprintInput {
            msg: msg.into(),
            echo_on: !configured,
        }))
    }
    fn start_template_removal(
        &self,
        context: &mut LocalHelloSession,
        retirement: Retirement,
    ) -> PamAuthResponse {
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let progress = Arc::new(std::sync::Mutex::new(
            "Removing the selected fingerprint.".into(),
        ));
        let handle = tokio::task::spawn_blocking(move || {
            FingerprintDevice::new()
                .prove_credential_on(
                    &retirement.path,
                    &retirement.credential,
                    &retirement.pin,
                    &worker_cancel,
                )
                .map_err(|_| ResolverError)?;
            FingerprintDevice::new()
                .remove_managed(
                    &retirement.path,
                    &retirement.template_id,
                    &retirement.pin,
                    &worker_cancel,
                )
                .map_err(|_| ResolverError)?;
            Ok(DeviceResult::Removed(retirement.template_id))
        });
        context.worker = Some(DeviceWorker {
            handle,
            cancel,
            progress,
        });
        Self::device_poll("Removing the selected fingerprint.".into())
    }
    async fn forget_template(&self, account: &str, template_id: &[u8]) -> ResolverResult<()> {
        let mut txn = self.db.write().await;
        let tag = format!("{}/hello_fingerprint", account.to_lowercase());
        let mut enrollment = txn
            .get_tagged_hsm_key::<Enrollment>(&tag)
            .map_err(|_| ResolverError)?
            .ok_or(ResolverError)?;
        enrollment.template_ids.retain(|id| id != template_id);
        if enrollment.template_id.as_deref() == Some(template_id) {
            enrollment.template_id = enrollment.template_ids.first().cloned();
        }
        if enrollment.template_ids.is_empty() && enrollment.template_id.is_none() {
            txn.delete_tagged_hsm_key(&tag).map_err(|_| ResolverError)?;
        } else {
            txn.insert_tagged_hsm_key(&tag, &enrollment)
                .map_err(|_| ResolverError)?;
        }
        txn.commit().map_err(|_| ResolverError)
    }
    pub async fn fingerprint_manage(
        &self,
        session: &mut AuthSession,
        account: &str,
        action: FingerprintAction,
    ) -> ResolverResult<PamAuthResponse> {
        if !self.fingerprint_enabled.load(Ordering::Acquire) {
            return Err(ResolverError);
        }
        let current = std::mem::replace(session, AuthSession::Denied);
        let AuthSession::HelloSuccess {
            account_id,
            pin,
            typed: true,
            created,
            generation,
        } = current
        else {
            return Err(ResolverError);
        };
        if account_id.to_lowercase() != account.to_lowercase()
            || created.elapsed() > Duration::from_secs(60)
        {
            return Err(ResolverError);
        }
        let current_generation = {
            let mut txn = self.db.write().await;
            Self::hello_generation(&mut txn, account)?
        };
        if generation.is_none() || generation != current_generation {
            return Err(ResolverError);
        }
        *session = AuthSession::LocalHello(Box::new(LocalHelloSession {
            inner: AuthSession::Success(account_id.clone()),
            account_id,
            pin: Some(pin),
            typed: true,
            action: Action::Enroll,
            preparation: None,
            management: Some(action),
            worker: None,
            management_authorization: false,
            selected_template: None,
            expires: Instant::now() + Duration::from_secs(300),
            pin_created: Some(created),
            reservation: None,
            operation_binding: None,
            authenticated_generation: generation,
        }));
        Ok(PamAuthResponse::Fingerprint { enrollment: true })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::setup_resolver;
    use super::*;
    fn context(typed: bool) -> LocalHelloSession {
        LocalHelloSession {
            inner: AuthSession::Success("testuser@example.com".into()),
            account_id: "testuser@example.com".into(),
            pin: Some(SecretBuffer::from_slice(b"123456").unwrap()),
            typed,
            action: Action::Continue,
            preparation: None,
            management: None,
            worker: None,
            management_authorization: false,
            selected_template: None,
            expires: Instant::now() + Duration::from_secs(300),
            pin_created: None,
            reservation: None,
            operation_binding: None,
            authenticated_generation: None,
        }
    }
    #[tokio::test]
    async fn management_requires_completed_typed_pin_on_same_session() {
        let resolver = setup_resolver().await;
        resolver.set_enable_hello_fingerprint(true);
        let mut session = AuthSession::Success("testuser@example.com".into());
        assert!(resolver
            .fingerprint_manage(&mut session, "testuser@example.com", FingerprintAction::Add)
            .await
            .is_err());
        let mut session = AuthSession::HelloSuccess {
            account_id: "testuser@example.com".into(),
            pin: SecretBuffer::from_slice(b"123456").unwrap(),
            typed: false,
            created: Instant::now(),
            generation: None,
        };
        assert!(resolver
            .fingerprint_manage(&mut session, "testuser@example.com", FingerprintAction::Add)
            .await
            .is_err());
        let mut session = AuthSession::HelloSuccess {
            account_id: "testuser@example.com".into(),
            pin: SecretBuffer::from_slice(b"123456").unwrap(),
            typed: true,
            created: Instant::now() - Duration::from_secs(61),
            generation: None,
        };
        assert!(resolver
            .fingerprint_manage(&mut session, "testuser@example.com", FingerprintAction::Add)
            .await
            .is_err());
    }
    #[tokio::test]
    async fn management_consumes_capability_and_never_returns_pin() {
        let resolver = setup_resolver().await;
        let mut session = AuthSession::Denied;
        let mut context = context(true);
        context.management = Some(FingerprintAction::Add);
        assert!(matches!(
            Resolver::<super::super::tests::OfflineFallbackProvider>::finish_hello(
                &mut session,
                context
            ),
            PamAuthResponse::Success
        ));
        assert!(matches!(session, AuthSession::Success(_)));
        drop(resolver);
    }
    #[tokio::test]
    async fn biometric_pin_only_released_on_completed_success() {
        let _resolver = setup_resolver().await;
        let mut session = AuthSession::Denied;
        let response = Resolver::<super::super::tests::OfflineFallbackProvider>::finish_hello(
            &mut session,
            context(false),
        );
        assert!(matches!(response,PamAuthResponse::SuccessWithPin {pin} if pin.as_str()=="123456"));
        assert!(matches!(session, AuthSession::Success(_)));
    }
    #[tokio::test]
    async fn persistent_budget_status_is_not_session_local() {
        let resolver = setup_resolver().await;
        resolver
            .fingerprint_failures("testuser@example.com", 3)
            .await
            .unwrap();
        assert_eq!(
            resolver
                .fingerprint_status("testuser@example.com")
                .await
                .unwrap()
                .failures,
            3
        );
        resolver
            .fingerprint_failures("testuser@example.com", 0)
            .await
            .unwrap();
        assert_eq!(
            resolver
                .fingerprint_status("testuser@example.com")
                .await
                .unwrap()
                .failures,
            0
        );
    }
    #[tokio::test]
    async fn cancellation_drops_worker_and_preserves_pin_fallback() {
        let resolver = setup_resolver().await;
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let mut context = context(false);
        context.pin = None;
        context.action = Action::Authenticate;
        context.worker = Some(DeviceWorker {
            handle: tokio::task::spawn_blocking(move || {
                while !worker_cancel.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(ResolverError)
            }),
            cancel: cancel.clone(),
            progress: Arc::new(std::sync::Mutex::new(String::new())),
        });
        let mut session = AuthSession::LocalHello(Box::new(context));
        assert!(matches!(
            resolver
                .pam_account_authenticate_step(&mut session, PamAuthRequest::FingerprintCancel)
                .await
                .unwrap(),
            PamAuthResponse::Pin
        ));
        assert!(cancel.load(Ordering::Acquire));
    }
    async fn seed_hello(
        resolver: &Resolver<super::super::tests::OfflineFallbackProvider>,
        generation: &str,
    ) {
        let mut txn = resolver.db.write().await;
        txn.insert_tagged_hsm_key(
            "testuser@example.com/hello",
            &serde_json::json!({"test_generation":generation}),
        )
        .unwrap();
        txn.commit().unwrap();
    }
    async fn save_test_enrollment(
        resolver: &Resolver<super::super::tests::OfflineFallbackProvider>,
        template: u8,
    ) {
        let credential = DeviceCredential {
            credential_id: vec![template],
            public_key_der: vec![1, 2, 3],
            salt: [0; 32],
        };
        let binding = resolver
            .fingerprint_binding("testuser@example.com", credential.credential_id.clone())
            .await
            .unwrap();
        let envelope = FingerprintEnvelope::encrypt(b"123456", &[7; 32], &binding).unwrap();
        resolver
            .save_enrollment(
                "testuser@example.com",
                credential,
                envelope,
                binding,
                vec![template],
                "/dev/hidraw-test".into(),
            )
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn changed_hello_key_makes_enrollment_pending() {
        let resolver = setup_resolver().await;
        seed_hello(&resolver, "first").await;
        save_test_enrollment(&resolver, 1).await;
        assert!(
            resolver
                .fingerprint_status("testuser@example.com")
                .await
                .unwrap()
                .enrolled
        );
        seed_hello(&resolver, "replacement").await;
        let status = resolver
            .fingerprint_status("testuser@example.com")
            .await
            .unwrap();
        assert!(!status.enrolled);
        assert!(status.pending);
    }
    #[tokio::test]
    async fn adding_keeps_existing_templates_and_removal_only_forgets_selected() {
        let resolver = setup_resolver().await;
        seed_hello(&resolver, "first").await;
        save_test_enrollment(&resolver, 1).await;
        save_test_enrollment(&resolver, 2).await;
        {
            let mut txn = resolver.db.write().await;
            let record: Enrollment = txn
                .get_tagged_hsm_key("testuser@example.com/hello_fingerprint")
                .unwrap()
                .unwrap();
            assert_eq!(record.template_ids, vec![vec![1], vec![2]]);
        }
        resolver
            .forget_template("testuser@example.com", &[1])
            .await
            .unwrap();
        assert!(
            resolver
                .fingerprint_status("testuser@example.com")
                .await
                .unwrap()
                .enrolled
        );
        resolver
            .forget_template("testuser@example.com", &[2])
            .await
            .unwrap();
        assert!(
            resolver
                .fingerprint_status("testuser@example.com")
                .await
                .unwrap()
                .pending
        );
    }
    #[tokio::test]
    async fn stale_worker_cannot_refund_new_reservation() {
        let resolver = setup_resolver().await;
        let mut context = context(false);
        context.reservation = Some("stale-worker".into());
        {
            let mut txn = resolver.db.write().await;
            txn.insert_tagged_hsm_key(
                "testuser@example.com/fingerprint_reservation",
                &"new-worker",
            )
            .unwrap();
            txn.insert_tagged_hsm_key("testuser@example.com/fingerprint_failures", &3u8)
                .unwrap();
            txn.commit().unwrap();
        }
        assert!(!resolver
            .finish_fingerprint_budget(&mut context, 0)
            .await
            .unwrap());
        assert_eq!(
            resolver
                .fingerprint_status("testuser@example.com")
                .await
                .unwrap()
                .failures,
            3
        );
    }
    #[tokio::test]
    async fn enrollment_timeout_wipes_pin_and_preserves_completed_login() {
        let resolver = setup_resolver().await;
        let mut context = context(true);
        context.action = Action::Enroll;
        context.pin_created = Some(Instant::now() - Duration::from_secs(61));
        let mut session = AuthSession::LocalHello(Box::new(context));
        session.expire_fingerprint_secrets();
        assert!(session.fingerprint_secret_remaining().is_none());
        assert!(matches!(
            resolver
                .pam_account_authenticate_step(
                    &mut session,
                    PamAuthRequest::MFAPoll { poll_attempt: 0 }
                )
                .await
                .unwrap(),
            PamAuthResponse::Success
        ));
        assert!(matches!(session, AuthSession::Success(_)));
    }
    #[tokio::test]
    async fn management_timeout_revokes_instead_of_completing_login() {
        let mut context = context(true);
        context.action = Action::Enroll;
        context.management = Some(FingerprintAction::Add);
        let mut session = AuthSession::LocalHello(Box::new(context));
        session.expire_fingerprint_secrets();
        assert!(matches!(session, AuthSession::Denied));
    }
    #[tokio::test]
    async fn user_cancel_autoenrollment_preserves_login_pending() {
        let resolver = setup_resolver().await;
        let mut context = context(true);
        context.action = Action::Enroll;
        let mut session = AuthSession::LocalHello(Box::new(context));
        assert!(matches!(
            resolver
                .pam_account_authenticate_step(&mut session, PamAuthRequest::FingerprintCancel)
                .await
                .unwrap(),
            PamAuthResponse::Success
        ));
        assert!(
            resolver
                .fingerprint_status("testuser@example.com")
                .await
                .unwrap()
                .pending
        );
    }
    #[tokio::test]
    async fn hello_reset_revokes_management_grant_before_hardware_use() {
        let resolver = setup_resolver().await;
        resolver.set_enable_hello_fingerprint(true);
        seed_hello(&resolver, "first").await;
        let generation = {
            let mut txn = resolver.db.write().await;
            Resolver::<super::super::tests::OfflineFallbackProvider>::hello_generation(
                &mut txn,
                "testuser@example.com",
            )
            .unwrap()
        };
        let mut session = AuthSession::HelloSuccess {
            account_id: "testuser@example.com".into(),
            pin: SecretBuffer::from_slice(b"123456").unwrap(),
            typed: true,
            created: Instant::now(),
            generation,
        };
        resolver
            .fingerprint_manage(&mut session, "testuser@example.com", FingerprintAction::Add)
            .await
            .unwrap();
        seed_hello(&resolver, "replacement").await;
        assert!(matches!(
            resolver
                .pam_account_authenticate_step(&mut session, PamAuthRequest::Fingerprint)
                .await
                .unwrap(),
            PamAuthResponse::Denied(_)
        ));
        assert!(matches!(session, AuthSession::Denied));
    }
}
