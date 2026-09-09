/* Native OIDC Interaction Code provider.
 * Copyright (C) David Mulder <dmulder@samba.org> 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#[cfg(test)]
mod access_tests;
mod diagnostics;
mod error;
mod forms;

use super::common::{
    flip_displayname_comma, oidc_issuer_matches, oidc_user_token_from_claims,
    should_block_hello_pin_attempts, BadPinCounter, KeyType, RefreshCache, RefreshCacheEntry,
    TotpEnrollmentRecord,
};
use super::interface::{
    tpm, AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, CacheState, GroupToken, Id,
    IdProvider, IdpError, UserToken, UserTokenState,
};
use super::openidconnect::OidcProvider;
use crate::config::HimmelblauConfig;
use crate::constants::{EDGE_BROWSER_CLIENT_ID, ID_MAP_CACHE};
use crate::db::KeyStoreTxn;
use crate::i18n::tr;
use crate::idmap_cache::StaticIdCache;
use crate::unix_proto::PamAuthRequest;
use crate::{
    check_hello_totp_enabled, check_hello_totp_setup, handle_hello_bad_pin_count,
    impl_handle_hello_pin_totp_auth, impl_himmelblau_hello_key_helpers,
    impl_himmelblau_offline_auth_init, impl_himmelblau_offline_auth_step,
    impl_himmelblau_try_unseal, impl_offline_break_glass, impl_setup_hello_totp,
    load_cached_prt_for_try_unseal_no_op, load_cached_prt_no_op,
};
use async_trait::async_trait;
use error::{classify, FailureAction};
use forms::{FlowPolicy, Form, Next};
use himmelblau::{ClientInfo, IdToken, UserToken as UnixUserToken};
use idmap::Idmap;
use kanidm_hsm_crypto::{
    structures::{LoadableMsHelloKey, SealedData},
    PinValue,
};
use okta::{
    AuthFlow, AuthOptions, AuthStatus, ClientConfig, OktaError, PublicClientApplication,
    RefreshCredential,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, Mutex, OnceCell};
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;
use zeroize::Zeroizing;

const OIDC_NAMESPACE: Uuid = uuid::uuid!("e669513b-1345-4853-96a7-596243184319");
const SESSION_LIFETIME: Duration = Duration::from_secs(10 * 60);

fn with_password_cache_action(
    result: AuthResult,
    password: &mut Option<Zeroizing<String>>,
    enabled: bool,
) -> (AuthResult, AuthCacheAction) {
    let action = match &result {
        AuthResult::Success { .. } | AuthResult::Next(AuthRequest::SetupPin { .. }) => password
            .take()
            .filter(|_| enabled)
            .map(|cred| AuthCacheAction::PasswordHashUpdate {
                cred: cred.to_string(),
            })
            .unwrap_or(AuthCacheAction::None),
        AuthResult::Denied(_) => {
            *password = None;
            AuthCacheAction::None
        }
        // The password must survive local TOTP authentication/enrollment, but
        // the resolver rejects password writes paired with these prompts.
        AuthResult::Next(_) => AuthCacheAction::None,
    };
    (result, action)
}

/// The SDK flow and its secret form data belong to a single PAM connection.
/// Never serialize this into Entra's MFA state or persist it in the database.
pub struct NativeAuthSession {
    client: Arc<PublicClientApplication>,
    flow: AuthFlow,
    form: Form,
    account: String,
    origin: String,
    remote: bool,
    policy: FlowPolicy,
    deadline: tokio::time::Instant,
    password: Option<Zeroizing<String>>,
    reauth_pin: Option<Zeroizing<String>>,
    pending: Option<UserToken>,
    phase: LocalPhase,
}

enum LocalPhase {
    Native,
    SetupPin,
    Acknowledge,
    Totp {
        pin: Zeroizing<String>,
        pending: Option<SealedData>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn success() -> AuthResult {
        AuthResult::Success {
            token: UserToken {
                name: "user@example.com".into(),
                spn: "user@example.com".into(),
                uuid: Uuid::nil(),
                real_gidnumber: None,
                gidnumber: 1000,
                displayname: "Test User".into(),
                shell: None,
                groups: vec![],
                tenant_id: None,
                valid: true,
            },
        }
    }

    #[test]
    fn password_cache_waits_for_totp_and_emits_only_once() {
        for prompt in [
            "Enter your Hello TOTP code",
            "Enroll and confirm your Hello TOTP code",
        ] {
            let mut password = Some(Zeroizing::new("accepted password".into()));
            let (result, action) = with_password_cache_action(
                AuthResult::Next(AuthRequest::HelloTOTP { msg: prompt.into() }),
                &mut password,
                true,
            );
            assert!(matches!(
                result,
                AuthResult::Next(AuthRequest::HelloTOTP { .. })
            ));
            assert!(matches!(action, AuthCacheAction::None));
            assert!(password.is_some());

            let (result, action) = with_password_cache_action(success(), &mut password, true);
            assert!(matches!(result, AuthResult::Success { .. }));
            assert!(
                matches!(action, AuthCacheAction::PasswordHashUpdate { cred } if cred == "accepted password")
            );
            assert!(password.is_none());
            let (_, action) = with_password_cache_action(success(), &mut password, true);
            assert!(matches!(action, AuthCacheAction::None));
        }
    }

    #[test]
    fn denied_totp_discards_password_without_caching() {
        let mut password = Some(Zeroizing::new("accepted password".into()));
        let (result, action) = with_password_cache_action(
            AuthResult::Denied("Invalid TOTP".into()),
            &mut password,
            true,
        );
        assert!(matches!(result, AuthResult::Denied(_)));
        assert!(matches!(action, AuthCacheAction::None));
        assert!(password.is_none());
    }

    #[test]
    fn disabled_breakglass_does_not_cache_after_totp() {
        let mut password = Some(Zeroizing::new("accepted password".into()));
        let (_, action) = with_password_cache_action(success(), &mut password, false);
        assert!(matches!(action, AuthCacheAction::None));
        assert!(password.is_none());
    }

    #[test]
    fn setup_pin_keeps_existing_password_cache_behavior() {
        let mut password = Some(Zeroizing::new("accepted password".into()));
        let (_, action) = with_password_cache_action(
            AuthResult::Next(AuthRequest::SetupPin {
                msg: "Set up a PIN".into(),
            }),
            &mut password,
            true,
        );
        assert!(matches!(action, AuthCacheAction::PasswordHashUpdate { .. }));
        assert!(password.is_none());
        let (_, action) = with_password_cache_action(success(), &mut password, true);
        assert!(matches!(action, AuthCacheAction::None));
    }
    struct EmptyKeyStore;
    impl KeyStoreTxn for EmptyKeyStore {
        fn get_tagged_hsm_key<K: serde::de::DeserializeOwned>(
            &mut self,
            _: &str,
        ) -> Result<Option<K>, crate::db::CacheError> {
            Ok(None)
        }
        fn insert_tagged_hsm_key<K: serde::Serialize>(
            &mut self,
            _: &str,
            _: &K,
        ) -> Result<(), crate::db::CacheError> {
            panic!("offline init must not write credentials")
        }
        fn delete_tagged_hsm_key(&mut self, _: &str) -> Result<(), crate::db::CacheError> {
            panic!("offline init must not delete credentials")
        }
    }

    async fn offline_prompt(breakglass: bool, sfa: bool, no_hello_pin: bool) -> AuthRequest {
        let mut cfg = HimmelblauConfig::new(Some("/dev/null")).unwrap();
        cfg.set(
            "global",
            "oidc_issuer_url",
            "https://example.okta.com/oauth2/default",
        );
        cfg.set("oidc", "app_id", "fixture-client");
        cfg.set(
            "offline_breakglass",
            "enabled",
            if breakglass { "true" } else { "false" },
        );
        cfg.set(
            "global",
            "enable_sfa_fallback",
            if sfa { "true" } else { "false" },
        );
        let cfg = Arc::new(Mutex::new(cfg));
        let idmap = Arc::new(Mutex::new(Idmap::new().unwrap()));
        let standard = OidcProvider::new(&cfg, "oidc", &idmap).unwrap();
        let native = OktaProvider::new(&cfg, "oidc", &idmap, &standard)
            .await
            .unwrap();
        native
            .unix_user_offline_auth_init(
                "user@example.com",
                None,
                "login",
                no_hello_pin,
                &mut EmptyKeyStore,
            )
            .await
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn enabled_breakglass_offers_password_without_a_pin() {
        assert!(matches!(
            offline_prompt(true, false, false).await,
            AuthRequest::Password { .. }
        ));
    }

    #[tokio::test]
    async fn enabled_breakglass_respects_no_hello_pin() {
        assert!(matches!(
            offline_prompt(true, false, true).await,
            AuthRequest::Password { .. }
        ));
    }

    #[tokio::test]
    async fn sfa_alone_does_not_enable_native_offline_passwords() {
        assert!(matches!(
            offline_prompt(false, true, true).await,
            AuthRequest::InitDenied { .. }
        ));
    }
}

impl std::fmt::Debug for NativeAuthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeAuthSession { .. }")
    }
}

impl Drop for NativeAuthSession {
    fn drop(&mut self) {
        // Best-effort local cleanup on PAM disconnect and daemon shutdown.
        // Explicit Cancel uses the server remediation while the flow is live.
        let _ = self.client.abandon_auth_flow(&mut self.flow);
    }
}

pub struct OktaProvider {
    config: Arc<Mutex<HimmelblauConfig>>,
    idmap: Arc<Mutex<Idmap>>,
    domain: String,
    pub(crate) state: Arc<Mutex<CacheState>>,
    refresh_cache: Arc<RefreshCache>,
    bad_pin_counter: Arc<BadPinCounter>,
    client: Arc<PublicClientApplication>,
    client_id: String,
    issuer: String,
    redirect_uri: String,
    origin: String,
    tenant_id: Uuid,
    initialized: OnceCell<()>,
    refresh_locks: Mutex<HashMap<String, std::sync::Weak<Mutex<()>>>>,
}

impl OktaProvider {
    fn normalize_broker_client(
        &self,
        client_id: &mut Option<String>,
        redirect_uri: &mut Option<String>,
    ) {
        // linux-entra-sso uses this Entra pair even for OIDC accounts. Replace
        // only the complete, recognized pair with our configured Okta app;
        // all other requests remain subject to the usual client validation.
        // This recognizes a request format, not the identity of the caller.
        if client_id.as_deref() == Some(EDGE_BROWSER_CLIENT_ID)
            && redirect_uri.as_deref()
                == Some("https://login.microsoftonline.com/common/oauth2/nativeclient")
        {
            *client_id = Some(self.client_id.clone());
            *redirect_uri = Some(self.redirect_uri.clone());
            debug!("Normalized linux-entra-sso broker request to configured Okta application");
        }
    }

    pub(crate) async fn new(
        config: &Arc<Mutex<HimmelblauConfig>>,
        domain: &str,
        idmap: &Arc<Mutex<Idmap>>,
        standard: &OidcProvider,
    ) -> Result<Self, OktaError> {
        let cfg = config.lock().await;
        let issuer = cfg.get_oidc_issuer_url().ok_or(OktaError::Configuration)?;
        let client_id = cfg.get_app_id(domain).ok_or(OktaError::Configuration)?;
        let redirect_uri = cfg.get_oidc_redirect_uri();
        let origin = reqwest::Url::parse(&issuer)
            .map_err(|_| OktaError::Configuration)?
            .origin()
            .ascii_serialization();
        let mut options = ClientConfig::new(&issuer, &client_id, &redirect_uri);
        options.timeout = Duration::from_secs(cfg.get_request_timeout());
        options.scopes = vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
        ];
        let client = Arc::new(PublicClientApplication::new(options)?);
        Ok(Self {
            config: config.clone(),
            domain: domain.into(),
            idmap: idmap.clone(),
            state: standard.state.clone(),
            refresh_cache: standard.refresh_cache.clone(),
            bad_pin_counter: standard.bad_pin_counter.clone(),
            client,
            client_id,
            redirect_uri,
            origin,
            tenant_id: Uuid::new_v5(&OIDC_NAMESPACE, issuer.as_bytes()),
            issuer,
            initialized: OnceCell::new(),
            refresh_locks: Mutex::new(HashMap::new()),
        })
    }

    /// Only startup selection uses this anonymous transaction; it never sends
    /// credentials or an identifier and never shares cookies with real logins.
    #[instrument(level = "debug", skip_all)]
    pub(crate) async fn probe(&self) -> Result<(), OktaError> {
        debug!("Probing Okta native authentication capability");
        let mut flow = self
            .client
            .initiate_auth_flow(AuthOptions::default())
            .await?;
        if flow.steps().iter().any(|step| step.name() == "cancel") {
            let _ = self.client.cancel_auth_flow(&mut flow).await;
        }
        let _ = self.client.abandon_auth_flow(&mut flow);
        debug!("Okta native authentication capability probe succeeded");
        Ok(())
    }

    pub(crate) fn log_failure(operation: &'static str, error: &OktaError) {
        error::log_failure(operation, error);
    }

    pub(crate) fn probe_fallback(error: &OktaError) -> bool {
        error::permits_probe_fallback(error)
    }

    pub(crate) fn retry_delay(error: &OktaError) -> Option<Duration> {
        match classify(error) {
            FailureAction::Retry(delay) => Some(delay),
            _ => None,
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn delayed_init(&self) -> Result<(), IdpError> {
        self.initialized
            .get_or_try_init(|| async {
                let range = self.config.lock().await.get_idmap_range(&self.domain);
                self.idmap
                    .lock()
                    .await
                    .add_gen_domain(&self.domain, &self.tenant_id.to_string(), range)
                    .map_err(|_| IdpError::BadRequest)
            })
            .await
            .map(|_| ())
    }

    async fn failure(&self, operation: &'static str, error: &OktaError) -> IdpError {
        error::log_failure(operation, error);
        if let Some(delay) = Self::retry_delay(error) {
            info!(
                retry_seconds = delay.as_secs(),
                "Okta provider offline until next retry"
            );
            *self.state.lock().await = CacheState::OfflineNextCheck(SystemTime::now() + delay);
            IdpError::Transport
        } else {
            IdpError::BadRequest
        }
    }

    async fn is_remote(&self, service: &str) -> bool {
        service.starts_with("remote:")
            || self
                .config
                .lock()
                .await
                .get_password_only_remote_services_deny_list()
                .iter()
                .any(|s| !s.is_empty() && service.contains(s))
    }

    async fn refresh_lock(&self, account: &str) -> Arc<Mutex<()>> {
        let mut locks = self.refresh_locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() != 0);
        if let Some(lock) = locks
            .get(&account.to_lowercase())
            .and_then(std::sync::Weak::upgrade)
        {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(account.to_lowercase(), Arc::downgrade(&lock));
        lock
    }

    #[instrument(level = "debug", skip_all)]
    async fn identity(
        &self,
        account: &str,
        token: &okta::UserToken,
        previous: Option<&UserToken>,
    ) -> Result<UserToken, IdpError> {
        debug!("Validating Okta authenticated identity");
        let claims = token
            .claims()
            .ok_or_else(|| diagnostics::invalid("missing_claims"))?;
        if !oidc_issuer_matches(&self.issuer, claims["iss"].as_str()) {
            return Err(diagnostics::invalid("issuer_mismatch"));
        }
        let userinfo = match self.client.user_info(token).await {
            Ok(info) => info,
            Err(error) => return Err(self.failure("userinfo", &error).await),
        };
        if claims["sub"].as_str().is_none() || claims["sub"] != userinfo["sub"] {
            return Err(diagnostics::invalid("subject_mismatch"));
        }
        let cfg = self.config.lock().await;
        let (shell, account_claims, strip) = (
            cfg.get_shell(None),
            cfg.get_oidc_account_id_claims(),
            cfg.get_oidc_account_id_strip_at_suffix(),
        );
        drop(cfg);
        let identity = oidc_user_token_from_claims(
            &userinfo,
            shell,
            &self.idmap,
            &self.tenant_id,
            &account_claims,
            strip,
        )
        .await
        .inspect_err(|error| diagnostics::local_error("identity_mapping", error))?;
        if !identity.name.eq_ignore_ascii_case(account) {
            return Err(diagnostics::invalid("account_mismatch"));
        }
        if previous.is_some_and(|previous| previous.uuid != identity.uuid) {
            return Err(diagnostics::invalid("identity_changed"));
        }
        debug!("Okta authenticated identity validated");
        Ok(identity)
    }

    async fn cache_refresh(&self, account: &str, token: &okta::UserToken) {
        if let Some(refresh) = token.refresh_credential() {
            self.refresh_cache
                .add(
                    account,
                    &RefreshCacheEntry::RefreshToken(refresh.expose_secret().to_string()),
                )
                .await;
        }
    }

    /// Call with the account refresh lock held; never reuse a spent disk token
    /// in preference to a more recent in-memory replacement.
    #[instrument(level = "debug", skip_all)]
    async fn refresh(&self, account: &str, scopes: &[String]) -> Result<okta::UserToken, IdpError> {
        let secret = match self
            .refresh_cache
            .refresh_token(account)
            .await
            .inspect_err(|_| debug!("No usable Okta refresh token cached"))?
        {
            RefreshCacheEntry::RefreshToken(secret) => secret,
            _ => return Err(IdpError::BadRequest),
        };
        debug!("Reusing cached refresh token for Okta token acquisition");
        let credential = RefreshCredential::import(
            self.issuer.trim_end_matches('/').into(),
            self.client_id.clone(),
            secret,
        );
        match self
            .client
            .refresh_tokens_with_scopes(&credential, scopes)
            .await
        {
            Ok(token) => {
                // The SDK validates refreshed ID tokens for this client.
                // Save rotation before a fallible user-info
                // request; otherwise an outage would lose the replacement.
                self.cache_refresh(account, &token).await;
                debug!("Okta token refresh succeeded; refresh cache updated");
                Ok(token)
            }
            Err(error) => {
                if classify(&error) == FailureAction::RejectRefresh {
                    error::log_failure("refresh", &error);
                    debug!("Okta refresh credential rejected; removing cached credential");
                    self.refresh_cache.remove_refresh_token(account).await;
                    return Err(IdpError::ProviderUnauthorised);
                }
                Err(self.failure("refresh", &error).await)
            }
        }
    }

    fn broker_token(
        &self,
        token: &okta::UserToken,
        identity: &UserToken,
    ) -> Result<UnixUserToken, IdpError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IdpError::BadRequest)?
            .as_secs();
        let expires = token.expires_at().ok_or(IdpError::BadRequest)?;
        let expires_in = expires.saturating_sub(now).min(u64::from(u32::MAX)) as u32;
        Ok(UnixUserToken {
            token_type: token.token_type().ok_or(IdpError::BadRequest)?.into(),
            scope: Some(token.scopes().ok_or(IdpError::BadRequest)?.join(" ")),
            expires_in,
            ext_expires_in: expires_in,
            access_token: Some(token.access_token().ok_or(IdpError::BadRequest)?.into()),
            refresh_token: token
                .refresh_credential()
                .map(|v| v.expose_secret().into())
                .unwrap_or_default(),
            // These are compatibility fields, never synthetic claims in the raw JWT.
            id_token: IdToken {
                name: identity.displayname.clone(),
                oid: identity.uuid.to_string(),
                preferred_username: Some(identity.spn.clone()),
                puid: None,
                tenant_region_scope: None,
                tid: self.tenant_id.to_string(),
                raw: Some(token.id_token().ok_or(IdpError::BadRequest)?.into()),
            },
            client_info: ClientInfo::default(),
            prt: None,
        })
    }

    impl_himmelblau_hello_key_helpers!();

    #[instrument(level = "debug", skip_all)]
    fn create_pin_credential<D: KeyStoreTxn + Send>(
        &self,
        account: &str,
        secret: &str,
        pin: &str,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<(), IdpError> {
        let pin = PinValue::new(pin)
            .map_err(|_| diagnostics::local_failure("create_pin_credential", IdpError::Tpm))?;
        let key = tpm
            .ms_hello_key_create(machine_key, &pin)
            .map_err(|_| diagnostics::local_failure("create_pin_credential", IdpError::Tpm))?;
        let (_, storage) = tpm
            .ms_hello_key_load(machine_key, &key, &pin)
            .map_err(|_| diagnostics::local_failure("create_pin_credential", IdpError::Tpm))?;
        let sealed = tpm
            .seal_data(&storage, Zeroizing::new(secret.as_bytes().to_vec()))
            .map_err(|_| diagnostics::local_failure("create_pin_credential", IdpError::Tpm))?;
        // Complete TPM operations before replacing any existing credentials.
        keystore
            .insert_tagged_hsm_key(&self.fetch_hello_key_tag(account, false), &key)
            .map_err(|_| diagnostics::local_failure("create_pin_credential", IdpError::KeyStore))?;
        keystore
            .insert_tagged_hsm_key(&self.fetch_hello_refresh_token_key_tag(account), &sealed)
            .map_err(|_| diagnostics::local_failure("create_pin_credential", IdpError::KeyStore))
    }

    #[instrument(level = "debug", skip_all)]
    fn seal_refresh<D: KeyStoreTxn + Send>(
        &self,
        account: &str,
        secret: &str,
        pin: &str,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<(), IdpError> {
        let (hello, _) = self.fetch_hello_key(account, keystore)?;
        let pin = PinValue::new(pin)
            .map_err(|_| diagnostics::local_failure("seal_refresh", IdpError::Tpm))?;
        let (_, storage) = tpm
            .ms_hello_key_load(machine_key, &hello, &pin)
            .map_err(|_| diagnostics::local_failure("seal_refresh", IdpError::Tpm))?;
        let sealed = tpm
            .seal_data(&storage, Zeroizing::new(secret.as_bytes().to_vec()))
            .map_err(|_| diagnostics::local_failure("seal_refresh", IdpError::Tpm))?;
        keystore
            .insert_tagged_hsm_key(&self.fetch_hello_refresh_token_key_tag(account), &sealed)
            .map_err(|_| diagnostics::local_failure("seal_refresh", IdpError::KeyStore))
    }

    #[instrument(level = "debug", skip_all)]
    async fn begin(
        &self,
        account: &str,
        remote: bool,
        pin: Option<Zeroizing<String>>,
        shutdown: &broadcast::Receiver<()>,
    ) -> Result<NativeAuthSession, IdpError> {
        debug!(
            remote,
            reauthentication = pin.is_some(),
            "Starting Okta native authentication"
        );
        let mut shutdown = shutdown.resubscribe();
        let flow = tokio::select! {
            result = self.client.initiate_auth_flow(AuthOptions { login_hint: Some(account.into()), ..Default::default() }) => {
                match result { Ok(flow) => flow, Err(error) => return Err(self.failure("initiate", &error).await) }
            }
            _ = shutdown.recv() => return Err(diagnostics::interrupted()),
        };
        let cfg = self.config.lock().await;
        let passwordless = cfg.get_enable_passwordless();
        let console_password_only = cfg.get_allow_console_password_only();
        let policy = FlowPolicy::new(
            remote,
            passwordless,
            console_password_only,
            cfg.get_mfa_method(),
        );
        debug!(
            remote,
            passwordless, console_password_only, "Evaluating Okta authentication policy"
        );
        debug!(requires_authenticator = policy.requires_authenticator(), status = ?flow.status(),
            "Okta native authentication initialized");
        drop(cfg);
        Ok(NativeAuthSession {
            client: self.client.clone(),
            flow,
            form: Form::default(),
            account: account.into(),
            origin: self.origin.clone(),
            remote,
            policy,
            deadline: tokio::time::Instant::now() + SESSION_LIFETIME,
            password: None,
            reauth_pin: pin,
            pending: None,
            phase: LocalPhase::Native,
        })
    }

    #[instrument(level = "debug", skip_all)]
    async fn advance(
        &self,
        session: &mut NativeAuthSession,
        mut next: Next,
        shutdown: &broadcast::Receiver<()>,
    ) -> Result<Option<AuthRequest>, IdpError> {
        // Bound zero-input remediations even if a broken server repeats them.
        for _ in 0..32 {
            if tokio::time::Instant::now() >= session.deadline {
                return Err(diagnostics::expired());
            }
            match next {
                Next::Prompt(mut request) => {
                    match &mut request {
                        AuthRequest::Input { enrollment, .. }
                        | AuthRequest::MFAPoll { enrollment, .. }
                        | AuthRequest::WebAuthn { enrollment, .. } => {
                            *enrollment = forms::enrollment(&session.flow);
                            if let Some(presentation) = enrollment {
                                debug!("Resolving Okta authenticator enrollment presentation");
                                let timeout = Duration::from_secs(
                                    self.config.lock().await.get_request_timeout(),
                                );
                                let mut shutdown = shutdown.resubscribe();
                                tokio::select! {
                                    result = tokio::time::timeout_at(
                                        session.deadline,
                                        crate::enrollment::resolve_image(presentation, &session.origin, timeout),
                                    ) => result.map_err(|_| diagnostics::expired())?,
                                    _ = shutdown.recv() => return Err(diagnostics::interrupted()),
                                }
                            }
                        }
                        _ => (),
                    }
                    return Ok(Some(request));
                }
                Next::Unsupported => {
                    warn!(
                        step = diagnostics::step(session.form.selected_name()),
                        "Okta authentication requires an unsupported step"
                    );
                    let alternatives = session.flow.steps().iter().any(|s| {
                        s.name() != session.form.selected_name()
                            && s.name() != "cancel"
                            && matches!(s.kind, okta::StepKind::Form | okta::StepKind::Poll)
                    });
                    if alternatives {
                        debug!("Offering alternative Okta authentication methods");
                        return match session.form.show_steps(&session.flow, true) {
                            Next::Prompt(prompt) => Ok(Some(prompt)),
                            _ => Err(IdpError::BadRequest),
                        };
                    }
                    return Ok(Some(AuthRequest::InitDenied {
                        msg: tr("This authentication policy requires an external or unsupported step. Choose a native method or contact your administrator."),
                    }));
                }
                Next::Submit(step, input, factor) => {
                    let polling = session.form.is_polling();
                    if polling {
                        trace!("Polling Okta authenticator approval");
                    } else {
                        debug!(step = diagnostics::step(session.form.selected_name()), factor = ?factor,
                            "Submitting Okta authentication step");
                    }
                    let previous = session.form.selected_name().to_string();
                    let previous_authenticator = forms::current_authenticator(&session.flow);
                    let password = session.form.password.take();
                    let mut shutdown = shutdown.resubscribe();
                    let result = tokio::select! {
                        result = self.client.continue_auth_flow(&mut session.flow, &step, input) => result,
                        _ = tokio::time::sleep_until(session.deadline) => return Err(diagnostics::expired()),
                        _ = shutdown.recv() => return Err(diagnostics::interrupted()),
                    };
                    if let Err(error) = result {
                        if session.flow.status() == AuthStatus::Uncertain {
                            error::log_reconciliation(&error);
                            debug!("Okta submission outcome uncertain; introspecting once without replaying input");
                            // Reconcile exactly once; never replay the submitted input.
                            let result = tokio::select! {
                                result = self.client.introspect_auth_flow(&mut session.flow) => result,
                                _ = tokio::time::sleep_until(session.deadline) => return Err(diagnostics::expired()),
                                _ = shutdown.recv() => return Err(diagnostics::interrupted()),
                            };
                            if let Err(error) = result {
                                return Err(self.failure("reconcile", &error).await);
                            }
                            debug!(status = ?session.flow.status(), "Okta uncertain submission reconciled");
                        } else {
                            return Err(self.failure("remediation", &error).await);
                        }
                    }
                    let accepted = !forms::has_validation_errors(&session.flow);
                    let factor_completed = forms::verification_completed(
                        &session.flow,
                        &previous,
                        &previous_authenticator,
                    );
                    if !polling
                        || session.flow.status() != AuthStatus::Pending
                        || factor_completed
                        || !accepted
                    {
                        debug!(status = ?session.flow.status(), validation_errors = !accepted,
                            factor_completed, "Okta authentication step completed");
                    }
                    if !accepted {
                        debug!("Okta authentication input rejected by provider validation");
                    }
                    session.policy.record(factor, factor_completed);
                    // Do not cache a password that produced validation messages.
                    if accepted {
                        if password.is_some() {
                            session.password = password;
                        }
                    } else if password.is_some() {
                        session.password = None;
                    }
                    match session.flow.status() {
                        AuthStatus::Success => {
                            debug!("Okta native flow succeeded; validating identity and local authentication requirements");
                            session.policy.warn_unmatched_preference();
                            if session.policy.requires_authenticator()
                                && !session.policy.authenticator_complete
                            {
                                warn!("Okta sign-in denied: required non-password authenticator was not completed");
                                return Ok(Some(AuthRequest::InitDenied {
                                    msg: tr("A non-password authenticator is required for this sign-in."),
                                }));
                            }
                            return Ok(None);
                        }
                        AuthStatus::Pending => {
                            next = session
                                .form
                                .start(
                                    &session.flow,
                                    Some(&previous),
                                    &session.account,
                                    &session.origin,
                                    &mut session.policy,
                                )
                                .inspect_err(|error| {
                                    diagnostics::local_error("form_start", error)
                                })?;
                        }
                        _ => {
                            debug!(status = ?session.flow.status(), "Okta native authentication canceled or denied");
                            session.policy.warn_unmatched_preference();
                            return Ok(Some(AuthRequest::InitDenied {
                                msg: if forms::messages(&session.flow).is_empty() {
                                    tr("Authentication canceled or denied.")
                                } else {
                                    forms::messages(&session.flow)
                                },
                            }));
                        }
                    }
                }
            }
        }
        warn!(
            reason = "remediation_limit",
            "Okta automatic remediation limit reached; restart sign-in"
        );
        Err(IdpError::BadRequest)
    }

    #[instrument(level = "debug", skip_all)]
    async fn start_request(
        &self,
        session: &mut NativeAuthSession,
        shutdown: &broadcast::Receiver<()>,
    ) -> Result<AuthRequest, IdpError> {
        if session.flow.status() == AuthStatus::Success {
            session.phase = LocalPhase::Acknowledge;
            return Ok(AuthRequest::Input {
                enrollment: None,
                msg: tr("Continue sign-in? Press Enter: "),
                echo_on: true,
            });
        }
        if session.flow.status() != AuthStatus::Pending {
            debug!(status = ?session.flow.status(), "Okta native authentication initialization rejected");
            return Ok(AuthRequest::InitDenied {
                msg: tr("Authentication was denied by the identity provider."),
            });
        }
        let next = session
            .form
            .start(
                &session.flow,
                None,
                &session.account,
                &session.origin,
                &mut session.policy,
            )
            .inspect_err(|error| diagnostics::local_error("form_start", error))?;
        if let Some(request) = self.advance(session, next, shutdown).await? {
            return Ok(request);
        }
        session.phase = LocalPhase::Acknowledge;
        Ok(AuthRequest::Input {
            enrollment: None,
            msg: tr("Continue sign-in? Press Enter: "),
            echo_on: true,
        })
    }

    #[instrument(level = "debug", skip_all)]
    async fn finish<D: KeyStoreTxn + Send>(
        &self,
        session: &mut NativeAuthSession,
        no_hello_pin: bool,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        if session.policy.requires_authenticator() && !session.policy.authenticator_complete {
            warn!("Okta sign-in denied: required non-password authenticator was not completed");
            return Ok((
                AuthResult::Denied(tr(
                    "A non-password authenticator is required for this sign-in.",
                )),
                AuthCacheAction::None,
            ));
        }
        let token = session
            .flow
            .tokens()
            .ok_or_else(|| diagnostics::invalid("missing_tokens"))?;
        let identity = self.identity(&session.account, token, None).await?;
        let lock = self.refresh_lock(&session.account).await;
        let guard = lock.lock().await;
        self.cache_refresh(&session.account, token).await;
        session.pending = Some(identity.clone());
        let enabled = self.config.lock().await.get_enable_hello();
        let has_refresh = token.refresh_credential().is_some();
        if let (Some(pin), Some(refresh)) = (&session.reauth_pin, token.refresh_credential()) {
            self.seal_refresh(
                &session.account,
                refresh.expose_secret(),
                pin,
                keystore,
                tpm,
                machine_key,
            )?;
        }
        drop(guard);
        let cache_password = self.config.lock().await.get_offline_breakglass_enabled();
        if enabled
            && !no_hello_pin
            && has_refresh
            && self.fetch_hello_key(&session.account, keystore).is_err()
        {
            debug!("Setting up Hello PIN after Okta authentication");
            session.phase = LocalPhase::SetupPin;
            return Ok(with_password_cache_action(
                AuthResult::Next(AuthRequest::SetupPin {
                    msg: tr("Set up a PIN to sign in to this device."),
                }),
                &mut session.password,
                cache_password,
            ));
        }
        debug!(
            hello_enabled = enabled,
            no_hello_pin, has_refresh, "Continuing Okta sign-in without new Hello PIN enrollment"
        );
        self.bad_pin_counter
            .reset_bad_pin_count(&session.account)
            .await;
        if let Some(pin) = session.reauth_pin.take() {
            let cfg = self.config.lock().await;
            let totp = cfg.get_enable_hello_totp()
                && (session.remote || !cfg.get_allow_console_password_only());
            drop(cfg);
            if totp {
                let account = session.account.clone();
                let result = self
                    .local_totp(
                        &account,
                        pin.to_string(),
                        &identity,
                        session,
                        keystore,
                        tpm,
                        machine_key,
                    )
                    .await?;
                return Ok(with_password_cache_action(
                    result,
                    &mut session.password,
                    cache_password,
                ));
            }
        }
        Ok(with_password_cache_action(
            AuthResult::Success { token: identity },
            &mut session.password,
            cache_password,
        ))
    }

    #[instrument(level = "debug", skip_all)]
    async fn local_totp<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        pin: String,
        identity: &UserToken,
        session: &mut NativeAuthSession,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<AuthResult, IdpError> {
        let mut local_handler = AuthCredHandler::None;
        let handler = &mut local_handler;
        let result = if !check_hello_totp_setup!(self, account_id, keystore) {
            debug!("Setting up local Hello TOTP after Okta authentication");
            let setup: Result<(AuthResult, AuthCacheAction), IdpError> = impl_setup_hello_totp!(
                self,
                account_id,
                keystore,
                identity,
                pin,
                tpm,
                machine_key,
                handler
            );
            let (result, _) = setup?;
            result
        } else {
            debug!("Local Hello TOTP verification required after Okta authentication");
            *handler = AuthCredHandler::HelloTOTP {
                cred: pin,
                pending_sealed_totp: None,
            };
            AuthResult::Next(AuthRequest::HelloTOTP {
                msg: tr("Enter your Hello TOTP code: "),
            })
        };
        if let AuthCredHandler::HelloTOTP {
            cred,
            pending_sealed_totp,
        } = local_handler
        {
            session.phase = LocalPhase::Totp {
                pin: Zeroizing::new(cred),
                pending: pending_sealed_totp,
            };
        }
        session.pending = Some(identity.clone());
        Ok(result)
    }

    #[instrument(level = "debug", skip_all)]
    async fn start_pin_totp<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        pin: String,
        identity: UserToken,
        cred_handler: &mut AuthCredHandler,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<AuthResult, IdpError> {
        let mut local_handler = AuthCredHandler::None;
        let handler = &mut local_handler;
        let result = if !check_hello_totp_setup!(self, account_id, keystore) {
            debug!("Setting up local Hello TOTP after Okta authentication");
            let setup: Result<(AuthResult, AuthCacheAction), IdpError> = impl_setup_hello_totp!(
                self,
                account_id,
                keystore,
                identity,
                pin,
                tpm,
                machine_key,
                handler
            );
            let (result, _) = setup?;
            result
        } else {
            debug!("Local Hello TOTP verification required after Okta authentication");
            *handler = AuthCredHandler::HelloTOTP {
                cred: pin,
                pending_sealed_totp: None,
            };
            AuthResult::Next(AuthRequest::HelloTOTP {
                msg: tr("Enter your Hello TOTP code: "),
            })
        };
        if let AuthCredHandler::HelloTOTP {
            cred,
            pending_sealed_totp,
        } = local_handler
        {
            *cred_handler = AuthCredHandler::OidcPinTotp {
                pin: Zeroizing::new(cred),
                pending: pending_sealed_totp,
                token: Box::new(identity),
            };
        }
        Ok(result)
    }
}

#[async_trait]
impl IdProvider for OktaProvider {
    #[instrument(level = "debug", skip_all)]
    async fn check_online(&self, _tpm: &mut tpm::provider::BoxedDynTpm, now: SystemTime) -> bool {
        let state = self.state.lock().await.clone();
        match state {
            CacheState::Online => return true,
            CacheState::Offline => return false,
            CacheState::OfflineNextCheck(next) if next > now => return false,
            _ => (),
        }
        // Use the SDK's trust-aware transport. A conclusive trust/protocol
        // rejection must reach online authentication as a denial, not turn
        // into an offline authentication opportunity.
        match self.probe().await {
            Err(error) if Self::retry_delay(&error).is_some() => {
                let _ = self.failure("online_probe", &error).await;
                false
            }
            result => {
                if let Err(error) = result {
                    error::log_failure("online_probe", &error);
                    debug!("Okta provider reachable; protocol rejection must be handled by online authentication");
                }
                info!("Okta provider is now online");
                *self.state.lock().await = CacheState::Online;
                true
            }
        }
    }

    async fn get_cachestate<D: KeyStoreTxn + Send>(
        &self,
        _account: Option<&str>,
        _keystore: &mut D,
    ) -> CacheState {
        self.state.lock().await.clone()
    }

    async fn offline_break_glass(&self, ttl: Option<u64>) -> Result<(), IdpError> {
        impl_offline_break_glass!(self, ttl)
    }

    async fn unix_user_get<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old: Option<&UserToken>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<UserTokenState, IdpError> {
        self.delayed_init().await?;
        let account = match (id, old) {
            (_, Some(old)) => old.name.as_str(),
            (Id::Name(name), None) => name.as_str(),
            _ => return Ok(UserTokenState::UseCached),
        };
        if let Some(old) = old {
            let lock = self.refresh_lock(account).await;
            let _guard = lock.lock().await;
            if self.refresh_cache.refresh_token(account).await.is_err() {
                return Ok(UserTokenState::UseCached);
            }
            return match self.refresh(account, &[]).await {
                Ok(token) => match self.identity(account, &token, Some(old)).await {
                    Ok(identity) => {
                        self.cache_refresh(account, &token).await;
                        Ok(UserTokenState::Update(identity))
                    }
                    Err(IdpError::Transport) => Ok(UserTokenState::UseCached),
                    Err(_) => Ok(UserTokenState::NotFound),
                },
                // Revoked SSO material does not revoke the local PIN or cached
                // identity. Interactive login will recover the native session.
                Err(IdpError::ProviderUnauthorised) => Ok(UserTokenState::UseCached),
                Err(_) => Ok(UserTokenState::UseCached),
            };
        }
        // Match ordinary OIDC's pre-authentication NSS placeholder. This cannot
        // overwrite authenticated groups; those take the refresh branch above.
        let object_id = Uuid::new_v4();
        let cache = StaticIdCache::new(ID_MAP_CACHE, false).map_err(|_| IdpError::BadRequest)?;
        let (uid, gid) = match cache.get_user_by_name(account) {
            Some(user) => (user.uid, user.gid),
            None => {
                let id = self
                    .idmap
                    .lock()
                    .await
                    .gen_to_unix(&self.tenant_id.to_string(), account)
                    .map_err(|_| IdpError::BadRequest)?;
                (id, id)
            }
        };
        Ok(UserTokenState::Update(UserToken {
            name: account.into(),
            spn: account.into(),
            uuid: object_id,
            real_gidnumber: Some(uid),
            gidnumber: gid,
            displayname: flip_displayname_comma(""),
            shell: Some(self.config.lock().await.get_shell(None)),
            groups: vec![GroupToken {
                name: account.into(),
                spn: account.into(),
                uuid: object_id,
                gidnumber: gid,
            }],
            tenant_id: Some(self.tenant_id),
            valid: true,
        }))
    }

    async fn unix_user_access<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        scopes: Vec<String>,
        old: Option<&UserToken>,
        mut client_id: Option<String>,
        mut redirect_uri: Option<String>,
        req_cnf: Option<String>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<UnixUserToken, IdpError> {
        self.delayed_init().await?;
        match *self.state.lock().await {
            CacheState::Offline => return Err(IdpError::Transport),
            CacheState::OfflineNextCheck(next) if next > SystemTime::now() => {
                return Err(IdpError::Transport)
            }
            _ => (),
        }
        self.normalize_broker_client(&mut client_id, &mut redirect_uri);
        if client_id.as_ref().is_some_and(|v| v != &self.client_id) {
            debug!(reason = "client_mismatch", "Okta broker request rejected");
            return Err(IdpError::BadRequest);
        }
        if redirect_uri
            .as_ref()
            .is_some_and(|v| v != &self.redirect_uri)
        {
            debug!(reason = "redirect_mismatch", "Okta broker request rejected");
            return Err(IdpError::BadRequest);
        }
        if req_cnf.is_some() {
            debug!(reason = "unsupported_pop", "Okta broker request rejected");
            return Err(IdpError::BadRequest);
        }
        let account = match (old, id) {
            (Some(old), _) => old.spn.as_str(),
            (None, Id::Name(account)) => account.as_str(),
            _ => return Err(IdpError::BadRequest),
        };
        let scopes: Vec<_> = scopes
            .into_iter()
            .filter(|s| s != "https://graph.microsoft.com/.default")
            .collect();
        let lock = self.refresh_lock(account).await;
        let _guard = lock.lock().await;
        let token = self.refresh(account, &scopes).await?;
        let identity = self.identity(account, &token, old).await?;
        self.cache_refresh(account, &token).await;
        self.broker_token(&token, &identity)
    }

    #[instrument(skip_all)]
    async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        _token: Option<&UserToken>,
        service: &str,
        no_hello_pin: bool,
        force_reauth: bool,
        keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
        shutdown: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        let result = async {
            self.delayed_init().await?;
            let remote = self.is_remote(service).await;
            let cfg = self.config.lock().await;
            let hello_enabled = cfg.get_enable_hello();
            let remote_pin_allowed =
                !remote || cfg.get_enable_hello_totp() || cfg.get_allow_remote_hello();
            let allow_pin = hello_enabled && !no_hello_pin && !force_reauth && remote_pin_allowed;
            let retry_count = cfg.get_hello_pin_retry_count();
            drop(cfg);
            debug!(
                remote,
                no_hello_pin,
                force_reauth,
                allow_pin,
                hello_enabled,
                remote_pin_allowed,
                "Evaluating Hello PIN for Okta authentication"
            );
            if allow_pin {
                if self.fetch_hello_key(account_id, keystore).is_ok() {
                    if !should_block_hello_pin_attempts(
                        self.bad_pin_counter.bad_pin_count(account_id).await,
                        retry_count,
                    ) {
                        debug!("Selected Hello PIN authentication for Okta");
                        return Ok((AuthRequest::Pin, AuthCredHandler::None));
                    }
                    debug!(
                        reason = "pin_attempts_exhausted",
                        "Selected Okta native authentication"
                    );
                } else {
                    debug!(
                        reason = "hello_key_unavailable",
                        "Selected Okta native authentication"
                    );
                }
            } else {
                debug!(
                    reason = "pin_disabled_by_policy_or_request",
                    "Selected Okta native authentication"
                );
            }
            let mut session = self.begin(account_id, remote, None, shutdown).await?;
            let prompt = self.start_request(&mut session, shutdown).await?;
            Ok((prompt, AuthCredHandler::InteractionCode(Box::new(session))))
        }
        .await;
        match &result {
            Ok((request, _)) => diagnostics::prompt(request),
            Err(error) => diagnostics::local_error("auth_init", error),
        }
        result
    }

    #[instrument(skip_all)]
    async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        old_token: &UserToken,
        service: &str,
        no_hello_pin: bool,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        shutdown: &broadcast::Receiver<()>,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        let result = async {
            self.delayed_init().await?;
            if let AuthCredHandler::InteractionCode(session) = cred_handler {
                if tokio::time::Instant::now() >= session.deadline {
                    return Err(diagnostics::expired());
                }
                if !session.account.eq_ignore_ascii_case(account_id) {
                    return Err(diagnostics::invalid("session_account_mismatch"));
                }
                match &session.phase {
                    LocalPhase::SetupPin => {
                        debug!("Creating Hello PIN credential for Okta sign-in");
                        let PamAuthRequest::SetupPin { pin } = pam_next_req else {
                            return Err(IdpError::BadRequest);
                        };
                        let pin = Zeroizing::new(pin);
                        let lock = self.refresh_lock(account_id).await;
                        let _guard = lock.lock().await;
                        if let RefreshCacheEntry::RefreshToken(secret) =
                            self.refresh_cache.refresh_token(account_id).await?
                        {
                            self.create_pin_credential(
                                account_id,
                                &secret,
                                &pin,
                                keystore,
                                tpm,
                                machine_key,
                            )?;
                        } else {
                            return Err(IdpError::BadRequest);
                        }
                        let identity = session.pending.clone().ok_or(IdpError::BadRequest)?;
                        let cfg = self.config.lock().await;
                        let totp = cfg.get_enable_hello_totp()
                            && (session.remote || !cfg.get_allow_console_password_only());
                        drop(cfg);
                        if totp {
                            let result = self
                                .local_totp(
                                    account_id,
                                    pin.to_string(),
                                    &identity,
                                    session,
                                    keystore,
                                    tpm,
                                    machine_key,
                                )
                                .await?;
                            return Ok((result, AuthCacheAction::None));
                        }
                        return Ok((
                            AuthResult::Success { token: identity },
                            AuthCacheAction::None,
                        ));
                    }
                    LocalPhase::Totp { pin, pending } => {
                        debug!("Verifying local Hello TOTP for Okta sign-in");
                        let PamAuthRequest::HelloTOTP { cred } = pam_next_req else {
                            return Err(IdpError::BadRequest);
                        };
                        let hello_pin = pin.to_string();
                        let pending_sealed_totp = pending.clone();
                        let identity = session.pending.clone().ok_or(IdpError::BadRequest)?;
                        let cache_password = self.config.lock().await.get_offline_breakglass_enabled();
                        return impl_handle_hello_pin_totp_auth!(
                            self,
                            account_id,
                            keystore,
                            identity,
                            cred,
                            hello_pin,
                            tpm,
                            machine_key,
                            pending_sealed_totp,
                            |result| with_password_cache_action(
                                result,
                                &mut session.password,
                                cache_password
                            )
                        );
                    }
                    LocalPhase::Acknowledge => {
                        debug!("Completing acknowledged Okta sign-in");
                        if !matches!(pam_next_req, PamAuthRequest::Input { .. }) {
                            return Err(IdpError::BadRequest);
                        }
                    }
                    LocalPhase::Native => {
                        let next = session.form.answer(
                            pam_next_req,
                            &session.flow,
                            account_id,
                            &session.origin,
                            &mut session.policy,
                        ).inspect_err(|error| diagnostics::local_error("form_answer", error))?;
                        if let Some(prompt) = self.advance(session, next, shutdown).await? {
                            return Ok((AuthResult::Next(prompt), AuthCacheAction::None));
                        }
                    }
                }
                return self
                    .finish(session, no_hello_pin, keystore, tpm, machine_key)
                    .await;
            }
            if matches!(
                cred_handler,
                AuthCredHandler::HelloTOTP { .. } | AuthCredHandler::OidcPinTotp { .. }
            ) {
                let result = self
                    .unix_user_offline_auth_step(
                        account_id,
                        old_token,
                        cred_handler,
                        pam_next_req,
                        keystore,
                        tpm,
                        machine_key,
                        true,
                    )
                    .await?;
                return Ok((result, AuthCacheAction::None));
            }
            let PamAuthRequest::Pin { cred } = pam_next_req else {
                return Err(IdpError::BadRequest);
            };
            let cred = Zeroizing::new(cred);
            let (hello, keytype) = self.fetch_hello_key(account_id, keystore)?;
            if keytype != KeyType::Decoupled {
                return Err(diagnostics::invalid("unexpected_hello_key_type"));
            }
            let pin = PinValue::new(&cred).map_err(|_| IdpError::Tpm)?;
            let storage = match tpm.ms_hello_key_load(machine_key, &hello, &pin) {
                Ok((_, storage)) => storage,
                Err(_) => {
                    debug!("Hello PIN authentication failed for Okta; updating failed-attempt count");
                    handle_hello_bad_pin_count!(self, account_id, keystore, |msg: &str| {
                        Ok((AuthResult::Denied(msg.into()), AuthCacheAction::None))
                    });
                    return Ok((
                        AuthResult::Denied(tr("Failed to authenticate with Hello PIN.")),
                        AuthCacheAction::None,
                    ));
                }
            };
            let remote = self.is_remote(service).await;
            let lock = self.refresh_lock(account_id).await;
            let guard = lock.lock().await;
            if self.refresh_cache.refresh_token(account_id).await.is_err() {
                debug!("No Okta refresh token in memory; checking sealed credential");
                let sealed: Option<SealedData> = keystore
                    .get_tagged_hsm_key(&self.fetch_hello_refresh_token_key_tag(account_id))
                    .map_err(|_| IdpError::KeyStore)?;
                if let Some(sealed) = sealed {
                    debug!("Unsealing cached Okta refresh credential with Hello PIN");
                    let bytes = tpm
                        .unseal_data(&storage, &sealed)
                        .map_err(|_| IdpError::Tpm)?;
                    let secret = String::from_utf8(bytes.to_vec()).map_err(|_| IdpError::Tpm)?;
                    self.refresh_cache
                        .add(account_id, &RefreshCacheEntry::RefreshToken(secret))
                        .await;
                }
            }
            drop(storage);
            let refreshed = self.refresh(account_id, &[]).await;
            match refreshed {
                Ok(token) => {
                    let identity = self.identity(account_id, &token, Some(old_token)).await?;
                    self.cache_refresh(account_id, &token).await;
                    if let Some(refresh) = token.refresh_credential() {
                        self.seal_refresh(
                            account_id,
                            refresh.expose_secret(),
                            &cred,
                            keystore,
                            tpm,
                            machine_key,
                        )?;
                    }
                    self.bad_pin_counter.reset_bad_pin_count(account_id).await;
                    let cfg = self.config.lock().await;
                    let totp = cfg.get_enable_hello_totp()
                        && (remote || !cfg.get_allow_console_password_only());
                    drop(cfg);
                    if totp {
                        // Keep the refreshed identity through the local second factor.
                        // A new anonymous flow is unnecessary: use a dedicated pending
                        // identity in the handler rather than the pre-auth NSS token.
                        let result = self
                            .start_pin_totp(
                                account_id,
                                cred.to_string(),
                                identity,
                                cred_handler,
                                keystore,
                                tpm,
                                machine_key,
                            )
                            .await?;
                        return Ok((result, AuthCacheAction::None));
                    }
                    Ok((
                        AuthResult::Success { token: identity },
                        AuthCacheAction::None,
                    ))
                }
                Err(IdpError::Transport) => {
                    debug!("Okta refresh unavailable; attempting offline Hello PIN authentication");
                    drop(guard);
                    let request = PamAuthRequest::Pin {
                        cred: cred.to_string(),
                    };
                    let result = self
                        .unix_user_offline_auth_step(
                            account_id,
                            old_token,
                            cred_handler,
                            request,
                            keystore,
                            tpm,
                            machine_key,
                            true,
                        )
                        .await?;
                    Ok((result, AuthCacheAction::None))
                }
                Err(IdpError::ProviderUnauthorised | IdpError::NotFound { .. }) => {
                    debug!("No usable Okta refresh credential; starting native reauthentication with existing Hello key");
                    // Keep the valid PIN/key, discard only the rejected credential.
                    keystore
                        .delete_tagged_hsm_key(&self.fetch_hello_refresh_token_key_tag(account_id))
                        .map_err(|_| IdpError::KeyStore)?;
                    drop(guard);
                    let mut session = self.begin(account_id, remote, Some(cred), shutdown).await?;
                    let prompt = self.start_request(&mut session, shutdown).await?;
                    *cred_handler = AuthCredHandler::InteractionCode(Box::new(session));
                    Ok((AuthResult::Next(prompt), AuthCacheAction::None))
                }
                Err(error) => Err(error),
            }
        }.await;
        match &result {
            Ok((result, _)) => diagnostics::result(result),
            Err(error) => diagnostics::local_error("auth_step", error),
        }
        result
    }

    #[instrument(skip_all)]
    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        _token: Option<&UserToken>,
        service: &str,
        no_hello_pin: bool,
        keystore: &mut D,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        let result = async {
            let password_auth = self.config.lock().await.get_offline_breakglass_enabled();
            debug!(
                password_auth,
                no_hello_pin, "Starting offline Okta authentication"
            );
            impl_himmelblau_offline_auth_init!(
                self,
                account_id,
                service,
                no_hello_pin,
                keystore,
                password_auth
            )
        }
        .await;
        match &result {
            Ok((request, _)) => diagnostics::prompt(request),
            Err(error) => diagnostics::local_error("auth_init", error),
        }
        result
    }

    #[instrument(skip_all)]
    async fn unix_user_offline_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UserToken,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        _online_at_init: bool,
    ) -> Result<AuthResult, IdpError> {
        let result = async {
            if let AuthCredHandler::OidcPinTotp {
                pin,
                pending,
                token,
            } = cred_handler
            {
                let PamAuthRequest::HelloTOTP { cred } = pam_next_req else {
                    return Err(IdpError::BadRequest);
                };
                let hello_pin = pin.to_string();
                let pending_sealed_totp = pending.clone();
                let identity = token.as_ref().clone();
                return impl_handle_hello_pin_totp_auth!(
                    self,
                    account_id,
                    keystore,
                    identity,
                    cred,
                    hello_pin,
                    tpm,
                    machine_key,
                    pending_sealed_totp,
                    |result| result
                );
            }
            impl_himmelblau_offline_auth_step!(
                cred_handler,
                pam_next_req,
                self,
                account_id,
                keystore,
                tpm,
                machine_key,
                token,
                load_cached_prt_no_op
            )
        }
        .await;
        match &result {
            Ok(result) => diagnostics::result(result),
            Err(error) => diagnostics::local_error("offline_auth_step", error),
        }
        result
    }

    async fn unix_user_try_unseal<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        cred: &str,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        online: bool,
    ) -> Result<bool, IdpError> {
        impl_himmelblau_try_unseal!(
            self,
            account_id,
            cred,
            keystore,
            tpm,
            machine_key,
            online,
            load_cached_prt_for_try_unseal_no_op
        )
    }

    async fn change_auth_token<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UnixUserToken,
        new_pin: &str,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<bool, IdpError> {
        self.delayed_init().await?;
        // Revalidate supplied refresh credentials against this configured client;
        // never derive ownership from an unverified access-token payload.
        let credential = RefreshCredential::import(
            self.issuer.trim_end_matches('/').into(),
            self.client_id.clone(),
            token.refresh_token.clone(),
        );
        let lock = self.refresh_lock(account_id).await;
        let _guard = lock.lock().await;
        let fresh = match self.client.refresh_tokens(&credential).await {
            Ok(token) => token,
            Err(error) => return Err(self.failure("pin_change_refresh", &error).await),
        };
        self.identity(account_id, &fresh, None).await?;
        let refresh = fresh.refresh_credential().ok_or(IdpError::BadRequest)?;
        self.create_pin_credential(
            account_id,
            refresh.expose_secret(),
            new_pin,
            keystore,
            tpm,
            machine_key,
        )?;
        for tag in [
            self.fetch_hello_prt_key_tag(account_id),
            self.fetch_hello_totp_key_tag(account_id),
        ] {
            keystore
                .delete_tagged_hsm_key(&tag)
                .map_err(|_| IdpError::KeyStore)?;
        }
        self.cache_refresh(account_id, &fresh).await;
        self.bad_pin_counter.reset_bad_pin_count(account_id).await;
        Ok(true)
    }

    async fn unix_group_get(
        &self,
        _id: &Id,
        _tpm: &mut tpm::provider::BoxedDynTpm,
    ) -> Result<GroupToken, IdpError> {
        Err(IdpError::BadRequest)
    }

    async fn unix_user_tgts<D: KeyStoreTxn + Send>(
        &self,
        _id: &Id,
        _token: Option<&UserToken>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> (
        Option<Box<libkrimes::proto::KerberosCredentials>>,
        Option<Box<libkrimes::proto::KerberosCredentials>>,
        Option<String>,
        Option<String>,
    ) {
        (None, None, None, None)
    }

    async fn unix_user_prt_cookie<D: KeyStoreTxn + Send>(
        &self,
        _id: &Id,
        _token: Option<&UserToken>,
        _nonce: Option<&str>,
        _keystore: &mut D,
        _tpm: &mut tpm::provider::BoxedDynTpm,
        _machine_key: &tpm::structures::StorageKey,
    ) -> Result<String, IdpError> {
        Err(IdpError::BadRequest)
    }
}
