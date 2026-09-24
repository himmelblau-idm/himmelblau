//! One conclusive OIDC backend selection per daemon lifetime. The standard
//! provider supplies shared offline state while selection is pending.
use super::common::oidc_issuer_matches;
use super::interface::*;
use super::okta::OktaProvider;
use super::openidconnect::OidcProvider;
use crate::config::HimmelblauConfig;
use crate::db::KeyStoreTxn;
use crate::i18n::tr;
use crate::unix_proto::PamAuthRequest;
use async_trait::async_trait;
use himmelblau::UserToken as UnixUserToken;
use idmap::Idmap;
use libkrimes::proto::KerberosCredentials;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Selection {
    Pending,
    StandardOidc,
    InteractionCode,
    Failed,
}

pub(crate) struct OidcRouter {
    standard: Arc<OidcProvider>,
    native: Result<Arc<OktaProvider>, okta::OktaError>,
    config: Arc<Mutex<HimmelblauConfig>>,
    selection: Mutex<Selection>,
}

enum Backend<'a> {
    Standard(&'a OidcProvider),
    Native(&'a OktaProvider),
}

fn has_grant(metadata: &Value, grant: &str) -> bool {
    metadata["grant_types_supported"]
        .as_array()
        .is_some_and(|grants| grants.iter().any(|value| value.as_str() == Some(grant)))
}

fn has_device_flow(metadata: &Value, configured_endpoint: Option<&str>) -> bool {
    let endpoint = metadata["device_authorization_endpoint"]
        .as_str()
        .or(configured_endpoint)
        .and_then(|s| reqwest::Url::parse(s).ok());
    endpoint.is_some_and(|url| url.scheme() == "https" && url.host_str().is_some())
        && (metadata.get("grant_types_supported").is_none()
            || has_grant(metadata, "urn:ietf:params:oauth:grant-type:device_code"))
}

fn is_okta(issuer: &str, metadata: &Value) -> bool {
    let hostname = reqwest::Url::parse(issuer)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned));
    let host_hint = hostname.is_some_and(|host| {
        ["okta.com", "oktapreview.com", "okta-emea.com"]
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    });
    let grant_hint = metadata["grant_types_supported"]
        .as_array()
        .is_some_and(|values| {
            values
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s.starts_with("urn:okta:")))
        });
    let mode_hint = metadata["response_modes_supported"]
        .as_array()
        .is_some_and(|values| {
            values
                .iter()
                .any(|v| v.as_str() == Some("okta_post_message"))
        });
    host_hint || grant_hint || mode_hint
}

fn should_probe(
    issuer: &str,
    metadata: &Value,
    configured_endpoint: Option<&str>,
    forced: bool,
) -> bool {
    forced
        || has_grant(metadata, "interaction_code")
        || is_okta(issuer, metadata)
        || !has_device_flow(metadata, configured_endpoint)
}

fn discovery_trust_failure(error: &reqwest::Error) -> bool {
    if error.is_builder() {
        return true;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = source {
        if error.downcast_ref::<rustls::Error>().is_some() {
            return true;
        }
        source = error.source();
    }
    false
}

impl OidcRouter {
    pub(crate) async fn new(
        config: &Arc<Mutex<HimmelblauConfig>>,
        domain: &str,
        idmap: &Arc<Mutex<Idmap>>,
    ) -> Result<Self, IdpError> {
        let standard = Arc::new(OidcProvider::new(config, domain, idmap)?);
        let native = OktaProvider::new(config, domain, idmap, &standard)
            .await
            .map(Arc::new);
        let router = Self {
            standard,
            native,
            config: config.clone(),
            selection: Mutex::new(Selection::Pending),
        };
        router.select_if_due().await;
        Ok(router)
    }

    async fn defer(&self, delay: Duration) {
        *self.standard.state.lock().await = CacheState::OfflineNextCheck(SystemTime::now() + delay);
    }

    async fn select_if_due(&self) {
        let mut selection = self.selection.lock().await;
        if *selection != Selection::Pending {
            return;
        }
        match *self.standard.state.lock().await {
            CacheState::Offline => return,
            CacheState::OfflineNextCheck(time) if time > SystemTime::now() => return,
            _ => (),
        }
        let cfg = self.config.lock().await;
        let Some(issuer) = cfg.get_oidc_issuer_url() else {
            *selection = Selection::Failed;
            return;
        };
        let forced = cfg.get_oidc_force_interaction_code();
        let configured_device_endpoint = cfg.get_oidc_device_authorization_endpoint();
        let request_timeout = Duration::from_secs(cfg.get_request_timeout());
        drop(cfg);
        let client = match reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(request_timeout)
            .connect_timeout(request_timeout.min(Duration::from_secs(3)))
            .build()
        {
            Ok(client) => client,
            Err(_) => {
                *selection = Selection::Failed;
                return;
            }
        };
        let response = client
            .get(format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            ))
            .send()
            .await;
        let mut response = match response {
            Ok(response) => response,
            Err(error) => {
                // TLS errors are nested in reqwest's generic connect category.
                if discovery_trust_failure(&error) {
                    error!("OIDC discovery trust validation failed");
                    *selection = Selection::Failed;
                    return;
                }
                debug!(
                    timeout = error.is_timeout(),
                    "OIDC discovery unavailable; selection deferred"
                );
                self.defer(Duration::from_secs(15)).await;
                return;
            }
        };
        let status = response.status();
        if matches!(status.as_u16(), 408 | 429 | 500 | 502 | 503 | 504) {
            let delay = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(15)
                .clamp(1, 3600);
            self.defer(Duration::from_secs(delay)).await;
            return;
        }
        if !status.is_success() {
            error!(
                status = status.as_u16(),
                "OIDC discovery rejected; check the configured issuer"
            );
            *selection = Selection::Failed;
            return;
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if body.len().saturating_add(chunk.len()) <= 4 * 1024 * 1024 => {
                    body.extend_from_slice(&chunk)
                }
                Ok(Some(_)) => {
                    *selection = Selection::Failed;
                    return;
                }
                Ok(None) => break,
                Err(_) => {
                    self.defer(Duration::from_secs(15)).await;
                    return;
                }
            }
        }
        let metadata: Value = match serde_json::from_slice(&body) {
            Ok(metadata) => metadata,
            Err(_) => {
                *selection = Selection::Failed;
                return;
            }
        };
        if !oidc_issuer_matches(&issuer, metadata["issuer"].as_str()) {
            error!("OIDC discovery issuer mismatch");
            *selection = Selection::Failed;
            return;
        }
        if !should_probe(
            &issuer,
            &metadata,
            configured_device_endpoint.as_deref(),
            forced,
        ) {
            *selection = Selection::StandardOidc;
        } else {
            let result = match &self.native {
                Ok(provider) => provider.probe().await,
                Err(_) => {
                    if forced {
                        error!("Invalid native OIDC client configuration; check app_id and oidc_redirect_uri");
                        *selection = Selection::Failed;
                    } else if has_device_flow(&metadata, configured_device_endpoint.as_deref()) {
                        *selection = Selection::StandardOidc;
                    } else {
                        *selection = Selection::Failed;
                    }
                    return;
                }
            };
            match result {
                Ok(()) => *selection = Selection::InteractionCode,
                Err(error) => {
                    OktaProvider::log_failure("capability_probe", &error);
                    if let Some(delay) = OktaProvider::retry_delay(&error) {
                        debug!("Native OIDC probe temporarily unavailable; selection deferred");
                        self.defer(delay).await;
                        return;
                    }
                    if !forced
                        && OktaProvider::probe_fallback(&error)
                        && has_device_flow(&metadata, configured_device_endpoint.as_deref())
                    {
                        debug!("Interaction Code unavailable; selected standard OIDC");
                        *selection = Selection::StandardOidc;
                    } else {
                        error!("Native OIDC unavailable and no permitted fallback exists");
                        *selection = Selection::Failed;
                    }
                }
            }
        }
        if *selection == Selection::InteractionCode {
            *self.standard.state.lock().await = CacheState::Online;
        }
        debug!(selection = ?*selection, "OIDC provider selection completed");
    }

    async fn backend(&self) -> Result<Backend<'_>, IdpError> {
        match *self.selection.lock().await {
            Selection::InteractionCode => self
                .native
                .as_ref()
                .map(|p| Backend::Native(p.as_ref()))
                .map_err(|_| IdpError::BadRequest),
            Selection::StandardOidc => Ok(Backend::Standard(&self.standard)),
            Selection::Pending | Selection::Failed => Err(IdpError::BadRequest),
        }
    }

    async fn offline_backend(&self) -> Result<Backend<'_>, IdpError> {
        if *self.selection.lock().await == Selection::Pending {
            return Ok(Backend::Standard(&self.standard));
        }
        self.backend().await
    }
}

#[async_trait]
impl IdProvider for OidcRouter {
    async fn check_online(&self, tpm: &mut tpm::provider::BoxedDynTpm, now: SystemTime) -> bool {
        self.select_if_due().await;
        match *self.selection.lock().await {
            Selection::Pending => return false,
            // A definite configuration/protocol failure must not enable offline
            // fallback. Report the actionable denial from online_auth_init.
            Selection::Failed => return true,
            _ => (),
        }
        match self.backend().await {
            Ok(Backend::Standard(p)) => p.check_online(tpm, now).await,
            Ok(Backend::Native(p)) => p.check_online(tpm, now).await,
            Err(_) => false,
        }
    }

    async fn get_cachestate<D: KeyStoreTxn + Send>(
        &self,
        account: Option<&str>,
        keystore: &mut D,
    ) -> CacheState {
        match *self.selection.lock().await {
            Selection::Pending => {
                return match self.standard.state.lock().await.clone() {
                    CacheState::Online => CacheState::OfflineNextCheck(SystemTime::now()),
                    state => state,
                };
            }
            Selection::Failed => return CacheState::Online,
            _ => (),
        }
        match self.backend().await {
            Ok(Backend::Standard(p)) => p.get_cachestate(account, keystore).await,
            Ok(Backend::Native(p)) => p.get_cachestate(account, keystore).await,
            Err(_) => CacheState::Online,
        }
    }

    async fn unix_user_get<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        token: Option<&UserToken>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<UserTokenState, IdpError> {
        self.select_if_due().await;
        if matches!(
            *self.selection.lock().await,
            Selection::Pending | Selection::Failed
        ) {
            return Ok(UserTokenState::UseCached);
        }
        match self.backend().await? {
            Backend::Standard(p) => p.unix_user_get(id, token, keystore, tpm, machine_key).await,
            Backend::Native(p) => p.unix_user_get(id, token, keystore, tpm, machine_key).await,
        }
    }

    async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account: &str,
        token: Option<&UserToken>,
        service: &str,
        no_hello_pin: bool,
        force_reauth: bool,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        shutdown: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        match self.backend().await {
            Ok(Backend::Standard(p)) => p.unix_user_online_auth_init(account, token, service, no_hello_pin, force_reauth, keystore, tpm, machine_key, shutdown).await,
            Ok(Backend::Native(p)) => p.unix_user_online_auth_init(account, token, service, no_hello_pin, force_reauth, keystore, tpm, machine_key, shutdown).await,
            Err(_) => Ok((AuthRequest::InitDenied { msg: tr("OIDC authentication is unavailable. Check the issuer, client ID, registered redirect URI and enabled grants.") }, AuthCredHandler::None)),
        }
    }
    async fn unix_user_access<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        scopes: Vec<String>,
        token: Option<&UserToken>,
        client_id: Option<String>,
        redirect_uri: Option<String>,
        req_cnf: Option<String>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<UnixUserToken, IdpError> {
        match self.backend().await? {
            Backend::Standard(p) => {
                p.unix_user_access(
                    id,
                    scopes,
                    token,
                    client_id,
                    redirect_uri,
                    req_cnf,
                    keystore,
                    tpm,
                    machine_key,
                )
                .await
            }
            Backend::Native(p) => {
                p.unix_user_access(
                    id,
                    scopes,
                    token,
                    client_id,
                    redirect_uri,
                    req_cnf,
                    keystore,
                    tpm,
                    machine_key,
                )
                .await
            }
        }
    }

    async fn unix_user_tgts<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> (
        Option<Box<KerberosCredentials>>,
        Option<Box<KerberosCredentials>>,
        Option<String>,
        Option<String>,
    ) {
        match self.backend().await {
            Ok(Backend::Standard(p)) => {
                p.unix_user_tgts(id, old_token, keystore, tpm, machine_key)
                    .await
            }
            Ok(Backend::Native(p)) => {
                p.unix_user_tgts(id, old_token, keystore, tpm, machine_key)
                    .await
            }
            Err(_) => (None, None, None, None),
        }
    }

    async fn unix_user_prt_cookie<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        token: Option<&UserToken>,
        sso_nonce: Option<&str>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<String, IdpError> {
        match self.backend().await? {
            Backend::Standard(p) => {
                p.unix_user_prt_cookie(id, token, sso_nonce, keystore, tpm, machine_key)
                    .await
            }
            Backend::Native(p) => {
                p.unix_user_prt_cookie(id, token, sso_nonce, keystore, tpm, machine_key)
                    .await
            }
        }
    }

    async fn change_auth_token<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UnixUserToken,
        new_tok: &str,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<bool, IdpError> {
        match self.backend().await? {
            Backend::Standard(p) => {
                p.change_auth_token(account_id, token, new_tok, keystore, tpm, machine_key)
                    .await
            }
            Backend::Native(p) => {
                p.change_auth_token(account_id, token, new_tok, keystore, tpm, machine_key)
                    .await
            }
        }
    }

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
        shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        match self.backend().await? {
            Backend::Standard(p) => {
                p.unix_user_online_auth_step(
                    account_id,
                    old_token,
                    service,
                    no_hello_pin,
                    cred_handler,
                    pam_next_req,
                    keystore,
                    tpm,
                    machine_key,
                    shutdown_rx,
                )
                .await
            }
            Backend::Native(p) => {
                p.unix_user_online_auth_step(
                    account_id,
                    old_token,
                    service,
                    no_hello_pin,
                    cred_handler,
                    pam_next_req,
                    keystore,
                    tpm,
                    machine_key,
                    shutdown_rx,
                )
                .await
            }
        }
    }

    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: Option<&UserToken>,
        service: &str,
        no_hello_pin: bool,
        keystore: &mut D,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        match self.offline_backend().await? {
            Backend::Standard(p) => {
                p.unix_user_offline_auth_init(account_id, token, service, no_hello_pin, keystore)
                    .await
            }
            Backend::Native(p) => {
                p.unix_user_offline_auth_init(account_id, token, service, no_hello_pin, keystore)
                    .await
            }
        }
    }

    async fn unix_user_offline_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UserToken,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        online_at_init: bool,
    ) -> Result<AuthResult, IdpError> {
        match self.offline_backend().await? {
            Backend::Standard(p) => {
                p.unix_user_offline_auth_step(
                    account_id,
                    token,
                    cred_handler,
                    pam_next_req,
                    keystore,
                    tpm,
                    machine_key,
                    online_at_init,
                )
                .await
            }
            Backend::Native(p) => {
                p.unix_user_offline_auth_step(
                    account_id,
                    token,
                    cred_handler,
                    pam_next_req,
                    keystore,
                    tpm,
                    machine_key,
                    online_at_init,
                )
                .await
            }
        }
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
        let backend = if online {
            self.backend().await?
        } else {
            self.offline_backend().await?
        };
        match backend {
            Backend::Standard(p) => {
                p.unix_user_try_unseal(account_id, cred, keystore, tpm, machine_key, online)
                    .await
            }
            Backend::Native(p) => {
                p.unix_user_try_unseal(account_id, cred, keystore, tpm, machine_key, online)
                    .await
            }
        }
    }

    async fn unix_group_get(
        &self,
        id: &Id,
        tpm: &mut tpm::provider::BoxedDynTpm,
    ) -> Result<GroupToken, IdpError> {
        match self.backend().await? {
            Backend::Standard(p) => p.unix_group_get(id, tpm).await,
            Backend::Native(p) => p.unix_group_get(id, tpm).await,
        }
    }

    async fn offline_break_glass(&self, ttl: Option<u64>) -> Result<(), IdpError> {
        match self.offline_backend().await? {
            Backend::Standard(p) => p.offline_break_glass(ttl).await,
            Backend::Native(p) => p.offline_break_glass(ttl).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Cache;
    use serde_json::json;

    #[allow(clippy::unwrap_used)]
    async fn pending_router() -> OidcRouter {
        let mut config = HimmelblauConfig::new(Some("/dev/null")).unwrap();
        config.set("global", "oidc_issuer_url", "https://127.0.0.1:9");
        config.set("global", "oidc_force_interaction_code", "true");
        config.set("oidc", "app_id", "fixture-client");
        let config = Arc::new(Mutex::new(config));
        let idmap = Arc::new(Mutex::new(Idmap::new().unwrap()));
        let standard = Arc::new(OidcProvider::new(&config, "oidc", &idmap).unwrap());
        let native = OktaProvider::new(&config, "oidc", &idmap, &standard)
            .await
            .map(Arc::new);
        assert!(native.is_ok());
        OidcRouter {
            standard,
            native,
            config,
            selection: Mutex::new(Selection::Pending),
        }
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn pending_selection_preserves_offline_state_but_never_reports_online() {
        let router = pending_router().await;
        let db = crate::db::Db::new("").unwrap();
        let mut txn = db.write().await;
        let deadline = SystemTime::now() + Duration::from_secs(60);
        *router.standard.state.lock().await = CacheState::OfflineNextCheck(deadline);
        assert!(matches!(router.get_cachestate(None, &mut txn).await,
            CacheState::OfflineNextCheck(time) if time == deadline));
        *router.standard.state.lock().await = CacheState::Offline;
        assert!(matches!(
            router.get_cachestate(None, &mut txn).await,
            CacheState::Offline
        ));
        *router.standard.state.lock().await = CacheState::Online;
        assert!(matches!(router.get_cachestate(None, &mut txn).await,
            CacheState::OfflineNextCheck(time) if time <= SystemTime::now()));
        assert!(router.backend().await.is_err());
        assert!(matches!(
            router.offline_backend().await,
            Ok(Backend::Standard(_))
        ));

        for selection in [Selection::StandardOidc, Selection::InteractionCode] {
            *router.selection.lock().await = selection;
            assert!(router.backend().await.is_ok());
            assert!(router.offline_backend().await.is_ok());
            assert!(matches!(
                router.get_cachestate(None, &mut txn).await,
                CacheState::Online
            ));
        }
        *router.selection.lock().await = Selection::Failed;
        assert!(router.backend().await.is_err());
        assert!(router.offline_backend().await.is_err());
        assert!(matches!(
            router.get_cachestate(None, &mut txn).await,
            CacheState::Online
        ));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn pending_selection_blocks_online_delegations() {
        use tpm::{provider::SoftTpm, provider::Tpm, AuthValue};
        let router = pending_router().await;
        let deadline = SystemTime::now() + Duration::from_secs(60);
        *router.standard.state.lock().await = CacheState::OfflineNextCheck(deadline);
        let db = crate::db::Db::new("").unwrap();
        let mut txn = db.write().await;
        let mut tpm = tpm::provider::BoxedDynTpm::new(SoftTpm::new());
        let auth = AuthValue::ephemeral().unwrap();
        let loadable = tpm.root_storage_key_create(&auth).unwrap();
        let key = tpm.root_storage_key_load(&auth, &loadable).unwrap();
        let (_, shutdown) = broadcast::channel(1);
        assert!(!router.check_online(&mut tpm, SystemTime::now()).await);
        let (prompt, handler) = router
            .unix_user_online_auth_init(
                "user@example.com",
                None,
                "login",
                true,
                false,
                &mut txn,
                &mut tpm,
                &key,
                &shutdown,
            )
            .await
            .unwrap();
        assert!(matches!(prompt, AuthRequest::InitDenied { .. }));
        assert!(matches!(handler, AuthCredHandler::None));
        assert!(router
            .unix_user_access(
                &Id::Name("user@example.com".into()),
                vec![],
                None,
                None,
                None,
                None,
                &mut txn,
                &mut tpm,
                &key,
            )
            .await
            .is_err());
        let token: UnixUserToken = serde_json::from_value(json!({
            "token_type": "Bearer", "expires_in": 60, "ext_expires_in": 60,
            "refresh_token": "fixture-refresh"
        }))
        .unwrap();
        assert!(router
            .change_auth_token(
                "user@example.com",
                &token,
                "123456",
                &mut txn,
                &mut tpm,
                &key,
            )
            .await
            .is_err());
        assert!(router
            .unix_user_try_unseal("user@example.com", "123456", &mut txn, &mut tpm, &key, true,)
            .await
            .is_err());
        assert!(matches!(*router.standard.state.lock().await,
            CacheState::OfflineNextCheck(time) if time == deadline));
        assert_eq!(*router.selection.lock().await, Selection::Pending);
    }

    fn dag() -> Value {
        json!({"device_authorization_endpoint":"https://example.com/device",
        "grant_types_supported":["urn:ietf:params:oauth:grant-type:device_code"]})
    }

    #[test]
    fn ordinary_dag_issuers_do_not_get_speculative_probes() {
        assert!(!should_probe("https://example.com", &dag(), None, false));
        assert!(should_probe("https://example.com", &dag(), None, true));
        assert!(should_probe("https://example.com", &json!({}), None, false));
        assert!(should_probe(
            "https://example.com",
            &json!({"grant_types_supported":["interaction_code"]}),
            None,
            false
        ));
    }

    #[test]
    fn configured_device_endpoint_avoids_speculative_probe() {
        let metadata = json!({
            "grant_types_supported":["urn:ietf:params:oauth:grant-type:device_code"]
        });
        assert!(!should_probe(
            "https://example.com",
            &metadata,
            Some("https://example.com/device"),
            false
        ));
    }

    #[test]
    fn okta_hints_handle_custom_domains_and_hostname_boundaries() {
        assert!(should_probe(
            "https://example.okta.com/oauth2/default",
            &dag(),
            None,
            false
        ));
        assert!(!is_okta("https://okta.com.attacker.example", &dag()));
        assert!(!is_okta("https://notokta.com", &dag()));
        let mut metadata = dag();
        metadata["response_modes_supported"] = json!(["okta_post_message"]);
        assert!(should_probe(
            "https://login.example.com",
            &metadata,
            None,
            false
        ));
    }
}
