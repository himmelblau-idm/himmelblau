/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// use async_trait::async_trait;
use hashbrown::HashSet;
use libc::uid_t;
use libkrimes::proto::KerberosCredentials;
use std::collections::BTreeSet;
use std::fmt::Display;
use std::fs;
use std::num::NonZeroUsize;
use std::ops::DerefMut;
use std::path::Path;
use std::string::ToString;
use std::time::{Duration, SystemTime};

use lru::LruCache;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::config::{split_username, InitgroupsMode};
use crate::constants::SERVER_CONFIG_PATH;
use crate::db::{Cache, CacheTxn, Db};
use crate::idprovider::interface::{
    AuthCacheAction,
    AuthCredHandler,
    AuthRequest,
    AuthResult,
    CacheState,
    GroupToken,
    Id,
    IdProvider,
    IdpError,
    // KeyStore,
    UserToken,
    UserTokenState,
};
use crate::unix_config::{HomeAttr, UidAttr};
use crate::unix_proto::{HomeDirectoryInfo, NssGroup, NssUser, PamAuthRequest, PamAuthResponse};

use kanidm_hsm_crypto::{
    provider::BoxedDynTpm, structures::HmacS256Key as HmacKey, structures::StorageKey as MachineKey,
};

use tokio::sync::broadcast;

use himmelblau::auth::UserToken as UnixUserToken;

const NXCACHE_SIZE: NonZeroUsize = NonZeroUsize::new(128).unwrap();

#[allow(clippy::large_enum_variant)]
pub enum AuthSession {
    InProgress {
        account_id: String,
        service: String,
        id: Id,
        token: Option<Box<UserToken>>,
        online_at_init: bool,
        cred_handler: AuthCredHandler,
        /// Some authentication operations may need to spawn background tasks. These tasks need
        /// to know when to stop as the caller has disconnected. This reciever allows that, so
        /// that tasks which .resubscribe() to this channel can then select! on it and be notified
        /// when they need to stop.
        shutdown_rx: broadcast::Receiver<()>,
        no_hello_pin: bool,
        force_reauth: bool,
    },
    Success(String),
    Denied,
}

pub struct Resolver<I>
where
    I: IdProvider + Sync,
{
    // Generic / modular types.
    db: Db,
    hsm: Mutex<BoxedDynTpm>,
    machine_key: MachineKey,
    hmac_key: HmacKey,
    client: I,
    pam_allow_groups: BTreeSet<String>,
    oidc_auth: bool,
    timeout_seconds: u64,
    default_shell: String,
    home_prefix: String,
    home_attr: HomeAttr,
    home_alias: Option<HomeAttr>,
    uid_attr_map: UidAttr,
    gid_attr_map: UidAttr,
    initgroups_mode: InitgroupsMode,
    allow_id_overrides: HashSet<Id>,
    nxset: Mutex<HashSet<Id>>,
    nxcache: Mutex<LruCache<Id, SystemTime>>,
    // Only exact, online user lookups with no cached alias may populate this.
    alias_absence: Mutex<LruCache<String, SystemTime>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolverError;

pub type ResolverResult<T> = Result<T, ResolverError>;

impl Display for ResolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("resolver error")
    }
}

impl std::error::Error for ResolverError {}

impl From<()> for ResolverError {
    fn from(_: ()) -> Self {
        Self
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            Id::Name(s) => s.to_string(),
            Id::Gid(g) => g.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{is_placeholder_token, AuthSession, Resolver};
    use crate::config::InitgroupsMode;
    use crate::db::{Cache, CacheTxn, Db, KeyStoreTxn};
    use crate::idprovider::interface::{
        tpm, AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, CacheState, GroupToken, Id,
        IdProvider, IdpError, UserToken, UserTokenState,
    };
    use crate::unix_config::{HomeAttr, UidAttr};
    use crate::unix_proto::{PamAuthRequest, PamAuthResponse};
    use async_trait::async_trait;
    use himmelblau::UserToken as UnixUserToken;
    use kanidm_hsm_crypto::{provider::BoxedDynTpm, provider::SoftTpm, provider::Tpm, AuthValue};
    use libkrimes::proto::KerberosCredentials;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::RwLock;
    use std::time::{Duration, SystemTime};
    use tokio::sync::broadcast;

    struct OfflineFallbackProvider {
        cache_state: RwLock<CacheState>,
        check_online_result: AtomicBool,
        cache_state_calls: AtomicUsize,
        check_online_calls: AtomicUsize,
        try_unseal_online: AtomicBool,
        user_get_calls: AtomicUsize,
        try_unseal_calls: AtomicUsize,
        user_get_error: AtomicUsize,
        exact_token: RwLock<Option<UserToken>>,
        exact_not_found: AtomicBool,
        lookup_ids: RwLock<Vec<(Id, Option<String>)>>,
        credential_ids: RwLock<Vec<String>>,
        pause_lookup: AtomicBool,
        lookup_started: tokio::sync::Notify,
        lookup_continue: tokio::sync::Notify,
    }

    impl OfflineFallbackProvider {
        fn new() -> Self {
            Self {
                cache_state: RwLock::new(CacheState::Online),
                check_online_result: AtomicBool::new(true),
                cache_state_calls: AtomicUsize::new(0),
                check_online_calls: AtomicUsize::new(0),
                try_unseal_online: AtomicBool::new(false),
                user_get_calls: AtomicUsize::new(0),
                try_unseal_calls: AtomicUsize::new(0),
                user_get_error: AtomicUsize::new(0),
                exact_token: RwLock::new(None),
                exact_not_found: AtomicBool::new(false),
                lookup_ids: RwLock::new(Vec::new()),
                credential_ids: RwLock::new(Vec::new()),
                pause_lookup: AtomicBool::new(false),
                lookup_started: tokio::sync::Notify::new(),
                lookup_continue: tokio::sync::Notify::new(),
            }
        }

        fn set_cache_state(&self, state: CacheState) {
            *self.cache_state.write().expect("cache state lock poisoned") = state;
        }
    }

    #[async_trait]
    impl IdProvider for OfflineFallbackProvider {
        async fn check_online(
            &self,
            _tpm: &mut tpm::provider::BoxedDynTpm,
            _now: SystemTime,
        ) -> bool {
            self.check_online_calls.fetch_add(1, Ordering::AcqRel);
            self.check_online_result.load(Ordering::Acquire)
        }

        async fn unix_user_get<D: KeyStoreTxn + Send>(
            &self,
            _id: &Id,
            _token: Option<&UserToken>,
            _keystore: &mut D,
            _tpm: &mut tpm::provider::BoxedDynTpm,
            _machine_key: &tpm::structures::StorageKey,
        ) -> Result<UserTokenState, IdpError> {
            self.user_get_calls.fetch_add(1, Ordering::AcqRel);
            self.lookup_ids
                .write()
                .unwrap()
                .push((_id.clone(), _token.map(|token| token.spn.clone())));
            if _token.is_none() {
                if self.pause_lookup.load(Ordering::Acquire) {
                    self.lookup_started.notify_one();
                    self.lookup_continue.notified().await;
                }
                if let Some(token) = self.exact_token.read().unwrap().clone() {
                    return Ok(UserTokenState::Update(token));
                }
                if self.exact_not_found.load(Ordering::Acquire) {
                    return Ok(UserTokenState::NotFound);
                }
            }
            match self.user_get_error.load(Ordering::Acquire) {
                1 => Err(IdpError::NotFound {
                    what: "user".to_string(),
                    where_: "test provider".to_string(),
                }),
                2 => Err(IdpError::BadRequest),
                3 => Err(IdpError::Transport),
                4 => Err(IdpError::ProviderUnauthorised),
                5 => Err(IdpError::KeyStore),
                6 => Err(IdpError::Tpm),
                _ => Ok(UserTokenState::UseCached),
            }
        }

        async fn unix_user_access<D: KeyStoreTxn + Send>(
            &self,
            _id: &Id,
            _scopes: Vec<String>,
            _token: Option<&UserToken>,
            _client_id: Option<String>,
            _redirect_uri: Option<String>,
            _req_cnf: Option<String>,
            _keystore: &mut D,
            _tpm: &mut tpm::provider::BoxedDynTpm,
            _machine_key: &tpm::structures::StorageKey,
        ) -> Result<UnixUserToken, IdpError> {
            Err(IdpError::BadRequest)
        }

        async fn unix_user_tgts<D: KeyStoreTxn + Send>(
            &self,
            _id: &Id,
            _old_token: Option<&UserToken>,
            _keystore: &mut D,
            _tpm: &mut tpm::provider::BoxedDynTpm,
            _machine_key: &tpm::structures::StorageKey,
        ) -> (
            Option<Box<KerberosCredentials>>,
            Option<Box<KerberosCredentials>>,
            Option<String>,
            Option<String>,
        ) {
            (None, None, None, None)
        }

        async fn unix_user_prt_cookie<D: KeyStoreTxn + Send>(
            &self,
            _id: &Id,
            _token: Option<&UserToken>,
            _sso_nonce: Option<&str>,
            _keystore: &mut D,
            _tpm: &mut tpm::provider::BoxedDynTpm,
            _machine_key: &tpm::structures::StorageKey,
        ) -> Result<String, IdpError> {
            Err(IdpError::BadRequest)
        }

        async fn change_auth_token<D: KeyStoreTxn + Send>(
            &self,
            _account_id: &str,
            _token: &UnixUserToken,
            _new_tok: &str,
            _keystore: &mut D,
            _tpm: &mut tpm::provider::BoxedDynTpm,
            _machine_key: &tpm::structures::StorageKey,
        ) -> Result<bool, IdpError> {
            self.credential_ids
                .write()
                .unwrap()
                .push(_account_id.to_string());
            Err(IdpError::BadRequest)
        }

        async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
            &self,
            _account_id: &str,
            _token: Option<&UserToken>,
            _service: &str,
            _no_hello_pin: bool,
            _force_reauth: bool,
            _keystore: &mut D,
            _tpm: &mut tpm::provider::BoxedDynTpm,
            _machine_key: &tpm::structures::StorageKey,
            _shutdown_rx: &broadcast::Receiver<()>,
        ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
            self.credential_ids
                .write()
                .unwrap()
                .push(_account_id.to_string());
            self.set_cache_state(CacheState::OfflineNextCheck(
                SystemTime::now() + Duration::from_secs(60),
            ));
            Err(IdpError::BadRequest)
        }

        async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
            &self,
            _account_id: &str,
            _old_token: &UserToken,
            _service: &str,
            _no_hello_pin: bool,
            _cred_handler: &mut AuthCredHandler,
            _pam_next_req: PamAuthRequest,
            _keystore: &mut D,
            _tpm: &mut tpm::provider::BoxedDynTpm,
            _machine_key: &tpm::structures::StorageKey,
            _shutdown_rx: &broadcast::Receiver<()>,
        ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
            Err(IdpError::BadRequest)
        }

        async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
            &self,
            _account_id: &str,
            _token: Option<&UserToken>,
            _service: &str,
            _no_hello_pin: bool,
            _keystore: &mut D,
        ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
            self.credential_ids
                .write()
                .unwrap()
                .push(_account_id.to_string());
            Ok((AuthRequest::Pin, AuthCredHandler::None))
        }

        async fn unix_user_offline_auth_step<D: KeyStoreTxn + Send>(
            &self,
            _account_id: &str,
            _token: &UserToken,
            _cred_handler: &mut AuthCredHandler,
            _pam_next_req: PamAuthRequest,
            _keystore: &mut D,
            _tpm: &mut tpm::provider::BoxedDynTpm,
            _machine_key: &tpm::structures::StorageKey,
            _online_at_init: bool,
        ) -> Result<AuthResult, IdpError> {
            Err(IdpError::BadRequest)
        }

        async fn unix_user_try_unseal<D: KeyStoreTxn + Send>(
            &self,
            _account_id: &str,
            _cred: &str,
            _keystore: &mut D,
            _tpm: &mut tpm::provider::BoxedDynTpm,
            _machine_key: &tpm::structures::StorageKey,
            online: bool,
        ) -> Result<bool, IdpError> {
            self.credential_ids
                .write()
                .unwrap()
                .push(_account_id.to_string());
            self.try_unseal_calls.fetch_add(1, Ordering::AcqRel);
            self.try_unseal_online.store(online, Ordering::Release);
            Ok(true)
        }

        async fn unix_group_get(
            &self,
            _id: &Id,
            _tpm: &mut tpm::provider::BoxedDynTpm,
        ) -> Result<GroupToken, IdpError> {
            Err(IdpError::NotFound {
                what: "group".to_string(),
                where_: "test".to_string(),
            })
        }

        async fn get_cachestate<D: KeyStoreTxn + Send>(
            &self,
            _account_id: Option<&str>,
            _keystore: &mut D,
        ) -> CacheState {
            self.cache_state_calls.fetch_add(1, Ordering::AcqRel);
            self.cache_state
                .read()
                .expect("cache state lock poisoned")
                .clone()
        }

        async fn offline_break_glass(&self, _ttl: Option<u64>) -> Result<(), IdpError> {
            Ok(())
        }
    }

    fn test_token() -> UserToken {
        let group = GroupToken {
            name: "linux-users".to_string(),
            spn: "linux-users".to_string(),
            uuid: uuid::uuid!("9f8a7a5a-a8e8-5c57-9f4f-7dfe21126c23"),
            gidnumber: 2100,
        };
        UserToken {
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
            real_gidnumber: Some(2000),
            gidnumber: 2000,
            displayname: "Test User".to_string(),
            shell: None,
            groups: vec![group],
            tenant_id: Some(uuid::uuid!("58e8a301-2502-4814-81c5-a4d17c399a45")),
            valid: true,
            is_placeholder: false,
        }
    }

    async fn setup_resolver_with_expiry(expiry: u64) -> Resolver<OfflineFallbackProvider> {
        setup_resolver_with(expiry, InitgroupsMode::Named, Vec::new()).await
    }

    async fn setup_resolver_with(
        expiry: u64,
        initgroups_mode: InitgroupsMode,
        extra_groups: Vec<GroupToken>,
    ) -> Resolver<OfflineFallbackProvider> {
        let allow_groups = vec!["9f8a7a5a-a8e8-5c57-9f4f-7dfe21126c23".to_string()];
        setup_resolver_allowing(expiry, initgroups_mode, extra_groups, allow_groups).await
    }

    async fn setup_resolver_allowing(
        expiry: u64,
        initgroups_mode: InitgroupsMode,
        extra_groups: Vec<GroupToken>,
        pam_allow_groups: Vec<String>,
    ) -> Resolver<OfflineFallbackProvider> {
        let db = Db::new("").expect("failed to create test db");
        let mut dbtxn = db.write().await;
        dbtxn.migrate().expect("failed to migrate test db");
        let mut token = test_token();
        let named_group = token.groups[0].clone();
        token.groups.extend(extra_groups);
        dbtxn
            .update_group(&named_group, expiry)
            .expect("failed to seed test group");
        dbtxn
            .update_account(&token, expiry)
            .expect("failed to seed test token");
        dbtxn.commit().expect("failed to commit test db");

        let mut hsm = BoxedDynTpm::new(SoftTpm::new());
        let auth_value = AuthValue::ephemeral().expect("failed to create auth value");
        let loadable_machine_key = hsm
            .root_storage_key_create(&auth_value)
            .expect("failed to create machine key");
        let machine_key = hsm
            .root_storage_key_load(&auth_value, &loadable_machine_key)
            .expect("failed to load machine key");

        Resolver::new(
            db,
            OfflineFallbackProvider::new(),
            hsm,
            machine_key,
            3600,
            pam_allow_groups,
            false,
            "/bin/sh".to_string(),
            "/home/".to_string(),
            HomeAttr::Name,
            None,
            UidAttr::Name,
            UidAttr::Name,
            initgroups_mode,
            Vec::new(),
        )
        .await
        .expect("failed to create resolver")
    }

    async fn setup_resolver() -> Resolver<OfflineFallbackProvider> {
        setup_resolver_with_expiry(0).await
    }

    #[tokio::test]
    async fn refresh_usertoken_logs_not_found_at_debug_and_other_errors_at_error() {
        use std::sync::{Arc, Mutex};
        use tracing::instrument::WithSubscriber;
        use tracing::{Event, Level, Subscriber};
        use tracing_subscriber::layer::{Context, SubscriberExt};
        use tracing_subscriber::Layer;

        struct Events(Arc<Mutex<Vec<Level>>>);
        impl<S: Subscriber> Layer<S> for Events {
            fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
                if event.metadata().target() == "himmelblau_unix_common::resolver" {
                    self.0
                        .lock()
                        .expect("events lock poisoned")
                        .push(*event.metadata().level());
                }
            }
        }

        let resolver = setup_resolver().await;
        let id = Id::Name("testuser@example.com".to_string());
        for (error, level) in [(1, Level::DEBUG), (2, Level::ERROR)] {
            resolver
                .client
                .user_get_error
                .store(error, Ordering::Release);
            for token in [None, Some(test_token())] {
                let expected_spn = token.as_ref().map(|token| token.spn.clone());
                let events = Arc::new(Mutex::new(Vec::new()));
                let subscriber = tracing_subscriber::registry().with(Events(events.clone()));
                let result = resolver
                    .refresh_usertoken(&id, token)
                    .with_subscriber(subscriber)
                    .await
                    .expect("refresh failed");
                assert_eq!(result.map(|token| token.spn), expected_spn);
                assert_eq!(*events.lock().expect("events lock poisoned"), vec![level]);
            }
        }
    }

    fn aliased_token() -> UserToken {
        let mut token = test_token();
        token.name = "onprem-user".to_string();
        token.spn = "first.last@example.com".to_string();
        token.uuid = uuid::uuid!("7d1a52f3-3f4e-4f7e-8f3e-3c3f0b2f9a10");
        token.real_gidnumber = Some(2001);
        token.gidnumber = 2001;
        token
    }

    async fn seed_aliased_token(resolver: &Resolver<OfflineFallbackProvider>) {
        let mut dbtxn = resolver.db.write().await;
        dbtxn
            .update_account(&aliased_token(), 0)
            .expect("failed to seed aliased token");
        dbtxn.commit().expect("failed to commit aliased token");
    }

    #[tokio::test]
    async fn cached_usertoken_is_found_by_expanded_local_name() {
        let resolver = setup_resolver().await;
        seed_aliased_token(&resolver).await;

        for (name, found) in [
            // The local name itself, and the UPN
            ("onprem-user", true),
            ("first.last@example.com", true),
            // The local name expanded into the same domain by cn_name_mapping
            ("onprem-user@example.com", true),
            ("ONPREM-USER@Example.com", true),
            // Never into another domain
            ("onprem-user@other.com", false),
            ("unknown@example.com", false),
        ] {
            let (_expired, cached) = resolver
                .get_cached_usertoken(&Id::Name(name.to_string()))
                .await
                .expect("failed to read cached user");
            assert_eq!(
                cached.map(|t| t.spn),
                found.then(|| aliased_token().spn),
                "lookup of {name}"
            );
        }
    }

    #[tokio::test]
    async fn exact_placeholder_wins_over_a_local_alias() {
        let resolver = setup_resolver().await;
        seed_aliased_token(&resolver).await;

        // What the identity provider cached when the expanded name was tried
        // as a UPN before the user was known.
        let uuid = uuid::uuid!("c0ffee00-0000-4000-8000-000000000001");
        let mut placeholder = test_token();
        placeholder.name = "onprem-user@example.com".to_string();
        placeholder.spn = "onprem-user@example.com".to_string();
        placeholder.uuid = uuid;
        placeholder.is_placeholder = true;
        placeholder.real_gidnumber = Some(2002);
        placeholder.gidnumber = 2002;
        placeholder.groups = vec![GroupToken {
            name: placeholder.spn.clone(),
            spn: placeholder.spn.clone(),
            uuid,
            gidnumber: 2002,
        }];
        assert!(is_placeholder_token(&placeholder));
        assert!(!is_placeholder_token(&aliased_token()));
        // The provider creates placeholders only after confirming this UPN
        // exists. Its canonical name must win over another user's local alias.
        resolver
            .set_cache_usertoken(&mut placeholder)
            .await
            .unwrap();

        let (_expired, cached) = resolver
            .get_cached_usertoken(&Id::Name("onprem-user@example.com".to_string()))
            .await
            .expect("failed to read cached user");
        assert_eq!(cached.map(|t| t.spn), Some(placeholder.spn));
    }

    #[tokio::test]
    async fn auth_init_uses_the_upn_of_a_local_name() {
        let resolver = setup_resolver().await;
        seed_aliased_token(&resolver).await;
        resolver
            .client
            .exact_not_found
            .store(true, Ordering::Release);
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let (session, _resp) = resolver
            .pam_account_authenticate_init(
                "onprem-user@example.com",
                "gdm-password",
                false,
                false,
                shutdown_rx,
            )
            .await
            .expect("auth init failed");
        match session {
            AuthSession::InProgress { account_id, .. } => {
                assert_eq!(account_id, "first.last@example.com")
            }
            _ => panic!("expected an in progress auth session"),
        }
    }

    #[tokio::test]
    async fn allow_list_matches_the_resolved_user_only() {
        // "onprem-user@example.com" is the UPN of some other user. Here it is
        // merely the expanded local name of the cached "first.last@example.com".
        for (allowed, admitted) in [
            ("onprem-user@example.com", false),
            ("first.last@example.com", true),
        ] {
            let resolver = setup_resolver_allowing(
                0,
                InitgroupsMode::Named,
                Vec::new(),
                vec![allowed.to_string()],
            )
            .await;
            seed_aliased_token(&resolver).await;
            resolver
                .client
                .exact_not_found
                .store(true, Ordering::Release);

            assert_eq!(
                resolver
                    .pam_account_allowed("onprem-user@example.com")
                    .await
                    .expect("allow-group check failed"),
                Some(admitted),
                "allow list {allowed}"
            );
        }
    }

    #[tokio::test]
    async fn nxset_compares_names_case_insensitively() {
        let resolver = setup_resolver().await;
        resolver
            .reload_nxset(vec![("Admin".to_string(), 4242u32)].into_iter())
            .await;

        for name in ["admin", "ADMIN", "Admin"] {
            assert!(resolver.check_nxset(Some(name), None).await, "{name}");
        }
        assert!(resolver.check_nxset(None, Some(4242)).await);
        assert!(!resolver.check_nxset(Some("administrator"), None).await);
        assert!(!resolver.check_nxset(Some("admin@example.com"), None).await);
    }

    #[tokio::test]
    async fn user_colliding_with_a_local_account_is_not_returned() {
        let resolver = setup_resolver().await;
        seed_aliased_token(&resolver).await;
        let id = Id::Name("first.last@example.com".to_string());

        let found = resolver
            .get_usertoken(id.clone())
            .await
            .expect("lookup failed");
        assert_eq!(found.map(|t| t.name), Some("onprem-user".to_string()));

        // A local account appears which has the Entra user's local name.
        resolver
            .reload_nxset(vec![("ONPREM-USER".to_string(), 99999u32)].into_iter())
            .await;
        assert!(resolver
            .get_usertoken(id)
            .await
            .expect("lookup failed")
            .is_none());
    }

    #[tokio::test]
    async fn authoritative_upn_with_synthetic_primary_group_wins_over_sam() {
        let resolver = setup_resolver().await;
        let mut bob = aliased_token();
        bob.spn = "bob@example.com".into();
        bob.name = "robert".into();
        bob.groups = vec![GroupToken {
            name: bob.spn.clone(),
            spn: bob.spn.clone(),
            uuid: bob.uuid,
            gidnumber: bob.gidnumber,
        }];
        let mut alice = test_token();
        alice.name = "bob".into();
        alice.spn = "alice@example.com".into();
        {
            let mut txn = resolver.db.write().await;
            txn.update_group(&bob.groups[0], 0).unwrap();
            txn.update_account(&bob, 0).unwrap();
            txn.update_account(&alice, 0).unwrap();
            txn.commit().unwrap();
        }
        let (_, cached) = resolver
            .get_cached_usertoken(&Id::Name(bob.spn.clone()))
            .await
            .unwrap();
        assert_eq!(cached.unwrap().uuid, bob.uuid);
        let (_tx, rx) = broadcast::channel(1);
        let (session, _) = resolver
            .pam_account_authenticate_init(&bob.spn, "gdm-password", false, false, rx)
            .await
            .unwrap();
        match session {
            AuthSession::InProgress { account_id, .. } => assert_eq!(account_id, bob.spn),
            _ => panic!("expected in-progress authentication"),
        }
    }

    #[test]
    fn legacy_token_is_not_classified_from_group_shape() {
        let mut token = test_token();
        token.groups[0].uuid = token.uuid;
        let mut serialized = serde_json::to_value(&token).unwrap();
        serialized.as_object_mut().unwrap().remove("is_placeholder");
        let restored: UserToken = serde_json::from_value(serialized).unwrap();
        assert!(!is_placeholder_token(&restored));
    }

    #[tokio::test]
    async fn conflicting_sam_falls_back_without_evicting_cached_credentials() {
        for name in ["onprem-user", "ONPREM-USER"] {
            let resolver = setup_resolver().await;
            let mut first = aliased_token();
            resolver.set_cache_usertoken(&mut first).await.unwrap();
            resolver
                .set_cache_userpassword(first.uuid, "keep-me")
                .await
                .unwrap();
            let mut second = test_token();
            second.name = name.into();
            second.spn = "second@other.com".into();
            resolver.set_cache_usertoken(&mut second).await.unwrap();
            assert_eq!(second.name, second.spn);
            assert!(resolver
                .check_cache_userpassword(first.uuid, "keep-me")
                .await
                .unwrap());
            let (_, cached) = resolver
                .get_cached_usertoken(&Id::Name(first.spn))
                .await
                .unwrap();
            assert_eq!(cached.unwrap().uuid, first.uuid);
        }
    }

    #[tokio::test]
    async fn same_spn_uuid_replacement_keeps_the_sam_name() {
        let resolver = setup_resolver().await;
        let mut token = aliased_token();
        resolver.set_cache_usertoken(&mut token).await.unwrap();
        let previous_uuid = token.uuid;
        resolver
            .set_cache_userpassword(previous_uuid, "old-account-password")
            .await
            .unwrap();
        token.uuid = uuid::Uuid::new_v4();
        resolver.set_cache_usertoken(&mut token).await.unwrap();
        assert_eq!(token.name, "onprem-user");
        let (_, cached) = resolver
            .get_cached_usertoken(&Id::Name(token.spn.clone()))
            .await
            .unwrap();
        assert_eq!(cached.unwrap().uuid, token.uuid);
        assert!(!resolver
            .check_cache_userpassword(token.uuid, "old-account-password")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn canonical_upn_reclaims_expanded_alias_without_deleting_its_owner() {
        let resolver = setup_resolver().await;
        let mut alice = aliased_token();
        alice.name = "bob".into();
        alice.spn = "alice@example.com".into();
        resolver.set_cache_usertoken(&mut alice).await.unwrap();
        resolver
            .set_cache_userpassword(alice.uuid, "alice-password")
            .await
            .unwrap();
        let mut bob = test_token();
        bob.name = "robert".into();
        bob.spn = "bob@example.com".into();
        resolver.set_cache_usertoken(&mut bob).await.unwrap();
        let (_, cached) = resolver
            .get_cached_usertoken(&Id::Name(alice.spn.clone()))
            .await
            .unwrap();
        assert_eq!(cached.unwrap().name, alice.spn);
        assert!(resolver
            .check_cache_userpassword(alice.uuid, "alice-password")
            .await
            .unwrap());
        let (_, cached) = resolver
            .get_cached_usertoken(&Id::Name(bob.spn))
            .await
            .unwrap();
        assert_eq!(cached.unwrap().uuid, bob.uuid);
    }

    #[tokio::test]
    async fn local_collisions_are_filtered_from_enumeration_refresh_and_members() {
        for (name, uid) in [("ONPREM-USER", 99999), ("unrelated", 2001)] {
            let resolver = setup_resolver().await;
            let mut token = aliased_token();
            resolver.set_cache_usertoken(&mut token).await.unwrap();
            assert!(resolver
                .get_nssaccounts()
                .await
                .unwrap()
                .iter()
                .any(|user| user.uid == token.gidnumber));
            resolver
                .reload_nxset(vec![(name.to_string(), uid)].into_iter())
                .await;
            assert!(!resolver
                .get_nssaccounts()
                .await
                .unwrap()
                .iter()
                .any(|user| user.uid == token.gidnumber));
            assert!(resolver
                .refresh_cached_usertoken(&token.spn)
                .await
                .unwrap()
                .is_none());
            assert!(!resolver
                .get_groupmembers(token.groups[0].uuid)
                .await
                .contains(&token.name));
        }
    }

    #[tokio::test]
    async fn group_exclusions_are_case_insensitive_during_cache_updates() {
        let resolver = setup_resolver().await;
        resolver
            .reload_nxset(vec![("Admin".into(), 99999)].into_iter())
            .await;
        for name in ["Admin", "ADMIN", "admin"] {
            let mut token = aliased_token();
            token.groups[0].name = name.into();
            resolver.set_cache_usertoken(&mut token).await.unwrap();
            assert!(token.groups.is_empty());
            assert!(resolver
                .get_groupmembers(test_token().groups[0].uuid)
                .await
                .iter()
                .all(|name| name != &token.name));
        }
    }

    #[tokio::test]
    async fn newly_excluded_groups_are_not_returned_from_old_cached_tokens() {
        for mode in [InitgroupsMode::Named, InitgroupsMode::Full] {
            let resolver = setup_resolver_with(0, mode, Vec::new()).await;
            let group = &test_token().groups[0];
            resolver
                .reload_nxset(vec![("LINUX-USERS".into(), 99999)].into_iter())
                .await;
            assert!(resolver
                .get_nssgroup_gid(group.gidnumber)
                .await
                .unwrap()
                .is_none());
            assert!(resolver
                .get_nssgroups()
                .await
                .unwrap()
                .iter()
                .all(|cached| cached.gid != group.gidnumber));
            assert!(resolver
                .get_initgroups("testuser")
                .await
                .unwrap()
                .unwrap()
                .is_empty());
        }
    }

    #[tokio::test]
    async fn qualified_secondary_sam_resolves_only_with_its_domain() {
        let resolver = setup_resolver().await;
        let mut token = aliased_token();
        token.name = "onprem-user@secondary.com".into();
        token.spn = "first.last@secondary.com".into();
        resolver.set_cache_usertoken(&mut token).await.unwrap();
        let nss = resolver
            .get_nssaccount_gid(token.gidnumber)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(nss.name, "onprem-user@secondary.com");
        let path =
            std::env::temp_dir().join(format!("himmelblau-sam-{}.conf", uuid::Uuid::new_v4()));
        std::fs::write(
            &path,
            "[global]\ndomains = primary.com,secondary.com\ncn_name_mapping = true\n",
        )
        .unwrap();
        let cfg = crate::config::HimmelblauConfig::new(path.to_str()).unwrap();
        std::fs::remove_file(path).unwrap();
        let displayed = cfg.map_upn_to_name(&nss.name);
        let lookup = cfg.map_name_to_upn(&displayed).unwrap();
        let (_, roundtrip) = resolver
            .get_cached_usertoken(&Id::Name(lookup))
            .await
            .unwrap();
        assert_eq!(roundtrip.unwrap().uuid, token.uuid);
        assert_eq!(
            nss.canonical_name.as_deref(),
            Some("first.last@secondary.com")
        );
        for (name, found) in [
            ("onprem-user@secondary.com", true),
            ("onprem-user@primary.com", false),
        ] {
            let (_, cached) = resolver
                .get_cached_usertoken(&Id::Name(name.into()))
                .await
                .unwrap();
            assert_eq!(cached.is_some(), found);
        }
    }

    async fn collision_resolver(
        qualified: bool,
        expiry: u64,
    ) -> (Resolver<OfflineFallbackProvider>, UserToken, UserToken) {
        let resolver = setup_resolver().await;
        let domain = if qualified {
            "secondary.com"
        } else {
            "example.com"
        };
        let mut alice = aliased_token();
        alice.name = if qualified {
            format!("bob@{domain}")
        } else {
            "bob".into()
        };
        alice.spn = format!("alice@{domain}");
        {
            let mut txn = resolver.db.write().await;
            txn.update_account(&alice, expiry).unwrap();
            txn.commit().unwrap();
        }
        let mut bob = test_token();
        bob.uuid = uuid::uuid!("cccccccc-0000-4000-8000-000000000001");
        bob.name = "robert".into();
        bob.spn = format!("bob@{domain}");
        bob.gidnumber = 2002;
        bob.real_gidnumber = Some(2002);
        (resolver, alice, bob)
    }

    fn future_expiry() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    #[tokio::test]
    async fn uncached_canonical_upn_wins_before_nss_and_authentication() {
        for qualified in [false, true] {
            for expiry in [0, future_expiry()] {
                for placeholder in [false, true] {
                    for authenticate in [false, true] {
                        let (resolver, alice, mut bob) =
                            collision_resolver(qualified, expiry).await;
                        bob.is_placeholder = placeholder;
                        if placeholder {
                            bob.name.clone_from(&bob.spn);
                        }
                        *resolver.client.exact_token.write().unwrap() = Some(bob.clone());
                        resolver
                            .set_cache_userpassword(alice.uuid, "alice-password")
                            .await
                            .unwrap();
                        let requested = bob.spn.to_uppercase();
                        if authenticate {
                            let (_tx, rx) = broadcast::channel(1);
                            let (session, _) = resolver
                                .pam_account_authenticate_init(
                                    &requested,
                                    "gdm-password",
                                    false,
                                    false,
                                    rx,
                                )
                                .await
                                .unwrap();
                            match session {
                                AuthSession::InProgress {
                                    account_id, token, ..
                                } => {
                                    assert_eq!(account_id, bob.spn);
                                    assert_eq!(token.unwrap().uuid, bob.uuid);
                                }
                                _ => panic!("expected Bob's authentication session"),
                            }
                            assert!(resolver
                                .client
                                .credential_ids
                                .read()
                                .unwrap()
                                .iter()
                                .all(|name| name == &bob.spn));
                        } else {
                            let user = resolver
                                .get_nssaccount_name(&requested)
                                .await
                                .unwrap()
                                .unwrap();
                            assert_eq!(user.uid, bob.gidnumber);
                            assert_eq!(user.canonical_name.as_deref(), Some(bob.spn.as_str()));
                        }
                        {
                            let lookups = resolver.client.lookup_ids.read().unwrap();
                            assert_eq!(lookups.len(), 1);
                            assert_eq!(lookups[0], (Id::Name(requested), None));
                        }
                        assert!(resolver
                            .check_cache_userpassword(alice.uuid, "alice-password")
                            .await
                            .unwrap());
                        let (_, cached) = resolver
                            .get_cached_usertoken(&Id::Name(alice.spn.clone()))
                            .await
                            .unwrap();
                        assert_eq!(cached.unwrap().name, alice.spn);
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn canonical_placeholder_reserves_its_name_in_both_insertion_orders() {
        for qualified in [false, true] {
            for placeholder_first in [false, true] {
                let (resolver, mut alice, mut bob) = collision_resolver(qualified, 0).await;
                bob.name.clone_from(&bob.spn);
                bob.is_placeholder = true;
                if placeholder_first {
                    resolver.delete_cache_usertoken(alice.uuid).await.unwrap();
                }
                resolver.set_cache_usertoken(&mut bob).await.unwrap();
                resolver.set_cache_usertoken(&mut alice).await.unwrap();
                let (_, resolved) = resolver
                    .resolve_cached_usertoken(&Id::Name(bob.spn.clone()))
                    .await
                    .unwrap();
                assert_eq!(resolved.unwrap().uuid, bob.uuid);
                assert_eq!(alice.name, alice.spn);
                assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
            }
        }
    }

    #[tokio::test]
    async fn alias_requires_explicit_exact_absence_not_generic_negative_cache() {
        let (resolver, alice, bob) = collision_resolver(false, future_expiry()).await;
        let id = Id::Name(bob.spn.clone());
        resolver.set_nxcache(&id).await;
        for error in 0..=6 {
            resolver
                .client
                .user_get_error
                .store(error, Ordering::Release);
            assert!(
                resolver.get_usertoken(id.clone()).await.is_err(),
                "error {error}"
            );
        }
        assert!(resolver.client.credential_ids.read().unwrap().is_empty());
        resolver.client.user_get_error.store(0, Ordering::Release);
        resolver
            .client
            .exact_not_found
            .store(true, Ordering::Release);
        assert_eq!(
            resolver
                .get_usertoken(id.clone())
                .await
                .unwrap()
                .unwrap()
                .uuid,
            alice.uuid
        );
        let calls = resolver.client.user_get_calls.load(Ordering::Acquire);
        resolver.client.set_cache_state(CacheState::Offline);
        assert_eq!(
            resolver.get_usertoken(id).await.unwrap().unwrap().uuid,
            alice.uuid
        );
        assert_eq!(
            resolver.client.user_get_calls.load(Ordering::Acquire),
            calls
        );
    }

    #[tokio::test]
    async fn unverified_offline_alias_cannot_select_credentials_or_nss_identity() {
        for state in [
            CacheState::Offline,
            CacheState::OfflineNextCheck(SystemTime::now() + Duration::from_secs(60)),
        ] {
            let (resolver, alice, bob) = collision_resolver(false, future_expiry()).await;
            resolver.client.set_cache_state(state);
            assert!(resolver.get_nssaccount_name(&bob.spn).await.is_err());
            let (_tx, rx) = broadcast::channel(1);
            assert!(resolver
                .pam_account_authenticate_init(&bob.spn, "gdm-password", false, false, rx)
                .await
                .is_err());
            assert!(resolver.pam_try_unseal(&bob.spn, "123456").await.is_err());
            assert!(resolver.refresh_cached_usertoken(&bob.spn).await.is_err());
            assert!(resolver.client.credential_ids.read().unwrap().is_empty());
            assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
            assert_eq!(
                resolver
                    .get_usertoken(Id::Name(alice.spn.clone()))
                    .await
                    .unwrap()
                    .unwrap()
                    .uuid,
                alice.uuid
            );
            assert_eq!(
                resolver
                    .get_usertoken(Id::Name("bob".into()))
                    .await
                    .unwrap()
                    .unwrap()
                    .uuid,
                alice.uuid
            );
            assert_eq!(
                resolver
                    .get_usertoken(Id::Name(alice.uuid.to_string()))
                    .await
                    .unwrap()
                    .unwrap()
                    .uuid,
                alice.uuid
            );
        }
    }

    #[tokio::test]
    async fn expired_alias_proof_requires_reverification_after_reconnect() {
        let (resolver, alice, bob) = collision_resolver(false, future_expiry()).await;
        let id = Id::Name(bob.spn.clone());
        resolver
            .client
            .exact_not_found
            .store(true, Ordering::Release);
        assert_eq!(
            resolver
                .get_usertoken(id.clone())
                .await
                .unwrap()
                .unwrap()
                .uuid,
            alice.uuid
        );
        resolver
            .alias_absence
            .lock()
            .await
            .put(bob.spn.clone(), SystemTime::UNIX_EPOCH);
        resolver.client.set_cache_state(CacheState::Offline);
        assert!(resolver.get_usertoken(id.clone()).await.is_err());
        resolver
            .client
            .set_cache_state(CacheState::OfflineNextCheck(SystemTime::UNIX_EPOCH));
        *resolver.client.exact_token.write().unwrap() = Some(bob.clone());
        let (_tx, rx) = broadcast::channel(1);
        let (session, _) = resolver
            .pam_account_authenticate_init(&bob.spn, "gdm-password", false, false, rx)
            .await
            .unwrap();
        match session {
            AuthSession::InProgress { account_id, .. } => assert_eq!(account_id, bob.spn),
            _ => panic!("expected Bob's session after reconnect"),
        }
        assert!(resolver
            .client
            .credential_ids
            .read()
            .unwrap()
            .iter()
            .all(|name| name == &bob.spn));
        assert!(resolver.alias_absence.lock().await.get(&bob.spn).is_none());
    }

    #[tokio::test]
    async fn unseal_and_forced_refresh_verify_the_exact_identity() {
        for unseal in [false, true] {
            let (resolver, _alice, bob) = collision_resolver(true, 0).await;
            *resolver.client.exact_token.write().unwrap() = Some(bob.clone());
            if unseal {
                assert!(resolver.pam_try_unseal(&bob.spn, "123456").await.unwrap());
                assert_eq!(
                    *resolver.client.credential_ids.read().unwrap(),
                    vec![bob.spn.clone()]
                );
            } else {
                assert_eq!(
                    resolver
                        .refresh_cached_usertoken(&bob.spn)
                        .await
                        .unwrap()
                        .unwrap()
                        .uuid,
                    bob.uuid
                );
            }
            assert_eq!(
                resolver.client.lookup_ids.read().unwrap()[0],
                (Id::Name(bob.spn), None)
            );
        }
    }

    #[tokio::test]
    async fn password_change_verifies_identity_before_selecting_a_provider_account() {
        let token = UnixUserToken {
            token_type: "Bearer".into(),
            scope: None,
            expires_in: 0,
            ext_expires_in: 0,
            access_token: None,
            refresh_token: String::new(),
            id_token: Default::default(),
            client_info: Default::default(),
            prt: None,
        };
        for online in [false, true] {
            let (resolver, _alice, bob) = collision_resolver(false, future_expiry()).await;
            if online {
                *resolver.client.exact_token.write().unwrap() = Some(bob.clone());
            } else {
                resolver.client.set_cache_state(CacheState::Offline);
            }
            // The mock provider rejects the operation; the destination still
            // proves that Alice's credential operation was never selected.
            assert!(resolver
                .change_auth_token(&bob.spn, &token, "test-password")
                .await
                .is_err());
            let expected = if online { vec![bob.spn] } else { Vec::new() };
            assert_eq!(*resolver.client.credential_ids.read().unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn canonical_insert_during_exact_probe_precedes_its_stale_result() {
        for result in 0..3 {
            let (resolver, _alice, mut bob) = collision_resolver(false, future_expiry()).await;
            let requested = bob.spn.clone();
            resolver.client.pause_lookup.store(true, Ordering::Release);
            resolver
                .client
                .exact_not_found
                .store(result == 1, Ordering::Release);
            if result == 0 {
                let mut provisional = bob.clone();
                provisional.uuid = uuid::uuid!("dddddddd-0000-4000-8000-000000000001");
                provisional.is_placeholder = true;
                *resolver.client.exact_token.write().unwrap() = Some(provisional);
            }
            let requested_id = Id::Name(requested.clone());
            let lookup = resolver.resolve_cached_usertoken(&requested_id);
            let concurrent_insert = async {
                resolver.client.lookup_started.notified().await;
                let release = async {
                    // Let set_cache_usertoken queue for the database lock held
                    // by the provider lookup before releasing that lookup.
                    tokio::task::yield_now().await;
                    resolver.client.lookup_continue.notify_one();
                };
                let (inserted, ()) = tokio::join!(resolver.set_cache_usertoken(&mut bob), release);
                inserted.unwrap();
            };
            let (resolved, ()) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(lookup, concurrent_insert)
            })
            .await
            .expect("concurrent identity lookup deadlocked");
            let (_, resolved) = resolved.unwrap();
            assert_eq!(resolved.unwrap().uuid, bob.uuid);
            assert!(resolver
                .alias_absence
                .lock()
                .await
                .get(&requested)
                .is_none());
        }
    }

    #[tokio::test]
    async fn invalidating_the_cache_discards_alias_absence_proof() {
        let (resolver, _alice, bob) = collision_resolver(false, future_expiry()).await;
        resolver
            .client
            .exact_not_found
            .store(true, Ordering::Release);
        resolver
            .get_usertoken(Id::Name(bob.spn.clone()))
            .await
            .unwrap()
            .unwrap();
        resolver.invalidate().await.unwrap();
        resolver.client.set_cache_state(CacheState::Offline);
        assert!(resolver.get_usertoken(Id::Name(bob.spn)).await.is_err());
    }

    #[tokio::test]
    async fn unrelated_probe_identity_never_authorizes_an_alias() {
        let (resolver, alice, bob) = collision_resolver(false, future_expiry()).await;
        *resolver.client.exact_token.write().unwrap() = Some(alice);
        assert!(resolver.get_usertoken(Id::Name(bob.spn)).await.is_err());
        assert!(resolver.alias_absence.lock().await.is_empty());
    }

    #[tokio::test]
    async fn initgroups_named_omits_gid_with_no_nss_name() {
        let unnamed = GroupToken {
            name: "unnamed".to_string(),
            spn: "unnamed".to_string(),
            uuid: uuid::uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            gidnumber: 299568524,
        };
        let named_resolver =
            setup_resolver_with(0, InitgroupsMode::Named, vec![unnamed.clone()]).await;
        let named = named_resolver
            .get_initgroups("testuser")
            .await
            .expect("named initgroups")
            .expect("cached user");
        assert_eq!(named, vec![2100]);

        let full_resolver = setup_resolver_with(0, InitgroupsMode::Full, vec![unnamed]).await;
        let full = full_resolver
            .get_initgroups("testuser")
            .await
            .expect("full initgroups")
            .expect("cached user");
        assert_eq!(full, vec![2100, 299568524]);
    }

    #[tokio::test]
    async fn online_auth_init_offline_fallback_does_not_reenter_db_lock() {
        let resolver = setup_resolver().await;
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            resolver.pam_account_authenticate_init(
                "testuser@example.com",
                "gdm-password",
                false,
                false,
                shutdown_rx,
            ),
        )
        .await
        .expect("auth init deadlocked waiting for the db lock")
        .expect("auth init failed");

        assert!(matches!(result.0, AuthSession::InProgress { .. }));
        assert!(matches!(result.1, PamAuthResponse::Pin));
    }

    #[tokio::test]
    async fn try_unseal_refreshes_only_an_expired_user_token() {
        let resolver = setup_resolver().await;

        assert!(resolver
            .pam_try_unseal("testuser@example.com", "123456")
            .await
            .expect("try_unseal failed"));
        assert_eq!(resolver.client.try_unseal_calls.load(Ordering::Acquire), 1);
        assert!(resolver.client.try_unseal_online.load(Ordering::Acquire));
        assert_eq!(resolver.client.cache_state_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            resolver.client.check_online_calls.load(Ordering::Acquire),
            0
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
        let (_expired, cached) = resolver
            .get_cached_usertoken(&Id::Name("testuser@example.com".to_string()))
            .await
            .expect("failed to reload cached user");
        let cached = cached.expect("cached user was removed");
        assert_eq!(cached.groups.len(), 1);
        assert_eq!(cached.groups[0].spn, "linux-users");
        assert_eq!(
            resolver
                .pam_account_allowed("testuser@example.com")
                .await
                .expect("allow-group check failed"),
            Some(true)
        );
    }

    #[tokio::test]
    async fn try_unseal_skips_refresh_for_a_valid_user_token() {
        let expiry = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock predates UNIX epoch")
            .as_secs()
            + 3600;
        let resolver = setup_resolver_with_expiry(expiry).await;

        assert!(resolver
            .pam_try_unseal("testuser@example.com", "123456")
            .await
            .expect("try_unseal failed"));
        assert_eq!(resolver.client.try_unseal_calls.load(Ordering::Acquire), 1);
        assert!(resolver.client.try_unseal_online.load(Ordering::Acquire));
        assert_eq!(resolver.client.cache_state_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            resolver.client.check_online_calls.load(Ordering::Acquire),
            0
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn try_unseal_passes_offline_state_to_provider() {
        let resolver = setup_resolver().await;
        resolver
            .client
            .set_cache_state(CacheState::OfflineNextCheck(
                SystemTime::now() + Duration::from_secs(60),
            ));

        assert!(resolver
            .pam_try_unseal("testuser@example.com", "123456")
            .await
            .expect("try_unseal failed"));
        assert_eq!(resolver.client.try_unseal_calls.load(Ordering::Acquire), 1);
        assert!(!resolver.client.try_unseal_online.load(Ordering::Acquire));
        assert_eq!(resolver.client.cache_state_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            resolver.client.check_online_calls.load(Ordering::Acquire),
            0
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn try_unseal_does_not_probe_or_refresh_when_offline() {
        let resolver = setup_resolver().await;
        resolver.client.set_cache_state(CacheState::Offline);

        assert!(resolver
            .pam_try_unseal("testuser@example.com", "123456")
            .await
            .expect("try_unseal failed"));
        assert_eq!(resolver.client.try_unseal_calls.load(Ordering::Acquire), 1);
        assert!(!resolver.client.try_unseal_online.load(Ordering::Acquire));
        assert_eq!(resolver.client.cache_state_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            resolver.client.check_online_calls.load(Ordering::Acquire),
            0
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn try_unseal_probes_and_refreshes_when_retry_is_due() {
        let resolver = setup_resolver().await;
        resolver
            .client
            .set_cache_state(CacheState::OfflineNextCheck(SystemTime::UNIX_EPOCH));

        assert!(resolver
            .pam_try_unseal("testuser@example.com", "123456")
            .await
            .expect("try_unseal failed"));
        assert_eq!(resolver.client.try_unseal_calls.load(Ordering::Acquire), 1);
        assert!(resolver.client.try_unseal_online.load(Ordering::Acquire));
        assert_eq!(resolver.client.cache_state_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            resolver.client.check_online_calls.load(Ordering::Acquire),
            1
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn try_unseal_does_not_refresh_when_due_probe_fails() {
        let resolver = setup_resolver().await;
        resolver
            .client
            .set_cache_state(CacheState::OfflineNextCheck(SystemTime::UNIX_EPOCH));
        resolver
            .client
            .check_online_result
            .store(false, Ordering::Release);

        assert!(resolver
            .pam_try_unseal("testuser@example.com", "123456")
            .await
            .expect("try_unseal failed"));
        assert_eq!(resolver.client.try_unseal_calls.load(Ordering::Acquire), 1);
        assert!(!resolver.client.try_unseal_online.load(Ordering::Acquire));
        assert_eq!(resolver.client.cache_state_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            resolver.client.check_online_calls.load(Ordering::Acquire),
            1
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn hello_password_reauth_cannot_fall_back_to_offline_auth() {
        let resolver = setup_resolver().await;
        resolver
            .set_cache_userpassword(test_token().uuid, "cached-password")
            .await
            .expect("failed to seed cached password");
        resolver.client.set_cache_state(CacheState::Offline);
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let mut auth_session = AuthSession::InProgress {
            account_id: "testuser@example.com".to_string(),
            service: "gdm-password".to_string(),
            id: Id::Name("testuser@example.com".to_string()),
            token: Some(Box::new(test_token())),
            online_at_init: true,
            cred_handler: AuthCredHandler::ReauthPassword {
                reauth_hello_pin: "123456".to_string().into(),
            },
            shutdown_rx,
            no_hello_pin: false,
            force_reauth: false,
        };

        let result = resolver
            .pam_account_authenticate_step(
                &mut auth_session,
                PamAuthRequest::Password {
                    cred: "cached-password".to_string(),
                },
            )
            .await;

        assert!(result.is_err());
    }
}

/// The identity provider caches a placeholder for a user which exists but could
/// not be fetched yet. Authenticated tokens can also have a synthetic primary
/// group with their own UUID, so only the explicit marker is trustworthy.
#[cfg(test)]
fn is_placeholder_token(token: &UserToken) -> bool {
    token.is_placeholder
}

/// Is `token` the user which `local@domain` was expanded from? That is so if
/// the token's local name is `local` and its UPN is in `domain`. A token whose
/// local name is its UPN never matches.
fn is_expanded_local_name(token: &UserToken, local: &str, domain: &str) -> bool {
    token.name.eq_ignore_ascii_case(local)
        && split_username(&token.spn)
            .map(|(_, spn_domain)| spn_domain.eq_ignore_ascii_case(domain))
            .unwrap_or(false)
}

/// Compare a local alias and its domain-qualified form with an account name.
fn local_name_matches(token: &UserToken, name: &str) -> bool {
    token.name.eq_ignore_ascii_case(name)
        || split_username(name)
            .map(|(local, domain)| is_expanded_local_name(token, local, domain))
            .unwrap_or(false)
}

impl<I> Resolver<I>
where
    I: IdProvider + Sync,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        db: Db,
        client: I,
        hsm: BoxedDynTpm,
        machine_key: MachineKey,
        // cache timeout
        timeout_seconds: u64,
        pam_allow_groups: Vec<String>,
        oidc_auth: bool,
        default_shell: String,
        home_prefix: String,
        home_attr: HomeAttr,
        home_alias: Option<HomeAttr>,
        uid_attr_map: UidAttr,
        gid_attr_map: UidAttr,
        initgroups_mode: InitgroupsMode,
        allow_id_overrides: Vec<String>,
    ) -> ResolverResult<Self> {
        let hsm = Mutex::new(hsm);
        let mut hsm_lock = hsm.lock().await;

        // Setup our internal keys
        let mut dbtxn = db.write().await;

        let loadable_hmac_key = match dbtxn.get_hsm_hmac_key() {
            Ok(Some(hmk)) => hmk,
            Ok(None) => {
                // generate a new key.
                let loadable_hmac_key = hsm_lock.hmac_s256_create(&machine_key).map_err(|err| {
                    error!(?err, "Unable to create hmac key");
                })?;

                dbtxn
                    .insert_hsm_hmac_key(&loadable_hmac_key)
                    .map_err(|err| {
                        error!(?err, "Unable to persist hmac key");
                    })?;

                loadable_hmac_key
            }
            Err(err) => {
                error!(?err, "Unable to retrieve loadable hmac key from db");
                return Err(ResolverError);
            }
        };

        let hmac_key = hsm_lock
            .hmac_s256_load(&machine_key, &loadable_hmac_key)
            .map_err(|err| {
                error!(?err, "Unable to load hmac key");
            })?;

        // Ask the client what keys it wants the HSM to configure.
        // make a key store
        // let mut ks = KeyStore::new(&mut dbtxn);

        let result = client
            .configure_hsm_keys(&mut dbtxn, hsm_lock.deref_mut(), &machine_key)
            .await;

        // drop(ks);
        drop(hsm_lock);

        result.map_err(|err| {
            error!(?err, "Client was unable to configure hsm keys");
        })?;

        dbtxn.commit().map_err(|_| ())?;

        if pam_allow_groups.is_empty() {
            warn!("pam_allow_groups config is not configured, all users will be authorized!");
        }

        // We assume we are offline at start up, and we mark the next "online check" as
        // being valid from "now".
        Ok(Resolver {
            db,
            hsm,
            machine_key,
            hmac_key,
            client,
            timeout_seconds,
            pam_allow_groups: pam_allow_groups.into_iter().collect(),
            oidc_auth,
            default_shell,
            home_prefix,
            home_attr,
            home_alias,
            uid_attr_map,
            gid_attr_map,
            initgroups_mode,
            allow_id_overrides: allow_id_overrides.into_iter().map(Id::Name).collect(),
            nxset: Mutex::new(HashSet::new()),
            nxcache: Mutex::new(LruCache::new(NXCACHE_SIZE)),
            alias_absence: Mutex::new(LruCache::new(NXCACHE_SIZE)),
        })
    }

    /// Export broker PRTs from the identity provider for fdstore
    /// persistence across daemon restarts.
    pub async fn export_broker_prts(&self) -> Result<Vec<u8>, serde_json::Error> {
        self.client.export_broker_prts().await
    }

    /// Import broker PRTs previously exported by [`Self::export_broker_prts`].
    pub async fn import_broker_prts(&self, data: &[u8]) -> Result<(), serde_json::Error> {
        self.client.import_broker_prts(data).await
    }

    async fn get_cachestate(&self, account_id: Option<&str>) -> CacheState {
        let mut dbtxn = self.db.write().await;
        let res = self.client.get_cachestate(account_id, &mut dbtxn).await;
        if let Err(e) = dbtxn.commit() {
            error!(
                "Failed to commit db transaction after getting cache state: {:?}",
                e
            );
        }
        res
    }

    pub async fn clear_cache(&self) -> ResolverResult<()> {
        let mut nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.clear();
        self.alias_absence.lock().await.clear();
        let mut dbtxn = self.db.write().await;
        dbtxn
            .clear()
            .and_then(|_| dbtxn.clear_hello_keys())
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())?;

        // Also delete the generated himmelblau.conf. This unjoins the host!
        let path = Path::new(SERVER_CONFIG_PATH);
        if path.exists() {
            fs::remove_file(path).map_err(|_| ())?;
        }
        Ok(())
    }

    pub async fn invalidate(&self) -> ResolverResult<()> {
        let mut nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.clear();
        self.alias_absence.lock().await.clear();
        let mut dbtxn = self.db.write().await;
        dbtxn
            .invalidate()
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ResolverError)
    }

    async fn get_cached_usertokens(&self) -> ResolverResult<Vec<UserToken>> {
        let mut dbtxn = self.db.write().await;
        dbtxn.get_accounts().map_err(|_| ResolverError)
    }

    pub async fn refresh_cached_usertoken(
        &self,
        account_id: &str,
    ) -> ResolverResult<Option<UserToken>> {
        let id = Id::Name(account_id.to_string());
        let (_expired, token) = self.resolve_cached_usertoken(&id).await?;
        let token = self.refresh_usertoken(&id, token).await?;
        match token {
            Some(token)
                if self
                    .check_nxset(Some(&token.name), Some(token.gidnumber))
                    .await =>
            {
                Ok(None)
            }
            token => Ok(token),
        }
    }

    async fn get_cached_grouptokens(&self) -> ResolverResult<Vec<GroupToken>> {
        let mut dbtxn = self.db.write().await;
        dbtxn.get_groups().map_err(|_| ResolverError)
    }

    async fn set_nxcache(&self, id: &Id) {
        let mut nxcache_txn = self.nxcache.lock().await;
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
        nxcache_txn.put(id.clone(), ex_time);
    }

    pub async fn check_nxcache(&self, id: &Id) -> Option<SystemTime> {
        let mut nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.get(id).copied()
    }

    pub async fn reload_nxset(&self, iter: impl Iterator<Item = (String, u32)>) {
        let mut nxset_txn = self.nxset.lock().await;
        nxset_txn.clear();
        for (name, gid) in iter {
            // The local name of an Entra user (an onPremisesSamAccountName) is
            // case insensitive: a local "admin" must exclude "ADMIN" as well.
            let key = Id::Name(name.to_ascii_lowercase());
            let name = Id::Name(name);
            let gid = Id::Gid(gid);

            // Skip anything that the admin opted in to
            if !(self.allow_id_overrides.contains(&gid) || self.allow_id_overrides.contains(&name))
            {
                trace!("Adding {:?}:{:?} to resolver exclusion set", name, gid);
                nxset_txn.insert(key);
                nxset_txn.insert(gid);
            }
        }
    }

    pub async fn check_nxset(&self, name: Option<&str>, idnumber: Option<u32>) -> bool {
        let nxset_txn = self.nxset.lock().await;
        if let Some(name) = name {
            if nxset_txn.contains(&Id::Name(name.to_ascii_lowercase())) {
                return true;
            }
        }
        if let Some(idnumber) = idnumber {
            if nxset_txn.contains(&Id::Gid(idnumber)) {
                return true;
            }
        }
        false
    }

    async fn get_cached_usertoken(
        &self,
        account_id: &Id,
    ) -> ResolverResult<(bool, Option<UserToken>)> {
        // Account_id could be:
        //  * gidnumber
        //  * name
        //  * spn
        //  * uuid
        //  Attempt to search these in the db.
        let mut dbtxn = self.db.write().await;
        let mut r = dbtxn.get_account(account_id).map_err(|err| {
            trace!("get_cached_usertoken {:?}", err);
        })?;

        // With cn_name_mapping, a local name such as an onPremisesSamAccountName
        // reaches us expanded to "<name>@<primary domain>", which matches neither
        // the cached name nor the cached SPN. Look for the user whose local name
        // it is. Exact canonical matches, including placeholders, always win.
        if r.is_none() {
            if let Id::Name(name) = account_id {
                if let Some((local, domain)) = split_username(name) {
                    let aliased = dbtxn
                        .get_account(&Id::Name(local.to_string()))
                        .map_err(|err| {
                            trace!("get_cached_usertoken {:?}", err);
                        })?
                        .filter(|(ut, _)| is_expanded_local_name(ut, local, domain));
                    if aliased.is_some() {
                        r = aliased;
                    }
                }
            }
        }

        drop(dbtxn);
        match r {
            Some((ut, ex)) => {
                // Are we expired?
                let offset = Duration::from_secs(ex);
                let ex_time = SystemTime::UNIX_EPOCH + offset;
                let now = SystemTime::now();

                if now >= ex_time {
                    Ok((true, Some(ut)))
                } else {
                    Ok((false, Some(ut)))
                }
            }
            None => {
                // it wasn't in the DB - lets see if it's in the nxcache.
                match self.check_nxcache(account_id).await {
                    Some(ex_time) => {
                        let now = SystemTime::now();
                        if now >= ex_time {
                            // It's in the LRU, but we are past the expiry so
                            // lets attempt a refresh.
                            Ok((true, None))
                        } else {
                            // It's in the LRU and still valid, so return that
                            // no check is needed.
                            Ok((false, None))
                        }
                    }
                    None => {
                        // Not in the LRU. Return that this IS expired
                        // and we have no data.
                        Ok((true, None))
                    }
                }
            }
        } // end match r
    }

    /// A domain-qualified local alias is indistinguishable from an uncached
    /// user's real UPN. Resolve that exact name before using the alias, even if
    /// the alias owner's cache entry is fresh. Never pass the alias as an old
    /// token: providers refresh old_token.spn instead of the requested identity.
    async fn resolve_cached_usertoken(
        &self,
        account_id: &Id,
    ) -> ResolverResult<(bool, Option<UserToken>)> {
        let cached = self.get_cached_usertoken(account_id).await?;
        let (Id::Name(name), Some(token)) = (account_id, cached.1.as_ref()) else {
            return Ok(cached);
        };
        if split_username(name).is_none() || token.spn.eq_ignore_ascii_case(name) {
            return Ok(cached);
        }

        let key = name.to_ascii_lowercase();
        let absent_until = self.alias_absence.lock().await.get(&key).copied();
        if absent_until.is_some_and(|expiry| SystemTime::now() < expiry) {
            return self.get_cached_usertoken(account_id).await;
        }

        let state = self.get_cachestate(Some(name)).await;
        if !self.test_connection_for_state(state).await {
            // Being offline says nothing about who owns an uncached UPN. The
            // caller can still use the cached user's canonical UPN offline.
            warn!("Cannot verify qualified local alias while offline");
            return Err(ResolverError);
        }

        let lookup = self.fetch_usertoken(account_id, None).await?;
        // Even an unsuccessful lookup must not hide a canonical identity that
        // another request cached while this provider request was in flight.
        let current = self.get_cached_usertoken(account_id).await?;
        if current
            .1
            .as_ref()
            .is_some_and(|token| token.spn.eq_ignore_ascii_case(name))
        {
            self.alias_absence.lock().await.pop(&key);
            return Ok(current);
        }
        match lookup {
            Ok(UserTokenState::Update(mut exact)) if exact.spn.eq_ignore_ascii_case(name) => {
                self.set_cache_usertoken(&mut exact).await?;
                Ok((false, Some(exact)))
            }
            Ok(UserTokenState::NotFound) => {
                let expiry = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
                self.alias_absence.lock().await.put(key.clone(), expiry);
                // Another lookup may have cached a canonical owner while the
                // provider request was in flight. Never return the old alias.
                let current = self.get_cached_usertoken(account_id).await?;
                if current
                    .1
                    .as_ref()
                    .is_some_and(|token| token.spn.eq_ignore_ascii_case(name))
                {
                    self.alias_absence.lock().await.pop(&key);
                }
                Ok(current)
            }
            // UseCached and errors (including IdpError::NotFound, which may
            // mean no matching provider) do not prove that the UPN is absent.
            _ => {
                warn!("Cannot establish ownership of qualified local alias");
                Err(ResolverError)
            }
        }
    }

    async fn get_cached_grouptoken(
        &self,
        grp_id: &Id,
    ) -> ResolverResult<(bool, Option<GroupToken>)> {
        // grp_id could be:
        //  * gidnumber
        //  * name
        //  * spn
        //  * uuid
        //  Attempt to search these in the db.
        let mut dbtxn = self.db.write().await;
        let r = dbtxn.get_group(grp_id).map_err(|_| ())?;

        match r {
            Some((ut, ex)) => {
                // Are we expired?
                let offset = Duration::from_secs(ex);
                let ex_time = SystemTime::UNIX_EPOCH + offset;
                let now = SystemTime::now();

                if now >= ex_time {
                    Ok((true, Some(ut)))
                } else {
                    Ok((false, Some(ut)))
                }
            }
            None => {
                // it wasn't in the DB - lets see if it's in the nxcache.
                match self.check_nxcache(grp_id).await {
                    Some(ex_time) => {
                        let now = SystemTime::now();
                        if now >= ex_time {
                            // It's in the LRU, but we are past the expiry so
                            // lets attempt a refresh.
                            Ok((true, None))
                        } else {
                            // It's in the LRU and still valid, so return that
                            // no check is needed.
                            Ok((false, None))
                        }
                    }
                    None => {
                        // Not in the LRU. Return that this IS expired
                        // and we have no data.
                        Ok((true, None))
                    }
                }
            }
        }
    }

    async fn set_cache_usertoken(&self, token: &mut UserToken) -> ResolverResult<()> {
        // Set an expiry
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
        let offset = ex_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                error!("time conversion error - ex_time less than epoch? {:?}", e);
            })?;

        // Check if requested `shell` exists on the system, else use `default_shell`
        let requested_shell_exists: bool = token
            .shell
            .as_ref()
            .map(|shell| {
                let exists = Path::new(shell).exists();
                if !exists {
                    info!(
                        "User shell is not present on this system - {}. Check `/etc/shells` for valid shell options.",
                        shell
                    )
                }
                exists
            })
            .unwrap_or_else(|| {
                info!("User has not specified a shell, using default");
                false
            });

        if !requested_shell_exists {
            token.shell = Some(self.default_shell.clone())
        }

        // Filter out groups that are in the nxset
        {
            let nxset_txn = self.nxset.lock().await;
            token.groups.retain(|g| {
                !(nxset_txn.contains(&Id::Gid(g.gidnumber))
                    || nxset_txn.contains(&Id::Name(g.name.to_ascii_lowercase())))
            });
        }

        let mut dbtxn = self.db.write().await;
        let cached = dbtxn.get_accounts().map_err(|_| ResolverError)?;
        for mut other in cached.into_iter().filter(|other| other.uuid != token.uuid) {
            if other.spn.eq_ignore_ascii_case(&token.spn) {
                // Same-SPN authoritative promotion/recreation is handled by the
                // database; it is not a conflict between different aliases.
                continue;
            }
            // Canonical identities own their names before optional local aliases.
            // Restore a conflicting alias to its canonical name without deleting
            // the account row (and its password or memberships).
            if local_name_matches(&other, &token.spn) {
                other.name.clone_from(&other.spn);
                let expiry = dbtxn
                    .get_account(&Id::Name(other.uuid.to_string()))
                    .map_err(|_| ResolverError)?
                    .map(|(_, expiry)| expiry)
                    .unwrap_or(0);
                dbtxn
                    .update_account(&other, expiry)
                    .map_err(|_| ResolverError)?;
            }
            if token.name.eq_ignore_ascii_case(&other.name) || local_name_matches(token, &other.spn)
            {
                token.name.clone_from(&token.spn);
            }
        }
        token
            .groups
            .iter()
            // We need to add the groups first
            .try_for_each(|g| dbtxn.update_group(g, offset.as_secs()))
            .and_then(|_|
                // So that when we add the account it can make the relationships.
                dbtxn
                    .update_account(token, offset.as_secs()))
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ResolverError)?;
        self.alias_absence
            .lock()
            .await
            .pop(&token.spn.to_ascii_lowercase());
        Ok(())
    }

    async fn set_cache_grouptoken(&self, token: &GroupToken) -> ResolverResult<()> {
        // Set an expiry
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
        let offset = ex_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                error!("time conversion error - ex_time less than epoch? {:?}", e);
            })?;

        let mut dbtxn = self.db.write().await;
        dbtxn
            .update_group(token, offset.as_secs())
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ResolverError)
    }

    async fn delete_cache_usertoken(&self, a_uuid: Uuid) -> ResolverResult<()> {
        let mut dbtxn = self.db.write().await;
        dbtxn
            .delete_account(a_uuid)
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ResolverError)
    }

    async fn delete_cache_grouptoken(&self, g_uuid: Uuid) -> ResolverResult<()> {
        let mut dbtxn = self.db.write().await;
        dbtxn
            .delete_group(g_uuid)
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ResolverError)
    }

    async fn set_cache_userpassword(&self, a_uuid: Uuid, cred: &str) -> ResolverResult<()> {
        let mut dbtxn = self.db.write().await;
        let mut hsm_txn = self.hsm.lock().await;
        dbtxn
            .update_account_password(a_uuid, cred, hsm_txn.deref_mut(), &self.hmac_key)
            .and_then(|x| dbtxn.commit().map(|_| x))
            .map_err(|_| ResolverError)
    }

    async fn check_cache_userpassword(&self, a_uuid: Uuid, cred: &str) -> ResolverResult<bool> {
        let mut dbtxn = self.db.write().await;
        let mut hsm_txn = self.hsm.lock().await;
        dbtxn
            .check_account_password(a_uuid, cred, hsm_txn.deref_mut(), &self.hmac_key)
            .and_then(|x| dbtxn.commit().map(|_| x))
            .map_err(|_| ResolverError)
    }

    async fn fetch_usertoken(
        &self,
        account_id: &Id,
        token: Option<&UserToken>,
    ) -> ResolverResult<Result<UserTokenState, IdpError>> {
        let mut hsm_lock = self.hsm.lock().await;
        let mut dbtxn = self.db.write().await;

        let user_get_result = self
            .client
            .unix_user_get(
                account_id,
                token,
                &mut dbtxn,
                hsm_lock.deref_mut(),
                &self.machine_key,
            )
            .await;

        drop(hsm_lock);
        dbtxn.commit().map_err(|_| ())?;

        Ok(user_get_result)
    }

    async fn refresh_usertoken(
        &self,
        account_id: &Id,
        token: Option<UserToken>,
    ) -> ResolverResult<Option<UserToken>> {
        match self.fetch_usertoken(account_id, token.as_ref()).await? {
            Ok(UserTokenState::Update(mut n_tok)) => {
                // We have the token!
                self.set_cache_usertoken(&mut n_tok).await?;
                Ok(Some(n_tok))
            }
            Ok(UserTokenState::NotFound) => {
                // It previously existed, so now purge it.
                if let Some(tok) = token {
                    self.delete_cache_usertoken(tok.uuid).await?;
                };
                // Cache the NX here.
                self.set_nxcache(account_id).await;
                Ok(None)
            }
            Ok(UserTokenState::UseCached) => Ok(token),
            Err(err @ IdpError::NotFound { .. }) => {
                // NSS may ask for local or unknown identities outside the provider.
                debug!(?err, "User lookup did not match an identity provider");
                Ok(token)
            }
            Err(err) => {
                // Something went wrong, we don't know what, but lets return the token
                // anyway.
                error!(?err);
                Ok(token)
            }
        }
    }

    async fn refresh_grouptoken(
        &self,
        grp_id: &Id,
        token: Option<GroupToken>,
    ) -> ResolverResult<Option<GroupToken>> {
        let mut hsm_lock = self.hsm.lock().await;

        let group_get_result = self
            .client
            .unix_group_get(grp_id, hsm_lock.deref_mut())
            .await;

        drop(hsm_lock);

        match group_get_result {
            Ok(n_tok) => {
                if self
                    .check_nxset(Some(&n_tok.name), Some(n_tok.gidnumber))
                    .await
                {
                    // Refuse to release the token, it's in the denied set.
                    self.delete_cache_grouptoken(n_tok.uuid).await?;
                    Ok(None)
                } else {
                    // We have the token!
                    self.set_cache_grouptoken(&n_tok).await?;
                    Ok(Some(n_tok))
                }
            }
            Err(e) => {
                // Some other transient error, continue with the token.
                error!(?e);
                Ok(token)
            }
        }
    }

    pub async fn get_user_accesstoken(
        &self,
        account_id: Id,
        scopes: Vec<String>,
        client_id: Option<String>,
        redirect_uri: Option<String>,
        req_cnf: Option<String>,
    ) -> Option<UnixUserToken> {
        // Validate the user isn't in the nxset (aka, it's a local user or group).
        let (name, idnumber) = match account_id.clone() {
            Id::Name(name) => (Some(name), None),
            Id::Gid(idnumber) => (None, Some(idnumber)),
        };
        if self.check_nxset(name.as_deref(), idnumber).await {
            return None;
        }

        let token = match self.get_usertoken(account_id.clone()).await {
            Ok(Some(token)) => token,
            _ => {
                error!("Failed to fetch unix user token during access token request!");
                return None;
            }
        };

        let mut hsm_lock = self.hsm.lock().await;
        let mut dbtxn = self.db.write().await;

        let user_get_result = self
            .client
            .unix_user_access(
                &account_id,
                scopes,
                Some(&token),
                client_id,
                redirect_uri,
                req_cnf,
                &mut dbtxn,
                hsm_lock.deref_mut(),
                &self.machine_key,
            )
            .await;

        drop(hsm_lock);
        if dbtxn.commit().is_err() {
            error!("Failed to commit user token DB transaction");
            return None;
        }

        match user_get_result {
            Ok(token) => Some(token),
            Err(e) => {
                error!("Failed to fetch access token: {:?}", e);
                None
            }
        }
    }

    pub async fn get_user_tgts(
        &self,
        account_id: Id,
    ) -> Option<(
        uid_t,
        uid_t,
        Option<Box<KerberosCredentials>>,
        Option<Box<KerberosCredentials>>,
        Option<String>,
        Option<String>,
    )> {
        // Validate the user isn't in the nxset (aka, it's a local user or group).
        let (name, idnumber) = match account_id.clone() {
            Id::Name(name) => (Some(name), None),
            Id::Gid(idnumber) => (None, Some(idnumber)),
        };
        if self.check_nxset(name.as_deref(), idnumber).await {
            return None;
        }

        let token = match self.get_usertoken(account_id.clone()).await {
            Ok(Some(token)) => token,
            _ => {
                error!("Failed to fetch unix user token during access token request!");
                return None;
            }
        };

        let mut hsm_lock = self.hsm.lock().await;
        let mut dbtxn = self.db.write().await;

        let (cloud_ccache, ad_ccache, top_level_names, tenant_id) = self
            .client
            .unix_user_tgts(
                &account_id,
                Some(&token),
                &mut dbtxn,
                hsm_lock.deref_mut(),
                &self.machine_key,
            )
            .await;

        drop(hsm_lock);
        if dbtxn.commit().is_err() {
            error!("Failed to commit user token DB transaction");
            return None;
        }

        Some((
            token.gidnumber,
            token.real_gidnumber.unwrap_or(token.gidnumber),
            cloud_ccache,
            ad_ccache,
            top_level_names,
            tenant_id,
        ))
    }

    pub async fn get_user_prt_cookie(
        &self,
        account_id: Id,
        sso_nonce: Option<&str>,
    ) -> Option<String> {
        // Validate the user isn't in the nxset (aka, it's a local user or group).
        let (name, idnumber) = match account_id.clone() {
            Id::Name(name) => (Some(name), None),
            Id::Gid(idnumber) => (None, Some(idnumber)),
        };
        if self.check_nxset(name.as_deref(), idnumber).await {
            return None;
        }

        let token = match self.get_usertoken(account_id.clone()).await {
            Ok(Some(token)) => token,
            _ => {
                error!("Failed to fetch unix user token during access token request!");
                return None;
            }
        };

        let mut hsm_lock = self.hsm.lock().await;
        let mut dbtxn = self.db.write().await;

        let cookie = self
            .client
            .unix_user_prt_cookie(
                &account_id,
                Some(&token),
                sso_nonce,
                &mut dbtxn,
                hsm_lock.deref_mut(),
                &self.machine_key,
            )
            .await;

        drop(hsm_lock);
        if dbtxn.commit().is_err() {
            error!("Failed to commit user token DB transaction");
            return None;
        }

        match cookie {
            Ok(cookie) => Some(cookie),
            Err(e) => {
                error!("Failed to fetch prt sso cookie: {:?}", e);
                None
            }
        }
    }

    pub async fn change_auth_token(
        &self,
        account_id: &str,
        token: &UnixUserToken,
        new_tok: &str,
    ) -> ResolverResult<bool> {
        // Validate the user isn't in the nxset (aka, it's a local user or group).
        if self.check_nxset(Some(account_id), None).await {
            return Ok(false);
        }

        let (_expired, cached) = self
            .resolve_cached_usertoken(&Id::Name(account_id.to_string()))
            .await?;
        let account_id = Self::canonical_account_id(account_id, cached.as_ref());
        let account_id = account_id.as_str();

        let mut hsm_lock = self.hsm.lock().await;
        let mut dbtxn = self.db.write().await;

        let res = self
            .client
            .change_auth_token(
                account_id,
                token,
                new_tok,
                &mut dbtxn,
                hsm_lock.deref_mut(),
                &self.machine_key,
            )
            .await;

        drop(hsm_lock);

        match res {
            Ok(res) => {
                dbtxn.commit().map_err(|_| ())?;
                Ok(res)
            }
            Err(e) => {
                trace!("change_auth_token error -> {:?}", e);
                Err(ResolverError)
            }
        }
    }

    pub async fn offline_break_glass(&self, ttl: Option<u64>) -> ResolverResult<()> {
        let res = self.client.offline_break_glass(ttl).await;

        res.map_err(|e| {
            trace!("offline_break_glass error -> {:?}", e);
            ResolverError
        })
    }

    /// The identity provider needs the UPN: the tenant is derived from its domain,
    /// and it is the name to sign in with and the tag of the Hello key. A login name
    /// which passed `resolve_cached_usertoken` is replaced by
    /// that user's SPN.
    fn canonical_account_id(account_id: &str, token: Option<&UserToken>) -> String {
        token
            .map(|tok| tok.spn.clone())
            .unwrap_or_else(|| account_id.to_string())
    }

    pub async fn get_usertoken(&self, account_id: Id) -> ResolverResult<Option<UserToken>> {
        // Validate the user isn't in the nxset (aka, it's a local user or group).
        let (name, idnumber) = match account_id.clone() {
            Id::Name(name) => (Some(name), None),
            Id::Gid(idnumber) => (None, Some(idnumber)),
        };
        if self.check_nxset(name.as_deref(), idnumber).await {
            return Ok(None);
        }

        trace!("get_usertoken");
        // get the item from the cache
        let (expired, item) = self
            .resolve_cached_usertoken(&account_id)
            .await
            .map_err(|e| {
                trace!("get_usertoken error -> {:?}", e);
            })?;

        // Prefer the SPN of the cached user. The requested name may be a local
        // name, from which no domain, and so no provider, can be derived.
        let state = match (&account_id, &item) {
            (_, Some(token)) => self.get_cachestate(Some(&token.spn)).await,
            (Id::Name(name), None) => self.get_cachestate(Some(name)).await,
            (Id::Gid(_), None) => self.get_cachestate(None).await,
        };

        let token = match (expired, state) {
            (_, CacheState::Offline) => {
                trace!("offline, returning cached item");
                Ok(item)
            }
            (false, CacheState::OfflineNextCheck(time)) => {
                trace!(
                    "offline valid, next check {:?}, returning cached item",
                    time
                );
                // Still valid within lifetime, return.
                Ok(item)
            }
            (false, CacheState::Online) => {
                trace!("online valid, returning cached item");
                // Still valid within lifetime, return.
                Ok(item)
            }
            (true, CacheState::OfflineNextCheck(time)) => {
                trace!("offline expired, next check {:?}, refresh cache", time);
                // Attempt to refresh the item
                // Return it.
                if SystemTime::now() >= time && self.test_connection().await {
                    // We brought ourselves online, lets go
                    self.refresh_usertoken(&account_id, item).await
                } else {
                    // Unable to bring up connection, return cache.
                    Ok(item)
                }
            }
            (true, CacheState::Online) => {
                trace!("online expired, refresh cache");
                // Attempt to refresh the item
                // Return it.
                self.refresh_usertoken(&account_id, item).await
            }
        }
        .map(|t| {
            trace!("token -> {:?}", t);
            t
        })?;

        // Only the requested name was checked above, and a UPN can't collide with
        // a local account. The name and id of the user we return can, and a local
        // account may have appeared since the user was cached.
        match token {
            Some(tok) if self.check_nxset(Some(&tok.name), Some(tok.gidnumber)).await => {
                warn!(
                    "Refusing '{}': its name or id collides with a local account",
                    tok.spn
                );
                Ok(None)
            }
            token => Ok(token),
        }
    }

    async fn get_grouptoken(&self, grp_id: Id) -> ResolverResult<Option<GroupToken>> {
        trace!("get_grouptoken");
        let (expired, item) = self.get_cached_grouptoken(&grp_id).await.map_err(|e| {
            trace!("get_grouptoken error -> {:?}", e);
        })?;

        // In Himmelblau, we only ever utilize cached group tokens
        let state = CacheState::Offline;

        match (expired, state) {
            (_, CacheState::Offline) => {
                trace!("offline, returning cached item");
                Ok(item)
            }
            (false, CacheState::OfflineNextCheck(time)) => {
                trace!(
                    "offline valid, next check {:?}, returning cached item",
                    time
                );
                // Still valid within lifetime, return.
                Ok(item)
            }
            (false, CacheState::Online) => {
                trace!("online valid, returning cached item");
                // Still valid within lifetime, return.
                Ok(item)
            }
            (true, CacheState::OfflineNextCheck(time)) => {
                trace!("offline expired, next check {:?}, refresh cache", time);
                // Attempt to refresh the item
                // Return it.
                if SystemTime::now() >= time && self.test_connection().await {
                    // We brought ourselves online, lets go
                    self.refresh_grouptoken(&grp_id, item).await
                } else {
                    // Unable to bring up connection, return cache.
                    Ok(item)
                }
            }
            (true, CacheState::Online) => {
                trace!("online expired, refresh cache");
                // Attempt to refresh the item
                // Return it.
                self.refresh_grouptoken(&grp_id, item).await
            }
        }
    }

    pub async fn get_groupmembers(&self, g_uuid: Uuid) -> Vec<String> {
        let members = {
            let mut dbtxn = self.db.write().await;
            dbtxn.get_group_members(g_uuid).unwrap_or_default()
        };
        let mut names = Vec::with_capacity(members.len());
        for token in members {
            if !self
                .check_nxset(Some(&token.name), Some(token.gidnumber))
                .await
            {
                names.push(self.token_uidattr(&token));
            }
        }
        names
    }

    #[inline(always)]
    fn token_homedirectory_alias(&self, token: &UserToken) -> Option<String> {
        self.home_alias.map(|t| match t {
            // If we have an alias. use it.
            HomeAttr::Uuid => token.uuid.hyphenated().to_string(),
            HomeAttr::Spn => token.spn.as_str().to_string(),
            HomeAttr::Name => token.name.as_str().to_string(),
            HomeAttr::Cn => token.spn.split('@').collect::<Vec<&str>>()[0].to_string(),
        })
    }

    #[inline(always)]
    fn token_homedirectory_attr(&self, token: &UserToken) -> String {
        match self.home_attr {
            HomeAttr::Uuid => token.uuid.hyphenated().to_string(),
            HomeAttr::Spn => token.spn.as_str().to_string(),
            HomeAttr::Name => token.name.as_str().to_string(),
            HomeAttr::Cn => token.spn.split('@').collect::<Vec<&str>>()[0].to_string(),
        }
    }

    #[inline(always)]
    fn token_homedirectory(&self, token: &UserToken) -> String {
        self.token_homedirectory_alias(token)
            .unwrap_or_else(|| self.token_homedirectory_attr(token))
    }

    #[inline(always)]
    fn token_abs_homedirectory(&self, token: &UserToken) -> String {
        format!("{}{}", self.home_prefix, self.token_homedirectory(token))
    }

    #[inline(always)]
    fn token_uidattr(&self, token: &UserToken) -> String {
        match self.uid_attr_map {
            UidAttr::Spn => token.spn.as_str(),
            UidAttr::Name => token.name.as_str(),
        }
        .to_string()
    }

    fn token_to_nssuser(&self, tok: UserToken) -> NssUser {
        let mut aliases = vec![tok.name.clone()];
        if !tok.name.contains('@') {
            if let Some((_, domain)) = split_username(&tok.spn) {
                aliases.push(format!("{}@{}", tok.name, domain));
            }
        }
        NssUser {
            homedir: self.token_abs_homedirectory(&tok),
            name: self.token_uidattr(&tok),
            canonical_name: Some(tok.spn),
            aliases,
            uid: tok.gidnumber,
            gid: tok.real_gidnumber.unwrap_or(tok.gidnumber),
            gecos: tok.displayname,
            shell: tok.shell.unwrap_or_else(|| self.default_shell.clone()),
        }
    }

    pub async fn get_nssaccounts(&self) -> ResolverResult<Vec<NssUser>> {
        let tokens = self.get_cached_usertokens().await?;
        let mut accounts = Vec::with_capacity(tokens.len());
        for token in tokens {
            if !self
                .check_nxset(Some(&token.name), Some(token.gidnumber))
                .await
            {
                accounts.push(self.token_to_nssuser(token));
            }
        }
        Ok(accounts)
    }

    async fn get_nssaccount(&self, account_id: Id) -> ResolverResult<Option<NssUser>> {
        let token = self.get_usertoken(account_id).await?;
        Ok(token.map(|token| self.token_to_nssuser(token)))
    }

    pub async fn get_nssaccount_name(&self, account_id: &str) -> ResolverResult<Option<NssUser>> {
        self.get_nssaccount(Id::Name(account_id.to_string())).await
    }

    pub async fn get_nssaccount_gid(&self, gid: u32) -> ResolverResult<Option<NssUser>> {
        self.get_nssaccount(Id::Gid(gid)).await
    }

    #[inline(always)]
    fn token_gidattr(&self, token: &GroupToken) -> String {
        match self.gid_attr_map {
            UidAttr::Spn => token.spn.as_str(),
            UidAttr::Name => token.name.as_str(),
        }
        .to_string()
    }

    pub async fn get_nssgroups(&self) -> ResolverResult<Vec<NssGroup>> {
        let l = self.get_cached_grouptokens().await?;
        let mut r: Vec<_> = Vec::with_capacity(l.len());
        for tok in l.into_iter() {
            if self.check_nxset(Some(&tok.name), Some(tok.gidnumber)).await {
                continue;
            }
            let members = self.get_groupmembers(tok.uuid).await;
            r.push(NssGroup {
                name: self.token_gidattr(&tok),
                gid: tok.gidnumber,
                members,
            })
        }
        Ok(r)
    }

    async fn get_nssgroup(&self, grp_id: Id) -> ResolverResult<Option<NssGroup>> {
        let token = self.get_grouptoken(grp_id).await?;
        // Get members set.
        match token {
            Some(tok) if self.check_nxset(Some(&tok.name), Some(tok.gidnumber)).await => Ok(None),
            Some(tok) => {
                let members = self.get_groupmembers(tok.uuid).await;
                Ok(Some(NssGroup {
                    name: self.token_gidattr(&tok),
                    gid: tok.gidnumber,
                    members,
                }))
            }
            None => Ok(None),
        }
    }

    pub async fn get_nssgroup_name(&self, grp_id: &str) -> ResolverResult<Option<NssGroup>> {
        self.get_nssgroup(Id::Name(grp_id.to_string())).await
    }

    pub async fn get_nssgroup_gid(&self, gid: u32) -> ResolverResult<Option<NssGroup>> {
        self.get_nssgroup(Id::Gid(gid)).await
    }

    pub async fn get_initgroups(&self, account_id: &str) -> ResolverResult<Option<Vec<u32>>> {
        let token = self.get_usertoken(Id::Name(account_id.to_string())).await?;
        let Some(tok) = token else {
            return Ok(None);
        };
        if self.initgroups_mode == InitgroupsMode::Full {
            let mut groups = Vec::with_capacity(tok.groups.len());
            for group in &tok.groups {
                if !self
                    .check_nxset(Some(&group.name), Some(group.gidnumber))
                    .await
                {
                    groups.push(group.gidnumber);
                }
            }
            return Ok(Some(groups));
        }
        let mut named = Vec::with_capacity(tok.groups.len());
        for group in &tok.groups {
            match self.get_nssgroup_gid(group.gidnumber).await {
                Ok(Some(nss_group)) if !nss_group.name.is_empty() => {
                    named.push(group.gidnumber);
                }
                Ok(Some(_)) | Ok(None) | Err(_) => {
                    debug!(
                        gid = group.gidnumber,
                        "skipping supplementary group with no NSS name"
                    );
                }
            }
        }
        Ok(Some(named))
    }

    pub async fn pam_account_allowed(&self, account_id: &str) -> ResolverResult<Option<bool>> {
        let token = self.get_usertoken(Id::Name(account_id.to_string())).await?;

        if self.pam_allow_groups.is_empty() {
            // An empty allow list permits all users
            Ok(Some(true))
        } else {
            Ok(token.map(|tok| {
                // Never ever EVER list Entra group names in the allowed groups
                // set. This is a SECURITY RISK! See CVE-2025-49012. Group
                // names ARE NOT unique in Entra Id. Only group Object Ids may
                // be listed here. Generic OIDC group claim values are accepted
                // only when OIDC authentication is configured, not for Entra
                // object-id groups.
                let user_set: BTreeSet<_> = tok
                    .groups
                    .iter()
                    .flat_map(|g| {
                        let mut ids = vec![g.uuid.hyphenated().to_string()];
                        if self.oidc_auth {
                            ids.push(g.spn.clone());
                        }
                        ids
                    })
                    // The name the user typed is only an alias when it is a local
                    // name, and may spell the UPN of another user. Match on the
                    // user the cache resolved it to.
                    .chain(std::iter::once(tok.spn.clone()))
                    .collect();

                debug!(
                    "Checking if user is in allowed groups ({:?}) -> {:?}",
                    self.pam_allow_groups,
                    user_set.iter().filter(|s| s.as_str() != tok.spn).cloned(),
                );
                let intersection_count = user_set.intersection(&self.pam_allow_groups).count();
                debug!("Number of intersecting groups: {}", intersection_count);
                debug!("User has valid token: {}", tok.valid);

                intersection_count > 0 && tok.valid
            }))
        }
    }

    pub async fn pam_account_authenticate_init(
        &self,
        account_id: &str,
        service: &str,
        no_hello_pin: bool,
        force_reauth: bool,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> ResolverResult<(AuthSession, PamAuthResponse)> {
        // Setup an auth session. If possible bring the resolver online.
        // Further steps won't attempt to bring the cache online to prevent
        // weird interactions - they should assume online/offline only for
        // the duration of their operation. A failure of connectivity during
        // an online operation will take the cache offline however.

        // Skip the whole auth dance if this user is in the nxset (aka, it's a
        // local user or group).
        if self.check_nxset(Some(account_id), None).await {
            return Ok((AuthSession::Denied, PamAuthResponse::Unknown));
        }

        let id = Id::Name(account_id.to_string());
        let (_expired, token) = self.resolve_cached_usertoken(&id).await?;
        // If we don't have a token here, then NSS has yet to be called. Failing
        // to request a token now will result in an auth failure in pam_account_authenticate_step.
        let token = match token {
            Some(token) => Some(token),
            None => self.refresh_usertoken(&id, None).await?,
        };
        let account_id = Self::canonical_account_id(account_id, token.as_ref());
        let account_id = account_id.as_str();
        let state = self.get_cachestate(Some(account_id)).await;

        let online_at_init = if !matches!(state, CacheState::Online) {
            // Attempt a cache online.
            self.test_connection().await
        } else {
            true
        };

        let maybe_err = if online_at_init {
            let online_result = {
                let mut hsm_lock = self.hsm.lock().await;
                let mut dbtxn = self.db.write().await;

                self.client
                    .unix_user_online_auth_init(
                        account_id,
                        token.as_ref(),
                        service,
                        no_hello_pin,
                        force_reauth,
                        &mut dbtxn,
                        hsm_lock.deref_mut(),
                        &self.machine_key,
                        &shutdown_rx,
                    )
                    .await
            };

            match online_result {
                Ok(res) => Ok(res),
                Err(e) => {
                    if force_reauth {
                        // force_reauth requires online auth, do not fall back
                        // to offline, as that cannot satisfy Entra sign-in
                        // frequency policy.
                        Err(e)
                    } else {
                        // Check if the failure is because we went offline
                        match self.get_cachestate(Some(account_id)).await {
                            CacheState::Offline | CacheState::OfflineNextCheck(_) => {
                                // Attempt to proceed offline
                                let mut dbtxn = self.db.write().await;
                                self.client
                                    .unix_user_offline_auth_init(
                                        account_id,
                                        token.as_ref(),
                                        service,
                                        no_hello_pin,
                                        &mut dbtxn,
                                    )
                                    .await
                            }
                            _ => Err(e),
                        }
                    }
                }
            }
        } else if force_reauth {
            // force_reauth requires online connectivity, so refuse to proceed
            // offline since cached auth cannot satisfy Entra sign-in frequency.
            return Ok((
                AuthSession::Denied,
                PamAuthResponse::InitDenied {
                    msg: "Re-authentication requires network connectivity.".to_string(),
                },
            ));
        } else {
            let mut dbtxn = self.db.write().await;

            // Can the auth proceed offline?
            self.client
                .unix_user_offline_auth_init(
                    account_id,
                    token.as_ref(),
                    service,
                    no_hello_pin,
                    &mut dbtxn,
                )
                .await
        };

        match maybe_err {
            Ok((next_req, cred_handler)) => {
                let auth_session = AuthSession::InProgress {
                    account_id: account_id.to_string(),
                    service: service.to_string(),
                    id,
                    token: token.map(Box::new),
                    online_at_init,
                    cred_handler,
                    shutdown_rx,
                    no_hello_pin,
                    force_reauth,
                };

                // Now identify what credentials are needed next. The auth session tells
                // us this.

                Ok((auth_session, next_req.into()))
            }
            Err(IdpError::NotFound { what, where_ }) => Ok((
                AuthSession::Denied,
                PamAuthResponse::InitDenied {
                    msg: format!("NotFound: {} in {}", what, where_),
                },
            )),
            Err(e) => {
                error!("{:?}", e);
                Err(ResolverError)
            }
        }
    }

    pub async fn pam_account_authenticate_step(
        &self,
        auth_session: &mut AuthSession,
        pam_next_req: PamAuthRequest,
    ) -> ResolverResult<PamAuthResponse> {
        let state = match auth_session {
            AuthSession::InProgress {
                account_id,
                service: _,
                id: _,
                token: _,
                online_at_init: _,
                cred_handler: _,
                shutdown_rx: _,
                no_hello_pin: _,
                force_reauth: _,
            } => self.get_cachestate(Some(account_id)).await,
            _ => self.get_cachestate(None).await,
        };

        let maybe_err = match (&mut *auth_session, state) {
            (
                &mut AuthSession::InProgress {
                    ref account_id,
                    ref service,
                    id: _,
                    token: Some(ref token),
                    online_at_init: true,
                    ref mut cred_handler,
                    ref shutdown_rx,
                    no_hello_pin,
                    force_reauth: _,
                },
                CacheState::Online,
            ) => {
                let mut hsm_lock = self.hsm.lock().await;
                let mut dbtxn = self.db.write().await;

                let maybe_cache_action = self
                    .client
                    .unix_user_online_auth_step(
                        account_id,
                        token,
                        service,
                        no_hello_pin,
                        cred_handler,
                        pam_next_req,
                        &mut dbtxn,
                        hsm_lock.deref_mut(),
                        &self.machine_key,
                        shutdown_rx,
                    )
                    .await;

                drop(hsm_lock);
                dbtxn.commit().map_err(|_| ())?;

                match maybe_cache_action {
                    Ok((res, AuthCacheAction::None)) => Ok(res),
                    Ok((
                        AuthResult::Success { token },
                        AuthCacheAction::PasswordHashUpdate { cred },
                    )) => {
                        // Might need a rework with the tpm code.
                        self.set_cache_userpassword(token.uuid, &cred).await?;
                        Ok(AuthResult::Success { token })
                    }
                    Ok((
                        next @ AuthResult::Next(AuthRequest::SetupPin { .. }),
                        AuthCacheAction::PasswordHashUpdate { cred },
                    )) => {
                        // SetupPin is offered only after the remote authentication
                        // flow has succeeded, so this is a post-authentication cache
                        // update rather than an in-progress MFA update.
                        self.set_cache_userpassword(token.uuid, &cred).await?;
                        Ok(next)
                    }
                    // Password verifiers may only be persisted after the complete
                    // remote authentication flow succeeds. Other `Next` variants
                    // still represent an authentication step such as MFA.
                    Ok((_, AuthCacheAction::PasswordHashUpdate { .. })) => {
                        error!("provider gave back illogical password hash update with a nonsuccess condition");
                        Err(IdpError::BadRequest)
                    }
                    Err(e) => Err(e),
                }
            }
            /*
            (
                &mut AuthSession::InProgress {
                    account_id: _,
                    id: _,
                    token: _,
                    online_at_init: true,
                    cred_handler: _,
                },
                _,
            ) => {
                // Fail, we went offline.
                error!("Unable to proceed with authentication, resolver has gone offline");
                Err(IdpError::Transport)
            }
            */
            (
                &mut AuthSession::InProgress {
                    ref account_id,
                    service: _,
                    id: _,
                    token: Some(ref token),
                    online_at_init,
                    ref mut cred_handler,
                    // Only need in online auth.
                    shutdown_rx: _,
                    no_hello_pin: _,
                    force_reauth,
                },
                _,
            ) => {
                // force_reauth requires online auth, refuse offline fallback.
                if force_reauth {
                    return Ok(PamAuthResponse::Denied(
                        "Re-authentication requires network connectivity.".to_string(),
                    ));
                }

                // We are offline, continue. Remember, authsession should have
                // *everything you need* to proceed here!
                //
                // Rather than calling client, should this actually be self
                // contained to the resolver so that it has generic offline-paths
                // that are possible?
                match (&cred_handler, &pam_next_req) {
                    (AuthCredHandler::InteractionCode(..), _) => {
                        // A partially completed native flow must finish online.
                        // This guard must precede the cached Password arm.
                        return Err(ResolverError);
                    }
                    (AuthCredHandler::OidcPinTotp { .. }, PamAuthRequest::Password { .. }) => {
                        // A pending native PIN second factor cannot be replaced
                        // by a cached password when connectivity changes.
                        return Err(ResolverError);
                    }
                    (AuthCredHandler::ReauthPassword { .. }, _) => {
                        // Password-based Hello reauthentication must complete online so
                        // that the provider can enforce the remaining MFA requirements.
                        return Err(ResolverError);
                    }
                    (_, PamAuthRequest::Password { cred }) => {
                        match self.check_cache_userpassword(token.uuid, cred).await {
                            Ok(true) => Ok(AuthResult::Success {
                                token: *token.clone(),
                            }),
                            Ok(false) => Ok(AuthResult::Denied("Offline auth failed".to_string())),
                            Err(_) => {
                                // We had a genuine backend error of some description.
                                return Err(ResolverError);
                            }
                        }
                    }
                    (AuthCredHandler::MFA { .. }, _) => {
                        // AuthCredHandler::MFA is invalid for offline auth
                        return Err(ResolverError);
                    }
                    (AuthCredHandler::SetupPin { .. }, _) => {
                        // AuthCredHandler::SetupPin is invalid for offline auth
                        return Err(ResolverError);
                    }
                    (AuthCredHandler::ChangePassword { .. }, _) => {
                        // AuthCredHandler::ChangePassword is invalid for offline auth
                        return Err(ResolverError);
                    }
                    (_, PamAuthRequest::Pin { .. }) | (_, PamAuthRequest::HelloTOTP { .. }) => {
                        // The Pin acts as a single device password, and can be
                        // used to unlock the TPM to validate the authentication.
                        let mut hsm_lock = self.hsm.lock().await;
                        let mut dbtxn = self.db.write().await;

                        let auth_result = self
                            .client
                            .unix_user_offline_auth_step(
                                account_id,
                                token,
                                cred_handler,
                                pam_next_req,
                                &mut dbtxn,
                                hsm_lock.deref_mut(),
                                &self.machine_key,
                                online_at_init,
                            )
                            .await;

                        drop(hsm_lock);
                        dbtxn.commit().map_err(|_| ())?;

                        auth_result
                    }
                    (AuthCredHandler::HelloTOTP { .. }, _) => {
                        // AuthCredHandler::HelloTOTP with anything other than HelloTOTP is invalid
                        return Err(ResolverError);
                    }
                    (AuthCredHandler::OidcPinTotp { .. }, _) => {
                        return Err(ResolverError);
                    }
                    (AuthCredHandler::None, PamAuthRequest::Input { .. }) => {
                        // AuthCredHandler::None is invalid with Input
                        return Err(ResolverError);
                    }
                    (AuthCredHandler::None, PamAuthRequest::MFAPoll { .. }) => {
                        // AuthCredHandler::None is invalid with MFAPoll
                        return Err(ResolverError);
                    }
                    (AuthCredHandler::None, PamAuthRequest::SetupPin { .. }) => {
                        // AuthCredHandler::None is invalid with SetupPin
                        return Err(ResolverError);
                    }
                    (AuthCredHandler::None, PamAuthRequest::Fido { .. }) => {
                        // AuthCredHandler::None is invalid with Fido
                        return Err(ResolverError);
                    }
                    (AuthCredHandler::None, PamAuthRequest::FidoUnavailable) => {
                        return Err(ResolverError);
                    }
                    (_, PamAuthRequest::WebAuthn { .. } | PamAuthRequest::WebAuthnUnavailable) => {
                        return Err(ResolverError);
                    }
                    (AuthCredHandler::PasswordFirst { .. }, _) => {
                        // AuthCredHandler::PasswordFirst with anything other than
                        // PamAuthRequest::Password is invalid.
                        return Err(ResolverError);
                    }
                }
            }
            (&mut AuthSession::InProgress { token: None, .. }, state) => {
                // Can't do much with online/offline auth when there is no token ...
                match state {
                    CacheState::Online => {
                        warn!("Unable to proceed with online auth, no token available");
                    }
                    CacheState::Offline | CacheState::OfflineNextCheck(_) => {
                        warn!("Unable to proceed with offline auth, no token available");
                    }
                }
                Err(IdpError::NotFound {
                    what: "token".to_string(),
                    where_: "AuthSession".to_string(),
                })
            }
            (&mut AuthSession::Success(_), _) | (&mut AuthSession::Denied, _) => {
                Err(IdpError::BadRequest)
            }
        };

        match maybe_err {
            // What did the provider direct us to do next?
            Ok(AuthResult::Success { mut token }) => {
                if self
                    .check_nxset(Some(&token.name), Some(token.gidnumber))
                    .await
                {
                    // Refuse to release the token, it's in the denied set.
                    self.delete_cache_usertoken(token.uuid).await?;
                    *auth_session = AuthSession::Denied;

                    Ok(PamAuthResponse::Unknown)
                } else {
                    trace!("provider authentication success.");
                    self.set_cache_usertoken(&mut token).await?;
                    *auth_session = AuthSession::Success(token.spn);

                    Ok(PamAuthResponse::Success)
                }
            }
            Ok(AuthResult::Denied(msg)) => {
                *auth_session = AuthSession::Denied;
                Ok(PamAuthResponse::Denied(msg))
            }
            Ok(AuthResult::Next(req)) => Ok(req.into()),
            Err(IdpError::NotFound { what, where_ }) => Ok(PamAuthResponse::InitDenied {
                msg: format!("NotFound: {} in {}", what, where_),
            }),
            Err(e) => {
                error!("{:?}", e);
                Err(ResolverError)
            }
        }
    }

    /// One-shot PIN-based unseal. Every invocation validates the PIN and
    /// restores valid cached SSO material through a dedicated provider path.
    /// An expired Entra PRT is renewed with the Hello key when the provider is
    /// online. A cached user record is refreshed online only when cache_timeout
    /// has elapsed.
    pub async fn pam_try_unseal(&self, account_id: &str, cred: &str) -> ResolverResult<bool> {
        let id = Id::Name(account_id.to_string());
        let (expired, token) = self.resolve_cached_usertoken(&id).await?;
        let Some(token) = token else {
            debug!("pam_try_unseal: no cached user token");
            return Ok(false);
        };

        let account_id = Self::canonical_account_id(account_id, Some(&token));
        let account_id = account_id.as_str();
        let state = self.get_cachestate(Some(account_id)).await;
        let online_at_init = self.test_connection_for_state(state).await;

        let mut hsm_lock = self.hsm.lock().await;
        let mut dbtxn = self.db.write().await;
        let unseal_result = self
            .client
            .unix_user_try_unseal(
                account_id,
                cred,
                &mut dbtxn,
                hsm_lock.deref_mut(),
                &self.machine_key,
                online_at_init,
            )
            .await;

        drop(hsm_lock);
        dbtxn.commit().map_err(|_| ())?;

        match unseal_result {
            Ok(true) => {
                if expired && online_at_init {
                    // This consumes the PRT restored above. Provider failures
                    // fall back to the cached user without extending its
                    // cache_timeout, so a later invocation can retry.
                    if self.refresh_usertoken(&id, Some(token)).await.is_err() {
                        debug!("pam_try_unseal: timed online refresh failed");
                    }
                }
                Ok(true)
            }
            Ok(false) => {
                debug!("pam_try_unseal: PIN auth denied");
                Ok(false)
            }
            Err(e) => {
                debug!("pam_try_unseal: local unseal failed: {:?}", e);
                Ok(false)
            }
        }
    }

    pub async fn pam_account_beginsession(
        &self,
        account_id: &str,
    ) -> ResolverResult<Option<HomeDirectoryInfo>> {
        let token = self.get_usertoken(Id::Name(account_id.to_string())).await?;
        Ok(token.as_ref().map(|tok| HomeDirectoryInfo {
            uid: tok.gidnumber,
            gid: tok.real_gidnumber.unwrap_or(tok.gidnumber),
            name: self.token_homedirectory_attr(tok),
            aliases: self
                .token_homedirectory_alias(tok)
                .map(|s| vec![s])
                .unwrap_or_default(),
        }))
    }

    pub async fn test_connection(&self) -> bool {
        let state = self.get_cachestate(None).await;
        self.test_connection_for_state(state).await
    }

    async fn test_connection_for_state(&self, state: CacheState) -> bool {
        match state {
            CacheState::Offline => {
                trace!("Offline -> no change");
                false
            }
            CacheState::OfflineNextCheck(time) => {
                let now = SystemTime::now();
                if now < time {
                    trace!(?time, "Offline -> next check not due");
                    return false;
                }

                let mut hsm_lock = self.hsm.lock().await;

                let res = self.client.check_online(hsm_lock.deref_mut(), now).await;

                drop(hsm_lock);

                res
            }
            CacheState::Online => {
                trace!("Online, no change");
                true
            }
        }
    }
}
