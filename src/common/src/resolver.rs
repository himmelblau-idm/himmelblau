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
use std::collections::{BTreeSet, HashMap};
use std::fmt::Display;
use std::fs;
use std::num::NonZeroUsize;
use std::ops::DerefMut;
use std::path::Path;
use std::string::ToString;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use lru::LruCache;
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;
use zeroize::Zeroizing;

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
    UpnVerdict,
    UserToken,
    UserTokenState,
};
use crate::unix_config::{HomeAttr, UidAttr};
use crate::unix_proto::{
    HomeDirectoryInfo, LocalTaskOwner, NssGroup, NssUser, PamAuthRequest, PamAuthResponse,
};
use crate::user_map::UserMap;

use kanidm_hsm_crypto::{
    provider::BoxedDynTpm, structures::HmacS256Key as HmacKey, structures::StorageKey as MachineKey,
};

use tokio::sync::broadcast;

use himmelblau::auth::UserToken as UnixUserToken;

const NXCACHE_SIZE: NonZeroUsize = NonZeroUsize::new(128).unwrap();
const UNREACHABLE_RETRY: Duration = Duration::from_secs(15);

// These keys deliberately mirror account_t's UUID/name/SPN/GID conflicts.
// They are not tenant-scoped because the database's uniqueness constraints are not.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PasswordCacheKey {
    Uuid(Uuid),
    Name(String),
    Spn(String),
    Gid(u32),
}

#[derive(Clone, Copy)]
struct PasswordCacheGeneration {
    identity_generation: u64,
    password_generation: Option<u64>,
    uuid: Uuid,
    tenant_id: Option<Uuid>,
}

#[derive(Debug, PartialEq, Eq)]
enum CacheUpdateResult {
    Updated,
    Superseded,
    IdentityChanged,
}

#[allow(clippy::large_enum_variant)]
pub enum AuthSession {
    InProgress {
        account_id: String,
        service: String,
        id: Id,
        token: Option<Box<UserToken>>,
        pending_password: Option<(u64, Zeroizing<String>)>,
        // Retain the accepted identity's order through local PIN/TOTP setup too.
        cache_generation: u64,
        identity_staged: bool,
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

/// How a user lookup treats an expired entry while the provider may be reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnExpiry {
    Refresh,
    RefreshIfReachable,
    RefreshInBackground,
}

#[derive(Default)]
struct IdentityRefreshes {
    queued: Vec<String>,
    // At most one refresh per identity per cache lifetime.
    next_allowed: HashMap<String, SystemTime>,
}

fn refresh_due(state: &CacheState) -> bool {
    match state {
        CacheState::Online => true,
        CacheState::OfflineNextCheck(time) => SystemTime::now() >= *time,
        CacheState::Offline => false,
    }
}

/// One token's view of the user for all tasks after `pam_sm_open_session`.
pub struct SessionIdentity {
    pub owner: LocalTaskOwner,
    pub home: HomeDirectoryInfo,
    pub account: NssUser,
    pub group_ids: Vec<Uuid>,
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
    user_map_file: Option<String>,
    cn_name_mapping: bool,
    name_mapping_script: bool,
    nxset: Mutex<HashSet<Id>>,
    nxcache: Mutex<LruCache<Id, SystemTime>>,
    alias_absence: Mutex<LruCache<String, SystemTime>>,
    password_generation: AtomicU64,
    // Keep committed identity observations and password invalidations while older sessions exist.
    // Both this map and all pending sessions disappear on daemon restart.
    password_cache_generations: Mutex<HashMap<PasswordCacheKey, PasswordCacheGeneration>>,
    identity_refreshes: Mutex<IdentityRefreshes>,
    identity_refresh_ready: Notify,
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
    use super::{AuthSession, CacheUpdateResult, NssAccountLookup, OnExpiry, Resolver};
    use crate::config::InitgroupsMode;
    use crate::db::{Cache, CacheTxn, Db, KeyStoreTxn};
    use crate::idprovider::interface::{
        tpm, AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, CacheState, GroupToken, Id,
        IdProvider, IdpError, UpnVerdict, UserToken, UserTokenState,
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
    use tokio::sync::{broadcast, Notify};

    struct OfflineFallbackProvider {
        cache_state: RwLock<CacheState>,
        check_online_result: AtomicBool,
        probe_online_result: AtomicBool,
        unreachable_domain: RwLock<Option<String>>,
        probe_stall: AtomicBool,
        probe_release: Notify,
        cache_state_calls: AtomicUsize,
        check_online_calls: AtomicUsize,
        probe_online_calls: AtomicUsize,
        try_unseal_online: AtomicBool,
        user_get_calls: AtomicUsize,
        try_unseal_calls: AtomicUsize,
        user_get_error: AtomicUsize,
        user_get_stall: AtomicBool,
        user_get_release: Notify,
        user_get_goes_offline: AtomicBool,
        exact_token: RwLock<Option<UserToken>>,
        exact_lookup_only: AtomicBool,
        exact_not_found: AtomicBool,
        upn_verdict: RwLock<UpnVerdict>,
        verify_calls: AtomicUsize,
        lookup_ids: RwLock<Vec<(Id, Option<String>)>>,
        credential_ids: RwLock<Vec<String>>,
        auth_token: RwLock<UserToken>,
    }

    impl OfflineFallbackProvider {
        fn new() -> Self {
            Self {
                cache_state: RwLock::new(CacheState::Online),
                check_online_result: AtomicBool::new(true),
                probe_online_result: AtomicBool::new(true),
                unreachable_domain: RwLock::new(None),
                probe_stall: AtomicBool::new(false),
                probe_release: Notify::new(),
                cache_state_calls: AtomicUsize::new(0),
                check_online_calls: AtomicUsize::new(0),
                probe_online_calls: AtomicUsize::new(0),
                try_unseal_online: AtomicBool::new(false),
                user_get_calls: AtomicUsize::new(0),
                try_unseal_calls: AtomicUsize::new(0),
                user_get_error: AtomicUsize::new(0),
                user_get_stall: AtomicBool::new(false),
                user_get_release: Notify::new(),
                user_get_goes_offline: AtomicBool::new(false),
                exact_token: RwLock::new(None),
                exact_lookup_only: AtomicBool::new(false),
                exact_not_found: AtomicBool::new(false),
                upn_verdict: RwLock::new(UpnVerdict::Unknown),
                verify_calls: AtomicUsize::new(0),
                lookup_ids: RwLock::new(Vec::new()),
                credential_ids: RwLock::new(Vec::new()),
                auth_token: RwLock::new(test_token()),
            }
        }

        fn auth_token(&self) -> UserToken {
            self.auth_token
                .read()
                .expect("auth token lock poisoned")
                .clone()
        }

        fn set_cache_state(&self, state: CacheState) {
            *self.cache_state.write().expect("cache state lock poisoned") = state;
        }

        fn set_not_found(&self) {
            self.exact_not_found.store(true, Ordering::Release);
        }

        fn set_lookup_only(&self) {
            self.exact_lookup_only.store(true, Ordering::Release);
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

        async fn probe_online(&self, account_id: Option<&str>, _now: SystemTime) -> bool {
            self.probe_online_calls.fetch_add(1, Ordering::AcqRel);
            if self.probe_stall.load(Ordering::Acquire) {
                self.probe_release.notified().await;
            }
            let unreachable = self
                .unreachable_domain
                .read()
                .expect("unreachable domain lock poisoned")
                .clone();
            if let (Some(domain), Some(account_id)) = (unreachable, account_id) {
                if account_id.ends_with(&format!("@{domain}")) {
                    return false;
                }
            }
            self.probe_online_result.load(Ordering::Acquire)
        }

        async fn unix_user_verify_upn(
            &self,
            _account_id: &str,
            _tpm: &mut tpm::provider::BoxedDynTpm,
            _machine_key: &tpm::structures::StorageKey,
        ) -> UpnVerdict {
            self.verify_calls.fetch_add(1, Ordering::AcqRel);
            *self.upn_verdict.read().unwrap()
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
            if self.user_get_stall.load(Ordering::Acquire) {
                self.user_get_release.notified().await;
            }
            if self.user_get_goes_offline.load(Ordering::Acquire) {
                self.set_cache_state(CacheState::OfflineNextCheck(
                    SystemTime::now() + Duration::from_secs(60),
                ));
                return Ok(UserTokenState::UseCached);
            }
            self.lookup_ids
                .write()
                .unwrap()
                .push((_id.clone(), _token.map(|token| token.spn.clone())));
            if _token.is_none() {
                if let Some(token) = self.exact_token.read().unwrap().clone() {
                    return Ok(if self.exact_lookup_only.load(Ordering::Acquire) {
                        UserTokenState::LookupOnly(token)
                    } else {
                        UserTokenState::Update(token)
                    });
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
                3..=5 | 7 if matches!(_id, Id::Name(_)) => {
                    Ok(UserTokenState::LookupOnly(test_token()))
                }
                6 => Ok(UserTokenState::Update(self.auth_token())),
                8 => Err(IdpError::Transport),
                9 => Err(IdpError::ProviderUnauthorised),
                10 => Err(IdpError::KeyStore),
                11 => Err(IdpError::Tpm),
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
            if matches!(self.user_get_error.load(Ordering::Acquire), 3..=5 | 7) {
                return Ok((
                    AuthRequest::Password {
                        prompt: None,
                        long_prompt: None,
                    },
                    AuthCredHandler::None,
                ));
            }
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
            if self.user_get_error.load(Ordering::Acquire) == 5 {
                return Ok((
                    AuthResult::Success {
                        token: self.auth_token(),
                    },
                    AuthCacheAction::None,
                ));
            }
            if self.user_get_error.load(Ordering::Acquire) == 3 {
                return Ok((
                    AuthResult::Success {
                        token: self.auth_token(),
                    },
                    AuthCacheAction::PasswordHashUpdate {
                        cred: match _pam_next_req {
                            PamAuthRequest::Password { cred } => cred,
                            _ => return Err(IdpError::BadRequest),
                        },
                    },
                ));
            }
            if matches!(self.user_get_error.load(Ordering::Acquire), 4 | 7) {
                if matches!(&_pam_next_req, PamAuthRequest::Password { cred } if cred == "direct-totp")
                {
                    return Ok((
                        AuthResult::Next(AuthRequest::HelloTOTP {
                            msg: "Enter local TOTP".to_string(),
                        }),
                        AuthCacheAction::None,
                    ));
                }
                if let PamAuthRequest::HelloTOTP { cred } = &_pam_next_req {
                    return Ok((
                        AuthResult::Success {
                            token: self.auth_token(),
                        },
                        if cred == "cache-password" {
                            AuthCacheAction::PasswordHashUpdate {
                                cred: "late-secret".to_string(),
                            }
                        } else {
                            AuthCacheAction::None
                        },
                    ));
                }
                if matches!(&_pam_next_req, PamAuthRequest::SetupPin { pin } if pin == "totp") {
                    return Ok((
                        AuthResult::Next(AuthRequest::HelloTOTP {
                            msg: "Enter local TOTP".to_string(),
                        }),
                        AuthCacheAction::None,
                    ));
                }
                if matches!(&_pam_next_req, PamAuthRequest::SetupPin { pin } if pin == "retry") {
                    return Ok((
                        AuthResult::Next(AuthRequest::SetupPin {
                            msg: "Try a different PIN".to_string(),
                        }),
                        AuthCacheAction::None,
                    ));
                }
                if matches!(_pam_next_req, PamAuthRequest::SetupPin { .. }) {
                    return Ok((
                        AuthResult::Success {
                            token: self.auth_token(),
                        },
                        AuthCacheAction::None,
                    ));
                }
                if self.user_get_error.load(Ordering::Acquire) == 7 {
                    return Ok((
                        AuthResult::Next(AuthRequest::SetupPin {
                            msg: "Set PIN".to_string(),
                        }),
                        AuthCacheAction::None,
                    ));
                }
                return Ok((
                    AuthResult::Next(AuthRequest::SetupPin {
                        msg: "Set PIN".to_string(),
                    }),
                    AuthCacheAction::PasswordHashUpdate {
                        cred: match _pam_next_req {
                            PamAuthRequest::Password { cred } => cred,
                            _ => return Err(IdpError::BadRequest),
                        },
                    },
                ));
            }
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

        async fn get_cachestate(&self, _account_id: Option<&str>) -> CacheState {
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
        let db = Db::new("").expect("failed to create test db");
        setup_resolver_with_db(db, expiry, initgroups_mode, extra_groups).await
    }

    async fn setup_resolver_with_db(
        db: Db,
        expiry: u64,
        initgroups_mode: InitgroupsMode,
        extra_groups: Vec<GroupToken>,
    ) -> Resolver<OfflineFallbackProvider> {
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
            vec!["9f8a7a5a-a8e8-5c57-9f4f-7dfe21126c23".to_string()],
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

    async fn setup_sql_resolver() -> (Resolver<OfflineFallbackProvider>, rusqlite::Connection) {
        let uri = format!(
            "file:password-cache-{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );
        let conn = rusqlite::Connection::open(&uri).unwrap();
        let db = Db::new(&uri).unwrap();
        let resolver = setup_resolver_with_db(db, 0, InitgroupsMode::Named, Vec::new()).await;
        (resolver, conn)
    }

    #[tokio::test]
    async fn lookup_only_user_is_not_cached_before_first_login() {
        let resolver = setup_resolver().await;
        resolver
            .delete_cache_usertoken(test_token().uuid)
            .await
            .unwrap();
        resolver.client.user_get_error.store(3, Ordering::Release);

        let user = resolver
            .get_nssaccount_name("testuser@example.com", OnExpiry::Refresh)
            .await
            .unwrap()
            .unwrap();
        assert!(!user.cacheable);
        assert!(resolver.get_cached_usertokens().await.unwrap().is_empty());
        assert!(resolver
            .get_nssaccount_gid(user.uid, OnExpiry::Refresh)
            .await
            .unwrap()
            .is_none());

        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (mut session, response) = resolver
            .pam_account_authenticate_init(
                "testuser@example.com",
                "sshd",
                false,
                false,
                shutdown_rx,
            )
            .await
            .unwrap();
        assert!(matches!(response, PamAuthResponse::Password { .. }));
        assert!(resolver.get_cached_usertokens().await.unwrap().is_empty());

        let response = resolver
            .pam_account_authenticate_step(
                &mut session,
                PamAuthRequest::Password {
                    cred: "secret".to_string(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(response, PamAuthResponse::Success));
        assert_eq!(resolver.get_cached_usertokens().await.unwrap().len(), 1);
        assert!(resolver
            .check_cache_userpassword(test_token().uuid, "secret")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn lookup_only_user_does_not_revalidate_expired_cached_identity() {
        let resolver = setup_resolver().await;
        let token = test_token();
        resolver
            .set_cache_userpassword(token.uuid, "secret")
            .await
            .unwrap();
        resolver.client.user_get_error.store(3, Ordering::Release);

        let user = resolver
            .get_nssaccount_name(&token.spn, OnExpiry::Refresh)
            .await
            .unwrap()
            .unwrap();
        assert!(!user.cacheable);
        assert!(resolver.get_nssaccounts().await.unwrap().is_empty());
        let mut dbtxn = resolver.db.write().await;
        let (cached, expiry) = dbtxn
            .get_account(&Id::Name(token.spn.clone()))
            .unwrap()
            .unwrap();
        // The lookup-only result deliberately has the same UUID as the
        // expired row left behind by migration.
        assert_eq!(cached.uuid, token.uuid);
        assert_eq!(expiry, 0);
        dbtxn.commit().unwrap();
        assert!(resolver
            .check_cache_userpassword(token.uuid, "secret")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn trusted_user_refresh_is_cacheable() {
        let resolver = setup_resolver().await;
        let token = test_token();
        resolver.client.user_get_error.store(6, Ordering::Release);

        assert!(
            resolver
                .get_nssaccount_name(&token.spn, OnExpiry::Refresh)
                .await
                .unwrap()
                .unwrap()
                .cacheable
        );
        let (expired, cached) = resolver
            .get_cached_usertoken(&Id::Name(token.spn))
            .await
            .unwrap();
        assert!(!expired);
        assert_eq!(cached.unwrap().uuid, token.uuid);
        assert!(
            resolver
                .get_nssaccount_gid(token.gidnumber, OnExpiry::Refresh)
                .await
                .unwrap()
                .unwrap()
                .cacheable
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn unexpired_cached_user_is_cacheable() {
        let expiry = (SystemTime::now() + Duration::from_secs(3600))
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for state in [
            CacheState::Online,
            CacheState::Offline,
            CacheState::OfflineNextCheck(SystemTime::now() + Duration::from_secs(60)),
        ] {
            let resolver = setup_resolver_with_expiry(expiry).await;
            resolver.client.set_cache_state(state);
            let token = test_token();
            for id in [
                Id::Name(token.spn),
                Id::Name(token.name),
                Id::Gid(token.gidnumber),
            ] {
                assert!(
                    resolver
                        .get_nssaccount(id, OnExpiry::Refresh)
                        .await
                        .unwrap()
                        .unwrap()
                        .cacheable
                );
            }
            assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
        }
    }

    #[tokio::test]
    async fn expired_cached_user_remains_available_but_not_cacheable() {
        for (state, error) in [
            (CacheState::Offline, 0),
            (
                CacheState::OfflineNextCheck(SystemTime::now() + Duration::from_secs(60)),
                0,
            ),
            (CacheState::OfflineNextCheck(SystemTime::UNIX_EPOCH), 0),
            (CacheState::Online, 0),
            (CacheState::Online, 1),
            (CacheState::Online, 2),
        ] {
            let resolver = setup_resolver().await;
            let token = test_token();
            resolver.client.set_cache_state(state);
            resolver
                .client
                .user_get_error
                .store(error, Ordering::Release);
            resolver
                .client
                .check_online_result
                .store(false, Ordering::Release);
            resolver
                .set_cache_userpassword(token.uuid, "secret")
                .await
                .unwrap();

            let cached = resolver
                .get_usertoken(Id::Name(token.spn.clone()))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(cached.uuid, token.uuid);
            for id in [Id::Name(token.spn.clone()), Id::Gid(token.gidnumber)] {
                assert!(
                    !resolver
                        .get_nssaccount(id, OnExpiry::Refresh)
                        .await
                        .unwrap()
                        .unwrap()
                        .cacheable
                );
            }
            let mut dbtxn = resolver.db.write().await;
            let (_, expiry) = dbtxn.get_account(&Id::Name(token.spn)).unwrap().unwrap();
            assert_eq!(expiry, 0);
            dbtxn.commit().unwrap();
            assert!(resolver
                .check_cache_userpassword(token.uuid, "secret")
                .await
                .unwrap());
        }
    }

    #[tokio::test]
    async fn background_lookup_answers_an_expired_entry_without_the_provider() {
        let resolver = setup_resolver().await;
        let token = test_token();
        resolver.client.user_get_error.store(6, Ordering::Release);

        for id in [
            Id::Name(token.spn.clone()),
            Id::Name(token.name.clone()),
            Id::Gid(token.gidnumber),
        ] {
            let user = resolver
                .get_nssaccount(id, OnExpiry::RefreshInBackground)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(user.uid, token.gidnumber);
            assert!(!user.cacheable);
        }
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
        assert_eq!(
            resolver.client.check_online_calls.load(Ordering::Acquire),
            0
        );
        assert_eq!(
            resolver.identity_refreshes.lock().await.queued,
            vec![token.spn.clone()]
        );
    }

    #[tokio::test]
    async fn background_lookup_does_not_queue_a_refresh_while_offline() {
        for state in [
            CacheState::Offline,
            CacheState::OfflineNextCheck(SystemTime::now() + Duration::from_secs(60)),
        ] {
            let resolver = setup_resolver().await;
            resolver.client.set_cache_state(state);

            let user = resolver
                .get_nssaccount_name(&test_token().spn, OnExpiry::RefreshInBackground)
                .await
                .unwrap()
                .unwrap();
            assert!(!user.cacheable);
            assert!(resolver.identity_refreshes.lock().await.queued.is_empty());
            assert_eq!(
                resolver.client.check_online_calls.load(Ordering::Acquire),
                0
            );
            assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
        }
    }

    #[tokio::test]
    async fn background_lookup_of_an_uncached_user_asks_the_provider() {
        let resolver = setup_resolver().await;
        resolver
            .delete_cache_usertoken(test_token().uuid)
            .await
            .unwrap();
        resolver.client.user_get_error.store(3, Ordering::Release);

        let user = resolver
            .get_nssaccount_name("testuser@example.com", OnExpiry::RefreshInBackground)
            .await
            .unwrap()
            .unwrap();
        assert!(!user.cacheable);
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
        assert!(resolver.identity_refreshes.lock().await.queued.is_empty());
    }

    #[tokio::test]
    async fn background_lookup_does_not_wait_for_provider_work() {
        let file = crate::db::TestDbFile::new();
        let db = Db::new(&file.0).expect("failed to create test db");
        let resolver = setup_resolver_with_db(db, 0, InitgroupsMode::Named, Vec::new()).await;
        let token = test_token();
        resolver
            .client
            .probe_online_result
            .store(false, Ordering::Release);

        let _hsm = resolver.hsm.lock().await;
        let mut dbtxn = resolver.db.write().await;
        dbtxn.update_account(&token, 0).unwrap();

        let lookups = async {
            let user = resolver
                .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
                .await
                .unwrap()
                .unwrap();
            let groups = resolver
                .get_initgroups(&token.spn, OnExpiry::RefreshIfReachable)
                .await
                .unwrap();
            let group = resolver
                .get_nssgroup_gid(token.groups[0].gidnumber)
                .await
                .unwrap();
            (user, groups, group)
        };
        let (user, groups, group) = tokio::time::timeout(Duration::from_secs(5), lookups)
            .await
            .expect("lookup waited for provider work");
        assert_eq!(user.uid, token.gidnumber);
        assert_eq!(groups, Some(vec![token.groups[0].gidnumber]));
        assert_eq!(group.unwrap().gid, token.groups[0].gidnumber);
    }

    fn removed_group() -> GroupToken {
        GroupToken {
            name: "removed-group".to_string(),
            spn: "removed-group".to_string(),
            uuid: uuid::uuid!("3c1e4f4a-8f3e-4a0e-9a54-0b6e2a0f8c11"),
            gidnumber: 2200,
        }
    }

    #[tokio::test]
    async fn initgroups_drops_a_removed_group_when_the_provider_is_reachable() {
        let resolver = setup_resolver_with(0, InitgroupsMode::Full, vec![removed_group()]).await;
        resolver.client.user_get_error.store(6, Ordering::Release);

        assert_eq!(
            resolver
                .get_initgroups(&test_token().spn, OnExpiry::RefreshIfReachable)
                .await
                .unwrap(),
            Some(vec![test_token().groups[0].gidnumber])
        );
        assert_eq!(
            resolver.client.probe_online_calls.load(Ordering::Acquire),
            1
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
        assert!(resolver.identity_refreshes.lock().await.queued.is_empty());
    }

    #[tokio::test]
    async fn initgroups_answers_from_the_cache_when_the_provider_is_unreachable() {
        let resolver = setup_resolver_with(0, InitgroupsMode::Full, vec![removed_group()]).await;
        resolver.client.user_get_error.store(6, Ordering::Release);
        resolver
            .client
            .probe_online_result
            .store(false, Ordering::Release);

        assert_eq!(
            resolver
                .get_initgroups(&test_token().spn, OnExpiry::RefreshIfReachable)
                .await
                .unwrap(),
            Some(vec![
                test_token().groups[0].gidnumber,
                removed_group().gidnumber
            ])
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
        assert_eq!(
            resolver.client.check_online_calls.load(Ordering::Acquire),
            0
        );
    }

    #[tokio::test]
    async fn queued_refresh_probes_the_provider_before_refreshing() {
        let (_shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
        let resolver = setup_resolver().await;
        let token = test_token();
        resolver.client.user_get_error.store(6, Ordering::Release);
        resolver
            .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap();

        resolver.refresh_queued_identities(&shutdown_rx).await;
        assert_eq!(
            resolver.client.probe_online_calls.load(Ordering::Acquire),
            1
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
        assert!(resolver.identity_refreshes.lock().await.queued.is_empty());

        let user = resolver
            .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap()
            .unwrap();
        assert!(user.cacheable);
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn queued_refresh_waits_for_an_unreachable_provider() {
        let (_shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
        let resolver = setup_resolver().await;
        let token = test_token();
        resolver.client.user_get_error.store(6, Ordering::Release);
        resolver
            .client
            .probe_online_result
            .store(false, Ordering::Release);
        resolver
            .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap();

        resolver.refresh_queued_identities(&shutdown_rx).await;
        assert_eq!(
            resolver.client.probe_online_calls.load(Ordering::Acquire),
            1
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);

        resolver
            .client
            .set_cache_state(CacheState::OfflineNextCheck(
                SystemTime::now() + Duration::from_secs(60),
            ));
        let user = resolver
            .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap()
            .unwrap();
        assert!(!user.cacheable);
        assert!(resolver.identity_refreshes.lock().await.queued.is_empty());

        resolver
            .client
            .set_cache_state(CacheState::OfflineNextCheck(SystemTime::UNIX_EPOCH));
        resolver
            .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap();
        assert!(resolver.identity_refreshes.lock().await.queued.is_empty());

        resolver
            .identity_refreshes
            .lock()
            .await
            .next_allowed
            .insert(token.spn.clone(), SystemTime::UNIX_EPOCH);
        resolver
            .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap();
        assert_eq!(
            resolver.identity_refreshes.lock().await.queued,
            vec![token.spn.clone()]
        );
    }

    #[tokio::test]
    async fn queued_refresh_runs_once_per_cache_lifetime() {
        let (_shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
        let resolver = setup_resolver().await;
        let token = test_token();
        resolver
            .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap();
        resolver.refresh_queued_identities(&shutdown_rx).await;
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);

        let user = resolver
            .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap()
            .unwrap();
        assert!(!user.cacheable);
        assert!(resolver.identity_refreshes.lock().await.queued.is_empty());
        resolver.refresh_queued_identities(&shutdown_rx).await;
        assert_eq!(
            resolver.client.probe_online_calls.load(Ordering::Acquire),
            1
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn queued_refresh_probes_each_domain_once() {
        let (_shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
        let resolver = setup_resolver().await;
        let mut dbtxn = resolver.db.write().await;
        for (index, spn) in ["second@example.com", "offline@contoso.com"]
            .into_iter()
            .enumerate()
        {
            let index = u32::try_from(index).unwrap();
            let token = UserToken {
                name: spn.split('@').next().unwrap().to_string(),
                spn: spn.to_string(),
                uuid: uuid::Uuid::new_v4(),
                gidnumber: 3000 + index,
                real_gidnumber: Some(3000 + index),
                ..test_token()
            };
            dbtxn.update_account(&token, 0).unwrap();
        }
        dbtxn.commit().unwrap();
        *resolver.client.unreachable_domain.write().unwrap() = Some("contoso.com".to_string());

        for spn in [
            "testuser@example.com",
            "second@example.com",
            "offline@contoso.com",
        ] {
            resolver
                .get_nssaccount_name(spn, OnExpiry::RefreshInBackground)
                .await
                .unwrap()
                .unwrap();
        }
        resolver.refresh_queued_identities(&shutdown_rx).await;

        assert_eq!(
            resolver.client.probe_online_calls.load(Ordering::Acquire),
            2
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn queued_refresh_stops_a_domain_once_a_refresh_finds_it_offline() {
        let (_shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
        let resolver = setup_resolver().await;
        let mut dbtxn = resolver.db.write().await;
        let second = UserToken {
            name: "second".to_string(),
            spn: "second@example.com".to_string(),
            uuid: uuid::Uuid::new_v4(),
            gidnumber: 3000,
            real_gidnumber: Some(3000),
            ..test_token()
        };
        dbtxn.update_account(&second, 0).unwrap();
        dbtxn.commit().unwrap();
        resolver
            .client
            .user_get_goes_offline
            .store(true, Ordering::Release);

        for spn in [test_token().spn, second.spn.clone()] {
            resolver
                .get_nssaccount_name(&spn, OnExpiry::RefreshInBackground)
                .await
                .unwrap();
        }
        resolver.refresh_queued_identities(&shutdown_rx).await;

        assert_eq!(
            resolver.client.probe_online_calls.load(Ordering::Acquire),
            1
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
        let refreshes = resolver.identity_refreshes.lock().await;
        for spn in [test_token().spn, second.spn] {
            assert!(refreshes
                .next_allowed
                .get(&spn)
                .is_some_and(|retry| *retry <= SystemTime::now() + Duration::from_secs(15)));
        }
    }

    #[tokio::test]
    async fn queued_refresh_skips_an_entry_cleared_during_the_probe() {
        let (_shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
        let resolver = setup_resolver().await;
        resolver.client.user_get_error.store(6, Ordering::Release);
        resolver
            .get_nssaccount_name(&test_token().spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap();
        resolver.client.probe_stall.store(true, Ordering::Release);

        let clear = async {
            while resolver.client.probe_online_calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
            resolver
                .delete_cache_usertoken(test_token().uuid)
                .await
                .unwrap();
            resolver.client.probe_release.notify_one();
        };
        tokio::join!(resolver.refresh_queued_identities(&shutdown_rx), clear);

        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
        assert!(resolver.get_cached_usertokens().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn invalidate_lets_lookups_queue_a_refresh_again() {
        let (_shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
        let resolver = setup_resolver().await;
        let spn = test_token().spn;
        resolver
            .get_nssaccount_name(&spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap();
        resolver.refresh_queued_identities(&shutdown_rx).await;
        resolver
            .get_nssaccount_name(&spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap();
        assert!(resolver.identity_refreshes.lock().await.queued.is_empty());

        resolver.invalidate().await.unwrap();
        resolver
            .get_nssaccount_name(&spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap();
        assert_eq!(resolver.identity_refreshes.lock().await.queued, vec![spn]);
    }

    #[tokio::test]
    async fn queued_refresh_stops_at_shutdown() {
        let resolver = setup_resolver().await;
        resolver.client.user_get_error.store(6, Ordering::Release);
        resolver
            .get_nssaccount_name(&test_token().spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap();
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        shutdown_tx.send(()).unwrap();

        resolver.refresh_queued_identities(&shutdown_rx).await;
        assert_eq!(
            resolver.client.probe_online_calls.load(Ordering::Acquire),
            0
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn lookups_answer_while_a_refresh_waits_on_the_provider() {
        let (_shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
        let file = crate::db::TestDbFile::new();
        let db = Db::new(&file.0).expect("failed to create test db");
        let resolver = setup_resolver_with_db(db, 0, InitgroupsMode::Named, Vec::new()).await;
        let token = test_token();
        resolver.client.user_get_error.store(6, Ordering::Release);
        resolver
            .client
            .user_get_stall
            .store(true, Ordering::Release);
        resolver
            .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
            .await
            .unwrap();

        let checks = async {
            while resolver.client.user_get_calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
            let lookups = async {
                resolver
                    .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
                    .await
                    .unwrap()
                    .unwrap();
                resolver
                    .get_nssgroup_gid(token.groups[0].gidnumber)
                    .await
                    .unwrap()
                    .unwrap();
            };
            tokio::time::timeout(Duration::from_secs(5), lookups)
                .await
                .expect("lookup waited for the refresh");
            assert!(
                tokio::time::timeout(Duration::from_millis(200), resolver.hsm.lock())
                    .await
                    .is_err()
            );
            resolver.client.user_get_release.notify_one();
        };
        tokio::join!(resolver.refresh_queued_identities(&shutdown_rx), checks);

        assert!(
            resolver
                .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
                .await
                .unwrap()
                .unwrap()
                .cacheable
        );
    }

    #[tokio::test]
    async fn refresh_worker_runs_queued_refreshes_until_shutdown() {
        let resolver = setup_resolver().await;
        let token = test_token();
        resolver.client.user_get_error.store(6, Ordering::Release);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let lookup = async {
            resolver
                .get_nssaccount_name(&token.spn, OnExpiry::RefreshInBackground)
                .await
                .unwrap();
            while resolver.client.user_get_calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
            shutdown_tx.send(()).unwrap();
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(resolver.refresh_expired_identities(shutdown_rx), lookup)
        })
        .await
        .expect("refresh worker did not stop");
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn account_authorization_refreshes_an_expired_entry_first() {
        let resolver = setup_resolver().await;
        resolver.client.user_get_error.store(6, Ordering::Release);

        assert_eq!(
            resolver
                .pam_account_allowed(&test_token().spn)
                .await
                .unwrap(),
            Some(true)
        );
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
        assert!(resolver.identity_refreshes.lock().await.queued.is_empty());
    }

    #[tokio::test]
    async fn online_auth_succeeds_when_offline_password_cache_fails() {
        for (setup_pin, cached_password) in [
            (false, None),
            (true, None),
            (false, Some("old-secret")),
            (true, Some("old-secret")),
            (false, Some("secret")),
        ] {
            // Share an isolated in-memory database with a connection that can
            // fail only verifier replacements, leaving identity caching operational.
            let (resolver, conn) = setup_sql_resolver().await;
            if let Some(cred) = cached_password {
                resolver
                    .set_cache_userpassword(test_token().uuid, cred)
                    .await
                    .unwrap();
            } else {
                resolver
                    .delete_cache_usertoken(test_token().uuid)
                    .await
                    .unwrap();
            }
            conn.execute_batch(
                "CREATE TRIGGER fail_password_cache BEFORE UPDATE OF password ON account_t
                 WHEN NEW.password IS NOT NULL
                 BEGIN SELECT RAISE(ABORT, 'injected password cache failure'); END;",
            )
            .unwrap();
            resolver
                .client
                .user_get_error
                .store(if setup_pin { 4 } else { 3 }, Ordering::Release);

            for cache_fails in [true, false] {
                if !cache_fails {
                    // A later login must update the verifier once storage
                    // recovers, including a password staged until PIN setup.
                    conn.execute_batch("DROP TRIGGER fail_password_cache")
                        .unwrap();
                }
                let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
                let (mut session, response) = resolver
                    .pam_account_authenticate_init(
                        "testuser@example.com",
                        "sshd",
                        false,
                        false,
                        shutdown_rx,
                    )
                    .await
                    .unwrap();
                assert!(matches!(response, PamAuthResponse::Password { .. }));
                let mut response = resolver
                    .pam_account_authenticate_step(
                        &mut session,
                        PamAuthRequest::Password {
                            cred: "secret".to_string(),
                        },
                    )
                    .await
                    .unwrap();
                if setup_pin {
                    assert!(matches!(response, PamAuthResponse::SetupPin { .. }));
                    if cache_fails && cached_password.is_none() {
                        assert!(resolver.get_cached_usertokens().await.unwrap().is_empty());
                    }
                    response = resolver
                        .pam_account_authenticate_step(
                            &mut session,
                            PamAuthRequest::SetupPin {
                                pin: "123456".to_string(),
                            },
                        )
                        .await
                        .unwrap();
                }

                assert!(matches!(response, PamAuthResponse::Success));
                assert!(
                    matches!(session, AuthSession::Success(ref spn) if spn == "testuser@example.com")
                );
                assert_eq!(resolver.get_cached_usertokens().await.unwrap().len(), 1);
                assert_eq!(
                    resolver
                        .check_cache_userpassword(test_token().uuid, "secret")
                        .await
                        .unwrap(),
                    !cache_fails
                );
                assert!(!resolver
                    .check_cache_userpassword(test_token().uuid, "old-secret")
                    .await
                    .unwrap());
            }
        }
    }

    #[tokio::test]
    async fn authentication_without_password_update_preserves_verifier() {
        let resolver = setup_resolver().await;
        resolver
            .set_cache_userpassword(test_token().uuid, "old-secret")
            .await
            .unwrap();
        let mut token = test_token();
        resolver
            .set_cache_usertoken(&mut token, false)
            .await
            .unwrap();
        assert!(resolver
            .check_cache_userpassword(token.uuid, "old-secret")
            .await
            .unwrap());

        resolver.client.user_get_error.store(5, Ordering::Release);
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (mut session, _) = resolver
            .pam_account_authenticate_init(
                "testuser@example.com",
                "sshd",
                false,
                false,
                shutdown_rx,
            )
            .await
            .unwrap();
        let response = resolver
            .pam_account_authenticate_step(
                &mut session,
                PamAuthRequest::Password {
                    cred: "secret".to_string(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(response, PamAuthResponse::Success));
        assert!(resolver
            .check_cache_userpassword(token.uuid, "old-secret")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn failed_password_invalidation_rejects_login_and_rolls_back_token() {
        let (resolver, conn) = setup_sql_resolver().await;
        let token = test_token();
        resolver
            .set_cache_userpassword(token.uuid, "old-secret")
            .await
            .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_password_invalidation BEFORE UPDATE OF password ON account_t
             WHEN NEW.password IS NULL
             BEGIN SELECT RAISE(ABORT, 'injected password invalidation failure'); END;",
        )
        .unwrap();
        resolver.client.user_get_error.store(3, Ordering::Release);
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (mut session, _) = resolver
            .pam_account_authenticate_init(
                "testuser@example.com",
                "sshd",
                false,
                false,
                shutdown_rx,
            )
            .await
            .unwrap();
        assert!(resolver
            .pam_account_authenticate_step(
                &mut session,
                PamAuthRequest::Password {
                    cred: "secret".to_string(),
                },
            )
            .await
            .is_err());
        assert!(!matches!(session, AuthSession::Success(_)));
        assert!(resolver.password_cache_generations.lock().await.is_empty());
        let mut dbtxn = resolver.db.write().await;
        let (cached, expiry) = dbtxn.get_account(&Id::Name(token.spn)).unwrap().unwrap();
        assert_eq!(expiry, 0);
        assert!(cached.shell.is_none());
        dbtxn.commit().unwrap();
        // Failed invalidation leaves the old transaction state intact, but
        // must never report this online authentication as successful.
        assert!(resolver
            .check_cache_userpassword(token.uuid, "old-secret")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn failed_password_replacement_does_not_erase_newer_verifier() {
        let (resolver, conn) = setup_sql_resolver().await;
        let mut token = test_token();
        resolver
            .set_cache_userpassword(token.uuid, "old-secret")
            .await
            .unwrap();
        resolver
            .set_cache_usertoken(&mut token, true)
            .await
            .unwrap();
        // Another authentication can save its verifier between this login's
        // invalidation and its replacement attempt.
        resolver
            .set_cache_userpassword(token.uuid, "newer-secret")
            .await
            .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_password_cache BEFORE UPDATE OF password ON account_t
             WHEN NEW.password IS NOT NULL
             BEGIN SELECT RAISE(ABORT, 'injected password cache failure'); END;",
        )
        .unwrap();
        assert!(resolver
            .set_cache_userpassword(token.uuid, "secret")
            .await
            .is_err());
        assert!(resolver
            .check_cache_userpassword(token.uuid, "newer-secret")
            .await
            .unwrap());
        assert!(!resolver
            .check_cache_userpassword(token.uuid, "old-secret")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn older_pin_setup_cannot_replace_newer_password_generation() {
        for (newer_cache_fails, older_cache_fails) in [(false, false), (true, false), (false, true)]
        {
            let (resolver, conn) = setup_sql_resolver().await;
            resolver.client.user_get_error.store(4, Ordering::Release);
            let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
            // Start B first: credential acceptance, not session creation,
            // determines which password update is newer.
            let (mut newer, _) = resolver
                .pam_account_authenticate_init(
                    "testuser@example.com",
                    "sshd",
                    false,
                    false,
                    shutdown_rx.resubscribe(),
                )
                .await
                .unwrap();
            let (mut older, _) = resolver
                .pam_account_authenticate_init(
                    "testuser@example.com",
                    "sshd",
                    false,
                    false,
                    shutdown_rx,
                )
                .await
                .unwrap();
            // An initial lookup may have a synthetic UUID. Use only the final
            // authenticated UUID when comparing password generations.
            if let AuthSession::InProgress {
                token: Some(token), ..
            } = &mut older
            {
                token.uuid = uuid::Uuid::new_v4();
            }
            let response = resolver
                .pam_account_authenticate_step(
                    &mut older,
                    PamAuthRequest::Password {
                        cred: "old-secret".to_string(),
                    },
                )
                .await
                .unwrap();
            assert!(matches!(response, PamAuthResponse::SetupPin { .. }));

            let fail_replacement =
                "CREATE TRIGGER fail_password_cache BEFORE UPDATE OF password ON account_t
                 WHEN NEW.password IS NOT NULL
                 BEGIN SELECT RAISE(ABORT, 'injected password cache failure'); END;";
            if newer_cache_fails {
                conn.execute_batch(fail_replacement).unwrap();
            }
            let mut newer_token = test_token();
            newer_token.displayname = "Newer profile".to_string();
            newer_token.groups.clear();
            *resolver.client.auth_token.write().unwrap() = newer_token.clone();
            resolver.client.user_get_error.store(3, Ordering::Release);
            let response = resolver
                .pam_account_authenticate_step(
                    &mut newer,
                    PamAuthRequest::Password {
                        cred: "new-secret".to_string(),
                    },
                )
                .await
                .unwrap();
            assert!(matches!(response, PamAuthResponse::Success));
            if newer_cache_fails {
                // A durable invalidation must also supersede older sessions
                // when its optional replacement failed.
                conn.execute_batch("DROP TRIGGER fail_password_cache")
                    .unwrap();
            } else if older_cache_fails {
                conn.execute_batch(fail_replacement).unwrap();
            }

            *resolver.client.auth_token.write().unwrap() = test_token();
            resolver.client.user_get_error.store(4, Ordering::Release);
            let response = resolver
                .pam_account_authenticate_step(
                    &mut older,
                    PamAuthRequest::SetupPin {
                        pin: "123456".to_string(),
                    },
                )
                .await
                .unwrap();
            assert!(matches!(response, PamAuthResponse::Success));
            let cached = resolver.get_cached_usertokens().await.unwrap();
            assert_eq!(cached.len(), 1);
            assert_eq!(cached[0].displayname, newer_token.displayname);
            assert!(cached[0].groups.is_empty());
            assert!(!resolver
                .check_cache_userpassword(test_token().uuid, "old-secret")
                .await
                .unwrap());
            assert_eq!(
                resolver
                    .check_cache_userpassword(test_token().uuid, "new-secret")
                    .await
                    .unwrap(),
                !newer_cache_fails
            );
        }
    }

    async fn stage_test_pin(
        resolver: &Resolver<OfflineFallbackProvider>,
        cache_password: bool,
    ) -> AuthSession {
        stage_test_local_auth(resolver, cache_password, false).await
    }

    async fn stage_test_local_auth(
        resolver: &Resolver<OfflineFallbackProvider>,
        cache_password: bool,
        direct_totp: bool,
    ) -> AuthSession {
        resolver
            .client
            .user_get_error
            .store(if cache_password { 4 } else { 7 }, Ordering::Release);
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (mut session, _) = resolver
            .pam_account_authenticate_init(
                "testuser@example.com",
                "sshd",
                false,
                false,
                shutdown_rx,
            )
            .await
            .unwrap();
        let response = resolver
            .pam_account_authenticate_step(
                &mut session,
                PamAuthRequest::Password {
                    cred: if direct_totp {
                        "direct-totp".to_string()
                    } else {
                        "staged-secret".to_string()
                    },
                },
            )
            .await
            .unwrap();
        if direct_totp {
            assert!(matches!(response, PamAuthResponse::HelloTOTP { .. }));
        } else {
            assert!(matches!(response, PamAuthResponse::SetupPin { .. }));
        }
        session
    }

    async fn complete_test_auth(
        resolver: &Resolver<OfflineFallbackProvider>,
        cache_password: bool,
    ) {
        resolver
            .client
            .user_get_error
            .store(if cache_password { 3 } else { 5 }, Ordering::Release);
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (mut session, _) = resolver
            .pam_account_authenticate_init(
                "testuser@example.com",
                "sshd",
                false,
                false,
                shutdown_rx,
            )
            .await
            .unwrap();
        let response = resolver
            .pam_account_authenticate_step(
                &mut session,
                PamAuthRequest::Password {
                    cred: "new-secret".to_string(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(response, PamAuthResponse::Success));
        assert!(matches!(session, AuthSession::Success(_)));
    }

    #[tokio::test]
    async fn stale_pin_cannot_restore_identity_replaced_through_any_cache_alias() {
        for collision in ["all", "spn", "tenant"] {
            for replacement in ["password", "failed-password", "passwordless", "refresh"] {
                let (resolver, conn) = setup_sql_resolver().await;
                resolver
                    .set_cache_userpassword(test_token().uuid, "old-secret")
                    .await
                    .unwrap();
                let mut older = stage_test_pin(&resolver, true).await;
                let mut newer_token = test_token();
                newer_token.uuid = uuid::Uuid::new_v4();
                newer_token.name = "replacement".to_string();
                newer_token.spn = "replacement@example.com".to_string();
                newer_token.gidnumber += 1;
                newer_token.displayname = "Replacement identity".to_string();
                newer_token.groups.clear();
                match collision {
                    "all" => {
                        newer_token.name = test_token().name;
                        newer_token.spn = test_token().spn;
                        newer_token.gidnumber = test_token().gidnumber;
                    }
                    "spn" => newer_token.spn = test_token().spn,
                    "tenant" => {
                        newer_token.uuid = test_token().uuid;
                        newer_token.tenant_id = Some(uuid::Uuid::new_v4());
                    }
                    _ => unreachable!(),
                }
                *resolver.client.auth_token.write().unwrap() = newer_token.clone();
                if replacement == "failed-password" {
                    conn.execute_batch(
                        "CREATE TRIGGER fail_password_cache BEFORE UPDATE OF password ON account_t
                         WHEN NEW.password IS NOT NULL
                         BEGIN SELECT RAISE(ABORT, 'injected password cache failure'); END;",
                    )
                    .unwrap();
                }
                if replacement == "refresh" {
                    resolver.client.user_get_error.store(6, Ordering::Release);
                    let refreshed = resolver
                        .refresh_usertoken(&Id::Name(test_token().spn), Some(test_token()))
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(refreshed.uuid, newer_token.uuid);
                } else {
                    complete_test_auth(&resolver, replacement != "passwordless").await;
                }
                if replacement == "failed-password" {
                    conn.execute_batch("DROP TRIGGER fail_password_cache")
                        .unwrap();
                }

                *resolver.client.auth_token.write().unwrap() = test_token();
                resolver.client.user_get_error.store(4, Ordering::Release);
                let response = resolver
                    .pam_account_authenticate_step(
                        &mut older,
                        PamAuthRequest::SetupPin {
                            pin: "123456".to_string(),
                        },
                    )
                    .await
                    .unwrap();
                assert!(matches!(response, PamAuthResponse::Denied(_)));
                assert!(matches!(older, AuthSession::Denied));
                let cached = resolver.get_cached_usertokens().await.unwrap();
                assert_eq!(cached.len(), 1);
                assert_eq!(cached[0].uuid, newer_token.uuid);
                assert_eq!(cached[0].tenant_id, newer_token.tenant_id);
                assert_eq!(cached[0].displayname, newer_token.displayname);
                assert!(cached[0].groups.is_empty());
                for password in ["old-secret", "staged-secret"] {
                    assert!(!resolver
                        .check_cache_userpassword(newer_token.uuid, password)
                        .await
                        .unwrap());
                }
                assert_eq!(
                    resolver
                        .check_cache_userpassword(newer_token.uuid, "new-secret")
                        .await
                        .unwrap(),
                    replacement == "password"
                );
            }
        }
    }

    #[tokio::test]
    async fn passwordless_pin_setup_keeps_its_original_identity_generation() {
        let resolver = setup_resolver().await;
        let mut older = stage_test_pin(&resolver, false).await;
        let mut replacement = test_token();
        replacement.uuid = uuid::Uuid::new_v4();
        *resolver.client.auth_token.write().unwrap() = replacement.clone();
        complete_test_auth(&resolver, false).await;
        *resolver.client.auth_token.write().unwrap() = test_token();
        resolver.client.user_get_error.store(7, Ordering::Release);
        let retry = resolver
            .pam_account_authenticate_step(
                &mut older,
                PamAuthRequest::SetupPin {
                    pin: "retry".to_string(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(retry, PamAuthResponse::SetupPin { .. }));
        let response = resolver
            .pam_account_authenticate_step(
                &mut older,
                PamAuthRequest::SetupPin {
                    pin: "123456".to_string(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(response, PamAuthResponse::Denied(_)));
        assert!(matches!(older, AuthSession::Denied));
        let cached = resolver.get_cached_usertokens().await.unwrap();
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].uuid, replacement.uuid);
    }

    #[tokio::test]
    async fn local_totp_completion_cannot_refresh_a_stale_identity_generation() {
        for direct_totp in [false, true] {
            for final_password_update in [false, true] {
                let resolver = setup_resolver().await;
                let mut older = stage_test_local_auth(&resolver, false, direct_totp).await;
                if !direct_totp {
                    let response = resolver
                        .pam_account_authenticate_step(
                            &mut older,
                            PamAuthRequest::SetupPin {
                                pin: "totp".to_string(),
                            },
                        )
                        .await
                        .unwrap();
                    assert!(matches!(response, PamAuthResponse::HelloTOTP { .. }));
                }
                let mut replacement = test_token();
                replacement.uuid = uuid::Uuid::new_v4();
                *resolver.client.auth_token.write().unwrap() = replacement.clone();
                complete_test_auth(&resolver, true).await;
                *resolver.client.auth_token.write().unwrap() = test_token();
                resolver.client.user_get_error.store(7, Ordering::Release);
                let response = resolver
                    .pam_account_authenticate_step(
                        &mut older,
                        PamAuthRequest::HelloTOTP {
                            cred: if final_password_update {
                                "cache-password".to_string()
                            } else {
                                "123456".to_string()
                            },
                        },
                    )
                    .await
                    .unwrap();
                assert!(matches!(response, PamAuthResponse::Denied(_)));
                assert!(matches!(older, AuthSession::Denied));
                let cached = resolver.get_cached_usertokens().await.unwrap();
                assert_eq!(cached.len(), 1);
                assert_eq!(cached[0].uuid, replacement.uuid);
                assert!(resolver
                    .check_cache_userpassword(replacement.uuid, "new-secret")
                    .await
                    .unwrap());
                assert!(!resolver
                    .check_cache_userpassword(replacement.uuid, "late-secret")
                    .await
                    .unwrap());
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
            ("onprem-user", true),
            ("first.last@example.com", true),
            ("onprem-user@example.com", true),
            ("ONPREM-USER@Example.com", true),
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

    async fn auth_init_account(resolver: &Resolver<OfflineFallbackProvider>, name: &str) -> String {
        let (_tx, rx) = broadcast::channel(1);
        match resolver
            .pam_account_authenticate_init(name, "gdm-password", false, false, rx)
            .await
            .expect("auth init failed")
            .0
        {
            AuthSession::InProgress { account_id, .. } => account_id,
            _ => panic!("expected an in progress auth session"),
        }
    }

    async fn prove_absent(resolver: &Resolver<OfflineFallbackProvider>, name: &str) {
        let expiry = SystemTime::now() + Duration::from_secs(60);
        resolver
            .alias_absence
            .lock()
            .await
            .put(name.to_string(), expiry);
    }

    async fn rendered_name(
        resolver: &Resolver<OfflineFallbackProvider>,
        token: &UserToken,
    ) -> String {
        let user = resolver.nss_user_from_token(token.clone(), true);
        resolver.render_alias(user, true).await.name
    }

    async fn cache_token(resolver: &Resolver<OfflineFallbackProvider>, token: &mut UserToken) {
        resolver.set_cache_usertoken(token, false).await.unwrap();
    }

    async fn cached_token(
        resolver: &Resolver<OfflineFallbackProvider>,
        name: &str,
    ) -> Option<UserToken> {
        let id = Id::Name(name.to_string());
        resolver.get_cached_usertoken(&id).await.unwrap().1
    }

    async fn user_token(resolver: &Resolver<OfflineFallbackProvider>, id: Id) -> UserToken {
        resolver.get_usertoken(id).await.unwrap().unwrap()
    }

    async fn spn_is_cached(resolver: &Resolver<OfflineFallbackProvider>, spn: &str) -> bool {
        resolver
            .get_cached_usertokens()
            .await
            .unwrap()
            .iter()
            .any(|t| t.spn.eq_ignore_ascii_case(spn))
    }

    #[tokio::test]
    async fn provider_placeholder_for_an_expanded_name_does_not_replace_the_alias_owner() {
        let (resolver, alice, bob) = collision_resolver(false, future_expiry()).await;
        let mut provisional = bob.clone();
        provisional.uuid = uuid::uuid!("dddddddd-0000-4000-8000-000000000002");
        provisional.name.clone_from(&provisional.spn);
        resolver.client.set_lookup_only();
        *resolver.client.exact_token.write().unwrap() = Some(provisional);
        *resolver.client.upn_verdict.write().unwrap() = UpnVerdict::Absent;
        let (_, resolved) = resolver
            .resolve_cached_usertoken(&Id::Name(bob.spn.clone()))
            .await
            .unwrap();
        assert_eq!(resolved.unwrap().uuid, alice.uuid);
        assert!(!spn_is_cached(&resolver, &bob.spn).await);
    }

    #[tokio::test]
    async fn nss_account_with_groups_resolves_every_spelling_to_one_identity() {
        let resolver = setup_resolver().await;
        seed_aliased_token(&resolver).await;
        resolver.client.set_not_found();
        let token = aliased_token();
        let expected: Vec<uuid::Uuid> = token.groups.iter().map(|group| group.uuid).collect();
        assert!(!expected.is_empty());

        let mut names = Vec::new();
        for typed in [token.spn.as_str(), "onprem-user", "onprem-user@example.com"] {
            let (account, groups) = resolver
                .get_nssaccount_with_groups(typed)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("{typed} did not resolve"));
            assert_eq!(account.uid, token.gidnumber, "{typed}");
            assert_eq!(groups, expected, "{typed}");
            names.push(account.name);
        }
        assert!(names.windows(2).all(|pair| pair[0] == pair[1]), "{names:?}");
    }

    #[tokio::test]
    async fn provisional_probe_with_an_absent_upn_routes_every_caller_to_the_alias_owner() {
        let (resolver, alice, bob) = collision_resolver(false, future_expiry()).await;
        resolver.client.set_lookup_only();
        *resolver.client.exact_token.write().unwrap() = Some(bob.clone());
        *resolver.client.upn_verdict.write().unwrap() = UpnVerdict::Absent;
        let key = bob.spn.to_ascii_lowercase();

        let token = user_token(&resolver, Id::Name(bob.spn.clone())).await;
        assert_eq!(token.uuid, alice.uuid);
        assert!(!spn_is_cached(&resolver, &bob.spn).await);
        assert!(resolver.alias_absence.lock().await.get(&key).is_some());
        let verifications = resolver.client.verify_calls.load(Ordering::Acquire);
        assert_eq!(verifications, 1);

        assert_eq!(auth_init_account(&resolver, &bob.spn).await, alice.spn);
        assert_eq!(
            resolver.client.verify_calls.load(Ordering::Acquire),
            verifications
        );
    }

    #[tokio::test]
    async fn provisional_probe_with_a_confirmed_upn_releases_the_alias() {
        let (resolver, alice, bob) = collision_resolver(false, future_expiry()).await;
        let mut provisional = bob.clone();
        provisional.uuid = uuid::uuid!("dddddddd-0000-4000-8000-000000000003");
        provisional.name.clone_from(&provisional.spn);
        resolver.client.set_lookup_only();
        *resolver.client.exact_token.write().unwrap() = Some(provisional.clone());
        *resolver.client.upn_verdict.write().unwrap() = UpnVerdict::Exists;

        let (token, cacheable) = resolver
            .get_usertoken_with_cacheability(Id::Name(bob.spn.clone()), OnExpiry::Refresh)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(token.uuid, provisional.uuid);
        assert!(!cacheable);
        assert!(resolver.alias_absence.lock().await.is_empty());
        assert!(!spn_is_cached(&resolver, &bob.spn).await);
        let alice_now = resolver
            .get_cached_usertokens()
            .await
            .unwrap()
            .into_iter()
            .find(|t| t.uuid == alice.uuid)
            .unwrap();
        assert_eq!(alice_now.name, alice.spn);

        assert_eq!(auth_init_account(&resolver, &bob.spn).await, bob.spn);
    }

    #[tokio::test]
    async fn try_unseal_never_reaches_the_provider_for_a_local_collision() {
        for (name, uid) in [("onprem-user", 99999), ("unrelated", 2001)] {
            let resolver = setup_resolver().await;
            seed_aliased_token(&resolver).await;
            resolver
                .reload_nxset(vec![(name.to_string(), uid)].into_iter())
                .await;
            assert!(!resolver
                .pam_try_unseal("onprem-user", "123456")
                .await
                .unwrap());
            assert_eq!(resolver.client.try_unseal_calls.load(Ordering::Acquire), 0);
        }
    }

    #[tokio::test]
    async fn unproved_alias_is_rendered_canonically_while_offline() {
        let resolver = setup_resolver().await.with_cn_name_mapping(true);
        seed_aliased_token(&resolver).await;
        let token = aliased_token();
        let render = || rendered_name(&resolver, &token);

        resolver.client.set_cache_state(CacheState::Offline);
        assert_eq!(render().await, token.spn);

        prove_absent(&resolver, "onprem-user@example.com").await;
        assert_eq!(render().await, "onprem-user");

        let plain = setup_resolver().await;
        plain.client.set_cache_state(CacheState::Offline);
        assert_eq!(rendered_name(&plain, &token).await, "onprem-user");

        let scripted = setup_resolver().await.with_name_mapping_script(true);
        scripted.client.set_cache_state(CacheState::Offline);
        assert_eq!(rendered_name(&scripted, &token).await, token.spn);
    }

    #[tokio::test]
    async fn unproved_alias_never_selects_the_home_directory() {
        let (resolver, alice, _bob) = collision_resolver(false, future_expiry()).await;
        let resolver = resolver.with_cn_name_mapping(true);
        resolver.client.set_cache_state(CacheState::Offline);
        let lookup = || resolver.get_nssaccount_name_lookup(&alice.spn);
        let begin = || resolver.pam_account_beginsession(&alice.spn);
        let home = |lookup: NssAccountLookup| match lookup {
            NssAccountLookup::Found(user) => user.homedir,
            _ => panic!("expected a found account"),
        };

        assert_eq!(
            home(lookup().await.unwrap()),
            format!("/home/{}", alice.spn)
        );
        assert_eq!(begin().await.unwrap().unwrap().name, alice.spn);

        prove_absent(&resolver, "bob@example.com").await;
        assert_eq!(home(lookup().await.unwrap()), "/home/bob");
        assert_eq!(begin().await.unwrap().unwrap().name, "bob");
    }

    #[tokio::test]
    async fn overdue_offline_check_renders_the_alias_only_after_a_successful_probe() {
        let resolver = setup_resolver().await.with_cn_name_mapping(true);
        seed_aliased_token(&resolver).await;
        resolver.client.set_not_found();
        let token = aliased_token();
        let render = || rendered_name(&resolver, &token);
        let probes = || resolver.client.check_online_calls.load(Ordering::Acquire);

        resolver
            .client
            .set_cache_state(CacheState::OfflineNextCheck(
                SystemTime::now() + Duration::from_secs(60),
            ));
        let before = probes();
        assert_eq!(render().await, token.spn);
        assert_eq!(probes(), before);

        resolver
            .client
            .set_cache_state(CacheState::OfflineNextCheck(SystemTime::UNIX_EPOCH));
        resolver
            .client
            .check_online_result
            .store(false, Ordering::Release);
        assert_eq!(render().await, token.spn);
        assert_eq!(probes(), before + 1);

        resolver
            .client
            .check_online_result
            .store(true, Ordering::Release);
        assert_eq!(render().await, "onprem-user");
    }

    #[tokio::test]
    async fn qualified_alias_is_rendered_canonically_while_offline_without_proof() {
        for cn_name_mapping in [false, true] {
            let resolver = setup_resolver().await.with_cn_name_mapping(cn_name_mapping);
            let mut token = aliased_token();
            token.name = "ops@secondary.com".into();
            token.spn = "alice@secondary.com".into();
            {
                let mut txn = resolver.db.write().await;
                txn.update_account(&token, 0).unwrap();
                txn.commit().unwrap();
            }
            let render = || rendered_name(&resolver, &token);

            resolver.client.set_cache_state(CacheState::Offline);
            assert_eq!(render().await, token.spn);

            prove_absent(&resolver, "ops@secondary.com").await;
            assert_eq!(render().await, token.name);
        }
    }

    #[tokio::test]
    async fn online_alias_is_published_only_once_its_qualified_name_is_verified() {
        for qualified in [false, true] {
            let (resolver, alice, bob) = collision_resolver(qualified, future_expiry()).await;
            let resolver = resolver.with_cn_name_mapping(true);
            *resolver.client.exact_token.write().unwrap() = Some(bob.clone());
            assert_eq!(rendered_name(&resolver, &alice).await, alice.spn);
            let owner = cached_token(&resolver, &bob.spn).await;
            assert_eq!(owner.unwrap().uuid, bob.uuid);

            let (resolver, alice, _) = collision_resolver(qualified, future_expiry()).await;
            let resolver = resolver.with_cn_name_mapping(true);
            assert_eq!(rendered_name(&resolver, &alice).await, alice.spn);
            resolver.client.set_not_found();
            assert_eq!(rendered_name(&resolver, &alice).await, alice.name);
        }
    }

    #[tokio::test]
    async fn refused_identity_is_reported_as_excluded_not_missing() {
        let resolver = setup_resolver().await;
        let mut token = aliased_token();
        cache_token(&resolver, &mut token).await;
        assert!(matches!(
            resolver
                .get_nssaccount_name_lookup(&token.spn)
                .await
                .unwrap(),
            NssAccountLookup::Found(_)
        ));
        resolver
            .reload_nxset(vec![("unrelated".to_string(), 2001)].into_iter())
            .await;
        match resolver
            .get_nssaccount_name_lookup(&token.spn)
            .await
            .unwrap()
        {
            NssAccountLookup::Excluded(user) => {
                assert!(!user.cacheable);
                assert_eq!(user.uid, token.gidnumber);
            }
            _ => panic!("expected the identity to be excluded"),
        }
        assert!(matches!(
            resolver
                .get_nssaccount_name_lookup("nobody@example.com")
                .await
                .unwrap(),
            NssAccountLookup::Missing
        ));
    }

    #[tokio::test]
    async fn cached_user_under_a_locally_reserved_key_is_reported_as_excluded() {
        let resolver = setup_resolver().await;
        let mut token = aliased_token();
        cache_token(&resolver, &mut token).await;
        resolver
            .reload_nxset(vec![(token.name.clone(), token.gidnumber)].into_iter())
            .await;
        for lookup in [
            resolver.get_nssaccount_name_lookup(&token.name).await,
            resolver.get_nssaccount_gid_lookup(token.gidnumber).await,
        ] {
            match lookup.unwrap() {
                NssAccountLookup::Excluded(user) => {
                    assert!(!user.cacheable);
                    assert_eq!(user.uid, token.gidnumber);
                }
                _ => panic!("expected the cached identity to be excluded"),
            }
        }
        resolver
            .reload_nxset(vec![("unrelated".to_string(), 2002)].into_iter())
            .await;
        assert!(matches!(
            resolver
                .get_nssaccount_name_lookup("unrelated")
                .await
                .unwrap(),
            NssAccountLookup::Missing
        ));
    }

    #[tokio::test]
    async fn group_member_alias_resolves_again_while_offline_without_proof() {
        let resolver = setup_resolver().await.with_cn_name_mapping(true);
        let mut member = test_token();
        member.name = "AADBOB".into();
        member.spn = "bob@example.com".into();
        cache_token(&resolver, &mut member).await;
        let group = member.groups[0].uuid;

        resolver.client.set_cache_state(CacheState::Offline);
        assert_eq!(
            resolver.get_groupmembers(group).await,
            vec!["bob@example.com".to_string()]
        );

        prove_absent(&resolver, "aadbob@example.com").await;
        assert_eq!(
            resolver.get_groupmembers(group).await,
            vec!["AADBOB".to_string()]
        );
    }

    #[tokio::test]
    async fn enumeration_publishes_only_proved_aliases_without_provider_lookups() {
        let resolver = setup_resolver().await.with_cn_name_mapping(true);
        let mut member = test_token();
        member.name = "AADBOB".into();
        member.spn = "bob@example.com".into();
        cache_token(&resolver, &mut member).await;
        let group = member.groups[0].uuid;
        let user = resolver.nss_user_from_token(member.clone(), true);
        let lookups = || resolver.client.user_get_calls.load(Ordering::Acquire);
        let before = lookups();

        assert_eq!(
            resolver.get_groupmembers(group).await,
            vec![member.spn.clone()]
        );
        let enumerated = resolver.render_alias(user.clone(), false);
        assert_eq!(enumerated.await.name, member.spn);
        assert_eq!(lookups(), before);

        prove_absent(&resolver, "aadbob@example.com").await;
        assert_eq!(
            resolver.get_groupmembers(group).await,
            vec!["AADBOB".to_string()]
        );
        let enumerated = resolver.render_alias(user, false);
        assert_eq!(enumerated.await.name, "AADBOB");
        assert_eq!(lookups(), before);
    }

    #[tokio::test]
    async fn provisional_probe_without_evidence_leaves_the_name_unresolved() {
        let (resolver, _alice, bob) = collision_resolver(false, future_expiry()).await;
        resolver.client.set_lookup_only();
        *resolver.client.exact_token.write().unwrap() = Some(bob.clone());
        assert!(resolver
            .get_usertoken(Id::Name(bob.spn.clone()))
            .await
            .is_err());
        assert!(resolver.alias_absence.lock().await.is_empty());
        assert!(!spn_is_cached(&resolver, &bob.spn).await);
    }

    #[tokio::test]
    async fn session_identity_describes_one_identity_whatever_the_cache_does_later() {
        let resolver = setup_resolver().await;
        seed_aliased_token(&resolver).await;
        resolver.client.set_not_found();
        let token = aliased_token();
        let groups: Vec<uuid::Uuid> = token.groups.iter().map(|group| group.uuid).collect();

        let identity = resolver
            .pam_account_beginsession_identity("onprem-user@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(identity.home.uid, identity.account.uid);
        assert_eq!(identity.home.uid, token.gidnumber);
        assert_eq!(identity.group_ids, groups);
        assert_eq!(identity.owner.object_id, token.uuid);
        assert_eq!(identity.owner.tenant_id, token.tenant_id);
        assert_eq!(identity.owner.upn, token.spn);
        let snapshot = (
            identity.account.name.clone(),
            identity.account.uid,
            identity.group_ids.clone(),
        );

        let other_group = uuid::uuid!("c0ffee00-0000-4000-8000-0000000000b1");
        let mut refreshed = aliased_token();
        refreshed.groups = vec![GroupToken {
            name: "other".to_string(),
            spn: "other@example.com".to_string(),
            uuid: other_group,
            gidnumber: 2999,
        }];
        cache_token(&resolver, &mut refreshed).await;

        assert_eq!(
            snapshot,
            (
                identity.account.name.clone(),
                identity.account.uid,
                identity.group_ids.clone()
            )
        );
        let later = resolver
            .pam_account_beginsession_identity(&token.spn)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(later.group_ids, vec![other_group]);
        assert_ne!(later.group_ids, snapshot.2);
        assert_eq!(later.account.uid, snapshot.1);

        let home = resolver
            .pam_account_beginsession(&token.spn)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(home.uid, later.home.uid);
        assert_eq!(home.name, later.home.name);
    }

    #[tokio::test]
    async fn auth_init_uses_the_upn_of_a_local_name() {
        let resolver = setup_resolver().await;
        seed_aliased_token(&resolver).await;
        resolver.client.set_not_found();
        assert_eq!(
            auth_init_account(&resolver, "onprem-user@example.com").await,
            "first.last@example.com"
        );
    }

    #[tokio::test]
    async fn allow_list_matches_the_resolved_user_only() {
        for (allowed, admitted) in [
            ("onprem-user@example.com", false),
            ("first.last@example.com", true),
        ] {
            let mut resolver = setup_resolver().await;
            resolver.pam_allow_groups = [allowed.to_string()].into();
            seed_aliased_token(&resolver).await;
            resolver.client.set_not_found();

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
        let cached = cached_token(&resolver, &bob.spn).await;
        assert_eq!(cached.unwrap().uuid, bob.uuid);
        assert_eq!(auth_init_account(&resolver, &bob.spn).await, bob.spn);
    }

    #[tokio::test]
    async fn conflicting_sam_falls_back_without_evicting_cached_credentials() {
        for name in ["onprem-user", "ONPREM-USER"] {
            let resolver = setup_resolver().await;
            let mut first = aliased_token();
            cache_token(&resolver, &mut first).await;
            resolver
                .set_cache_userpassword(first.uuid, "keep-me")
                .await
                .unwrap();
            let mut second = test_token();
            second.name = name.into();
            second.spn = "second@other.com".into();
            cache_token(&resolver, &mut second).await;
            assert_eq!(second.name, second.spn);
            assert!(resolver
                .check_cache_userpassword(first.uuid, "keep-me")
                .await
                .unwrap());
            let cached = cached_token(&resolver, &first.spn).await;
            assert_eq!(cached.unwrap().uuid, first.uuid);
        }
    }

    #[tokio::test]
    async fn same_spn_uuid_replacement_keeps_the_sam_name() {
        let resolver = setup_resolver().await;
        let mut token = aliased_token();
        cache_token(&resolver, &mut token).await;
        let previous_uuid = token.uuid;
        resolver
            .set_cache_userpassword(previous_uuid, "old-account-password")
            .await
            .unwrap();
        token.uuid = uuid::Uuid::new_v4();
        cache_token(&resolver, &mut token).await;
        assert_eq!(token.name, "onprem-user");
        let cached = cached_token(&resolver, &token.spn).await;
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
        cache_token(&resolver, &mut alice).await;
        resolver
            .set_cache_userpassword(alice.uuid, "alice-password")
            .await
            .unwrap();
        let mut bob = test_token();
        bob.name = "robert".into();
        bob.spn = "bob@example.com".into();
        resolver.set_cache_usertoken(&mut bob, false).await.unwrap();
        let cached = cached_token(&resolver, &alice.spn).await;
        assert_eq!(cached.unwrap().name, alice.spn);
        assert!(resolver
            .check_cache_userpassword(alice.uuid, "alice-password")
            .await
            .unwrap());
        let cached = cached_token(&resolver, &bob.spn).await;
        assert_eq!(cached.unwrap().uuid, bob.uuid);
    }

    #[tokio::test]
    async fn local_collisions_are_filtered_from_enumeration_refresh_and_members() {
        for (name, uid) in [("ONPREM-USER", 99999), ("unrelated", 2001)] {
            let resolver = setup_resolver().await;
            let mut token = aliased_token();
            cache_token(&resolver, &mut token).await;
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
    async fn group_members_use_the_user_map_local_account() {
        let map = crate::db::TestDbFile::new();
        std::fs::write(&map.0, "alice:Alice@Example.com\ncarol:carol@example.com\n").unwrap();
        let resolver = setup_resolver().await.with_user_map_file(map.0.clone());
        let mut mapped = test_token();
        mapped.name = "AADALICE".into();
        mapped.spn = "alice@example.com".into();
        cache_token(&resolver, &mut mapped).await;
        let mut unmapped = test_token();
        unmapped.uuid = uuid::uuid!("1302b99c-f0f6-41ab-9492-852692b0fd16");
        unmapped.name = "AADBOB".into();
        unmapped.spn = "bob@example.com".into();
        unmapped.gidnumber = 2001;
        unmapped.real_gidnumber = Some(2001);
        cache_token(&resolver, &mut unmapped).await;

        let mut upn_named = test_token();
        upn_named.uuid = uuid::uuid!("2302b99c-f0f6-41ab-9492-852692b0fd16");
        upn_named.name = "carol@example.com".into();
        upn_named.spn = "carol@example.com".into();
        upn_named.gidnumber = 2002;
        upn_named.real_gidnumber = Some(2002);
        cache_token(&resolver, &mut upn_named).await;

        let mut members = resolver.get_groupmembers(mapped.groups[0].uuid).await;
        members.sort();
        assert_eq!(
            members,
            vec![
                "AADBOB".to_string(),
                "alice".to_string(),
                "carol".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn group_members_never_take_a_name_mapped_to_another_upn() {
        let file = crate::db::TestDbFile::new();
        std::fs::write(&file.0, "alice:alice@example.com\n").unwrap();
        let resolver = setup_resolver().await.with_user_map_file(file.0.clone());
        let mut intruder = test_token();
        intruder.uuid = uuid::uuid!("1302b99c-f0f6-41ab-9492-852692b0fd16");
        intruder.name = "alice".into();
        intruder.spn = "mallory@example.com".into();
        intruder.gidnumber = 2001;
        intruder.real_gidnumber = Some(2001);
        cache_token(&resolver, &mut intruder).await;

        let members = resolver.get_groupmembers(intruder.groups[0].uuid).await;
        assert!(members.contains(&intruder.spn));
        assert!(!members.contains(&"alice".to_string()));
    }

    #[tokio::test]
    async fn cached_alias_never_takes_a_name_mapped_to_another_upn() {
        let file = crate::db::TestDbFile::new();
        std::fs::write(&file.0, "alice:alice@example.com\n").unwrap();
        let mut token = test_token();
        token.name = "alice".into();
        token.spn = "mallory@example.com".into();

        let plain = setup_resolver().await;
        let kept = plain.canonical_alias_token(token.clone(), false).await;
        let mapped = setup_resolver().await.with_user_map_file(file.0.clone());
        let canonical = mapped.canonical_alias_token(token.clone(), false).await;
        assert_eq!(kept.name, "alice");
        assert_eq!(canonical.name, token.spn);
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
            cache_token(&resolver, &mut token).await;
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
                .get_initgroups("testuser", OnExpiry::Refresh)
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
        cache_token(&resolver, &mut token).await;
        let nss = resolver
            .get_nssaccount_gid(token.gidnumber, OnExpiry::Refresh)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(nss.name, "onprem-user@secondary.com");
        let file = crate::db::TestDbFile::new();
        let conf = "[global]\ndomains = primary.com\ncn_name_mapping = true\n";
        std::fs::write(&file.0, conf).unwrap();
        let cfg = crate::config::HimmelblauConfig::new(Some(&file.0)).unwrap();
        let displayed = cfg.map_upn_to_name(&nss.name);
        let lookup = cfg.map_name_to_upn(&displayed).unwrap();
        let roundtrip = cached_token(&resolver, &lookup).await;
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
                for authenticate in [false, true] {
                    let (resolver, alice, bob) = collision_resolver(qualified, expiry).await;
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
                            .get_nssaccount_name(&requested, OnExpiry::Refresh)
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
                    let cached = cached_token(&resolver, &alice.spn).await;
                    assert_eq!(cached.unwrap().name, alice.spn);
                }
            }
        }
    }

    #[tokio::test]
    async fn provisional_exact_probe_never_authorizes_alias_fallback() {
        let (resolver, _alice, bob) = collision_resolver(false, future_expiry()).await;
        resolver.client.set_lookup_only();
        *resolver.client.exact_token.write().unwrap() = Some(bob.clone());
        assert!(resolver
            .get_usertoken(Id::Name(bob.spn.clone()))
            .await
            .is_err());
        assert!(resolver.alias_absence.lock().await.get(&bob.spn).is_none());
        let (_tx, rx) = broadcast::channel(1);
        assert!(resolver
            .pam_account_authenticate_init(&bob.spn, "gdm-password", false, false, rx,)
            .await
            .is_err());
        assert!(resolver.client.credential_ids.read().unwrap().is_empty());
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
        resolver.client.set_not_found();
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
            assert!(resolver
                .get_nssaccount_name(&bob.spn, OnExpiry::Refresh)
                .await
                .is_err());
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
        resolver.client.set_not_found();
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
        assert_eq!(auth_init_account(&resolver, &bob.spn).await, bob.spn);
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
            resolver
                .client
                .user_get_stall
                .store(true, Ordering::Release);
            resolver
                .client
                .exact_not_found
                .store(result == 1, Ordering::Release);
            if result == 0 {
                let mut provisional = bob.clone();
                provisional.uuid = uuid::uuid!("dddddddd-0000-4000-8000-000000000001");
                resolver.client.set_lookup_only();
                *resolver.client.exact_token.write().unwrap() = Some(provisional);
            }
            let requested_id = Id::Name(requested.clone());
            let lookup = resolver.resolve_cached_usertoken(&requested_id);
            let concurrent_insert = async {
                while resolver.client.user_get_calls.load(Ordering::Acquire) == 0 {
                    tokio::task::yield_now().await;
                }
                let release = async {
                    tokio::task::yield_now().await;
                    resolver.client.user_get_release.notify_one();
                };
                let (inserted, ()) =
                    tokio::join!(resolver.set_cache_usertoken(&mut bob, false), release);
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
        resolver.client.set_not_found();
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
    async fn same_identity_refresh_preserves_claims_without_suppressing_password_invalidation() {
        for refresh in [false, true] {
            let resolver = setup_resolver().await;
            resolver
                .set_cache_userpassword(test_token().uuid, "old-secret")
                .await
                .unwrap();
            let mut session = stage_test_pin(&resolver, true).await;
            let mut refreshed = test_token();
            refreshed.displayname = "Refreshed claims".to_string();
            refreshed.groups.clear();
            *resolver.client.auth_token.write().unwrap() = refreshed.clone();
            if refresh {
                resolver.client.user_get_error.store(6, Ordering::Release);
                resolver
                    .refresh_usertoken(&Id::Name(test_token().spn), Some(test_token()))
                    .await
                    .unwrap();
            } else {
                complete_test_auth(&resolver, false).await;
            }
            assert!(resolver
                .check_cache_userpassword(test_token().uuid, "old-secret")
                .await
                .unwrap());
            *resolver.client.auth_token.write().unwrap() = test_token();
            resolver.client.user_get_error.store(4, Ordering::Release);
            let response = resolver
                .pam_account_authenticate_step(
                    &mut session,
                    PamAuthRequest::SetupPin {
                        pin: "123456".to_string(),
                    },
                )
                .await
                .unwrap();
            assert!(matches!(response, PamAuthResponse::Success));
            let cached = resolver.get_cached_usertokens().await.unwrap();
            assert_eq!(cached[0].displayname, refreshed.displayname);
            assert!(cached[0].groups.is_empty());
            assert!(!resolver
                .check_cache_userpassword(test_token().uuid, "old-secret")
                .await
                .unwrap());
            assert!(resolver
                .check_cache_userpassword(test_token().uuid, "staged-secret")
                .await
                .unwrap());
        }
    }

    #[tokio::test]
    async fn stale_passwordless_cache_writer_cannot_replace_newer_identity() {
        let resolver = setup_resolver().await;
        let mut newer = test_token();
        newer.uuid = uuid::Uuid::new_v4();
        assert_eq!(
            resolver
                .set_cache_usertoken_guarded(&mut newer, 2, None)
                .await
                .unwrap(),
            CacheUpdateResult::Updated
        );
        assert_eq!(
            resolver
                .set_cache_usertoken_guarded(&mut test_token(), 1, None)
                .await
                .unwrap(),
            CacheUpdateResult::IdentityChanged
        );
        assert_eq!(
            resolver.get_cached_usertokens().await.unwrap()[0].uuid,
            newer.uuid
        );
    }

    #[tokio::test]
    async fn cache_generation_guard_does_not_block_unrelated_identities() {
        let resolver = setup_resolver().await;
        let mut unrelated = test_token();
        unrelated.uuid = uuid::Uuid::new_v4();
        unrelated.name = "unrelated".to_string();
        unrelated.spn = "unrelated@example.com".to_string();
        unrelated.gidnumber += 1;
        assert_eq!(
            resolver
                .set_cache_usertoken_guarded(&mut unrelated, 2, Some("other-secret"))
                .await
                .unwrap(),
            CacheUpdateResult::Updated
        );
        assert_eq!(
            resolver
                .set_cache_usertoken_guarded(&mut test_token(), 1, Some("original-secret"))
                .await
                .unwrap(),
            CacheUpdateResult::Updated
        );
        assert_eq!(resolver.get_cached_usertokens().await.unwrap().len(), 2);
        assert!(resolver
            .check_cache_userpassword(unrelated.uuid, "other-secret")
            .await
            .unwrap());
        assert!(resolver
            .check_cache_userpassword(test_token().uuid, "original-secret")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn password_helpers_wait_for_hsm_before_acquiring_database() {
        let resolver = setup_resolver().await;
        for write in [true, false] {
            let hsm_guard = resolver.hsm.lock().await;
            let password_operation = async {
                if write {
                    resolver
                        .set_cache_userpassword(test_token().uuid, "secret")
                        .await
                        .unwrap();
                } else {
                    assert!(resolver
                        .check_cache_userpassword(test_token().uuid, "secret")
                        .await
                        .unwrap());
                }
            };
            tokio::pin!(password_operation);
            tokio::select! {
                biased;
                _ = &mut password_operation => panic!("password operation bypassed the HSM lock"),
                _ = tokio::task::yield_now() => {}
            }
            // The provider's HSM -> DB order must remain possible while the
            // password operation is waiting, rather than form a lock cycle.
            let dbtxn = tokio::time::timeout(Duration::from_secs(1), resolver.db.write())
                .await
                .expect("password operation held the database while waiting for the HSM");
            dbtxn.commit().unwrap();
            drop(hsm_guard);
            password_operation.await;
        }
    }

    #[tokio::test]
    async fn enumeration_and_reconciliation_ignore_expired_accounts() {
        let resolver = setup_resolver().await;
        let token = test_token();
        resolver
            .set_cache_userpassword(token.uuid, "secret")
            .await
            .unwrap();
        assert!(resolver.get_nssaccounts().await.unwrap().is_empty());
        assert!(resolver
            .get_unexpired_nssaccounts()
            .await
            .unwrap()
            .is_empty());

        let mut fresh_token = token.clone();
        fresh_token.uuid = uuid::Uuid::new_v4();
        fresh_token.name = "freshuser".to_string();
        fresh_token.spn = "freshuser@example.com".to_string();
        fresh_token.gidnumber += 1;
        resolver
            .set_cache_usertoken(&mut fresh_token, false)
            .await
            .unwrap();
        for users in [
            resolver.get_nssaccounts().await.unwrap(),
            resolver.get_unexpired_nssaccounts().await.unwrap(),
        ] {
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].name, fresh_token.name);
            assert!(users[0].cacheable);
        }
        // Enumeration filters expired accounts without removing their offline
        // identity or password verifier from the database.
        assert_eq!(resolver.get_cached_usertokens().await.unwrap().len(), 2);
        let mut dbtxn = resolver.db.write().await;
        let (_, expiry) = dbtxn.get_account(&Id::Name(token.spn)).unwrap().unwrap();
        assert_eq!(expiry, 0);
        dbtxn.commit().unwrap();
        assert!(resolver
            .check_cache_userpassword(token.uuid, "secret")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn reconciliation_refresh_requires_an_unexpired_cached_identity() {
        let resolver = setup_resolver().await;
        let token = test_token();
        // Even a trusted refresh must not revive an ineligible account for
        // reconciliation, or discover an account that was not already cached.
        resolver.client.user_get_error.store(6, Ordering::Release);
        assert!(resolver
            .refresh_cached_usertoken(&token.name)
            .await
            .unwrap()
            .is_none());
        let (expired, cached) = resolver
            .get_cached_usertoken(&Id::Name(token.name.clone()))
            .await
            .unwrap();
        assert!(expired);
        assert_eq!(cached.unwrap().uuid, token.uuid);

        resolver.delete_cache_usertoken(token.uuid).await.unwrap();
        assert!(resolver
            .refresh_cached_usertoken(&token.name)
            .await
            .unwrap()
            .is_none());
        resolver.set_nxcache(&Id::Name(token.name.clone())).await;
        assert!(resolver
            .refresh_cached_usertoken(&token.name)
            .await
            .unwrap()
            .is_none());
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn reconciliation_refresh_rejects_lookup_only_and_replacement_identities() {
        let token = test_token();
        let other_uuid = uuid::Uuid::new_v4();
        let other_tenant = Some(uuid::Uuid::new_v4());
        for (mode, cached_uuid, cached_tenant) in [
            (3, token.uuid, token.tenant_id),
            (3, other_uuid, token.tenant_id),
            (3, token.uuid, other_tenant),
            (3, token.uuid, None),
            (6, other_uuid, token.tenant_id),
            (6, token.uuid, other_tenant),
            (6, token.uuid, None),
        ] {
            let resolver = setup_resolver().await;
            resolver.delete_cache_usertoken(token.uuid).await.unwrap();
            let mut cached = token.clone();
            cached.uuid = cached_uuid;
            cached.tenant_id = cached_tenant;
            cached.groups.clear();
            resolver
                .set_cache_usertoken(&mut cached, false)
                .await
                .unwrap();
            resolver
                .client
                .user_get_error
                .store(mode, Ordering::Release);

            let accounts = resolver.get_unexpired_nssaccounts().await.unwrap();
            assert_eq!(accounts.len(), 1);
            // Both provider modes return the same name and new group claims.
            // Lookup-only claims remain ineligible even for the same UUID;
            // trusted updates must still match both the UUID and tenant.
            assert!(resolver
                .refresh_cached_usertoken(&accounts[0].name)
                .await
                .unwrap()
                .is_none());
            assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
            if mode == 3 {
                let (expired, cached) = resolver
                    .get_cached_usertoken(&Id::Name(token.name.clone()))
                    .await
                    .unwrap();
                let cached = cached.unwrap();
                assert!(!expired);
                assert_eq!(cached.uuid, cached_uuid);
                assert_eq!(cached.tenant_id, cached_tenant);
                assert!(cached.groups.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn reconciliation_refresh_accepts_a_matching_trusted_update() {
        let resolver = setup_resolver().await;
        let mut cached = test_token();
        cached.groups.clear();
        resolver
            .set_cache_usertoken(&mut cached, false)
            .await
            .unwrap();
        resolver.client.user_get_error.store(6, Ordering::Release);

        let refreshed = resolver
            .refresh_cached_usertoken(&cached.name)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(refreshed.uuid, cached.uuid);
        assert_eq!(refreshed.tenant_id, cached.tenant_id);
        assert_eq!(refreshed.groups.len(), 1);
        assert_eq!(refreshed.groups[0].uuid, test_token().groups[0].uuid);
        assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn reconciliation_refresh_preserves_unexpired_cached_fallback() {
        let expiry = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        for mode in [0, 1, 2] {
            let resolver = setup_resolver_with_expiry(expiry).await;
            let token = test_token();
            resolver
                .client
                .user_get_error
                .store(mode, Ordering::Release);
            let refreshed = resolver
                .refresh_cached_usertoken(&token.name)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(refreshed.uuid, token.uuid);
            assert_eq!(refreshed.tenant_id, token.tenant_id);
            assert_eq!(refreshed.groups[0].uuid, token.groups[0].uuid);
            assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
            let mut dbtxn = resolver.db.write().await;
            let (_, cached_expiry) = dbtxn.get_account(&Id::Name(token.name)).unwrap().unwrap();
            assert_eq!(cached_expiry, expiry);
            dbtxn.commit().unwrap();
        }
    }

    #[tokio::test]
    async fn reconciliation_refresh_rechecks_cached_eligibility_after_wait() {
        let expiry = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        for mode in [0, 1, 2] {
            for change in ["expire", "remove", "uuid", "tenant", "claims"] {
                let resolver = setup_resolver_with_expiry(expiry).await;
                let token = test_token();
                resolver
                    .client
                    .user_get_error
                    .store(mode, Ordering::Release);
                // Stop after the initial eligible snapshot, before provider
                // work resumes, without relying on wall-clock sleeps.
                let hsm_guard = resolver.hsm.lock().await;
                let refresh = resolver.refresh_cached_usertoken(&token.name);
                tokio::pin!(refresh);
                tokio::select! {
                    biased;
                    _ = &mut refresh => panic!("refresh bypassed the HSM lock"),
                    _ = tokio::task::yield_now() => {}
                }
                assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 0);
                match change {
                    "expire" => resolver.invalidate().await.unwrap(),
                    "remove" => resolver.delete_cache_usertoken(token.uuid).await.unwrap(),
                    _ => {
                        let mut current = token.clone();
                        current.groups.clear();
                        if change == "uuid" {
                            current.uuid = uuid::Uuid::new_v4();
                        } else if change == "tenant" {
                            current.tenant_id = Some(uuid::Uuid::new_v4());
                        }
                        resolver
                            .set_cache_usertoken(&mut current, false)
                            .await
                            .unwrap();
                    }
                }
                drop(hsm_guard);

                let refreshed = refresh.await.unwrap();
                if change == "claims" {
                    let refreshed = refreshed.unwrap();
                    assert_eq!(refreshed.uuid, token.uuid);
                    assert_eq!(refreshed.tenant_id, token.tenant_id);
                    assert!(refreshed.groups.is_empty());
                } else {
                    assert!(refreshed.is_none());
                }
                assert_eq!(resolver.client.user_get_calls.load(Ordering::Acquire), 1);
            }
        }
    }

    #[tokio::test]
    async fn abandoned_pin_setup_does_not_cache_identity_or_password() {
        let resolver = setup_resolver().await;
        resolver
            .delete_cache_usertoken(test_token().uuid)
            .await
            .unwrap();
        resolver.client.user_get_error.store(4, Ordering::Release);
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (mut session, _) = resolver
            .pam_account_authenticate_init(
                "testuser@example.com",
                "sshd",
                false,
                false,
                shutdown_rx,
            )
            .await
            .unwrap();
        let response = resolver
            .pam_account_authenticate_step(
                &mut session,
                PamAuthRequest::Password {
                    cred: "secret".to_string(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(response, PamAuthResponse::SetupPin { .. }));
        drop(session);
        assert!(resolver.get_cached_usertokens().await.unwrap().is_empty());
        assert!(!resolver
            .check_cache_userpassword(test_token().uuid, "secret")
            .await
            .unwrap());
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
            .get_initgroups("testuser", OnExpiry::Refresh)
            .await
            .expect("named initgroups")
            .expect("cached user");
        assert_eq!(named, vec![2100]);

        let full_resolver = setup_resolver_with(0, InitgroupsMode::Full, vec![unnamed]).await;
        let full = full_resolver
            .get_initgroups("testuser", OnExpiry::Refresh)
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
            pending_password: None,
            cache_generation: 0,
            identity_staged: false,
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

/// Is `token` the user which `local@domain` was expanded from?
fn is_expanded_local_name(token: &UserToken, local: &str, domain: &str) -> bool {
    token.name.eq_ignore_ascii_case(local)
        && split_username(&token.spn)
            .map(|(_, spn_domain)| spn_domain.eq_ignore_ascii_case(domain))
            .unwrap_or(false)
}

fn local_name_matches(token: &UserToken, name: &str) -> bool {
    token.name.eq_ignore_ascii_case(name)
        || split_username(name)
            .map(|(local, domain)| is_expanded_local_name(token, local, domain))
            .unwrap_or(false)
}

pub enum NssAccountLookup {
    Found(NssUser),
    Excluded(NssUser),
    Missing,
}

enum UserTokenLookup {
    Found((UserToken, bool)),
    Excluded(UserToken),
    Missing,
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
            user_map_file: None,
            cn_name_mapping: false,
            name_mapping_script: false,
            nxset: Mutex::new(HashSet::new()),
            nxcache: Mutex::new(LruCache::new(NXCACHE_SIZE)),
            alias_absence: Mutex::new(LruCache::unbounded()),
            password_generation: AtomicU64::new(0),
            password_cache_generations: Mutex::new(HashMap::new()),
            identity_refreshes: Mutex::new(IdentityRefreshes::default()),
            identity_refresh_ready: Notify::new(),
        })
    }

    pub fn with_user_map_file(mut self, user_map_file: String) -> Self {
        self.user_map_file = Some(user_map_file);
        self
    }

    /// Declare that clients expand local names to `<name>@<domain>` (cn_name_mapping).
    pub fn with_cn_name_mapping(mut self, cn_name_mapping: bool) -> Self {
        self.cn_name_mapping = cn_name_mapping;
        self
    }

    /// Declare a name mapping script; its output is not probed, so aliases stay canonical.
    pub fn with_name_mapping_script(mut self, name_mapping_script: bool) -> Self {
        self.name_mapping_script = name_mapping_script;
        self
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
        self.client.get_cachestate(account_id).await
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
        *self.identity_refreshes.lock().await = IdentityRefreshes::default();

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
            .map_err(|_| ResolverError)?;
        self.identity_refreshes.lock().await.next_allowed.clear();
        Ok(())
    }

    #[cfg(test)]
    async fn get_cached_usertokens(&self) -> ResolverResult<Vec<UserToken>> {
        let mut dbtxn = self.db.write().await;
        dbtxn.get_accounts().map_err(|_| ResolverError)
    }

    pub async fn refresh_cached_usertoken(
        &self,
        account_id: &str,
    ) -> ResolverResult<Option<UserToken>> {
        let id = Id::Name(account_id.to_string());
        let (expired, token) = self.resolve_cached_usertoken(&id).await?;
        let Some(token) = token.filter(|_| !expired) else {
            return Ok(None);
        };
        let uuid = token.uuid;
        let tenant_id = token.tenant_id;
        // Reconciliation may use only the authenticated identity that made
        // this account eligible, never a lookup-only or replacement identity.
        let Some((refreshed, true)) = self
            .refresh_usertoken_with_cacheability(&id, Some((token, true)))
            .await?
        else {
            return Ok(None);
        };
        if refreshed.uuid != uuid || refreshed.tenant_id != tenant_id {
            return Ok(None);
        }
        // Provider work can yield while eligibility or memberships change.
        // Use current claims only if the same cached identity is still eligible.
        let (expired, current) = self.get_cached_usertoken(&id).await?;
        let current =
            current.filter(|token| !expired && token.uuid == uuid && token.tenant_id == tenant_id);
        match current {
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

    async fn queue_identity_refresh(&self, spn: &str) {
        let now = SystemTime::now();
        let mut refreshes = self.identity_refreshes.lock().await;
        if refreshes
            .next_allowed
            .get(spn)
            .is_some_and(|next_allowed| now < *next_allowed)
        {
            return;
        }
        refreshes
            .next_allowed
            .retain(|_, next_allowed| now < *next_allowed);
        refreshes.next_allowed.insert(
            spn.to_string(),
            now + Duration::from_secs(self.timeout_seconds),
        );
        refreshes.queued.push(spn.to_string());
        drop(refreshes);
        self.identity_refresh_ready.notify_one();
    }

    /// Refresh identities that lookups answered from expired entries, until shutdown.
    pub async fn refresh_expired_identities<T: Clone>(
        &self,
        mut shutdown_rx: broadcast::Receiver<T>,
    ) {
        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.recv() => break,
                _ = self.identity_refresh_ready.notified() => {}
            }
            self.refresh_queued_identities(&shutdown_rx).await;
        }
    }

    // On shutdown, finish the refresh in progress but skip the rest of the batch.
    async fn refresh_queued_identities<T>(&self, shutdown_rx: &broadcast::Receiver<T>) {
        let queued = std::mem::take(&mut self.identity_refreshes.lock().await.queued);
        // Identities of one domain share a provider: probe once, until a refresh finds it offline.
        let mut reachable: HashMap<String, bool> = HashMap::new();
        for spn in queued {
            if !shutdown_rx.is_empty() {
                break;
            }
            let id = Id::Name(spn.clone());
            match self.lookup_cached_usertoken(&id).await {
                Ok((true, Some(_))) => {}
                Ok(_) => continue,
                Err(_) => {
                    warn!(account_id = %id, "Failed to read a queued identity");
                    continue;
                }
            }
            if !shutdown_rx.is_empty() {
                break;
            }
            let domain = spn
                .rsplit_once('@')
                .map_or(spn.as_str(), |(_, domain)| domain);
            // A refresh holds the HSM and database locks that sign-in needs, so probe first.
            let online = match reachable.get(domain) {
                Some(online) => *online,
                None => {
                    let online = self
                        .client
                        .probe_online(Some(&spn), SystemTime::now())
                        .await;
                    reachable.insert(domain.to_string(), online);
                    online
                }
            };
            if !online {
                debug!(
                    account_id = %id,
                    "Identity provider unreachable, keeping expired identities cached"
                );
                let retry = SystemTime::now() + UNREACHABLE_RETRY;
                self.identity_refreshes
                    .lock()
                    .await
                    .next_allowed
                    .insert(spn, retry);
                continue;
            }
            // The entry may have been cleared or refreshed while the probe ran.
            let Ok((true, Some(token))) = self.lookup_cached_usertoken(&id).await else {
                continue;
            };
            if self.refresh_usertoken(&id, Some(token)).await.is_err() {
                warn!(account_id = %id, "Failed to refresh an expired cached identity");
            }
            if !matches!(self.get_cachestate(Some(&spn)).await, CacheState::Online) {
                reachable.insert(domain.to_string(), false);
                let retry = SystemTime::now() + UNREACHABLE_RETRY;
                self.identity_refreshes
                    .lock()
                    .await
                    .next_allowed
                    .insert(spn, retry);
            }
        }
    }

    async fn get_cached_grouptokens(&self) -> ResolverResult<Vec<GroupToken>> {
        let mut dbtxn = self.db.read().await;
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
        let r = self
            .db
            .write()
            .await
            .get_account(account_id)
            .map_err(|err| {
                trace!("get_cached_usertoken {:?}", err);
            })?;
        self.cached_usertoken_with_expiry(account_id, r).await
    }

    async fn lookup_cached_usertoken(
        &self,
        account_id: &Id,
    ) -> ResolverResult<(bool, Option<UserToken>)> {
        let r = self
            .db
            .read()
            .await
            .get_account(account_id)
            .map_err(|err| {
                trace!("lookup_cached_usertoken {:?}", err);
            })?;
        self.cached_usertoken_with_expiry(account_id, r).await
    }

    async fn cached_usertoken_with_expiry(
        &self,
        account_id: &Id,
        mut r: Option<(UserToken, u64)>,
    ) -> ResolverResult<(bool, Option<UserToken>)> {
        // With cn_name_mapping a local name arrives as `<name>@<domain>`; find the user it was expanded from.
        if r.is_none() {
            if let Id::Name(name) = account_id {
                if let Some((local, domain)) = split_username(name) {
                    r = self
                        .db
                        .read()
                        .await
                        .get_account(&Id::Name(local.to_string()))
                        .map_err(|err| {
                            trace!("cached_usertoken_with_expiry {:?}", err);
                        })?
                        .filter(|(ut, _)| is_expanded_local_name(ut, local, domain));
                }
            }
        }

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

    /// Is the alias `key` (lowercase qualified name) proved to own it, and the proof still valid?
    async fn alias_proved(&self, key: &str) -> bool {
        let mut proofs = self.alias_absence.lock().await;
        proofs
            .get(key)
            .is_some_and(|expiry| SystemTime::now() < *expiry)
    }

    /// A qualified alias looks like an uncached user's UPN: resolve the exact name first.
    async fn resolve_cached_usertoken(
        &self,
        account_id: &Id,
    ) -> ResolverResult<(bool, Option<UserToken>)> {
        let cached = self.get_cached_usertoken(account_id).await?;
        self.resolve_alias(account_id, cached).await
    }

    async fn resolve_alias(
        &self,
        account_id: &Id,
        cached: (bool, Option<UserToken>),
    ) -> ResolverResult<(bool, Option<UserToken>)> {
        let (Id::Name(name), Some(alias)) = (account_id, cached.1.as_ref()) else {
            return Ok(cached);
        };
        if split_username(name).is_none() || alias.spn.eq_ignore_ascii_case(name) {
            return Ok(cached);
        }

        if self.alias_proved(&name.to_ascii_lowercase()).await {
            return Ok(cached);
        }

        let state = self.get_cachestate(Some(name)).await;
        if !self.test_connection_for_state(state).await {
            warn!("Cannot verify qualified local alias while offline");
            return Err(ResolverError);
        }

        let (lookup, generation) = self.fetch_usertoken(account_id, None).await?;
        // Even a failed lookup must not hide a canonical identity cached meanwhile.
        let current = self.settle_alias(account_id, name, false).await?;
        if current
            .1
            .as_ref()
            .is_some_and(|token| token.spn.eq_ignore_ascii_case(name))
        {
            return Ok(current);
        }
        match lookup {
            Ok(UserTokenState::Update(mut exact)) if exact.spn.eq_ignore_ascii_case(name) => {
                match self
                    .set_cache_usertoken_guarded(&mut exact, generation, None)
                    .await?
                {
                    CacheUpdateResult::Updated => Ok((false, Some(exact))),
                    CacheUpdateResult::Superseded | CacheUpdateResult::IdentityChanged => {
                        self.get_cached_usertoken(account_id).await
                    }
                }
            }
            // The provider returns a placeholder for unknown names, so ask for evidence.
            Ok(UserTokenState::LookupOnly(exact)) if exact.spn.eq_ignore_ascii_case(name) => {
                let verdict = {
                    let mut hsm_lock = self.hsm.lock().await;
                    self.client
                        .unix_user_verify_upn(name, hsm_lock.deref_mut(), &self.machine_key)
                        .await
                };
                match verdict {
                    UpnVerdict::Exists => {
                        self.release_alias(alias.uuid).await?;
                        Ok((true, None))
                    }
                    UpnVerdict::Absent => self.settle_alias(account_id, name, true).await,
                    UpnVerdict::Unknown => {
                        warn!("Cannot establish whether a qualified name is a UPN");
                        Err(ResolverError)
                    }
                }
            }
            Ok(UserTokenState::NotFound) => self.settle_alias(account_id, name, true).await,
            _ => {
                warn!("Cannot establish ownership of qualified local alias");
                Err(ResolverError)
            }
        }
    }

    /// With `proved`, the alias owns `name` until the proof expires. Either way the proof is
    /// dropped if a canonical owner of `name` is cached, and the current cache view returned.
    async fn settle_alias(
        &self,
        account_id: &Id,
        name: &str,
        proved: bool,
    ) -> ResolverResult<(bool, Option<UserToken>)> {
        let key = name.to_ascii_lowercase();
        if proved {
            let expiry = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
            self.alias_absence.lock().await.put(key.clone(), expiry);
        }
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

    /// Restore an alias to its canonical name, keeping the account (password, memberships).
    async fn release_alias(&self, uuid: Uuid) -> ResolverResult<()> {
        let mut dbtxn = self.db.write().await;
        let Some((mut current, expiry)) = dbtxn
            .get_account(&Id::Name(uuid.to_string()))
            .map_err(|_| ResolverError)?
        else {
            return Ok(());
        };
        current.name.clone_from(&current.spn);
        dbtxn
            .update_account(&current, expiry)
            .map_err(|_| ResolverError)?;
        dbtxn.commit().map_err(|_| ResolverError)
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
        let r = self.db.read().await.get_group(grp_id).map_err(|_| ())?;

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

    async fn set_cache_usertoken_guarded(
        &self,
        token: &mut UserToken,
        generation: u64,
        password: Option<&str>,
    ) -> ResolverResult<CacheUpdateResult> {
        let keys = [
            PasswordCacheKey::Uuid(token.uuid),
            PasswordCacheKey::Name(token.name.clone()),
            PasswordCacheKey::Spn(token.spn.clone()),
            PasswordCacheKey::Gid(token.gidnumber),
        ];
        let mut generations = self.password_cache_generations.lock().await;
        let same_identity = |latest: &&PasswordCacheGeneration| {
            latest.uuid == token.uuid && latest.tenant_id == token.tenant_id
        };
        if keys
            .iter()
            .filter_map(|key| generations.get(key))
            .any(|latest| latest.identity_generation > generation && !same_identity(&latest))
        {
            return Ok(CacheUpdateResult::IdentityChanged);
        }
        let latest_identity_generation = keys
            .iter()
            .filter_map(|key| generations.get(key))
            .filter(same_identity)
            .map(|latest| latest.identity_generation)
            .max();
        let latest_password_generation = keys
            .iter()
            .filter_map(|key| generations.get(key))
            .filter(same_identity)
            .filter_map(|latest| latest.password_generation)
            .max();
        if latest_password_generation.is_some_and(|latest| latest >= generation)
            || (password.is_none()
                && latest_identity_generation.is_some_and(|latest| latest > generation))
        {
            // Never restore stale identity claims or group memberships either.
            return Ok(CacheUpdateResult::Superseded);
        }

        if latest_identity_generation.is_some_and(|latest| latest > generation) {
            // A same-identity refresh must not suppress password invalidation,
            // but its newer identity claims and memberships must be preserved.
            let (_, current) = self
                .get_cached_usertoken(&Id::Name(token.uuid.hyphenated().to_string()))
                .await?;
            let Some(current) = current.filter(|current| {
                current.uuid == token.uuid && current.tenant_id == token.tenant_id
            }) else {
                return Ok(CacheUpdateResult::IdentityChanged);
            };
            *token = current;
        }
        self.set_cache_usertoken(token, password.is_some()).await?;
        let keys = [
            PasswordCacheKey::Uuid(token.uuid),
            PasswordCacheKey::Name(token.name.clone()),
            PasswordCacheKey::Spn(token.spn.clone()),
            PasswordCacheKey::Gid(token.gidnumber),
        ];
        // Publish only after durable token storage/invalidation. A passwordless
        // refresh advances identity ordering without suppressing an accepted
        // password that still needs to invalidate the previous verifier.
        let latest = PasswordCacheGeneration {
            identity_generation: latest_identity_generation
                .map_or(generation, |latest| latest.max(generation)),
            password_generation: if password.is_some() {
                Some(generation)
            } else {
                latest_password_generation
            },
            uuid: token.uuid,
            tenant_id: token.tenant_id,
        };
        generations.extend(keys.into_iter().map(|key| (key, latest)));
        if let Some(password) = password {
            if self
                .set_cache_userpassword(token.uuid, password)
                .await
                .is_err()
            {
                error!("Failed to cache offline password after successful authentication");
            }
        }
        Ok(CacheUpdateResult::Updated)
    }

    async fn set_cache_usertoken(
        &self,
        token: &mut UserToken,
        clear_password: bool,
    ) -> ResolverResult<()> {
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
        let clear_password = clear_password
            || dbtxn
                .get_account(&Id::Name(token.uuid.hyphenated().to_string()))
                .map_err(|_| ResolverError)?
                .is_some_and(|(cached, _)| {
                    cached.uuid == token.uuid && cached.tenant_id != token.tenant_id
                });
        let cached = dbtxn.get_accounts().map_err(|_| ResolverError)?;
        for mut other in cached.into_iter().filter(|other| other.uuid != token.uuid) {
            if other.spn.eq_ignore_ascii_case(&token.spn) {
                continue;
            }
            // Canonical identities own their names: restore a conflicting alias to its canonical name.
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
        let stored = token
            .groups
            .iter()
            // We need to add the groups first
            .try_for_each(|g| dbtxn.update_group(g, offset.as_secs()))
            .and_then(|_|
                // So that when we add the account it can make the relationships.
                dbtxn
                    .update_account(token, offset.as_secs()))
            .and_then(|_| {
                if clear_password {
                    // Commit invalidation with the authenticated identity so
                    // a failed replacement cannot retain the old verifier.
                    dbtxn.clear_account_password(token.uuid)
                } else {
                    Ok(())
                }
            })
            .and_then(|_| dbtxn.commit());
        stored.map_err(|_| ResolverError)?;
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
        let mut hsm_txn = self.hsm.lock().await;
        let mut dbtxn = self.db.write().await;
        dbtxn
            .update_account_password(a_uuid, cred, hsm_txn.deref_mut(), &self.hmac_key)
            .and_then(|x| dbtxn.commit().map(|_| x))
            .map_err(|_| ResolverError)
    }

    async fn check_cache_userpassword(&self, a_uuid: Uuid, cred: &str) -> ResolverResult<bool> {
        let mut hsm_txn = self.hsm.lock().await;
        let mut dbtxn = self.db.write().await;
        dbtxn
            .check_account_password(a_uuid, cred, hsm_txn.deref_mut(), &self.hmac_key)
            .and_then(|x| dbtxn.commit().map(|_| x))
            .map_err(|_| ResolverError)
    }

    async fn refresh_usertoken(
        &self,
        account_id: &Id,
        token: Option<UserToken>,
    ) -> ResolverResult<Option<UserToken>> {
        self.refresh_usertoken_with_cacheability(account_id, token.map(|token| (token, false)))
            .await
            .map(|result| result.map(|(token, _)| token))
    }

    /// Provider lookup; the generation orders it against other observations and password changes.
    async fn fetch_usertoken(
        &self,
        account_id: &Id,
        token: Option<&UserToken>,
    ) -> ResolverResult<(Result<UserTokenState, IdpError>, u64)> {
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

        // Order this provider observation before another request can replace it.
        let generation = self.password_generation.fetch_add(1, Ordering::Relaxed);
        drop(hsm_lock);
        dbtxn.commit().map_err(|_| ())?;

        Ok((user_get_result, generation))
    }

    async fn refresh_usertoken_with_cacheability(
        &self,
        account_id: &Id,
        token: Option<(UserToken, bool)>,
    ) -> ResolverResult<Option<(UserToken, bool)>> {
        let (user_get_result, generation) = self
            .fetch_usertoken(account_id, token.as_ref().map(|(token, _)| token))
            .await?;

        match user_get_result {
            Ok(UserTokenState::Update(mut n_tok)) => {
                match self
                    .set_cache_usertoken_guarded(&mut n_tok, generation, None)
                    .await?
                {
                    CacheUpdateResult::Updated => Ok(Some((n_tok, true))),
                    CacheUpdateResult::Superseded | CacheUpdateResult::IdentityChanged => {
                        // A newer observation won. Never return the stale token
                        // as authenticated/cacheable after discarding its write.
                        self.get_cached_usertoken(account_id)
                            .await
                            .map(|(expired, token)| token.map(|token| (token, !expired)))
                    }
                }
            }
            Ok(UserTokenState::LookupOnly(n_tok)) => Ok(Some((n_tok, false))),
            Ok(UserTokenState::NotFound) => {
                // It previously existed, so now purge it.
                if let Some((tok, _)) = token {
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

    /// The provider needs the UPN (tenant, sign-in name, Hello key tag): replace a login name by its SPN.
    fn canonical_account_id(account_id: &str, token: Option<&UserToken>) -> String {
        token
            .map(|tok| tok.spn.clone())
            .unwrap_or_else(|| account_id.to_string())
    }

    pub async fn get_usertoken(&self, account_id: Id) -> ResolverResult<Option<UserToken>> {
        self.get_usertoken_with_cacheability(account_id, OnExpiry::Refresh)
            .await
            .map(|result| result.map(|(token, _)| token))
    }

    // Keep the result's persistence eligibility alongside the token so a
    // lookup-only response cannot inherit eligibility from an old database row.
    async fn get_usertoken_with_cacheability(
        &self,
        account_id: Id,
        on_expiry: OnExpiry,
    ) -> ResolverResult<Option<(UserToken, bool)>> {
        match self.get_usertoken_checked(account_id, on_expiry).await? {
            UserTokenLookup::Found(found) => Ok(Some(found)),
            UserTokenLookup::Excluded(_) | UserTokenLookup::Missing => Ok(None),
        }
    }

    /// Like `get_usertoken_with_cacheability`, but tells a refused identity from a missing one.
    async fn get_usertoken_checked(
        &self,
        account_id: Id,
        on_expiry: OnExpiry,
    ) -> ResolverResult<UserTokenLookup> {
        // Validate the user isn't in the nxset (aka, it's a local user or group).
        let (name, idnumber) = match account_id.clone() {
            Id::Name(name) => (Some(name), None),
            Id::Gid(idnumber) => (None, Some(idnumber)),
        };
        if self.check_nxset(name.as_deref(), idnumber).await {
            return Ok(match self.lookup_cached_usertoken(&account_id).await {
                Ok((_, Some(tok))) => UserTokenLookup::Excluded(tok),
                _ => UserTokenLookup::Missing,
            });
        }

        // A local account may have appeared since caching; check the returned user's name and id.
        match self.get_usertoken_unchecked(account_id, on_expiry).await? {
            Some((tok, _)) if self.check_nxset(Some(&tok.name), Some(tok.gidnumber)).await => {
                warn!(
                    "Refusing '{}': its name or id collides with a local account",
                    tok.spn
                );
                Ok(UserTokenLookup::Excluded(tok))
            }
            Some(found) => Ok(UserTokenLookup::Found(found)),
            None => Ok(UserTokenLookup::Missing),
        }
    }

    async fn get_usertoken_unchecked(
        &self,
        account_id: Id,
        on_expiry: OnExpiry,
    ) -> ResolverResult<Option<(UserToken, bool)>> {
        trace!("get_usertoken");
        // get the item from the cache
        let (expired, item) = match on_expiry {
            OnExpiry::Refresh => self.get_cached_usertoken(&account_id).await,
            OnExpiry::RefreshIfReachable | OnExpiry::RefreshInBackground => {
                self.lookup_cached_usertoken(&account_id).await
            }
        }
        .map_err(|e| {
            trace!("get_usertoken error -> {:?}", e);
        })?;
        let (expired, item) = self.resolve_alias(&account_id, (expired, item)).await?;

        let state = match (&account_id, &item) {
            (_, Some(token)) => self.get_cachestate(Some(&token.spn)).await,
            (Id::Name(name), None) => self.get_cachestate(Some(name)).await,
            (Id::Gid(_), None) => self.get_cachestate(None).await,
        };

        // Expired records remain available for offline use, but must not
        // repopulate persistent NSS caches without a trusted refresh.
        let item = item.map(|token| (token, !expired));

        if expired && refresh_due(&state) {
            if let Some((token, _)) = &item {
                match on_expiry {
                    OnExpiry::Refresh => {}
                    OnExpiry::RefreshIfReachable => {
                        if !self
                            .client
                            .probe_online(Some(&token.spn), SystemTime::now())
                            .await
                        {
                            trace!("expired, provider unreachable, returning cached item");
                            return Ok(item);
                        }
                        return self
                            .refresh_usertoken_with_cacheability(&account_id, item)
                            .await;
                    }
                    OnExpiry::RefreshInBackground => {
                        trace!(
                            "expired, returning cached item and refreshing it in the background"
                        );
                        self.queue_identity_refresh(&token.spn).await;
                        return Ok(item);
                    }
                }
            }
        }

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
                    self.refresh_usertoken_with_cacheability(&account_id, item)
                        .await
                } else {
                    // Unable to bring up connection, return cache.
                    Ok(item)
                }
            }
            (true, CacheState::Online) => {
                trace!("online expired, refresh cache");
                // Attempt to refresh the item
                // Return it.
                self.refresh_usertoken_with_cacheability(&account_id, item)
                    .await
            }
        }
        .map(|t| {
            trace!("token -> {:?}", t);
            t
        })
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
        let user_map = self.user_map_file.as_deref().map(UserMap::new);
        self.group_members(g_uuid, user_map.as_ref()).await
    }

    async fn group_members(&self, g_uuid: Uuid, user_map: Option<&UserMap>) -> Vec<String> {
        let members = {
            let mut dbtxn = self.db.read().await;
            dbtxn.get_group_members(g_uuid).unwrap_or_default()
        };
        let mut names = Vec::with_capacity(members.len());
        for token in members {
            if !self
                .check_nxset(Some(&token.name), Some(token.gidnumber))
                .await
            {
                let mapped =
                    user_map.and_then(|map| map.get_local_from_upn(&token.spn.to_lowercase()));
                let name = match mapped {
                    Some(mapped) => mapped,
                    None => {
                        let rendered = self.token_uidattr(&token);
                        if user_map
                            .is_some_and(|map| map.is_mapped_to_another_upn(&rendered, &token.spn))
                            || self.alias_unproved(&rendered, &token.spn, false).await
                        {
                            token.spn.clone()
                        } else {
                            rendered
                        }
                    }
                };
                names.push(name);
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

    async fn canonical_alias_token(&self, mut tok: UserToken, probe: bool) -> UserToken {
        if self.alias_unproved(&tok.name, &tok.spn, probe).await {
            tok.name.clone_from(&tok.spn);
        }
        tok
    }

    pub async fn get_nssaccounts(&self) -> ResolverResult<Vec<NssUser>> {
        self.get_unexpired_nssaccounts().await
    }

    pub async fn get_unexpired_nssaccounts(&self) -> ResolverResult<Vec<NssUser>> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| ResolverError)?
            .as_secs();
        let tokens = {
            let mut dbtxn = self.db.read().await;
            dbtxn
                .get_unexpired_accounts(now)
                .map_err(|_| ResolverError)?
        };
        let mut accounts = Vec::with_capacity(tokens.len());
        for token in tokens {
            if !self
                .check_nxset(Some(&token.name), Some(token.gidnumber))
                .await
            {
                let token = self.canonical_alias_token(token, false).await;
                accounts.push(self.nss_user_from_token(token, true));
            }
        }
        Ok(accounts)
    }

    async fn get_nssaccount(
        &self,
        account_id: Id,
        on_expiry: OnExpiry,
    ) -> ResolverResult<Option<NssUser>> {
        self.get_usertoken_with_cacheability(account_id, on_expiry)
            .await
            .map(|result| result.map(|(tok, cacheable)| self.nss_user_from_token(tok, cacheable)))
    }

    fn nss_user_from_token(&self, tok: UserToken, cacheable: bool) -> NssUser {
        NssUser {
            homedir: self.token_abs_homedirectory(&tok),
            name: self.token_uidattr(&tok),
            canonical_name: Some(tok.spn),
            uid: tok.gidnumber,
            gid: tok.real_gidnumber.unwrap_or(tok.gidnumber),
            gecos: tok.displayname,
            shell: tok.shell.unwrap_or_else(|| self.default_shell.clone()),
            cacheable,
        }
    }

    /// Answers name service lookups, so an expired entry is refreshed in the background.
    async fn get_nssaccount_lookup(&self, account_id: Id) -> ResolverResult<NssAccountLookup> {
        let lookup = self.get_usertoken_checked(account_id, OnExpiry::RefreshInBackground);
        Ok(match lookup.await? {
            UserTokenLookup::Found((tok, cacheable)) => {
                let tok = self.canonical_alias_token(tok, true).await;
                NssAccountLookup::Found(self.nss_user_from_token(tok, cacheable))
            }
            UserTokenLookup::Excluded(tok) => {
                NssAccountLookup::Excluded(self.nss_user_from_token(tok, false))
            }
            UserTokenLookup::Missing => NssAccountLookup::Missing,
        })
    }

    pub async fn get_nssaccount_name_lookup(
        &self,
        account_id: &str,
    ) -> ResolverResult<NssAccountLookup> {
        self.get_nssaccount_lookup(Id::Name(account_id.to_string()))
            .await
    }

    pub async fn get_nssaccount_gid_lookup(&self, gid: u32) -> ResolverResult<NssAccountLookup> {
        self.get_nssaccount_lookup(Id::Gid(gid)).await
    }

    /// Render an alias canonically unless proved; `probe = false` (enumeration) never queries the provider.
    pub async fn render_alias(&self, mut user: NssUser, probe: bool) -> NssUser {
        if let Some(spn) = user.canonical_name.clone() {
            if self.alias_unproved(&user.name, &spn, probe).await {
                user.name = spn;
            }
        }
        user
    }

    async fn alias_unproved(&self, name: &str, spn: &str, probe: bool) -> bool {
        // A name the user map assigns to another UPN is never this user's alias.
        if !name.eq_ignore_ascii_case(spn) {
            let map = self.user_map_file.as_deref().map(UserMap::new);
            if map.is_some_and(|map| map.is_mapped_to_another_upn(name, spn)) {
                return true;
            }
        }
        let qualified = if name.contains('@') {
            name.to_string()
        } else if self.name_mapping_script {
            return true;
        } else if self.cn_name_mapping {
            let Some((_, domain)) = split_username(spn) else {
                return false;
            };
            format!("{}@{}", name, domain)
        } else {
            return false;
        };
        if qualified.eq_ignore_ascii_case(spn) {
            return false;
        }
        if !probe {
            return !self.alias_proved(&qualified.to_ascii_lowercase()).await;
        }
        !matches!(
            self.resolve_cached_usertoken(&Id::Name(qualified)).await,
            Ok((_, Some(token))) if token.spn.eq_ignore_ascii_case(spn)
        )
    }

    pub async fn get_nssaccount_name(
        &self,
        account_id: &str,
        on_expiry: OnExpiry,
    ) -> ResolverResult<Option<NssUser>> {
        self.get_nssaccount(Id::Name(account_id.to_string()), on_expiry)
            .await
    }

    pub async fn get_nssaccount_gid(
        &self,
        gid: u32,
        on_expiry: OnExpiry,
    ) -> ResolverResult<Option<NssUser>> {
        self.get_nssaccount(Id::Gid(gid), on_expiry).await
    }

    /// Name, uid and group UUIDs of one token, so local-account tasks never mix identities.
    pub async fn get_nssaccount_with_groups(
        &self,
        account_id: &str,
    ) -> ResolverResult<Option<(NssUser, Vec<Uuid>)>> {
        let token = self.get_usertoken(Id::Name(account_id.to_string())).await?;
        Ok(token.map(|token| {
            let groups = token.groups.iter().map(|group| group.uuid).collect();
            (self.nss_user_from_token(token, true), groups)
        }))
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
        let user_map = self.user_map_file.as_deref().map(UserMap::new);
        let mut r: Vec<_> = Vec::with_capacity(l.len());
        for tok in l.into_iter() {
            if self.check_nxset(Some(&tok.name), Some(tok.gidnumber)).await {
                continue;
            }
            let members = self.group_members(tok.uuid, user_map.as_ref()).await;
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

    pub async fn get_initgroups(
        &self,
        account_id: &str,
        on_expiry: OnExpiry,
    ) -> ResolverResult<Option<Vec<u32>>> {
        let token = self
            .get_usertoken_with_cacheability(Id::Name(account_id.to_string()), on_expiry)
            .await?;
        let Some((tok, _)) = token else {
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

        // An offline session must not overwrite an identity replaced after its lookup.
        let cache_generation = self.password_generation.fetch_add(1, Ordering::Relaxed);
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
                    pending_password: None,
                    cache_generation,
                    identity_staged: false,
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
                pending_password: _,
                cache_generation: _,
                identity_staged: _,
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
                    ref mut pending_password,
                    ref mut cache_generation,
                    ref mut identity_staged,
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

                // Order accepted credentials before releasing the provider locks.
                // A password staged for PIN setup retains this generation, so
                // completing an older session cannot restore a revoked verifier.
                let observation = self.password_generation.fetch_add(1, Ordering::Relaxed);
                // Local PIN/TOTP setup may take several steps and retries. None
                // of them re-authenticates the staged remote identity or password.
                let generation = if *identity_staged {
                    *cache_generation
                } else {
                    observation
                };
                if matches!(
                    &maybe_cache_action,
                    Ok((
                        AuthResult::Success { .. }
                            | AuthResult::Next(
                                AuthRequest::SetupPin { .. } | AuthRequest::HelloTOTP { .. }
                            ),
                        _
                    ))
                ) {
                    *cache_generation = generation;
                }
                if matches!(
                    &maybe_cache_action,
                    Ok((
                        AuthResult::Next(
                            AuthRequest::SetupPin { .. } | AuthRequest::HelloTOTP { .. }
                        ),
                        _
                    ))
                ) {
                    *identity_staged = true;
                }
                drop(hsm_lock);
                dbtxn.commit().map_err(|_| ())?;

                match maybe_cache_action {
                    Ok((res, AuthCacheAction::None)) => Ok(res),
                    Ok((
                        AuthResult::Success { token },
                        AuthCacheAction::PasswordHashUpdate { cred },
                    )) => {
                        *pending_password = Some((generation, Zeroizing::new(cred)));
                        Ok(AuthResult::Success { token })
                    }
                    Ok((
                        next @ AuthResult::Next(AuthRequest::SetupPin { .. }),
                        AuthCacheAction::PasswordHashUpdate { cred },
                    )) => {
                        // Wait until the PIN setup completes before caching credentials.
                        *pending_password = Some((generation, Zeroizing::new(cred)));
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
                    pending_password: _,
                    cache_generation: _,
                    identity_staged: _,
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
                    let (generation, pending_password) = match &*auth_session {
                        AuthSession::InProgress {
                            cache_generation,
                            pending_password,
                            ..
                        } => (
                            pending_password
                                .as_ref()
                                .map_or(*cache_generation, |(generation, _)| *generation),
                            pending_password.as_ref().map(|(_, cred)| cred.as_str()),
                        ),
                        _ => return Err(ResolverError),
                    };
                    if self
                        .set_cache_usertoken_guarded(&mut token, generation, pending_password)
                        .await?
                        == CacheUpdateResult::IdentityChanged
                    {
                        // Success(name) would let the old session sign in as the
                        // replacement identity even if no cache write occurred.
                        *auth_session = AuthSession::Denied;
                        return Ok(PamAuthResponse::Denied(
                            "Account identity changed during authentication; sign in again."
                                .to_string(),
                        ));
                    }
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
        if self.check_nxset(Some(account_id), None).await {
            return Ok(false);
        }
        let id = Id::Name(account_id.to_string());
        let (expired, token) = self.resolve_cached_usertoken(&id).await?;
        let Some(token) = token else {
            debug!("pam_try_unseal: no cached user token");
            return Ok(false);
        };
        if self
            .check_nxset(Some(&token.name), Some(token.gidnumber))
            .await
        {
            warn!(
                "pam_try_unseal: refusing '{}': its name or id collides with a local account",
                token.spn
            );
            return Ok(false);
        }

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

    fn home_directory_info(&self, tok: &UserToken) -> HomeDirectoryInfo {
        HomeDirectoryInfo {
            uid: tok.gidnumber,
            gid: tok.real_gidnumber.unwrap_or(tok.gidnumber),
            name: self.token_homedirectory_attr(tok),
            aliases: self
                .token_homedirectory_alias(tok)
                .map(|s| vec![s])
                .unwrap_or_default(),
        }
    }

    pub async fn pam_account_beginsession(
        &self,
        account_id: &str,
    ) -> ResolverResult<Option<HomeDirectoryInfo>> {
        Ok(self
            .pam_account_beginsession_identity(account_id)
            .await?
            .map(|identity| identity.home))
    }

    /// Resolve once for `pam_sm_open_session`: home, NSS identity and groups come from one token.
    pub async fn pam_account_beginsession_identity(
        &self,
        account_id: &str,
    ) -> ResolverResult<Option<SessionIdentity>> {
        self.get_session_identity(Id::Name(account_id.to_string()))
            .await
    }

    /// Resolve a single token snapshot for local account tasks, including immutable ownership.
    pub async fn get_session_identity(
        &self,
        account_id: Id,
    ) -> ResolverResult<Option<SessionIdentity>> {
        let Some(tok) = self.get_usertoken(account_id).await? else {
            return Ok(None);
        };
        let tok = self.canonical_alias_token(tok, true).await;
        let home = self.home_directory_info(&tok);
        let group_ids = tok.groups.iter().map(|group| group.uuid).collect();
        Ok(Some(SessionIdentity {
            owner: LocalTaskOwner {
                object_id: tok.uuid,
                tenant_id: tok.tenant_id,
                upn: tok.spn.clone(),
            },
            home,
            account: self.nss_user_from_token(tok, true),
            group_ids,
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
