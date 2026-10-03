/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::convert::TryFrom;
use std::fmt;
use std::time::Duration;

use crate::idprovider::himmelblau::is_synthetic_primary_group;
use crate::idprovider::interface::{GroupToken, Id, UserToken};
use async_trait::async_trait;
use kanidm_lib_crypto::CryptoPolicy;
use kanidm_lib_crypto::DbPasswordV1;
use kanidm_lib_crypto::Password;
use libc::umask;
use rusqlite::{Connection, OptionalExtension};
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

use serde::{de::DeserializeOwned, Serialize};

use kanidm_hsm_crypto::{
    provider::BoxedDynTpm, provider::TpmHmacS256, structures::HmacS256Key as HmacKey,
    structures::LoadableHmacS256Key as LoadableHmacKey,
    structures::LoadableStorageKey as LoadableMachineKey,
};

const DBV_MAIN: &str = "main";

#[async_trait]
pub trait Cache {
    type Txn<'db>
    where
        Self: 'db;

    async fn write<'db>(&'db self) -> Self::Txn<'db>;
}

#[async_trait]
pub trait KeyStore {
    type Txn<'db>
    where
        Self: 'db;

    async fn write_keystore<'db>(&'db self) -> Self::Txn<'db>;
}

#[derive(Debug)]
pub enum CacheError {
    Cryptography,
    SerdeJson,
    Parse,
    Sqlite,
    TooManyResults,
    TransactionInvalidState,
    Tpm,
}

pub trait CacheTxn {
    fn migrate(&mut self) -> Result<(), CacheError>;

    fn commit(self) -> Result<(), CacheError>;

    fn invalidate(&mut self) -> Result<(), CacheError>;

    fn clear(&mut self) -> Result<(), CacheError>;

    fn clear_hello_keys(&mut self) -> Result<(), CacheError>;

    fn clear_hsm(&mut self) -> Result<(), CacheError>;

    fn get_hsm_machine_key(&mut self) -> Result<Option<LoadableMachineKey>, CacheError>;

    fn insert_hsm_machine_key(
        &mut self,
        machine_key: &LoadableMachineKey,
    ) -> Result<(), CacheError>;

    fn get_hsm_hmac_key(&mut self) -> Result<Option<LoadableHmacKey>, CacheError>;

    fn insert_hsm_hmac_key(&mut self, hmac_key: &LoadableHmacKey) -> Result<(), CacheError>;

    fn get_account(&mut self, account_id: &Id) -> Result<Option<(UserToken, u64)>, CacheError>;

    fn get_accounts(&mut self) -> Result<Vec<UserToken>, CacheError>;

    fn update_account(&mut self, account: &UserToken, expire: u64) -> Result<(), CacheError>;

    fn delete_account(&mut self, a_uuid: Uuid) -> Result<(), CacheError>;

    fn update_account_password(
        &mut self,
        a_uuid: Uuid,
        cred: &str,
        tpm: &mut BoxedDynTpm,
        hmac_key: &HmacKey,
    ) -> Result<(), CacheError>;

    fn check_account_password(
        &mut self,
        a_uuid: Uuid,
        cred: &str,
        tpm: &mut BoxedDynTpm,
        hmac_key: &HmacKey,
    ) -> Result<bool, CacheError>;

    fn get_group(&mut self, grp_id: &Id) -> Result<Option<(GroupToken, u64)>, CacheError>;

    fn get_group_members(&mut self, g_uuid: Uuid) -> Result<Vec<UserToken>, CacheError>;

    fn get_groups(&mut self) -> Result<Vec<GroupToken>, CacheError>;

    fn update_group_with_owner(
        &mut self,
        grp: &GroupToken,
        expire: u64,
        owner: Option<Uuid>,
    ) -> Result<(), CacheError>;

    fn update_group(&mut self, grp: &GroupToken, expire: u64) -> Result<(), CacheError> {
        self.update_group_with_owner(grp, expire, None)
    }

    fn delete_group(&mut self, g_uuid: Uuid) -> Result<(), CacheError>;
}

pub trait KeyStoreTxn {
    fn get_tagged_hsm_key<K: DeserializeOwned>(
        &mut self,
        tag: &str,
    ) -> Result<Option<K>, CacheError>;

    fn insert_tagged_hsm_key<K: Serialize>(&mut self, tag: &str, key: &K)
        -> Result<(), CacheError>;

    fn delete_tagged_hsm_key(&mut self, tag: &str) -> Result<(), CacheError>;
}

pub struct Db {
    conn: Mutex<Connection>,
    crypto_policy: CryptoPolicy,
}

pub struct DbTxn<'a> {
    conn: MutexGuard<'a, Connection>,
    committed: bool,
    crypto_policy: &'a CryptoPolicy,
}

#[derive(Debug)]
/// Errors coming back from the `Db` struct
pub enum DbError {
    Sqlite,
    Tpm,
}

impl Db {
    pub fn new(path: &str) -> Result<Self, DbError> {
        let before = unsafe { umask(0o0077) };
        let conn = Connection::open(path).map_err(|e| {
            error!(err = ?e, "rusqulite error");
            DbError::Sqlite
        })?;
        let _ = unsafe { umask(before) };
        // We only build a single thread. If we need more than one, we'll
        // need to re-do this to account for path = "" for debug.
        let crypto_policy = CryptoPolicy::time_target(Duration::from_millis(250));

        trace!("Configured {:?}", crypto_policy);

        Ok(Db {
            conn: Mutex::new(conn),
            crypto_policy,
        })
    }
}

#[async_trait]
impl Cache for Db {
    type Txn<'db> = DbTxn<'db>;

    #[allow(clippy::expect_used)]
    async fn write<'db>(&'db self) -> Self::Txn<'db> {
        let conn = self.conn.lock().await;
        DbTxn::new(conn, &self.crypto_policy)
    }
}

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Db {{}}")
    }
}

impl<'a> DbTxn<'a> {
    fn new(conn: MutexGuard<'a, Connection>, crypto_policy: &'a CryptoPolicy) -> Self {
        // Start the transaction
        // trace!("Starting db WR txn ...");
        #[allow(clippy::expect_used)]
        conn.execute("BEGIN TRANSACTION", [])
            .expect("Unable to begin transaction!");
        DbTxn {
            committed: false,
            conn,
            crypto_policy,
        }
    }

    /// This handles an error coming back from an sqlite event and dumps more information from it
    fn sqlite_error(&self, msg: &str, error: &rusqlite::Error) -> CacheError {
        error!(
            "sqlite {} error: {:?} db_path={:?}",
            msg,
            error,
            &self.conn.path()
        );
        CacheError::Sqlite
    }

    /// This handles an error coming back from an sqlite transaction and dumps a load of information from it
    fn sqlite_transaction_error(
        &self,
        error: &rusqlite::Error,
        _stmt: &rusqlite::Statement,
    ) -> CacheError {
        error!(
            "sqlite transaction error={:?} db_path={:?}",
            error,
            &self.conn.path(),
        );
        // TODO: one day figure out if there's an easy way to dump the transaction without the token...
        CacheError::Sqlite
    }

    fn is_cached_legacy_primary_group(&self, group: &GroupToken) -> Result<bool, CacheError> {
        if group.name != group.spn {
            return Ok(false);
        }

        self.conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM account_t WHERE uuid = ?1 AND spn = ?2)",
                rusqlite::params![group.uuid.to_string(), &group.spn],
                |row| row.get(0),
            )
            .map_err(|e| self.sqlite_error("legacy primary group lookup", &e))
    }

    fn cached_group_by_uuid(&self, uuid: Uuid) -> Result<Option<GroupToken>, CacheError> {
        let data = self
            .conn
            .query_row(
                "SELECT token FROM group_t WHERE uuid = ?1",
                [uuid.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|e| self.sqlite_error("group UUID lookup", &e))?;
        Ok(data.and_then(|token| serde_json::from_slice(&token).ok()))
    }

    fn is_private_cached_legacy_primary_group(
        &self,
        group: &GroupToken,
        owner: Uuid,
    ) -> Result<bool, CacheError> {
        if group.uuid != owner || !self.is_cached_legacy_primary_group(group)? {
            return Ok(false);
        }

        self.conn
            .query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM memberof_t WHERE g_uuid = ?1 AND a_uuid != ?2)",
                rusqlite::params![group.uuid.to_string(), owner.to_string()],
                |row| row.get(0),
            )
            .map_err(|e| self.sqlite_error("legacy primary group ownership lookup", &e))
    }

    fn canonicalize_cached_legacy_primary_group(
        &self,
        legacy: &GroupToken,
        synthetic: &GroupToken,
        owner: Uuid,
    ) -> Result<bool, CacheError> {
        if legacy.uuid != owner
            || !self.is_private_cached_legacy_primary_group(legacy, owner)?
            || legacy.gidnumber != synthetic.gidnumber
        {
            return Ok(false);
        }

        let data = self
            .conn
            .query_row(
                "SELECT token FROM account_t WHERE uuid = ?1",
                [legacy.uuid.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|e| self.sqlite_error("legacy primary account lookup", &e))?;
        let Some(data) = data else {
            return Ok(false);
        };
        let mut account = match serde_json::from_slice::<UserToken>(&data) {
            Ok(account) => account,
            Err(error) => {
                warn!(
                    "unable to canonicalize legacy primary group token: {:?}",
                    error
                );
                return Ok(false);
            }
        };
        let mut replaced = false;
        for group in &mut account.groups {
            if group.uuid == legacy.uuid
                && group.name == legacy.name
                && group.spn == legacy.spn
                && group.gidnumber == legacy.gidnumber
            {
                *group = synthetic.clone();
                replaced = true;
            }
        }
        if !replaced {
            return Ok(false);
        }

        let data = serde_json::to_vec(&account).map_err(|error| {
            error!(
                "unable to serialize canonicalized account token: {:?}",
                error
            );
            CacheError::SerdeJson
        })?;
        self.conn
            .execute(
                "UPDATE account_t SET token = ?1 WHERE uuid = ?2",
                rusqlite::params![data, legacy.uuid.to_string()],
            )
            .map_err(|e| self.sqlite_error("canonicalize legacy primary account", &e))?;
        Ok(true)
    }

    fn get_db_version(&self, key: &str) -> i64 {
        self.conn
            .query_row(
                "SELECT version FROM db_version_t WHERE id = :id",
                &[(":id", key)],
                |row| row.get(0),
            )
            .unwrap_or({
                // The value is missing, default to 0.
                0
            })
    }

    fn set_db_version(&self, key: &str, v: i64) -> Result<(), CacheError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO db_version_t (id, version) VALUES(:id, :dbv)",
                named_params! {
                    ":id": &key,
                    ":dbv": v,
                },
            )
            .map(|_| ())
            .map_err(|e| self.sqlite_error("set db_version_t", &e))
    }

    fn get_account_data_name(
        &mut self,
        account_id: &str,
    ) -> Result<Vec<(Vec<u8>, i64)>, CacheError> {
        let mut stmt = self.conn
            .prepare(
        "SELECT token, expiry FROM account_t WHERE uuid = :account_id OR name = :account_id COLLATE NOCASE OR spn = :account_id COLLATE NOCASE"
            )
            .map_err(|e| {
                self.sqlite_error("select prepare", &e)
            })?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map([account_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| self.sqlite_error("query_map failure", &e))?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map failure", &e)))
            .collect();
        data
    }

    fn get_account_data_gid(&mut self, gid: u32) -> Result<Vec<(Vec<u8>, i64)>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT token, expiry FROM account_t WHERE gidnumber = :gid")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map(params![gid], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
            .collect();
        data
    }

    fn get_group_data_name(&mut self, grp_id: &str) -> Result<Vec<(Vec<u8>, i64)>, CacheError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT token, expiry FROM group_t WHERE uuid = :grp_id OR name = :grp_id OR spn = :grp_id"
            )
            .map_err(|e| {
                self.sqlite_error("select prepare", &e)
            })?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map([grp_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
            .collect();
        data
    }

    fn get_group_data_gid(&mut self, gid: u32) -> Result<Vec<(Vec<u8>, i64)>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT token, expiry FROM group_t WHERE gidnumber = :gid")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map(params![gid], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
            .collect();
        data
    }
}

impl<'a> KeyStoreTxn for DbTxn<'a> {
    fn get_tagged_hsm_key<K: DeserializeOwned>(
        &mut self,
        tag: &str,
    ) -> Result<Option<K>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM hsm_data_t WHERE key = :key")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        let data: Option<Vec<u8>> = stmt
            .query_row(
                named_params! {
                    ":key": tag
                },
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| self.sqlite_error("query_row", &e))?;

        match data {
            Some(d) => Ok(serde_json::from_slice(d.as_slice())
                .map_err(|e| {
                    error!("json error -> {:?}", e);
                })
                .ok()),
            None => Ok(None),
        }
    }

    fn insert_tagged_hsm_key<K: Serialize>(
        &mut self,
        tag: &str,
        key: &K,
    ) -> Result<(), CacheError> {
        let data = serde_json::to_vec(key).map_err(|e| {
            error!("insert_hsm_machine_key json error -> {:?}", e);
            CacheError::SerdeJson
        })?;

        let mut stmt = self
            .conn
            .prepare("INSERT OR REPLACE INTO hsm_data_t (key, value) VALUES (:key, :value)")
            .map_err(|e| self.sqlite_error("prepare", &e))?;

        stmt.execute(named_params! {
            ":key": tag,
            ":value": &data,
        })
        .map(|r| {
            trace!("insert -> {:?}", r);
        })
        .map_err(|e| self.sqlite_error("execute", &e))
    }

    fn delete_tagged_hsm_key(&mut self, tag: &str) -> Result<(), CacheError> {
        self.conn
            .execute(
                "DELETE FROM hsm_data_t where key = :key",
                named_params! {
                    ":key": tag,
                },
            )
            .map(|_| ())
            .map_err(|e| self.sqlite_error("delete hsm_data_t", &e))
    }
}

impl<'a> CacheTxn for DbTxn<'a> {
    fn migrate(&mut self) -> Result<(), CacheError> {
        self.conn.set_prepared_statement_cache_capacity(16);
        self.conn
            .prepare("PRAGMA journal_mode=WAL;")
            .and_then(|mut wal_stmt| wal_stmt.query([]).map(|_| ()))
            .map_err(|e| self.sqlite_error("account_t create", &e))?;

        // This definition can never change.
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS db_version_t (
                    id TEXT PRIMARY KEY,
                    version INTEGER
                )",
                [],
            )
            .map_err(|e| self.sqlite_error("db_version_t create", &e))?;

        let db_version = self.get_db_version(DBV_MAIN);

        if db_version < 1 {
            // Setup two tables - one for accounts, one for groups.
            // correctly index the columns.
            // Optional pw hash field
            self.conn
                .execute(
                    "CREATE TABLE IF NOT EXISTS account_t (
                    uuid TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    spn TEXT NOT NULL UNIQUE,
                    gidnumber INTEGER NOT NULL UNIQUE,
                    password BLOB,
                    token BLOB NOT NULL,
                    expiry NUMERIC NOT NULL
                )
                ",
                    [],
                )
                .map_err(|e| self.sqlite_error("account_t create", &e))?;

            self.conn
                .execute(
                    "CREATE TABLE IF NOT EXISTS group_t (
                    uuid TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    spn TEXT NOT NULL UNIQUE,
                    gidnumber INTEGER NOT NULL UNIQUE,
                    token BLOB NOT NULL,
                    expiry NUMERIC NOT NULL
                )
                ",
                    [],
                )
                .map_err(|e| self.sqlite_error("group_t create", &e))?;

            // We defer group foreign keys here because we now manually cascade delete these when
            // required. This is because insert or replace into will always delete then add
            // which triggers this. So instead we defer and manually cascade.
            //
            // However, on accounts, we CAN delete cascade because accounts will always redefine
            // their memberships on updates so this is safe to cascade on this direction.
            self.conn
                .execute(
                    "CREATE TABLE IF NOT EXISTS memberof_t (
                    g_uuid TEXT,
                    a_uuid TEXT,
                    FOREIGN KEY(g_uuid) REFERENCES group_t(uuid) DEFERRABLE INITIALLY DEFERRED,
                    FOREIGN KEY(a_uuid) REFERENCES account_t(uuid) ON DELETE CASCADE
                )
                ",
                    [],
                )
                .map_err(|e| self.sqlite_error("memberof_t create error", &e))?;

            // Create the hsm_data store. These are all generally encrypted private
            // keys, and the hsm structures will decrypt these as required.
            self.conn
                .execute(
                    "CREATE TABLE IF NOT EXISTS hsm_int_t (
                        key TEXT PRIMARY KEY,
                        value BLOB NOT NULL
                    )
                    ",
                    [],
                )
                .map_err(|e| self.sqlite_error("hsm_int_t create error", &e))?;

            self.conn
                .execute(
                    "CREATE TABLE IF NOT EXISTS hsm_data_t (
                        key TEXT PRIMARY KEY,
                        value BLOB NOT NULL
                    )
                    ",
                    [],
                )
                .map_err(|e| self.sqlite_error("hsm_data_t create error", &e))?;

            // Since this is the 0th migration, we have to reset the HSM here.
            self.clear_hsm()?;
        }

        self.set_db_version(DBV_MAIN, 1)?;

        Ok(())
    }

    fn commit(mut self) -> Result<(), CacheError> {
        // trace!("Committing BE txn");
        if self.committed {
            error!("Invalid state, SQL transaction was already committed!");
            return Err(CacheError::TransactionInvalidState);
        }
        self.committed = true;

        self.conn
            .execute("COMMIT TRANSACTION", [])
            .map(|_| ())
            .map_err(|e| self.sqlite_error("commit", &e))
    }

    fn invalidate(&mut self) -> Result<(), CacheError> {
        self.conn
            .execute("UPDATE group_t SET expiry = 0", [])
            .map_err(|e| self.sqlite_error("update group_t", &e))?;

        self.conn
            .execute("UPDATE account_t SET expiry = 0", [])
            .map_err(|e| self.sqlite_error("update account_t", &e))?;

        Ok(())
    }

    fn clear(&mut self) -> Result<(), CacheError> {
        self.conn
            .execute("DELETE FROM memberof_t", [])
            .map_err(|e| self.sqlite_error("delete memberof_t", &e))?;

        self.conn
            .execute("DELETE FROM group_t", [])
            .map_err(|e| self.sqlite_error("delete group_t", &e))?;

        self.conn
            .execute("DELETE FROM account_t", [])
            .map_err(|e| self.sqlite_error("delete group_t", &e))?;

        Ok(())
    }

    fn clear_hello_keys(&mut self) -> Result<(), CacheError> {
        self.conn
            .execute(
                "DELETE FROM hsm_data_t
                 WHERE key LIKE '%/hello'
                    OR key LIKE '%/hello_decoupled'
                    OR key LIKE '%/hello_prt'
                    OR key LIKE '%/hello_refresh_token'
                    OR key LIKE '%/hello_totp'",
                [],
            )
            .map_err(|e| self.sqlite_error("delete hello keys", &e))?;

        Ok(())
    }

    fn clear_hsm(&mut self) -> Result<(), CacheError> {
        self.clear()?;

        self.conn
            .execute("DELETE FROM hsm_int_t", [])
            .map_err(|e| self.sqlite_error("delete hsm_int_t", &e))?;

        self.conn
            .execute("DELETE FROM hsm_data_t", [])
            .map_err(|e| self.sqlite_error("delete hsm_data_t", &e))?;

        Ok(())
    }

    fn get_hsm_machine_key(&mut self) -> Result<Option<LoadableMachineKey>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM hsm_int_t WHERE key = 'mk'")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        let data: Option<Vec<u8>> = stmt
            .query_row([], |row| row.get(0))
            .optional()
            .map_err(|e| self.sqlite_error("query_row", &e))?;

        match data {
            Some(d) => Ok(serde_json::from_slice(d.as_slice())
                .map_err(|e| {
                    error!("json error -> {:?}", e);
                })
                .ok()),
            None => Ok(None),
        }
    }

    fn insert_hsm_machine_key(
        &mut self,
        machine_key: &LoadableMachineKey,
    ) -> Result<(), CacheError> {
        let data = serde_json::to_vec(machine_key).map_err(|e| {
            error!("insert_hsm_machine_key json error -> {:?}", e);
            CacheError::SerdeJson
        })?;

        let mut stmt = self
            .conn
            .prepare("INSERT OR REPLACE INTO hsm_int_t (key, value) VALUES (:key, :value)")
            .map_err(|e| self.sqlite_error("prepare", &e))?;

        stmt.execute(named_params! {
            ":key": "mk",
            ":value": &data,
        })
        .map(|r| {
            trace!("insert -> {:?}", r);
        })
        .map_err(|e| self.sqlite_error("execute", &e))
    }

    fn get_hsm_hmac_key(&mut self) -> Result<Option<LoadableHmacKey>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM hsm_int_t WHERE key = 'hmac'")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        let data: Option<Vec<u8>> = stmt
            .query_row([], |row| row.get(0))
            .optional()
            .map_err(|e| self.sqlite_error("query_row", &e))?;

        match data {
            Some(d) => Ok(serde_json::from_slice(d.as_slice())
                .map_err(|e| {
                    error!("json error -> {:?}", e);
                })
                .ok()),
            None => Ok(None),
        }
    }

    fn insert_hsm_hmac_key(&mut self, hmac_key: &LoadableHmacKey) -> Result<(), CacheError> {
        let data = serde_json::to_vec(hmac_key).map_err(|e| {
            error!("insert_hsm_hmac_key json error -> {:?}", e);
            CacheError::SerdeJson
        })?;

        let mut stmt = self
            .conn
            .prepare("INSERT OR REPLACE INTO hsm_int_t (key, value) VALUES (:key, :value)")
            .map_err(|e| self.sqlite_error("prepare", &e))?;

        stmt.execute(named_params! {
            ":key": "hmac",
            ":value": &data,
        })
        .map(|r| {
            trace!("insert -> {:?}", r);
        })
        .map_err(|e| self.sqlite_error("execute", &e))
    }

    fn get_account(&mut self, account_id: &Id) -> Result<Option<(UserToken, u64)>, CacheError> {
        let data = match account_id {
            Id::Name(n) => self.get_account_data_name(n.as_str()),
            Id::Gid(g) => self.get_account_data_gid(*g),
        }?;

        // Assert only one result?
        if data.len() >= 2 {
            error!("invalid db state, multiple entries matched query?");
            return Err(CacheError::TooManyResults);
        }

        if let Some((token, expiry)) = data.first() {
            // token convert with json.
            // If this errors, we specifically return Ok(None) because that triggers
            // the cache to refetch the token.
            match serde_json::from_slice(token.as_slice()) {
                Ok(t) => {
                    let e = u64::try_from(*expiry).map_err(|e| {
                        error!("u64 convert error -> {:?}", e);
                        CacheError::Parse
                    })?;
                    Ok(Some((t, e)))
                }
                Err(e) => {
                    warn!("recoverable - json error -> {:?}", e);
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    fn get_accounts(&mut self) -> Result<Vec<UserToken>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT token FROM account_t")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        let data_iter = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<Vec<u8>>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
            .collect();

        let data = data?;

        Ok(data
            .iter()
            // We filter map here so that anything invalid is skipped.
            .filter_map(|token| {
                // token convert with json.
                serde_json::from_slice(token.as_slice())
                    .map_err(|e| {
                        warn!("get_accounts json error -> {:?}", e);
                    })
                    .ok()
            })
            .collect())
    }

    fn update_account(&mut self, account: &UserToken, expire: u64) -> Result<(), CacheError> {
        let group_expire = expire;
        let data = serde_json::to_vec(account).map_err(|e| {
            error!("update_account json error -> {:?}", e);
            CacheError::SerdeJson
        })?;
        let expire = i64::try_from(expire).map_err(|e| {
            error!("update_account i64 conversion error -> {:?}", e);
            CacheError::Parse
        })?;

        // This is needed because sqlites 'insert or replace into', will null the password field
        // if present, and upsert MUST match the exact conflicting column, so that means we have
        // to manually manage the update or insert :( :(
        let account_uuid = account.uuid.as_hyphenated().to_string();

        // A UPN change can otherwise strand the old per-user fallback group:
        // after account_t is updated, its old labels can no longer be proven to
        // belong to this account. Remove it while the previous SPN is available.
        let previous_spn = self
            .conn
            .query_row(
                "SELECT spn FROM account_t WHERE uuid = :uuid",
                named_params! { ":uuid": &account_uuid },
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| self.sqlite_error("select previous account spn", &e))?;
        if let Some(previous_spn) = previous_spn.filter(|spn| spn != &account.spn) {
            if let Some(group) = self.cached_group_by_uuid(account.uuid)? {
                if group.name == previous_spn
                    && group.spn == previous_spn
                    && self.is_private_cached_legacy_primary_group(&group, account.uuid)?
                {
                    self.delete_group(group.uuid)?;
                }
            }
        }

        // Find anything conflicting and purge it through delete_account so a
        // legacy per-user primary-group row is removed while the account row
        // still proves its origin.
        let mut stmt = self
            .conn
            .prepare("SELECT uuid FROM account_t WHERE NOT uuid = :uuid AND (name = :name OR spn = :spn OR gidnumber = :gidnumber)")
            .map_err(|e| self.sqlite_error("select account_t duplicate", &e))?;
        let duplicates = stmt
            .query_map(
                named_params! {
                ":uuid": &account_uuid,
                ":name": &account.name,
                ":spn": &account.spn,
                ":gidnumber": &account.gidnumber,
                },
                |row| row.get::<_, String>(0),
            )
            .map_err(|e| self.sqlite_error("query account_t duplicate", &e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| self.sqlite_error("collect account_t duplicate", &e))?;
        drop(stmt);
        for duplicate in duplicates {
            let uuid = Uuid::parse_str(&duplicate).map_err(|e| {
                error!("invalid cached account UUID: {:?}", e);
                CacheError::Parse
            })?;
            self.delete_account(uuid)?;
        }

        let updated = self.conn.execute(
                "UPDATE account_t SET name=:name, spn=:spn, gidnumber=:gidnumber, token=:token, expiry=:expiry WHERE uuid = :uuid",
            named_params!{
                ":uuid": &account_uuid,
                ":name": &account.name,
                ":spn": &account.spn,
                ":gidnumber": &account.gidnumber,
                ":token": &data,
                ":expiry": &expire,
            }
            )
            .map_err(|e| {
                self.sqlite_error("delete account_t duplicate", &e)
            })?;

        if updated == 0 {
            let mut stmt = self.conn
                .prepare("INSERT INTO account_t (uuid, name, spn, gidnumber, token, expiry) VALUES (:uuid, :name, :spn, :gidnumber, :token, :expiry) ON CONFLICT(uuid) DO UPDATE SET name=excluded.name, spn=excluded.name, gidnumber=excluded.gidnumber, token=excluded.token, expiry=excluded.expiry")
                .map_err(|e| {
                    self.sqlite_error("prepare", &e)
                })?;

            stmt.execute(named_params! {
                ":uuid": &account_uuid,
                ":name": &account.name,
                ":spn": &account.spn,
                ":gidnumber": &account.gidnumber,
                ":token": &data,
                ":expiry": &expire,
            })
            .map(|r| {
                trace!("insert -> {:?}", r);
            })
            .map_err(|error| self.sqlite_transaction_error(&error, &stmt))?;
        }

        // Now, we have to update the group memberships.

        // First remove everything that already exists:
        let mut stmt = self
            .conn
            .prepare("DELETE FROM memberof_t WHERE a_uuid = :a_uuid")
            .map_err(|e| self.sqlite_error("prepare", &e))?;

        stmt.execute([&account_uuid])
            .map(|r| {
                trace!("delete memberships -> {:?}", r);
            })
            .map_err(|error| self.sqlite_transaction_error(&error, &stmt))?;

        drop(stmt);
        // Preserve the synthetic authorization claim in the account token,
        // but never attach it to an unrelated provider row which happens to
        // occupy the same numeric GID in the shared cache.
        let mut groups = Vec::with_capacity(account.groups.len());
        let mut deferred_groups = Vec::new();
        for group in &account.groups {
            if is_synthetic_primary_group(group) {
                match self.get_group(&Id::Gid(group.gidnumber))? {
                    Some((cached, _)) if is_synthetic_primary_group(&cached) => {
                        groups.push(cached.uuid)
                    }
                    Some(_) => {}
                    None => groups.push(group.uuid),
                }
            } else {
                match self.cached_group_by_uuid(group.uuid)? {
                    Some(cached) if cached.gidnumber == group.gidnumber => groups.push(group.uuid),
                    _ => {
                        // A different provider identity may already own the
                        // incoming GID, while this UUID still names a stale row
                        // at its previous GID. Keep the claim in the serialized
                        // account token, but do not attach membership unless the
                        // cached identity matches the current numeric identity.
                        deferred_groups.push(group.clone());
                    }
                }
            }
        }
        let mut stmt = self
            .conn
            .prepare("INSERT INTO memberof_t (a_uuid, g_uuid) VALUES (:a_uuid, :g_uuid)")
            .map_err(|e| self.sqlite_error("prepare", &e))?;
        // Now for each group, add the relation.
        groups.iter().try_for_each(|group_uuid| {
            stmt.execute(named_params! {
                ":a_uuid": &account_uuid,
                ":g_uuid": &group_uuid.as_hyphenated().to_string(),
            })
            .map(|r| {
                trace!("insert membership -> {:?}", r);
            })
            .map_err(|error| self.sqlite_transaction_error(&error, &stmt))
        })?;
        drop(stmt);
        // Only unreferenced deterministic synthetic rows and legacy per-user
        // fallback rows may be removed. A second cached account sharing the old
        // GID keeps its row alive.
        let mut stmt = self.conn.prepare("SELECT token FROM group_t WHERE (name GLOB 'himmelblau-primary-group-*' OR spn GLOB 'himmelblau-primary-group-*' OR (name = spn AND EXISTS (SELECT 1 FROM account_t WHERE account_t.uuid = group_t.uuid AND account_t.spn = group_t.spn))) AND NOT EXISTS (SELECT 1 FROM memberof_t WHERE memberof_t.g_uuid = group_t.uuid)")
            .map_err(|e| self.sqlite_error("unused groups prepare", &e))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|e| self.sqlite_error("unused groups query", &e))?;
        let unused = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| self.sqlite_error("unused groups collect", &e))?;
        drop(stmt);
        for data in unused {
            // A corrupt unrelated row cannot be identified as synthetic;
            // retain it rather than blocking this account's cache update.
            if let Ok(group) = serde_json::from_slice::<GroupToken>(&data) {
                if is_synthetic_primary_group(&group)
                    || self.is_cached_legacy_primary_group(&group)?
                {
                    self.delete_group(group.uuid)?;
                }
            }
        }
        // A same-account Entra refresh can replace the old UPN-named fallback
        // with a real directory group at the same GID. The group update cannot
        // prove that transition while the ambiguous old row is still present,
        // so retry only after account reconciliation has removed the obsolete
        // membership and cleanup has freed the GID. Generic OIDC claims which
        // collide with their still-referenced primary row remain deferred.
        for group in deferred_groups {
            if self.get_group(&Id::Gid(group.gidnumber))?.is_none() {
                self.update_group_with_owner(&group, group_expire, Some(account.uuid))?;
                if self.cached_group_by_uuid(group.uuid)?.is_some() {
                    self.conn
                        .execute(
                            "INSERT INTO memberof_t (a_uuid, g_uuid) VALUES (:a_uuid, :g_uuid)",
                            named_params! {
                                ":a_uuid": &account_uuid,
                                ":g_uuid": group.uuid.as_hyphenated().to_string(),
                            },
                        )
                        .map_err(|e| self.sqlite_error("insert deferred membership", &e))?;
                }
            }
        }
        Ok(())
    }

    fn delete_account(&mut self, a_uuid: Uuid) -> Result<(), CacheError> {
        let account_uuid = a_uuid.as_hyphenated().to_string();

        // A legacy fallback is private only when no other cached account uses
        // it. A generic claim can otherwise share its UUID and labels.
        let private_legacy_group = match self.cached_group_by_uuid(a_uuid)? {
            Some(group) if self.is_private_cached_legacy_primary_group(&group, a_uuid)? => {
                Some(group)
            }
            _ => None,
        };

        self.conn
            .execute(
                "DELETE FROM memberof_t WHERE a_uuid = :a_uuid",
                params![&account_uuid],
            )
            .map(|_| ())
            .map_err(|e| self.sqlite_error("account_t memberof_t cascade delete", &e))?;

        if let Some(group) = private_legacy_group {
            // Use the normal cascade path even though the ownership check
            // proves that only this account could have referenced the row.
            self.delete_group(group.uuid)?;
        }

        self.conn
            .execute(
                "DELETE FROM account_t WHERE uuid = :a_uuid",
                params![&account_uuid],
            )
            .map(|_| ())
            .map_err(|e| self.sqlite_error("account_t delete", &e))
    }

    fn update_account_password(
        &mut self,
        a_uuid: Uuid,
        cred: &str,
        tpm: &mut BoxedDynTpm,
        hmac_key: &HmacKey,
    ) -> Result<(), CacheError> {
        let tpm_ctx: &mut dyn TpmHmacS256 = &mut **tpm;

        let pw = Password::new_argon2id_hsm(self.crypto_policy, cred, tpm_ctx, hmac_key).map_err(
            |e| {
                error!("password error -> {:?}", e);
                CacheError::Cryptography
            },
        )?;

        let dbpw = pw.to_dbpasswordv1();
        let data = serde_json::to_vec(&dbpw).map_err(|e| {
            error!("json error -> {:?}", e);
            CacheError::SerdeJson
        })?;

        self.conn
            .execute(
                "UPDATE account_t SET password = :data WHERE uuid = :a_uuid",
                named_params! {
                    ":a_uuid": &a_uuid.as_hyphenated().to_string(),
                    ":data": &data,
                },
            )
            .map_err(|e| self.sqlite_error("update account_t password", &e))
            .map(|_| ())
    }

    fn check_account_password(
        &mut self,
        a_uuid: Uuid,
        cred: &str,
        tpm: &mut BoxedDynTpm,
        hmac_key: &HmacKey,
    ) -> Result<bool, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT password FROM account_t WHERE uuid = :a_uuid AND password IS NOT NULL")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map([a_uuid.as_hyphenated().to_string()], |row| row.get(0))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<Vec<u8>>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
            .collect();

        let data = data?;

        if data.is_empty() {
            info!("No cached password, failing authentication");
            return Ok(false);
        }

        if data.len() >= 2 {
            error!("invalid db state, multiple entries matched query?");
            return Err(CacheError::TooManyResults);
        }

        let pw = data.first().map(|raw| {
            // Map the option from data.first.
            let dbpw: DbPasswordV1 = serde_json::from_slice(raw.as_slice()).map_err(|e| {
                error!("json error -> {:?}", e);
            })?;
            Password::try_from(dbpw)
        });

        let pw = match pw {
            Some(Ok(p)) => p,
            _ => return Ok(false),
        };

        let tpm_ctx: &mut dyn TpmHmacS256 = &mut **tpm;

        pw.verify_ctx(cred, Some((tpm_ctx, hmac_key))).map_err(|e| {
            error!("password error -> {:?}", e);
            CacheError::Cryptography
        })
    }

    fn get_group(&mut self, grp_id: &Id) -> Result<Option<(GroupToken, u64)>, CacheError> {
        let data = match grp_id {
            Id::Name(n) => self.get_group_data_name(n.as_str()),
            Id::Gid(g) => self.get_group_data_gid(*g),
        }?;

        // Assert only one result?
        if data.len() >= 2 {
            error!("invalid db state, multiple entries matched query?");
            return Err(CacheError::TooManyResults);
        }

        if let Some((token, expiry)) = data.first() {
            // token convert with json.
            // If this errors, we specifically return Ok(None) because that triggers
            // the cache to refetch the token.
            match serde_json::from_slice(token.as_slice()) {
                Ok(t) => {
                    let e = u64::try_from(*expiry).map_err(|e| {
                        error!("u64 convert error -> {:?}", e);
                        CacheError::Parse
                    })?;
                    Ok(Some((t, e)))
                }
                Err(e) => {
                    warn!("recoverable - json error -> {:?}", e);
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    fn get_group_members(&mut self, g_uuid: Uuid) -> Result<Vec<UserToken>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT account_t.token FROM (account_t, memberof_t) WHERE account_t.uuid = memberof_t.a_uuid AND memberof_t.g_uuid = :g_uuid")
            .map_err(|e| {
                self.sqlite_error("select prepare", &e)
            })?;

        let data_iter = stmt
            .query_map([g_uuid.as_hyphenated().to_string()], |row| row.get(0))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<Vec<u8>>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
            .collect();

        let data = data?;

        data.iter()
            .map(|token| {
                // token convert with json.
                // trace!("{:?}", token);
                serde_json::from_slice(token.as_slice()).map_err(|e| {
                    error!("json error -> {:?}", e);
                    CacheError::SerdeJson
                })
            })
            .collect()
    }

    fn get_groups(&mut self) -> Result<Vec<GroupToken>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT token FROM group_t")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        let data_iter = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<Vec<u8>>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
            .collect();

        let data = data?;

        Ok(data
            .iter()
            .filter_map(|token| {
                // token convert with json.
                // trace!("{:?}", token);
                serde_json::from_slice(token.as_slice())
                    .map_err(|e| {
                        error!("json error -> {:?}", e);
                    })
                    .ok()
            })
            .collect())
    }

    fn update_group_with_owner(
        &mut self,
        grp: &GroupToken,
        expire: u64,
        owner: Option<Uuid>,
    ) -> Result<(), CacheError> {
        let synthetic = is_synthetic_primary_group(grp);
        let mut stored = grp.clone();
        if !synthetic {
            // Generic OIDC claims may legitimately use the textual namespace
            // reserved by the Entra synthetic-group implementation. If such a
            // claim arrives after a stale synthetic cache row, remove that row
            // and its NSS memberships before INSERT OR REPLACE can orphan them.
            let mut stmt = self
                .conn
                .prepare("SELECT token FROM group_t WHERE uuid != :uuid AND (name = :name OR name = :spn OR spn = :name OR spn = :spn)")
                .map_err(|e| self.sqlite_error("synthetic label collision prepare", &e))?;
            let rows = stmt
                .query_map(
                    named_params! {
                        ":uuid": grp.uuid.as_hyphenated().to_string(),
                        ":name": &grp.name,
                        ":spn": &grp.spn,
                    },
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(|e| self.sqlite_error("synthetic label collision query", &e))?;
            let collisions = rows
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| self.sqlite_error("synthetic label collision collect", &e))?;
            drop(stmt);
            let mut isolate_labels = false;
            for data in collisions {
                if let Ok(cached) = serde_json::from_slice::<GroupToken>(&data) {
                    if is_synthetic_primary_group(&cached) {
                        self.delete_group(cached.uuid)?;
                    } else if self.is_cached_legacy_primary_group(&cached)?
                        || self
                            .conn
                            .query_row(
                                "SELECT EXISTS(SELECT 1 FROM memberof_t WHERE g_uuid = ?1)",
                                [cached.uuid.to_string()],
                                |row| row.get::<_, bool>(0),
                            )
                            .map_err(|e| self.sqlite_error("group membership lookup", &e))?
                    {
                        // An account-shaped row may be either an old Entra
                        // fallback or generic OIDC's synthesized primary group;
                        // its shape is not provider provenance. Preserve it, as
                        // well as any other referenced provider identity, and
                        // isolate the incoming cache identity under a stable
                        // UUID-derived alias. Keep established replacement
                        // behavior only for unreferenced ordinary duplicates.
                        isolate_labels = true;
                    }
                }
            }
            if isolate_labels {
                let base = format!("himmelblau-directory-group-{}", grp.uuid);
                let mut alias = base.clone();
                let mut suffix = 0u64;
                while self
                    .conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM group_t WHERE uuid != ?1 AND (name = ?2 OR spn = ?2))",
                        rusqlite::params![grp.uuid.to_string(), alias],
                        |row| row.get::<_, bool>(0),
                    )
                    .map_err(|e| self.sqlite_error("provider group alias lookup", &e))?
                {
                    suffix += 1;
                    alias = format!("{base}-{suffix}");
                }
                stored.name = alias.clone();
                stored.spn = alias;
            }
        }
        let mut discarded_primary = None;
        let replaced_primary = match self.get_group(&Id::Gid(grp.gidnumber))? {
            Some((cached, _)) if cached.uuid != grp.uuid => {
                if synthetic && !is_synthetic_primary_group(&cached) {
                    if let Some(owner) = owner {
                        if self.canonicalize_cached_legacy_primary_group(&cached, grp, owner)? {
                            Some(cached)
                        } else {
                            // A genuine directory group or another provider's
                            // account group owns this GID. Preserve it;
                            // update_account will avoid granting membership.
                            return Ok(());
                        }
                    } else {
                        return Ok(());
                    }
                } else if !synthetic && is_synthetic_primary_group(&cached) {
                    // Provider provenance is unavailable at this layer. Do not
                    // turn stale Entra fallback memberships into authorization
                    // for an unrelated generic OIDC group sharing its GID.
                    discarded_primary = Some(cached);
                    None
                } else if !synthetic {
                    let referenced = self
                        .conn
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM memberof_t WHERE g_uuid = ?1)",
                            [cached.uuid.to_string()],
                            |row| row.get::<_, bool>(0),
                        )
                        .map_err(|e| self.sqlite_error("group membership lookup", &e))?;
                    if self.is_cached_legacy_primary_group(&cached)? || referenced {
                        // UUID/name/SPN shape is not provider provenance: a
                        // generic OIDC primary group has the same shape as the
                        // old Entra fallback. Preserve ambiguous or referenced
                        // identities instead of letting SQLite's GID conflict
                        // replacement delete their row and memberships.
                        return Ok(());
                    }
                    None
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(previous) = discarded_primary {
            self.delete_group(previous.uuid)?;
        }
        if synthetic {
            let occupied = self
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM group_t WHERE uuid != ?1 AND (name = ?2 OR spn = ?2 OR name = ?3 OR spn = ?3))",
                    rusqlite::params![grp.uuid.to_string(), &grp.name, &grp.spn],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|e| self.sqlite_error("synthetic group collision lookup", &e))?;
            if occupied {
                // Generic OIDC claims may legitimately own the canonical text.
                // Keep that identity unchanged and give the deterministic Entra
                // row a stable cache/NSS alias instead.
                let base = format!("{}-synthetic", grp.name);
                let mut alias = base.clone();
                let mut suffix = 0u64;
                while self
                    .conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM group_t WHERE uuid != ?1 AND (name = ?2 OR spn = ?2))",
                        rusqlite::params![grp.uuid.to_string(), alias],
                        |row| row.get::<_, bool>(0),
                    )
                    .map_err(|e| self.sqlite_error("synthetic group alias lookup", &e))?
                {
                    suffix += 1;
                    alias = format!("{base}-{suffix}");
                }
                stored.name = alias.clone();
                stored.spn = alias;
            }
        }
        let data = serde_json::to_vec(&stored).map_err(|e| {
            error!("json error -> {:?}", e);
            CacheError::SerdeJson
        })?;
        let expire = i64::try_from(expire).map_err(|e| {
            error!("i64 convert error -> {:?}", e);
            CacheError::Parse
        })?;

        let mut stmt = self.conn
            .prepare("INSERT OR REPLACE INTO group_t (uuid, name, spn, gidnumber, token, expiry) VALUES (:uuid, :name, :spn, :gidnumber, :token, :expiry)")
            .map_err(|e| {
                self.sqlite_error("prepare", &e)
            })?;

        // We have to to-str uuid as the sqlite impl makes it a blob which breaks our selects in get.
        stmt.execute(named_params! {
            ":uuid": &stored.uuid.as_hyphenated().to_string(),
            ":name": &stored.name,
            ":spn": &stored.spn,
            ":gidnumber": &stored.gidnumber,
            ":token": &data,
            ":expiry": &expire,
        })
        .map(|r| {
            trace!("insert -> {:?}", r);
        })
        .map_err(|e| self.sqlite_error("execute", &e))?;
        if let Some(previous) = replaced_primary {
            self.conn
                .execute(
                    "UPDATE memberof_t SET g_uuid = :new_uuid WHERE g_uuid = :old_uuid",
                    named_params! {
                        ":new_uuid": grp.uuid.as_hyphenated().to_string(),
                        ":old_uuid": previous.uuid.as_hyphenated().to_string(),
                    },
                )
                .map_err(|e| self.sqlite_error("migrate synthetic memberships", &e))?;
        }
        Ok(())
    }

    fn delete_group(&mut self, g_uuid: Uuid) -> Result<(), CacheError> {
        let group_uuid = g_uuid.as_hyphenated().to_string();
        self.conn
            .execute(
                "DELETE FROM memberof_t WHERE g_uuid = :g_uuid",
                [&group_uuid],
            )
            .map(|_| ())
            .map_err(|e| self.sqlite_error("group_t memberof_t cascade delete", &e))?;
        self.conn
            .execute("DELETE FROM group_t WHERE uuid = :g_uuid", [&group_uuid])
            .map(|_| ())
            .map_err(|e| self.sqlite_error("group_t delete", &e))
    }
}

impl<'a> fmt::Debug for DbTxn<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DbTxn {{}}")
    }
}

impl<'a> Drop for DbTxn<'a> {
    // Abort
    fn drop(&mut self) {
        if !self.committed {
            // trace!("Aborting BE WR txn");
            #[allow(clippy::expect_used)]
            self.conn
                .execute("ROLLBACK TRANSACTION", [])
                .expect("Unable to rollback transaction! Can not proceed!!!");
        }
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn duplicate_account_purge_removes_legacy_primary_group() {
        use crate::idprovider::himmelblau::synthetic_primary_group;

        let db = super::Db::new("").expect("database");
        let mut txn = db.write().await;
        txn.migrate().expect("schema");
        let old = super::UserToken {
            name: "alice".into(),
            spn: "alice@example.com".into(),
            uuid: uuid::uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            gidnumber: 2400,
            real_gidnumber: None,
            displayname: "Alice".into(),
            shell: None,
            groups: vec![],
            tenant_id: None,
            valid: true,
        };
        let legacy = super::GroupToken {
            name: old.spn.clone(),
            spn: old.spn.clone(),
            uuid: old.uuid,
            gidnumber: old.gidnumber,
        };
        let mut old = old;
        old.groups = vec![legacy.clone()];
        txn.update_group(&legacy, 0).expect("legacy group");
        txn.update_account(&old, 0).expect("old account");

        let mut replacement = old.clone();
        replacement.uuid = uuid::uuid!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        replacement.spn = "replacement@example.com".into();
        replacement.gidnumber = 3000;
        replacement.groups.clear();
        txn.update_account(&replacement, 0)
            .expect("replace duplicate name");

        assert!(txn
            .get_group(&super::Id::Name(old.spn.clone()))
            .expect("legacy lookup")
            .is_none());
        let synthetic = synthetic_primary_group(legacy.gidnumber);
        txn.update_group(&synthetic, 0)
            .expect("reused GID accepts canonical synthetic group");
        assert_eq!(
            txn.get_group(&super::Id::Gid(legacy.gidnumber))
                .expect("synthetic lookup")
                .expect("canonical synthetic group")
                .0
                .uuid,
            synthetic.uuid
        );
        txn.commit().expect("valid duplicate cleanup");
    }

    #[tokio::test]
    async fn deleting_account_preserves_shared_generic_group() {
        let db = super::Db::new("").expect("database");
        let mut txn = db.write().await;
        txn.migrate().expect("schema");
        let owner = super::UserToken {
            name: "alice".into(),
            spn: "alice@example.com".into(),
            uuid: uuid::uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            gidnumber: 2400,
            real_gidnumber: None,
            displayname: "Alice".into(),
            shell: None,
            groups: vec![],
            tenant_id: None,
            valid: true,
        };
        let generic = super::GroupToken {
            name: owner.spn.clone(),
            spn: owner.spn.clone(),
            uuid: owner.uuid,
            gidnumber: owner.gidnumber,
        };
        txn.update_group(&generic, 0).expect("generic group");
        let mut owner = owner;
        owner.groups = vec![generic.clone()];
        txn.update_account(&owner, 0).expect("owner account");
        let other = super::UserToken {
            name: "bob".into(),
            spn: "bob@example.com".into(),
            uuid: uuid::uuid!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            gidnumber: 2500,
            real_gidnumber: None,
            displayname: "Bob".into(),
            shell: None,
            groups: vec![generic.clone()],
            tenant_id: None,
            valid: true,
        };
        txn.update_account(&other, 0).expect("other account");

        txn.delete_account(owner.uuid).expect("delete owner");

        assert_eq!(
            txn.get_group(&super::Id::Gid(generic.gidnumber))
                .expect("group lookup")
                .expect("shared generic group retained")
                .0
                .uuid,
            generic.uuid
        );
        assert_eq!(
            txn.get_group_members(generic.uuid).expect("members")[0].uuid,
            other.uuid
        );
        txn.commit().expect("no dangling memberships");
    }

    #[tokio::test]
    async fn generic_label_collision_isolates_private_account_group() {
        let db = super::Db::new("").expect("database");
        let mut txn = db.write().await;
        txn.migrate().expect("schema");
        let owner = super::UserToken {
            name: "alice".into(),
            spn: "alice@example.com".into(),
            uuid: uuid::uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            gidnumber: 2400,
            real_gidnumber: None,
            displayname: "Alice".into(),
            shell: None,
            groups: vec![],
            tenant_id: None,
            valid: true,
        };
        let legacy = super::GroupToken {
            name: owner.spn.clone(),
            spn: owner.spn.clone(),
            uuid: owner.uuid,
            gidnumber: owner.gidnumber,
        };
        txn.update_group(&legacy, 0).expect("legacy group");
        let mut owner = owner;
        owner.groups = vec![legacy.clone()];
        txn.update_account(&owner, 0).expect("owner account");
        let provider = super::GroupToken {
            name: legacy.name.clone(),
            spn: legacy.spn.clone(),
            uuid: uuid::uuid!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            gidnumber: 2500,
        };

        txn.update_group(&provider, 0)
            .expect("provider isolates ambiguous account labels");

        let retained = txn
            .cached_group_by_uuid(legacy.uuid)
            .expect("legacy lookup")
            .expect("account-shaped group retained");
        assert_eq!(retained.name, legacy.name);
        assert_eq!(retained.spn, legacy.spn);
        assert_eq!(
            txn.get_group_members(legacy.uuid)
                .expect("owner membership")[0]
                .uuid,
            owner.uuid
        );
        let expected_alias = format!("himmelblau-directory-group-{}", provider.uuid);
        let cached = txn
            .cached_group_by_uuid(provider.uuid)
            .expect("provider lookup")
            .expect("provider group");
        assert_eq!(cached.name, expected_alias);
        assert_eq!(cached.spn, expected_alias);
        assert!(txn
            .get_group_members(provider.uuid)
            .expect("provider members")
            .is_empty());

        txn.update_group(&provider, 0)
            .expect("provider refresh remains isolated");
        let refreshed = txn
            .cached_group_by_uuid(provider.uuid)
            .expect("refreshed provider lookup")
            .expect("refreshed provider group");
        assert_eq!(refreshed.name, expected_alias);
        assert_eq!(refreshed.spn, expected_alias);
        assert!(txn
            .cached_group_by_uuid(legacy.uuid)
            .expect("legacy refresh lookup")
            .is_some());
        txn.commit().expect("no dangling account membership");
    }

    #[tokio::test]
    async fn generic_label_collision_isolates_shared_legacy_identity() {
        let db = super::Db::new("").expect("database");
        let mut txn = db.write().await;
        txn.migrate().expect("schema");
        let owner = super::UserToken {
            name: "alice".into(),
            spn: "alice@example.com".into(),
            uuid: uuid::uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            gidnumber: 2400,
            real_gidnumber: None,
            displayname: "Alice".into(),
            shell: None,
            groups: vec![],
            tenant_id: None,
            valid: true,
        };
        let shared = super::GroupToken {
            name: owner.spn.clone(),
            spn: owner.spn.clone(),
            uuid: owner.uuid,
            gidnumber: owner.gidnumber,
        };
        txn.update_group(&shared, 0).expect("shared group");
        let mut owner = owner;
        owner.groups = vec![shared.clone()];
        txn.update_account(&owner, 0).expect("owner account");
        let other = super::UserToken {
            name: "bob".into(),
            spn: "bob@example.com".into(),
            uuid: uuid::uuid!("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            gidnumber: 2600,
            real_gidnumber: None,
            displayname: "Bob".into(),
            shell: None,
            groups: vec![shared.clone()],
            tenant_id: None,
            valid: true,
        };
        txn.update_account(&other, 0).expect("other account");
        let provider = super::GroupToken {
            name: shared.name.clone(),
            spn: shared.spn.clone(),
            uuid: uuid::uuid!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            gidnumber: 2500,
        };

        txn.update_group(&provider, 0)
            .expect("provider labels are isolated");

        let preserved = txn
            .cached_group_by_uuid(shared.uuid)
            .expect("shared lookup")
            .expect("shared group preserved");
        assert_eq!(preserved.uuid, shared.uuid);
        assert_eq!(preserved.name, shared.name);
        assert_eq!(preserved.spn, shared.spn);
        assert_eq!(preserved.gidnumber, shared.gidnumber);
        assert_eq!(
            txn.get_group_members(shared.uuid).expect("members").len(),
            2
        );
        let cached = txn
            .cached_group_by_uuid(provider.uuid)
            .expect("provider lookup")
            .expect("provider group");
        assert_eq!(
            cached.name,
            format!("himmelblau-directory-group-{}", provider.uuid)
        );
        assert_eq!(cached.spn, cached.name);
        txn.commit().expect("shared identity remains consistent");
    }

    #[tokio::test]
    async fn synthetic_gid_collision_preserves_other_provider_owner() {
        use crate::idprovider::himmelblau::synthetic_primary_group;

        let db = super::Db::new("").expect("database");
        let mut txn = db.write().await;
        txn.migrate().expect("schema");
        let owner = super::UserToken {
            name: "alice".into(),
            spn: "alice@example.com".into(),
            uuid: uuid::uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            gidnumber: 1000,
            real_gidnumber: Some(2400),
            displayname: "Alice".into(),
            shell: None,
            groups: vec![],
            tenant_id: None,
            valid: true,
        };
        // Generic OIDC synthesizes exactly this account-group shape, which is
        // indistinguishable in the shared cache from the old Entra fallback.
        let oidc_group = super::GroupToken {
            name: owner.spn.clone(),
            spn: owner.spn.clone(),
            uuid: owner.uuid,
            gidnumber: 2400,
        };
        txn.update_group_with_owner(&oidc_group, 0, Some(owner.uuid))
            .expect("OIDC account group");
        let mut owner = owner;
        owner.groups = vec![oidc_group.clone()];
        txn.update_account(&owner, 0).expect("OIDC account");

        let synthetic = synthetic_primary_group(oidc_group.gidnumber);
        let second = super::UserToken {
            name: "bob".into(),
            spn: "bob@example.com".into(),
            uuid: uuid::uuid!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            gidnumber: 3000,
            real_gidnumber: Some(synthetic.gidnumber),
            displayname: "Bob".into(),
            shell: None,
            groups: vec![synthetic.clone()],
            tenant_id: None,
            valid: true,
        };
        txn.update_group_with_owner(&synthetic, 0, Some(second.uuid))
            .expect("preserve ambiguous GID owner");
        txn.update_account(&second, 0).expect("Entra account");

        let cached_owner = txn
            .get_account(&super::Id::Name(owner.spn.clone()))
            .expect("owner lookup")
            .expect("owner account retained")
            .0;
        assert_eq!(cached_owner.groups.len(), 1);
        assert_eq!(cached_owner.groups[0].uuid, oidc_group.uuid);
        assert_eq!(cached_owner.groups[0].name, oidc_group.name);
        assert_eq!(
            txn.get_group_members(oidc_group.uuid)
                .expect("OIDC members")[0]
                .uuid,
            owner.uuid
        );
        assert!(txn
            .cached_group_by_uuid(synthetic.uuid)
            .expect("synthetic lookup")
            .is_none());

        // Refreshing either provider must not alternate the cached GID owner.
        for account in [&owner, &second] {
            txn.update_group_with_owner(&account.groups[0], 0, Some(account.uuid))
                .expect("refresh provider group");
            txn.update_account(account, 0)
                .expect("refresh provider account");
        }
        assert_eq!(
            txn.get_group(&super::Id::Gid(oidc_group.gidnumber))
                .expect("GID lookup")
                .expect("OIDC group retained")
                .0
                .uuid,
            oidc_group.uuid
        );
        assert_eq!(
            txn.get_group_members(oidc_group.uuid)
                .expect("OIDC members after refresh")[0]
                .uuid,
            owner.uuid
        );
        txn.commit().expect("provider identities remain stable");
    }

    #[tokio::test]
    async fn generic_gid_collision_preserves_ambiguous_account_group() {
        let db = super::Db::new("").expect("database");
        let mut txn = db.write().await;
        txn.migrate().expect("schema");
        let owner = super::UserToken {
            name: "alice".into(),
            spn: "alice@example.com".into(),
            uuid: uuid::uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            gidnumber: 2400,
            real_gidnumber: Some(2400),
            displayname: "Alice".into(),
            shell: None,
            groups: vec![],
            tenant_id: None,
            valid: true,
        };
        // Generic OIDC creates this account-shaped primary group. Its shape is
        // indistinguishable from the old Entra per-user fallback.
        let primary = super::GroupToken {
            name: owner.spn.clone(),
            spn: owner.spn.clone(),
            uuid: owner.uuid,
            gidnumber: owner.gidnumber,
        };
        txn.update_group_with_owner(&primary, 0, Some(owner.uuid))
            .expect("OIDC primary group");
        let mut owner = owner;
        owner.groups = vec![primary.clone()];
        txn.update_account(&owner, 0).expect("OIDC owner account");

        let incoming = super::GroupToken {
            name: "unrelated-provider-claim".into(),
            spn: "unrelated-provider-claim@example.net".into(),
            uuid: uuid::uuid!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            gidnumber: primary.gidnumber,
        };
        let second = super::UserToken {
            name: "bob".into(),
            spn: "bob@example.com".into(),
            uuid: uuid::uuid!("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            gidnumber: 3000,
            real_gidnumber: Some(incoming.gidnumber),
            displayname: "Bob".into(),
            shell: None,
            groups: vec![incoming.clone()],
            tenant_id: None,
            valid: true,
        };
        txn.update_group_with_owner(&incoming, 0, Some(second.uuid))
            .expect("ambiguous GID owner is preserved");
        txn.update_account(&second, 0)
            .expect("uncached claim does not create a dangling membership");

        assert_eq!(
            txn.get_group(&super::Id::Gid(primary.gidnumber))
                .expect("GID lookup")
                .expect("OIDC primary retained")
                .0
                .uuid,
            primary.uuid
        );
        assert!(txn
            .cached_group_by_uuid(incoming.uuid)
            .expect("incoming lookup")
            .is_none());
        assert_eq!(
            txn.get_group_members(primary.uuid)
                .expect("primary members")
                .iter()
                .map(|account| account.uuid)
                .collect::<Vec<_>>(),
            vec![owner.uuid]
        );
        let cached_second = txn
            .get_account(&super::Id::Name(second.spn.clone()))
            .expect("second account lookup")
            .expect("second account cached")
            .0;
        assert_eq!(cached_second.groups.len(), 1);
        assert_eq!(cached_second.groups[0].uuid, incoming.uuid);
        assert_eq!(cached_second.groups[0].name, incoming.name);
        assert_eq!(cached_second.groups[0].spn, incoming.spn);
        assert_eq!(cached_second.groups[0].gidnumber, incoming.gidnumber);

        txn.update_group_with_owner(&incoming, 0, Some(second.uuid))
            .expect("provider refresh remains non-destructive");
        txn.update_account(&second, 0)
            .expect("provider account refresh remains consistent");
        assert_eq!(
            txn.get_group(&super::Id::Gid(primary.gidnumber))
                .expect("refreshed GID lookup")
                .expect("refreshed primary retained")
                .0
                .uuid,
            primary.uuid
        );
        txn.commit().expect("no dangling provider membership");
    }

    #[tokio::test]
    async fn changed_group_gid_does_not_reuse_stale_uuid_membership() {
        let db = super::Db::new("").expect("database");
        let mut txn = db.write().await;
        txn.migrate().expect("schema");
        let stale = super::GroupToken {
            name: "directory-group".into(),
            spn: "directory-group@example.com".into(),
            uuid: uuid::uuid!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            gidnumber: 2400,
        };
        txn.update_group(&stale, 0).expect("old group GID");
        let mut user = super::UserToken {
            name: "alice".into(),
            spn: "alice@example.com".into(),
            uuid: uuid::uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            gidnumber: 2000,
            real_gidnumber: Some(stale.gidnumber),
            displayname: "Alice".into(),
            shell: None,
            groups: vec![stale.clone()],
            tenant_id: None,
            valid: true,
        };
        txn.update_account(&user, 0).expect("old group membership");

        let occupied = super::GroupToken {
            name: "other-provider-group".into(),
            spn: "other-provider-group@example.net".into(),
            uuid: uuid::uuid!("dddddddd-dddd-dddd-dddd-dddddddddddd"),
            gidnumber: 2500,
        };
        txn.update_group(&occupied, 0).expect("occupied target GID");
        let other = super::UserToken {
            name: "bob".into(),
            spn: "bob@example.net".into(),
            uuid: uuid::uuid!("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            gidnumber: 3000,
            real_gidnumber: Some(occupied.gidnumber),
            displayname: "Bob".into(),
            shell: None,
            groups: vec![occupied.clone()],
            tenant_id: None,
            valid: true,
        };
        txn.update_account(&other, 0)
            .expect("target GID membership");

        let mut incoming = stale.clone();
        incoming.gidnumber = occupied.gidnumber;
        txn.update_group_with_owner(&incoming, 0, Some(user.uuid))
            .expect("referenced target GID is preserved");
        user.real_gidnumber = Some(incoming.gidnumber);
        user.groups = vec![incoming.clone()];
        txn.update_account(&user, 0)
            .expect("changed GID remains deferred");

        let cached_stale = txn
            .cached_group_by_uuid(stale.uuid)
            .expect("stale UUID lookup")
            .expect("stale row retained");
        assert_eq!(cached_stale.gidnumber, stale.gidnumber);
        assert!(txn
            .get_group_members(stale.uuid)
            .expect("stale memberships")
            .is_empty());
        assert_eq!(
            txn.get_group_members(occupied.uuid)
                .expect("occupied memberships")
                .iter()
                .map(|account| account.uuid)
                .collect::<Vec<_>>(),
            vec![other.uuid]
        );
        let cached_user = txn
            .get_account(&super::Id::Name(user.spn.clone()))
            .expect("user lookup")
            .expect("user account")
            .0;
        assert_eq!(cached_user.groups[0].uuid, incoming.uuid);
        assert_eq!(cached_user.groups[0].gidnumber, incoming.gidnumber);
        txn.commit().expect("no stale-GID membership");
    }

    #[tokio::test]
    async fn generic_gid_collision_discards_stale_synthetic_memberships() {
        use crate::idprovider::himmelblau::synthetic_primary_group;

        let db = super::Db::new("").expect("database");
        let mut txn = db.write().await;
        txn.migrate().expect("schema");
        let synthetic = synthetic_primary_group(2400);
        txn.update_group(&synthetic, 0).expect("synthetic group");
        let stale_user = super::UserToken {
            name: "alice".into(),
            spn: "alice@example.com".into(),
            uuid: uuid::uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            gidnumber: 2400,
            real_gidnumber: None,
            displayname: "Alice".into(),
            shell: None,
            groups: vec![synthetic.clone()],
            tenant_id: None,
            valid: true,
        };
        txn.update_account(&stale_user, 0).expect("stale account");
        let generic = super::GroupToken {
            name: "unrelated-claim".into(),
            spn: "unrelated-claim@example.net".into(),
            uuid: uuid::uuid!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            gidnumber: synthetic.gidnumber,
        };

        txn.update_group(&generic, 0).expect("generic replacement");

        assert!(txn
            .get_group_members(generic.uuid)
            .expect("generic members")
            .is_empty());
        assert!(txn
            .get_group(&super::Id::Name(synthetic.uuid.to_string()))
            .expect("synthetic lookup")
            .is_none());
        txn.commit().expect("no dangling memberships");
    }

    #[tokio::test]
    async fn synthetic_claim_does_not_join_cached_generic_gid_collision() {
        use crate::idprovider::himmelblau::synthetic_primary_group;

        let db = super::Db::new("").expect("database");
        let mut txn = db.write().await;
        txn.migrate().expect("schema");
        let generic = super::GroupToken {
            name: "generic-claim".into(),
            spn: "generic-claim@example.net".into(),
            uuid: uuid::uuid!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            gidnumber: 2400,
        };
        txn.update_group(&generic, 0).expect("generic group");
        let synthetic = synthetic_primary_group(generic.gidnumber);
        txn.update_group(&synthetic, 0)
            .expect("synthetic collision is non-destructive");
        let user = super::UserToken {
            name: "alice".into(),
            spn: "alice@example.com".into(),
            uuid: uuid::uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            gidnumber: synthetic.gidnumber,
            real_gidnumber: Some(synthetic.gidnumber),
            displayname: "Alice".into(),
            shell: None,
            groups: vec![synthetic],
            tenant_id: None,
            valid: true,
        };

        txn.update_account(&user, 0).expect("cache user");

        assert!(txn
            .get_group_members(generic.uuid)
            .expect("generic members")
            .is_empty());
        assert_eq!(
            txn.get_group(&super::Id::Gid(generic.gidnumber))
                .expect("GID lookup")
                .expect("generic group retained")
                .0
                .uuid,
            generic.uuid
        );
        txn.commit().expect("no cross-provider membership");
    }

    #[tokio::test]
    async fn synthetic_name_collision_preserves_generic_identity_and_members() {
        use crate::idprovider::himmelblau::{is_synthetic_primary_group, synthetic_primary_group};
        let db = super::Db::new("").expect("database");
        let mut txn = db.write().await;
        txn.migrate().expect("schema");
        let synthetic = synthetic_primary_group(2400);
        let real = super::GroupToken {
            uuid: uuid::uuid!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            name: synthetic.name.clone(),
            spn: synthetic.spn.clone(),
            gidnumber: 2500,
        };
        // Emulate an older cache populated before the namespace was reserved.
        txn.conn.execute("INSERT INTO group_t (uuid,name,spn,gidnumber,token,expiry) VALUES (?1,?2,?3,?4,?5,0)", rusqlite::params![real.uuid.to_string(), real.name, real.spn, real.gidnumber, serde_json::to_vec(&real).expect("token JSON")]).expect("seed old group");
        let user = super::UserToken {
            name: "alice".into(),
            spn: "alice@example.com".into(),
            uuid: uuid::uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            gidnumber: 1000,
            real_gidnumber: Some(2500),
            displayname: "Alice".into(),
            shell: None,
            groups: vec![real.clone()],
            tenant_id: None,
            valid: true,
        };
        txn.update_account(&user, 0).expect("old group member");
        let occupied_alias = super::GroupToken {
            uuid: uuid::uuid!("dddddddd-dddd-dddd-dddd-dddddddddddd"),
            name: format!("{}-synthetic", synthetic.name),
            spn: "other-directory-group".into(),
            gidnumber: 2600,
        };
        txn.update_group(&occupied_alias, 0)
            .expect("existing migration-alias name");
        txn.update_group(&synthetic, 0)
            .expect("migrate conflicting reserved labels");
        let (cached, _) = txn
            .get_group(&super::Id::Gid(2500))
            .expect("lookup")
            .expect("real group preserved");
        assert_eq!(cached.uuid, real.uuid);
        assert_eq!(cached.gidnumber, real.gidnumber);
        assert_eq!(cached.name, real.name);
        assert_eq!(cached.spn, real.spn);
        assert_eq!(
            txn.get_group_members(real.uuid).expect("members")[0].uuid,
            user.uuid
        );
        let (stored_synthetic, _) = txn
            .get_group(&super::Id::Gid(2400))
            .expect("synthetic lookup")
            .expect("synthetic inserted");
        assert_eq!(stored_synthetic.uuid, synthetic.uuid);
        assert_eq!(
            stored_synthetic.name,
            format!("{}-synthetic-1", synthetic.name)
        );
        assert!(is_synthetic_primary_group(&stored_synthetic));
        let mut new_user = user.clone();
        new_user.uuid = uuid::uuid!("cccccccc-cccc-cccc-cccc-cccccccccccc");
        new_user.name = "new-user".into();
        new_user.spn = "new-user@example.com".into();
        new_user.gidnumber = 3000;
        new_user.groups = vec![synthetic];
        txn.update_account(&new_user, 0)
            .expect("new account caches without denial");
        assert_eq!(
            txn.get_group_members(real.uuid).expect("original members")[0].uuid,
            user.uuid
        );
        assert_eq!(
            txn.get_group(&super::Id::Gid(2600))
                .expect("occupied alias lookup")
                .expect("occupied group preserved")
                .0
                .uuid,
            occupied_alias.uuid
        );
        txn.commit().expect("no dangling memberships");
    }

    use super::{Cache, CacheTxn, Db, KeyStoreTxn};
    use crate::idprovider::interface::{GroupToken, Id, UserToken};
    use kanidm_hsm_crypto::{provider::BoxedDynTpm, provider::Tpm, AuthValue};

    const TESTACCOUNT1_PASSWORD_A: &str = "password a for account1 test";
    const TESTACCOUNT1_PASSWORD_B: &str = "password b for account1 test";

    #[cfg(feature = "tpm")]
    fn setup_tpm() -> BoxedDynTpm {
        use kanidm_hsm_crypto::provider::TssTpm;
        BoxedDynTpm::new(TssTpm::new("device:/dev/tpmrm0").expect("Unable to build Tpm Context"))
    }

    #[cfg(not(feature = "tpm"))]
    fn setup_tpm() -> BoxedDynTpm {
        use kanidm_hsm_crypto::provider::SoftTpm;
        BoxedDynTpm::new(SoftTpm::new())
    }

    #[tokio::test]
    async fn test_clear_hello_keys() {
        sketching::test_init();
        let db = Db::new("").expect("failed to create.");
        let mut dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let hello_keys = [
            "testuser@example.com/hello",
            "testuser@example.com/hello_decoupled",
            "testuser@example.com/hello_prt",
            "testuser@example.com/hello_refresh_token",
            "testuser@example.com/hello_totp",
        ];
        let unrelated_key = "testuser@example.com/not_hello";
        let value = "test value".to_string();

        for key in hello_keys {
            dbtxn.insert_tagged_hsm_key(key, &value).unwrap();
        }
        dbtxn.insert_tagged_hsm_key(unrelated_key, &value).unwrap();

        assert!(dbtxn.clear_hello_keys().is_ok());

        for key in hello_keys {
            let stored: Option<String> = dbtxn.get_tagged_hsm_key(key).unwrap();
            assert!(stored.is_none());
        }

        let stored: Option<String> = dbtxn.get_tagged_hsm_key(unrelated_key).unwrap();
        assert_eq!(stored, Some(value));

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_account_basic() {
        sketching::test_init();
        let db = Db::new("").expect("failed to create.");
        let mut dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let mut ut1 = UserToken {
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            real_gidnumber: Some(2000),
            gidnumber: 2000,
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
            shell: None,
            groups: Vec::new(),
            tenant_id: Some(uuid::uuid!("58e8a301-2502-4814-81c5-a4d17c399a45")),
            valid: true,
        };

        let id_name = Id::Name("testuser".to_string());
        let id_name2 = Id::Name("testuser2".to_string());
        let id_spn = Id::Name("testuser@example.com".to_string());
        let id_spn2 = Id::Name("testuser2@example.com".to_string());
        let id_uuid = Id::Name("0302b99c-f0f6-41ab-9492-852692b0fd16".to_string());
        let id_gid = Id::Gid(2000);

        // test finding no account
        let r1 = dbtxn.get_account(&id_name).unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_account(&id_spn).unwrap();
        assert!(r2.is_none());
        let r3 = dbtxn.get_account(&id_uuid).unwrap();
        assert!(r3.is_none());
        let r4 = dbtxn.get_account(&id_gid).unwrap();
        assert!(r4.is_none());

        // test adding an account
        dbtxn.update_account(&ut1, 0).unwrap();

        // test we can get it.
        let r1 = dbtxn.get_account(&id_name).unwrap();
        assert!(r1.is_some());
        let r2 = dbtxn.get_account(&id_spn).unwrap();
        assert!(r2.is_some());
        let r3 = dbtxn.get_account(&id_uuid).unwrap();
        assert!(r3.is_some());
        let r4 = dbtxn.get_account(&id_gid).unwrap();
        assert!(r4.is_some());

        // test adding an account that was renamed
        ut1.name = "testuser2".to_string();
        ut1.spn = "testuser2@example.com".to_string();
        dbtxn.update_account(&ut1, 0).unwrap();

        // get the account
        let r1 = dbtxn.get_account(&id_name).unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_account(&id_spn).unwrap();
        assert!(r2.is_none());
        let r1 = dbtxn.get_account(&id_name2).unwrap();
        assert!(r1.is_some());
        let r2 = dbtxn.get_account(&id_spn2).unwrap();
        assert!(r2.is_some());
        let r3 = dbtxn.get_account(&id_uuid).unwrap();
        assert!(r3.is_some());
        let r4 = dbtxn.get_account(&id_gid).unwrap();
        assert!(r4.is_some());

        // Clear cache
        assert!(dbtxn.clear().is_ok());

        // should be nothing
        let r1 = dbtxn.get_account(&id_name2).unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_account(&id_spn2).unwrap();
        assert!(r2.is_none());
        let r3 = dbtxn.get_account(&id_uuid).unwrap();
        assert!(r3.is_none());
        let r4 = dbtxn.get_account(&id_gid).unwrap();
        assert!(r4.is_none());

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_group_basic() {
        sketching::test_init();
        let db = Db::new("").expect("failed to create.");
        let mut dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let mut gt1 = GroupToken {
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            gidnumber: 2000,
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
        };

        let id_name = Id::Name("testgroup".to_string());
        let id_name2 = Id::Name("testgroup2".to_string());
        let id_spn = Id::Name("testgroup@example.com".to_string());
        let id_spn2 = Id::Name("testgroup2@example.com".to_string());
        let id_uuid = Id::Name("0302b99c-f0f6-41ab-9492-852692b0fd16".to_string());
        let id_gid = Id::Gid(2000);

        // test finding no group
        let r1 = dbtxn.get_group(&id_name).unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_group(&id_spn).unwrap();
        assert!(r2.is_none());
        let r3 = dbtxn.get_group(&id_uuid).unwrap();
        assert!(r3.is_none());
        let r4 = dbtxn.get_group(&id_gid).unwrap();
        assert!(r4.is_none());

        // test adding a group
        dbtxn.update_group(&gt1, 0).unwrap();
        let r1 = dbtxn.get_group(&id_name).unwrap();
        assert!(r1.is_some());
        let r2 = dbtxn.get_group(&id_spn).unwrap();
        assert!(r2.is_some());
        let r3 = dbtxn.get_group(&id_uuid).unwrap();
        assert!(r3.is_some());
        let r4 = dbtxn.get_group(&id_gid).unwrap();
        assert!(r4.is_some());

        // add a group via update
        gt1.name = "testgroup2".to_string();
        gt1.spn = "testgroup2@example.com".to_string();
        dbtxn.update_group(&gt1, 0).unwrap();
        let r1 = dbtxn.get_group(&id_name).unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_group(&id_spn).unwrap();
        assert!(r2.is_none());
        let r1 = dbtxn.get_group(&id_name2).unwrap();
        assert!(r1.is_some());
        let r2 = dbtxn.get_group(&id_spn2).unwrap();
        assert!(r2.is_some());
        let r3 = dbtxn.get_group(&id_uuid).unwrap();
        assert!(r3.is_some());
        let r4 = dbtxn.get_group(&id_gid).unwrap();
        assert!(r4.is_some());

        // clear cache
        assert!(dbtxn.clear().is_ok());

        // should be nothing.
        let r1 = dbtxn.get_group(&id_name2).unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_group(&id_spn2).unwrap();
        assert!(r2.is_none());
        let r3 = dbtxn.get_group(&id_uuid).unwrap();
        assert!(r3.is_none());
        let r4 = dbtxn.get_group(&id_gid).unwrap();
        assert!(r4.is_none());

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_account_group_update() {
        sketching::test_init();
        let db = Db::new("").expect("failed to create.");
        let mut dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let gt1 = GroupToken {
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            gidnumber: 2000,
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
        };

        let gt2 = GroupToken {
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            gidnumber: 2001,
            uuid: uuid::uuid!("b500be97-8552-42a5-aca0-668bc5625705"),
        };

        let mut ut1 = UserToken {
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            real_gidnumber: Some(2000),
            gidnumber: 2000,
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
            shell: None,
            groups: vec![gt1.clone(), gt2],
            tenant_id: Some(uuid::uuid!("58e8a301-2502-4814-81c5-a4d17c399a45")),
            valid: true,
        };

        // First, add the groups.
        ut1.groups.iter().for_each(|g| {
            dbtxn.update_group(g, 0).unwrap();
        });

        // The add the account
        dbtxn.update_account(&ut1, 0).unwrap();

        // Now, get the memberships of the two groups.
        let m1 = dbtxn
            .get_group_members(uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"))
            .unwrap();
        let m2 = dbtxn
            .get_group_members(uuid::uuid!("b500be97-8552-42a5-aca0-668bc5625705"))
            .unwrap();
        assert!(m1[0].name == "testuser");
        assert!(m2[0].name == "testuser");

        // Now alter testuser, remove gt2, update.
        ut1.groups = vec![gt1];
        dbtxn.update_account(&ut1, 0).unwrap();

        // Check that the memberships have updated correctly.
        let m1 = dbtxn
            .get_group_members(uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"))
            .unwrap();
        let m2 = dbtxn
            .get_group_members(uuid::uuid!("b500be97-8552-42a5-aca0-668bc5625705"))
            .unwrap();
        assert!(m1[0].name == "testuser");
        assert!(m2.is_empty());

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_account_password() {
        sketching::test_init();

        let db = Db::new("").expect("failed to create.");

        let mut dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let mut hsm = setup_tpm();

        let auth_value = AuthValue::ephemeral().unwrap();

        let loadable_machine_key = hsm.root_storage_key_create(&auth_value).unwrap();
        let machine_key = hsm
            .root_storage_key_load(&auth_value, &loadable_machine_key)
            .unwrap();

        let loadable_hmac_key = hsm.hmac_s256_create(&machine_key).unwrap();
        let hmac_key = hsm
            .hmac_s256_load(&machine_key, &loadable_hmac_key)
            .unwrap();

        let uuid1 = uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16");
        let mut ut1 = UserToken {
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            real_gidnumber: Some(2000),
            gidnumber: 2000,
            uuid: uuid1,
            shell: None,
            groups: Vec::new(),
            tenant_id: Some(uuid::uuid!("58e8a301-2502-4814-81c5-a4d17c399a45")),
            valid: true,
        };

        // Test that with no account, is false
        assert!(matches!(
            dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_A, &mut hsm, &hmac_key),
            Ok(false)
        ));
        // test adding an account
        dbtxn.update_account(&ut1, 0).unwrap();
        // check with no password is false.
        assert!(matches!(
            dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_A, &mut hsm, &hmac_key),
            Ok(false)
        ));
        // update the pw
        assert!(dbtxn
            .update_account_password(uuid1, TESTACCOUNT1_PASSWORD_A, &mut hsm, &hmac_key)
            .is_ok());
        // Check it now works.
        assert!(matches!(
            dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_A, &mut hsm, &hmac_key),
            Ok(true)
        ));
        assert!(matches!(
            dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_B, &mut hsm, &hmac_key),
            Ok(false)
        ));
        // Update the pw
        assert!(dbtxn
            .update_account_password(uuid1, TESTACCOUNT1_PASSWORD_B, &mut hsm, &hmac_key)
            .is_ok());
        // Check it matches.
        assert!(matches!(
            dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_A, &mut hsm, &hmac_key),
            Ok(false)
        ));
        assert!(matches!(
            dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_B, &mut hsm, &hmac_key),
            Ok(true)
        ));

        // Check that updating the account does not break the password.
        ut1.displayname = "Test User Update".to_string();
        dbtxn.update_account(&ut1, 0).unwrap();
        assert!(matches!(
            dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_B, &mut hsm, &hmac_key),
            Ok(true)
        ));

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_group_rename_duplicate() {
        sketching::test_init();
        let db = Db::new("").expect("failed to create.");
        let mut dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let mut gt1 = GroupToken {
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            gidnumber: 2000,
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
        };

        let gt2 = GroupToken {
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            gidnumber: 2001,
            uuid: uuid::uuid!("799123b2-3802-4b19-b0b8-1ffae2aa9a4b"),
        };

        let id_name = Id::Name("testgroup".to_string());
        let id_name2 = Id::Name("testgroup2".to_string());

        // test finding no group
        let r1 = dbtxn.get_group(&id_name).unwrap();
        assert!(r1.is_none());

        // test adding a group
        dbtxn.update_group(&gt1, 0).unwrap();
        let r0 = dbtxn.get_group(&id_name).unwrap();
        assert!(r0.unwrap().0.uuid == uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"));

        // Do the "rename" of gt1 which is what would allow gt2 to be valid.
        gt1.name = "testgroup2".to_string();
        gt1.spn = "testgroup2@example.com".to_string();
        // Now, add gt2 which dups on gt1 name/spn.
        dbtxn.update_group(&gt2, 0).unwrap();
        let r2 = dbtxn.get_group(&id_name).unwrap();
        assert!(r2.unwrap().0.uuid == uuid::uuid!("799123b2-3802-4b19-b0b8-1ffae2aa9a4b"));
        let r3 = dbtxn.get_group(&id_name2).unwrap();
        assert!(r3.is_none());

        // Now finally update gt1
        dbtxn.update_group(&gt1, 0).unwrap();

        // Both now coexist
        let r4 = dbtxn.get_group(&id_name).unwrap();
        assert!(r4.unwrap().0.uuid == uuid::uuid!("799123b2-3802-4b19-b0b8-1ffae2aa9a4b"));
        let r5 = dbtxn.get_group(&id_name2).unwrap();
        assert!(r5.unwrap().0.uuid == uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"));

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_account_rename_duplicate() {
        sketching::test_init();
        let db = Db::new("").expect("failed to create.");
        let mut dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let mut ut1 = UserToken {
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            real_gidnumber: Some(2000),
            gidnumber: 2000,
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
            shell: None,
            groups: Vec::new(),
            tenant_id: Some(uuid::uuid!("58e8a301-2502-4814-81c5-a4d17c399a45")),
            valid: true,
        };

        let ut2 = UserToken {
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            real_gidnumber: Some(2001),
            gidnumber: 2001,
            uuid: uuid::uuid!("799123b2-3802-4b19-b0b8-1ffae2aa9a4b"),
            shell: None,
            groups: Vec::new(),
            tenant_id: Some(uuid::uuid!("58e8a301-2502-4814-81c5-a4d17c399a45")),
            valid: true,
        };

        let id_name = Id::Name("testuser".to_string());
        let id_name2 = Id::Name("testuser2".to_string());

        // test finding no account
        let r1 = dbtxn.get_account(&id_name).unwrap();
        assert!(r1.is_none());

        // test adding an account
        dbtxn.update_account(&ut1, 0).unwrap();
        let r0 = dbtxn.get_account(&id_name).unwrap();
        assert!(r0.unwrap().0.uuid == uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"));

        // Do the "rename" of gt1 which is what would allow gt2 to be valid.
        ut1.name = "testuser2".to_string();
        ut1.spn = "testuser2@example.com".to_string();
        // Now, add gt2 which dups on gt1 name/spn.
        dbtxn.update_account(&ut2, 0).unwrap();
        let r2 = dbtxn.get_account(&id_name).unwrap();
        assert!(r2.unwrap().0.uuid == uuid::uuid!("799123b2-3802-4b19-b0b8-1ffae2aa9a4b"));
        let r3 = dbtxn.get_account(&id_name2).unwrap();
        assert!(r3.is_none());

        // Now finally update gt1
        dbtxn.update_account(&ut1, 0).unwrap();

        // Both now coexist
        let r4 = dbtxn.get_account(&id_name).unwrap();
        assert!(r4.unwrap().0.uuid == uuid::uuid!("799123b2-3802-4b19-b0b8-1ffae2aa9a4b"));
        let r5 = dbtxn.get_account(&id_name2).unwrap();
        assert!(r5.unwrap().0.uuid == uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"));

        assert!(dbtxn.commit().is_ok());
    }
}
