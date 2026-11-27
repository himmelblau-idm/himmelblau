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
use crate::idprovider::common::IdmapScriptResult;
use crate::reserved_ids::{is_systemd_dynamic_id, SYSTEMD_DYNAMIC_ID_MAX, SYSTEMD_DYNAMIC_ID_MIN};
use rusqlite::{params, Connection, OpenFlags, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Debug)]
pub struct StaticUser {
    pub name: String,
    pub username: Option<String>,
    pub uid: u32,
    pub gid: u32,
    /// Raw uid returned by idmap_script (None = not explicitly set).
    pub script_uid: Option<u32>,
    /// Raw gid returned by idmap_script (None = not explicitly set).
    pub script_gid: Option<u32>,
    /// True when this entry was written by code that tracks raw script
    /// output.  Legacy entries (created before this field existed) have
    /// false, which tells the comparison logic to accept any script
    /// output and re-cache.
    pub script_ran: bool,
}

#[derive(Debug)]
pub struct StaticGroup {
    pub name: String,
    pub gid: u32,
}

pub struct StaticIdCache {
    conn: Option<Connection>,
    writable: bool,
}

/// Reject a cached user whose UID or GID lands in systemd's dynamic user
/// range. The cache is populated from directory supplied rfc2307 attributes
/// (`aad-tool enumerate`) and from `aad-tool idmap user-add`, and it is
/// consulted before those attributes are re-read, so a cache poisoned before
/// this check existed must not be trusted. See GHSA-6gp8-pp9v-gx45.
fn static_user_is_safe(user: &StaticUser) -> bool {
    if is_systemd_dynamic_id(user.uid) || is_systemd_dynamic_id(user.gid) {
        error!(
            "Ignoring cached idmap entry for user {:?} (uid {}, gid {}): {}-{} is reserved for systemd dynamic users",
            user.name, user.uid, user.gid, SYSTEMD_DYNAMIC_ID_MIN, SYSTEMD_DYNAMIC_ID_MAX
        );
        return false;
    }
    true
}

/// Reject a cached group whose GID lands in systemd's dynamic user range.
/// See [`static_user_is_safe`] and GHSA-6gp8-pp9v-gx45.
fn static_group_is_safe(group: &StaticGroup) -> bool {
    if is_systemd_dynamic_id(group.gid) {
        error!(
            "Ignoring cached idmap entry for group {:?} (gid {}): {}-{} is reserved for systemd dynamic users",
            group.name, group.gid, SYSTEMD_DYNAMIC_ID_MIN, SYSTEMD_DYNAMIC_ID_MAX
        );
        return false;
    }
    true
}

fn ensure_static_users_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS static_users (
            name TEXT PRIMARY KEY,
            username TEXT,
            uid INTEGER NOT NULL,
            gid INTEGER NOT NULL,
            script_uid INTEGER,
            script_gid INTEGER,
            script_ran INTEGER NOT NULL DEFAULT 0
        );
         CREATE TABLE IF NOT EXISTS static_groups (
            name TEXT PRIMARY KEY,
            gid INTEGER NOT NULL
        );",
    )?;

    let mut stmt = conn.prepare("PRAGMA table_info(static_users)")?;
    let mut rows = stmt.query([])?;
    let mut has_username = false;
    let mut has_script_ran = false;
    while let Some(row) = rows.next()? {
        let column_name: String = row.get(1)?;
        if column_name == "username" {
            has_username = true;
        }
        if column_name == "script_ran" {
            has_script_ran = true;
        }
    }

    if !has_username {
        conn.execute_batch("ALTER TABLE static_users ADD COLUMN username TEXT;")?;
    }
    if !has_script_ran {
        conn.execute_batch(
            "ALTER TABLE static_users ADD COLUMN script_uid INTEGER;
             ALTER TABLE static_users ADD COLUMN script_gid INTEGER;
             ALTER TABLE static_users ADD COLUMN script_ran INTEGER NOT NULL DEFAULT 0;",
        )?;
    }

    Ok(())
}

impl StaticIdCache {
    pub fn new(db_path: &str, writable: bool) -> Result<Self> {
        let is_root = unsafe { libc::getuid() } == 0;
        Self::open(db_path, writable, is_root)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(db_path: &str, writable: bool) -> Result<Self> {
        Self::open(db_path, writable, true)
    }

    fn open(db_path: &str, writable: bool, privileged: bool) -> Result<Self> {
        let path = Path::new(db_path);
        let mut write = false;

        if !path.exists() && privileged && writable {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|_| rusqlite::Error::InvalidPath(parent.into()))?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
                    .map_err(|_| rusqlite::Error::InvalidPath(parent.into()))?;
            }
        }

        let conn = if path.exists() {
            if privileged {
                let migrate_conn =
                    Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
                ensure_static_users_schema(&migrate_conn)?;
            }
            let flags = if writable && privileged {
                write = true;
                OpenFlags::SQLITE_OPEN_READ_WRITE
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            };
            Some(Connection::open_with_flags(db_path, flags)?)
        } else if writable && privileged {
            write = true;
            let conn = Connection::open(db_path)?;
            ensure_static_users_schema(&conn)?;
            fs::set_permissions(db_path, fs::Permissions::from_mode(0o644))
                .map_err(|_| rusqlite::Error::InvalidPath(db_path.into()))?;
            Some(conn)
        } else {
            None
        };

        Ok(Self {
            conn,
            writable: write,
        })
    }

    pub fn apply_idmap_script(
        &self,
        spn: &str,
        result: Option<&IdmapScriptResult>,
        default_ids: Option<(u32, u32)>,
    ) -> std::result::Result<(), String> {
        let cached = self.get_user_by_name(spn);
        match result {
            Some(result) => {
                let (uid, gid) = match (result.uid, result.gid, default_ids) {
                    (Some(uid), Some(gid), _) => (uid, gid),
                    (Some(uid), None, _) => (uid, uid),
                    (None, Some(gid), Some((def_uid, _))) => (def_uid, gid),
                    (None, None, Some((def_uid, def_gid))) => (def_uid, def_gid),
                    _ => {
                        let msg = "idmap script omitted uid and no default uid is available";
                        error!("{} for {}", msg, spn);
                        return Err(msg.to_string());
                    }
                };

                if let Some(ref old) = cached {
                    if old.script_ran {
                        if old.script_uid != result.uid
                            || old.script_gid != result.gid
                            || old.username != result.username
                        {
                            error!(
                                "idmap script mismatch for {}: \
                                 cached=(uid={:?},gid={:?},username={:?}) \
                                 script=(uid={:?},gid={:?},username={:?})",
                                spn,
                                old.script_uid,
                                old.script_gid,
                                old.username,
                                result.uid,
                                result.gid,
                                result.username,
                            );
                            return Err(
                                "idmap script returned different values than cached".to_string()
                            );
                        }
                        return Ok(());
                    }
                }

                self.persist_script_user(&StaticUser {
                    name: spn.to_string(),
                    username: result.username.clone(),
                    uid,
                    gid,
                    script_uid: result.uid,
                    script_gid: result.gid,
                    script_ran: true,
                })
            }
            None => {
                if cached.is_some() {
                    Ok(())
                } else if let Some((def_uid, def_gid)) = default_ids {
                    self.persist_script_user(&StaticUser {
                        name: spn.to_string(),
                        username: None,
                        uid: def_uid,
                        gid: def_gid,
                        script_uid: None,
                        script_gid: None,
                        script_ran: true,
                    })
                } else {
                    let msg = "idmap script returned empty output and no default ids available";
                    error!("{} for {}", msg, spn);
                    Err(msg.to_string())
                }
            }
        }
    }

    fn persist_script_user(&self, user: &StaticUser) -> std::result::Result<(), String> {
        if user.uid == 0 || user.gid == 0 || !static_user_is_safe(user) {
            let msg = "idmap resolved to a reserved uid or gid";
            error!(
                "{} for {} (uid={}, gid={})",
                msg, user.name, user.uid, user.gid
            );
            return Err(msg.to_string());
        }
        if !self.writable {
            let msg = "idmap cache is not writable";
            error!("{} for {}", msg, user.name);
            return Err(msg.to_string());
        }
        self.insert_user(user).map_err(|e| {
            error!("Failed to cache idmap result: {:?}", e);
            format!("Failed to cache idmap result: {:?}", e)
        })
    }

    pub fn insert_user(&self, user: &StaticUser) -> Result<()> {
        if let Some(conn) = &self.conn {
            if self.writable {
                conn.execute(
                    "INSERT OR REPLACE INTO static_users \
                     (name, username, uid, gid, script_uid, script_gid, script_ran) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        user.name,
                        user.username,
                        user.uid,
                        user.gid,
                        user.script_uid,
                        user.script_gid,
                        user.script_ran
                    ],
                )?;
            }
        }
        Ok(())
    }

    pub fn insert_group(&self, group: &StaticGroup) -> Result<()> {
        if let Some(conn) = &self.conn {
            if self.writable {
                conn.execute(
                    "INSERT OR REPLACE INTO static_groups (name, gid) VALUES (?1, ?2)",
                    params![group.name, group.gid],
                )?;
            }
        }
        Ok(())
    }

    pub fn get_user_by_name(&self, name: &str) -> Option<StaticUser> {
        self.conn.as_ref()?;
        let conn = self.conn.as_ref()?;

        let user = if let Ok(mut stmt) = conn.prepare(
            "SELECT name, username, uid, gid, script_uid, script_gid, script_ran \
             FROM static_users WHERE name = ?1",
        ) {
            let mut rows = stmt.query([name]).ok()?;
            let row = rows.next().ok().flatten()?;

            StaticUser {
                name: row.get(0).ok()?,
                username: row.get(1).ok()?,
                uid: row.get(2).ok()?,
                gid: row.get(3).ok()?,
                script_uid: row.get(4).ok()?,
                script_gid: row.get(5).ok()?,
                script_ran: row.get::<_, i32>(6).unwrap_or(0) != 0,
            }
        } else if let Ok(mut stmt) =
            conn.prepare("SELECT name, username, uid, gid FROM static_users WHERE name = ?1")
        {
            let mut rows = stmt.query([name]).ok()?;
            let row = rows.next().ok().flatten()?;

            StaticUser {
                name: row.get(0).ok()?,
                username: row.get(1).ok()?,
                uid: row.get(2).ok()?,
                gid: row.get(3).ok()?,
                script_uid: None,
                script_gid: None,
                script_ran: false,
            }
        } else {
            let mut stmt = conn
                .prepare("SELECT name, uid, gid FROM static_users WHERE name = ?1")
                .ok()?;
            let mut rows = stmt.query([name]).ok()?;
            let row = rows.next().ok().flatten()?;

            StaticUser {
                name: row.get(0).ok()?,
                username: None,
                uid: row.get(1).ok()?,
                gid: row.get(2).ok()?,
                script_uid: None,
                script_gid: None,
                script_ran: false,
            }
        };

        if !static_user_is_safe(&user) {
            return None;
        }

        Some(user)
    }

    pub fn get_group_by_name(&self, name: &str) -> Option<StaticGroup> {
        self.conn.as_ref()?;
        let conn = self.conn.as_ref()?;

        let mut stmt = conn
            .prepare("SELECT name, gid FROM static_groups WHERE name = ?1")
            .ok()?;
        let mut rows = stmt.query([name]).ok()?;
        let row = rows.next().ok().flatten()?;

        let group = StaticGroup {
            name: row.get(0).ok()?,
            gid: row.get(1).ok()?,
        };

        if !static_group_is_safe(&group) {
            return None;
        }

        Some(group)
    }

    pub fn list_users(&self) -> Vec<StaticUser> {
        let mut users = Vec::new();
        let conn = match &self.conn {
            Some(c) => c,
            None => return users,
        };

        if let Ok(mut stmt) = conn.prepare(
            "SELECT name, username, uid, gid, script_uid, script_gid, script_ran \
             FROM static_users",
        ) {
            if let Ok(mapped) = stmt.query_map([], |row| {
                Ok(StaticUser {
                    name: row.get(0)?,
                    username: row.get(1)?,
                    uid: row.get(2)?,
                    gid: row.get(3)?,
                    script_uid: row.get(4)?,
                    script_gid: row.get(5)?,
                    script_ran: row.get::<_, i32>(6).unwrap_or(0) != 0,
                })
            }) {
                for user in mapped.flatten() {
                    if !static_user_is_safe(&user) {
                        continue;
                    }
                    users.push(user);
                }
            }

            return users;
        }

        if let Ok(mut stmt) = conn.prepare("SELECT name, username, uid, gid FROM static_users") {
            if let Ok(mapped) = stmt.query_map([], |row| {
                Ok(StaticUser {
                    name: row.get(0)?,
                    username: row.get(1)?,
                    uid: row.get(2)?,
                    gid: row.get(3)?,
                    script_uid: None,
                    script_gid: None,
                    script_ran: false,
                })
            }) {
                for user in mapped.flatten() {
                    if !static_user_is_safe(&user) {
                        continue;
                    }
                    users.push(user);
                }
            }

            return users;
        }

        let mut stmt = match conn.prepare("SELECT name, uid, gid FROM static_users") {
            Ok(s) => s,
            Err(_) => return users,
        };

        if let Ok(mapped) = stmt.query_map([], |row| {
            Ok(StaticUser {
                name: row.get(0)?,
                username: None,
                uid: row.get(1)?,
                gid: row.get(2)?,
                script_uid: None,
                script_gid: None,
                script_ran: false,
            })
        }) {
            for user in mapped.flatten() {
                if !static_user_is_safe(&user) {
                    continue;
                }
                users.push(user);
            }
        }

        users
    }

    pub fn list_groups(&self) -> Vec<StaticGroup> {
        let mut groups = Vec::new();
        let conn = match &self.conn {
            Some(c) => c,
            None => return groups,
        };

        let mut stmt = match conn.prepare("SELECT name, gid FROM static_groups") {
            Ok(s) => s,
            Err(_) => return groups,
        };

        if let Ok(mapped) = stmt.query_map([], |row| {
            Ok(StaticGroup {
                name: row.get(0)?,
                gid: row.get(1)?,
            })
        }) {
            for group in mapped.flatten() {
                if !static_group_is_safe(&group) {
                    continue;
                }
                groups.push(group);
            }
        }

        groups
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn test_db_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("idmap-cache-test-{}.sqlite", Uuid::new_v4()));
        path
    }

    fn create_legacy_cache(db_path: &Path) {
        let conn = Connection::open(db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE static_users (
                name TEXT PRIMARY KEY,
                uid INTEGER NOT NULL,
                gid INTEGER NOT NULL
            );
             CREATE TABLE static_groups (
                name TEXT PRIMARY KEY,
                gid INTEGER NOT NULL
            );
             INSERT INTO static_users (name, uid, gid)
             VALUES ('alice@example.com', 1000, 1001);",
        )
        .unwrap();
    }

    #[test]
    fn test_get_user_by_name_reads_legacy_schema() {
        let db_path = test_db_path();
        create_legacy_cache(&db_path);

        let cache = StaticIdCache::new(db_path.to_str().unwrap(), false).unwrap();
        let user = cache.get_user_by_name("alice@example.com").unwrap();

        assert_eq!(user.name, "alice@example.com");
        assert_eq!(user.username, None);
        assert_eq!(user.uid, 1000);
        assert_eq!(user.gid, 1001);
        assert_eq!(user.script_uid, None);
        assert_eq!(user.script_gid, None);
        assert!(!user.script_ran);

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn test_ensure_static_users_schema_adds_username_column() {
        let db_path = test_db_path();
        create_legacy_cache(&db_path);

        let conn = Connection::open(&db_path).unwrap();
        ensure_static_users_schema(&conn).unwrap();

        let user = conn
            .query_row(
                "SELECT name, username, uid, gid, script_uid, script_gid, script_ran \
                 FROM static_users WHERE name = ?1",
                ["alice@example.com"],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, u32>(3)?,
                        row.get::<_, Option<u32>>(4)?,
                        row.get::<_, Option<u32>>(5)?,
                        row.get::<_, i32>(6)?,
                    ))
                },
            )
            .unwrap();

        assert_eq!(user.0, "alice@example.com");
        assert_eq!(user.1, None);
        assert_eq!(user.2, 1000);
        assert_eq!(user.3, 1001);
        assert_eq!(user.4, None);
        assert_eq!(user.5, None);
        assert_eq!(user.6, 0);

        let _ = fs::remove_file(db_path);
    }

    /// Helper: create a DB with the full (migrated) schema so that
    /// non-root tests can read it back.
    fn create_full_schema_cache(db_path: &Path) {
        let conn = Connection::open(db_path).unwrap();
        ensure_static_users_schema(&conn).unwrap();
    }

    #[test]
    fn test_insert_and_read_script_raw_fields() {
        let db_path = test_db_path();
        create_full_schema_cache(&db_path);

        // Insert directly via SQL (non-root can't write through the cache API).
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO static_users \
             (name, username, uid, gid, script_uid, script_gid, script_ran) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "bob@example.com",
                Some("bob"),
                500u32,
                500u32,
                Some(500u32),
                Some(500u32),
                1
            ],
        )
        .unwrap();
        drop(conn);

        let cache = StaticIdCache::new(db_path.to_str().unwrap(), false).unwrap();
        let user = cache.get_user_by_name("bob@example.com").unwrap();
        assert_eq!(user.uid, 500);
        assert_eq!(user.gid, 500);
        assert_eq!(user.script_uid, Some(500));
        assert_eq!(user.script_gid, Some(500));
        assert!(user.script_ran);
        assert_eq!(user.username, Some("bob".to_string()));

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn test_insert_empty_script_output() {
        let db_path = test_db_path();
        create_full_schema_cache(&db_path);

        // Simulate first login with "" — script_uid/gid are NULL,
        // resolved defaults stored in uid/gid.
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO static_users \
             (name, username, uid, gid, script_uid, script_gid, script_ran) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "carol@example.com",
                None::<String>,
                12345u32,
                12345u32,
                None::<u32>,
                None::<u32>,
                1
            ],
        )
        .unwrap();
        drop(conn);

        let cache = StaticIdCache::new(db_path.to_str().unwrap(), false).unwrap();
        let user = cache.get_user_by_name("carol@example.com").unwrap();
        assert_eq!(user.uid, 12345);
        assert_eq!(user.gid, 12345);
        assert_eq!(user.script_uid, None);
        assert_eq!(user.script_gid, None);
        assert!(user.script_ran);

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn test_legacy_entry_has_script_ran_false() {
        let db_path = test_db_path();
        create_legacy_cache(&db_path);

        // Migrate the schema (adds new columns with defaults).
        let conn = Connection::open(&db_path).unwrap();
        ensure_static_users_schema(&conn).unwrap();
        drop(conn);

        let cache = StaticIdCache::new(db_path.to_str().unwrap(), false).unwrap();
        let user = cache.get_user_by_name("alice@example.com").unwrap();
        assert_eq!(user.uid, 1000);
        assert_eq!(user.gid, 1001);
        assert_eq!(user.script_uid, None);
        assert_eq!(user.script_gid, None);
        assert!(!user.script_ran);

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn test_apply_idmap_script_persists_verifies_mismatch_and_retains_empty_output() {
        let db_dir = std::env::temp_dir().join(format!("idmap-apply-{}", Uuid::new_v4()));
        let db_path = db_dir.join("idmap.cache.db");
        let db_str = db_path.to_str().unwrap();

        let non_writable = StaticIdCache::open(db_str, true, false).unwrap();
        let first = IdmapScriptResult {
            username: Some("jdoe".to_string()),
            uid: Some(2500),
            gid: None,
        };
        assert!(non_writable
            .apply_idmap_script("jdoe@example.com", Some(&first), Some((9000, 9000)))
            .is_err());

        let cache = StaticIdCache::open_for_test(db_str, true).unwrap();
        cache
            .apply_idmap_script("jdoe@example.com", Some(&first), Some((9000, 9000)))
            .unwrap();
        let stored = cache.get_user_by_name("jdoe@example.com").unwrap();
        assert_eq!(stored.uid, 2500);
        assert_eq!(stored.gid, 2500);
        assert_eq!(stored.username.as_deref(), Some("jdoe"));
        assert_eq!(stored.script_uid, Some(2500));
        assert_eq!(stored.script_gid, None);
        assert!(stored.script_ran);

        cache
            .apply_idmap_script("jdoe@example.com", Some(&first), Some((9000, 9000)))
            .unwrap();
        cache
            .apply_idmap_script("jdoe@example.com", None, Some((9000, 9000)))
            .unwrap();
        let retained = cache.get_user_by_name("jdoe@example.com").unwrap();
        assert_eq!(retained.uid, 2500);
        assert_eq!(retained.gid, 2500);
        assert_eq!(retained.username.as_deref(), Some("jdoe"));

        let changed = IdmapScriptResult {
            username: Some("jdoe".to_string()),
            uid: Some(2501),
            gid: None,
        };
        assert!(cache
            .apply_idmap_script("jdoe@example.com", Some(&changed), Some((9000, 9000)))
            .is_err());
        assert!(cache
            .apply_idmap_script("root@example.com", None, Some((0, 1000)))
            .is_err());
        assert!(cache
            .apply_idmap_script(
                "dyn@example.com",
                None,
                Some((SYSTEMD_DYNAMIC_ID_MIN, SYSTEMD_DYNAMIC_ID_MIN)),
            )
            .is_err());

        let _ = fs::remove_dir_all(db_dir);
    }
}
