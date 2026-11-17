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
use crate::reserved_ids::{is_systemd_dynamic_id, SYSTEMD_DYNAMIC_ID_MAX, SYSTEMD_DYNAMIC_ID_MIN};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Debug)]
pub struct StaticUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
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

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UserMappingMigration {
    Migrated,
    MissingSource,
    Conflict,
    Unavailable,
    ReadOnly,
}

const CREATE_TABLES: &str = "CREATE TABLE IF NOT EXISTS static_users (
    name TEXT PRIMARY KEY,
    uid INTEGER NOT NULL,
    gid INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS static_groups (
    name TEXT PRIMARY KEY,
    gid INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS provider_static_users (
    provider TEXT NOT NULL,
    name TEXT NOT NULL,
    uid INTEGER NOT NULL,
    gid INTEGER NOT NULL,
    manual_override INTEGER NOT NULL DEFAULT 0 CHECK (manual_override IN (0, 1)),
    PRIMARY KEY (provider, name)
);
CREATE TABLE IF NOT EXISTS provider_static_groups (
    provider TEXT NOT NULL,
    name TEXT NOT NULL,
    gid INTEGER NOT NULL,
    manual_override INTEGER NOT NULL DEFAULT 0 CHECK (manual_override IN (0, 1)),
    PRIMARY KEY (provider, name)
);";

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(CREATE_TABLES)?;
    for table in ["provider_static_users", "provider_static_groups"] {
        let has_manual_override = {
            let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                if column? == "manual_override" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_manual_override {
            conn.execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN manual_override INTEGER NOT NULL DEFAULT 0 CHECK (manual_override IN (0, 1));"
            ))?;
        }
    }
    Ok(())
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

impl StaticIdCache {
    pub fn new(db_path: &str, writable: bool) -> Result<Self> {
        let is_root = unsafe { libc::getuid() } == 0;
        let path = Path::new(db_path);
        let mut write = false;

        if !path.exists() && is_root && writable {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|_| rusqlite::Error::InvalidPath(parent.into()))?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
                    .map_err(|_| rusqlite::Error::InvalidPath(parent.into()))?;
            }
        }

        let conn = if path.exists() {
            let flags = if writable && is_root {
                write = true;
                OpenFlags::SQLITE_OPEN_READ_WRITE
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            };
            Some(Connection::open_with_flags(db_path, flags)?)
        } else if writable && is_root {
            write = true;
            let conn = Connection::open(db_path)?;
            fs::set_permissions(db_path, fs::Permissions::from_mode(0o644))
                .map_err(|_| rusqlite::Error::InvalidPath(db_path.into()))?;
            Some(conn)
        } else {
            None
        };

        if write {
            if let Some(conn) = &conn {
                ensure_schema(conn)?;
            }
        }

        Ok(Self {
            conn,
            writable: write,
        })
    }

    /// Atomically replaces one provider's enumerated mappings.
    ///
    /// When `remove_legacy_entries` is true, unscoped mappings are removed in
    /// the same transaction.
    pub fn replace_provider_entries(
        &mut self,
        provider: &str,
        users: &[StaticUser],
        groups: &[StaticGroup],
        remove_legacy_entries: bool,
    ) -> Result<()> {
        let Some(conn) = self.conn.as_mut() else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        if !self.writable {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let tx = conn.transaction()?;
        if remove_legacy_entries {
            tx.execute("DELETE FROM static_users", [])?;
            tx.execute("DELETE FROM static_groups", [])?;
        }
        tx.execute(
            "DELETE FROM provider_static_users WHERE provider = ?1 AND manual_override = 0",
            [provider],
        )?;
        tx.execute(
            "DELETE FROM provider_static_groups WHERE provider = ?1 AND manual_override = 0",
            [provider],
        )?;
        for user in users {
            tx.execute(
                "INSERT INTO provider_static_users (provider, name, uid, gid, manual_override) VALUES (?1, ?2, ?3, ?4, 0) ON CONFLICT(provider, name) DO UPDATE SET uid = excluded.uid, gid = excluded.gid WHERE provider_static_users.manual_override = 0",
                params![provider, user.name, user.uid, user.gid],
            )?;
        }
        for group in groups {
            tx.execute(
                "INSERT INTO provider_static_groups (provider, name, gid, manual_override) VALUES (?1, ?2, ?3, 0) ON CONFLICT(provider, name) DO UPDATE SET gid = excluded.gid WHERE provider_static_groups.manual_override = 0",
                params![provider, group.name, group.gid],
            )?;
        }
        tx.commit()
    }

    pub fn set_provider_user_override(&self, provider: &str, user: &StaticUser) -> Result<()> {
        let Some(conn) = self.conn.as_ref() else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        if !self.writable {
            return Err(rusqlite::Error::InvalidQuery);
        }
        conn.execute(
            "INSERT INTO provider_static_users (provider, name, uid, gid, manual_override) VALUES (?1, ?2, ?3, ?4, 1) ON CONFLICT(provider, name) DO UPDATE SET uid = excluded.uid, gid = excluded.gid, manual_override = 1",
            params![provider, user.name, user.uid, user.gid],
        )?;
        Ok(())
    }

    pub fn set_provider_group_override(&self, provider: &str, group: &StaticGroup) -> Result<()> {
        let Some(conn) = self.conn.as_ref() else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        if !self.writable {
            return Err(rusqlite::Error::InvalidQuery);
        }
        conn.execute(
            "INSERT INTO provider_static_groups (provider, name, gid, manual_override) VALUES (?1, ?2, ?3, 1) ON CONFLICT(provider, name) DO UPDATE SET gid = excluded.gid, manual_override = 1",
            params![provider, group.name, group.gid],
        )?;
        Ok(())
    }

    pub fn get_user_by_provider_name(&self, provider: &str, name: &str) -> Option<StaticUser> {
        let conn = self.conn.as_ref()?;
        let user = conn
            .query_row(
                "SELECT name, uid, gid FROM provider_static_users WHERE provider = ?1 AND name = ?2",
                params![provider, name],
                |row| {
                    Ok(StaticUser {
                        name: row.get(0)?,
                        uid: row.get(1)?,
                        gid: row.get(2)?,
                    })
                },
            )
            .optional()
            .ok()
            .flatten();
        if let Some(user) = user {
            return static_user_is_safe(&user).then_some(user);
        }
        self.get_user_by_name(name)
    }

    pub fn get_group_by_provider_name(&self, provider: &str, name: &str) -> Option<StaticGroup> {
        let conn = self.conn.as_ref()?;
        let group = conn
            .query_row(
                "SELECT name, gid FROM provider_static_groups WHERE provider = ?1 AND name = ?2",
                params![provider, name],
                |row| {
                    Ok(StaticGroup {
                        name: row.get(0)?,
                        gid: row.get(1)?,
                    })
                },
            )
            .optional()
            .ok()
            .flatten();
        if let Some(group) = group {
            return static_group_is_safe(&group).then_some(group);
        }
        self.get_group_by_name(name)
    }

    pub(crate) fn migrate_user_mapping(
        &mut self,
        source: &str,
        target: &str,
    ) -> Result<UserMappingMigration> {
        if source == target {
            return Ok(UserMappingMigration::Migrated);
        }
        let Some(conn) = self.conn.as_mut() else {
            return Ok(UserMappingMigration::Unavailable);
        };
        if !self.writable {
            return Ok(UserMappingMigration::ReadOnly);
        }

        let tx = conn.transaction()?;
        let source_user = tx
            .query_row(
                "SELECT name, uid, gid FROM static_users WHERE name = ?1",
                [source],
                |row| {
                    Ok(StaticUser {
                        name: row.get(0)?,
                        uid: row.get(1)?,
                        gid: row.get(2)?,
                    })
                },
            )
            .optional()?;
        let Some(source_user) = source_user else {
            tx.commit()?;
            return Ok(UserMappingMigration::MissingSource);
        };
        if !static_user_is_safe(&source_user) {
            tx.commit()?;
            return Ok(UserMappingMigration::MissingSource);
        }

        let target_user = tx
            .query_row(
                "SELECT name, uid, gid FROM static_users WHERE name = ?1",
                [target],
                |row| {
                    Ok(StaticUser {
                        name: row.get(0)?,
                        uid: row.get(1)?,
                        gid: row.get(2)?,
                    })
                },
            )
            .optional()?;
        if let Some(target_user) = target_user {
            if target_user.uid != source_user.uid
                || target_user.gid != source_user.gid
                || !static_user_is_safe(&target_user)
            {
                return Ok(UserMappingMigration::Conflict);
            }
        } else {
            tx.execute(
                "INSERT INTO static_users (name, uid, gid) VALUES (?1, ?2, ?3)",
                params![target, source_user.uid, source_user.gid],
            )?;
        }
        tx.execute("DELETE FROM static_users WHERE name = ?1", [source])?;
        tx.commit()?;
        Ok(UserMappingMigration::Migrated)
    }

    pub fn insert_user(&self, user: &StaticUser) -> Result<()> {
        if let Some(conn) = &self.conn {
            if self.writable {
                conn.execute(
                    "INSERT OR REPLACE INTO static_users (name, uid, gid) VALUES (?1, ?2, ?3)",
                    params![user.name, user.uid, user.gid],
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

        let mut stmt = conn
            .prepare("SELECT name, uid, gid FROM static_users WHERE name = ?1")
            .ok()?;
        let mut rows = stmt.query([name]).ok()?;
        let row = rows.next().ok().flatten()?;

        let user = StaticUser {
            name: row.get(0).ok()?,
            uid: row.get(1).ok()?,
            gid: row.get(2).ok()?,
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

        let mut stmt = match conn.prepare("SELECT name, uid, gid FROM static_users") {
            Ok(s) => s,
            Err(_) => return users,
        };

        if let Ok(mapped) = stmt.query_map([], |row| {
            Ok(StaticUser {
                name: row.get(0)?,
                uid: row.get(1)?,
                gid: row.get(2)?,
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

    #[cfg(test)]
    pub(crate) fn in_memory_for_test() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(CREATE_TABLES)?;
        Ok(Self {
            conn: Some(conn),
            writable: true,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cache_with_user(user: &StaticUser) -> StaticIdCache {
        let cache = StaticIdCache::in_memory_for_test().unwrap();
        cache.insert_user(user).unwrap();
        cache
    }

    #[test]
    fn user_mapping_migration_renames_without_overwriting() {
        let mut cache = cache_with_user(&StaticUser {
            name: "alice".to_string(),
            uid: 1234,
            gid: 5678,
        });

        assert_eq!(
            cache.migrate_user_mapping("alice", "alice@work").unwrap(),
            UserMappingMigration::Migrated
        );
        assert!(cache.get_user_by_name("alice").is_none());
        let migrated = cache.get_user_by_name("alice@work").unwrap();
        assert_eq!((migrated.uid, migrated.gid), (1234, 5678));
    }

    #[test]
    fn user_mapping_migration_keeps_conflicting_entries() {
        let mut cache = cache_with_user(&StaticUser {
            name: "alice".to_string(),
            uid: 1234,
            gid: 5678,
        });
        cache
            .insert_user(&StaticUser {
                name: "alice@work".to_string(),
                uid: 9876,
                gid: 5432,
            })
            .unwrap();

        assert_eq!(
            cache.migrate_user_mapping("alice", "alice@work").unwrap(),
            UserMappingMigration::Conflict
        );
        assert_eq!(cache.get_user_by_name("alice").unwrap().uid, 1234);
        assert_eq!(cache.get_user_by_name("alice@work").unwrap().uid, 9876);
    }

    #[test]
    fn provider_replacement_preserves_other_providers_and_prefers_scoped_entries() {
        let mut cache = cache_with_user(&StaticUser {
            name: "alice@example.org".to_string(),
            uid: 1234,
            gid: 5678,
        });
        cache
            .insert_group(&StaticGroup {
                name: "legacy-group".to_string(),
                gid: 6000,
            })
            .unwrap();
        cache
            .replace_provider_entries(
                "provider-a",
                &[StaticUser {
                    name: "alice@example.org".to_string(),
                    uid: 2345,
                    gid: 6789,
                }],
                &[StaticGroup {
                    name: "group-a".to_string(),
                    gid: 7000,
                }],
                true,
            )
            .unwrap();
        cache
            .replace_provider_entries(
                "provider-b",
                &[StaticUser {
                    name: "alice@example.org".to_string(),
                    uid: 3456,
                    gid: 7890,
                }],
                &[StaticGroup {
                    name: "group-b".to_string(),
                    gid: 8000,
                }],
                false,
            )
            .unwrap();

        assert!(cache.get_user_by_name("alice@example.org").is_none());
        assert!(cache.get_group_by_name("legacy-group").is_none());
        assert_eq!(
            cache
                .get_user_by_provider_name("provider-a", "alice@example.org")
                .map(|user| (user.uid, user.gid)),
            Some((2345, 6789))
        );
        assert_eq!(
            cache
                .get_user_by_provider_name("provider-b", "alice@example.org")
                .map(|user| (user.uid, user.gid)),
            Some((3456, 7890))
        );

        cache
            .replace_provider_entries("provider-a", &[], &[], false)
            .unwrap();
        assert!(cache
            .get_user_by_provider_name("provider-a", "alice@example.org")
            .is_none());
        assert_eq!(
            cache
                .get_user_by_provider_name("provider-b", "alice@example.org")
                .map(|user| (user.uid, user.gid)),
            Some((3456, 7890))
        );
        assert_eq!(
            cache
                .get_group_by_provider_name("provider-b", "group-b")
                .map(|group| group.gid),
            Some(8000)
        );
    }

    #[test]
    fn provider_replacement_can_preserve_legacy_mappings() {
        let mut cache = cache_with_user(&StaticUser {
            name: "legacy-user".to_string(),
            uid: 1234,
            gid: 5678,
        });
        cache
            .replace_provider_entries("provider-a", &[], &[], false)
            .unwrap();

        assert_eq!(
            cache
                .get_user_by_provider_name("provider-a", "legacy-user")
                .map(|user| user.uid),
            Some(1234)
        );
    }

    #[test]
    fn manual_provider_overrides_survive_enumeration() {
        let mut cache = StaticIdCache::in_memory_for_test().unwrap();
        let user_name = "alice@example.org";
        let group_name = "group-object-id";
        cache
            .replace_provider_entries(
                "provider-a",
                &[StaticUser {
                    name: user_name.to_string(),
                    uid: 1234,
                    gid: 5678,
                }],
                &[StaticGroup {
                    name: group_name.to_string(),
                    gid: 6000,
                }],
                false,
            )
            .unwrap();
        cache
            .replace_provider_entries(
                "provider-b",
                &[StaticUser {
                    name: user_name.to_string(),
                    uid: 2345,
                    gid: 6789,
                }],
                &[StaticGroup {
                    name: group_name.to_string(),
                    gid: 7000,
                }],
                false,
            )
            .unwrap();
        cache
            .set_provider_user_override(
                "provider-a",
                &StaticUser {
                    name: user_name.to_string(),
                    uid: 3456,
                    gid: 7890,
                },
            )
            .unwrap();
        cache
            .set_provider_group_override(
                "provider-a",
                &StaticGroup {
                    name: group_name.to_string(),
                    gid: 8000,
                },
            )
            .unwrap();
        cache
            .replace_provider_entries(
                "provider-a",
                &[StaticUser {
                    name: user_name.to_string(),
                    uid: 4567,
                    gid: 8901,
                }],
                &[StaticGroup {
                    name: group_name.to_string(),
                    gid: 9000,
                }],
                false,
            )
            .unwrap();

        assert_eq!(
            cache
                .get_user_by_provider_name("provider-a", user_name)
                .map(|user| (user.uid, user.gid)),
            Some((3456, 7890))
        );
        assert_eq!(
            cache
                .get_group_by_provider_name("provider-a", group_name)
                .map(|group| group.gid),
            Some(8000)
        );
        assert_eq!(
            cache
                .get_user_by_provider_name("provider-b", user_name)
                .map(|user| (user.uid, user.gid)),
            Some((2345, 6789))
        );
        assert_eq!(
            cache
                .get_group_by_provider_name("provider-b", group_name)
                .map(|group| group.gid),
            Some(7000)
        );
    }

    #[test]
    fn provider_replacement_rolls_back_legacy_deletion_on_error() {
        let mut cache = cache_with_user(&StaticUser {
            name: "legacy-user".to_string(),
            uid: 1234,
            gid: 5678,
        });
        cache
            .replace_provider_entries(
                "provider-a",
                &[StaticUser {
                    name: "existing-user".to_string(),
                    uid: 2345,
                    gid: 6789,
                }],
                &[],
                false,
            )
            .unwrap();
        cache
            .conn
            .as_ref()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_provider_user
                 BEFORE INSERT ON provider_static_users
                 BEGIN
                     SELECT RAISE(ABORT, 'blocked');
                 END;",
            )
            .unwrap();
        let replacement = [StaticUser {
            name: "replacement-user".to_string(),
            uid: 2000,
            gid: 2000,
        }];
        assert!(cache
            .replace_provider_entries("provider-a", &replacement, &[], true)
            .is_err());
        assert_eq!(cache.get_user_by_name("legacy-user").unwrap().uid, 1234);
        assert!(cache
            .get_user_by_provider_name("provider-a", "replacement-user")
            .is_none());
        assert_eq!(
            cache
                .get_user_by_provider_name("provider-a", "existing-user")
                .map(|user| (user.uid, user.gid)),
            Some((2345, 6789))
        );
    }

    #[test]
    fn provider_replacement_rejects_read_only_caches() {
        let conn = Connection::open_in_memory().unwrap();
        let mut cache = StaticIdCache {
            conn: Some(conn),
            writable: false,
        };
        assert!(cache
            .replace_provider_entries("provider-a", &[], &[], false)
            .is_err());
    }

    #[test]
    fn writable_schema_setup_preserves_legacy_mappings() {
        let conn = Connection::open_in_memory().unwrap();
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
            INSERT INTO static_users (name, uid, gid) VALUES ('legacy-user', 1234, 5678);",
        )
        .unwrap();
        ensure_schema(&conn).unwrap();
        let cache = StaticIdCache {
            conn: Some(conn),
            writable: true,
        };
        assert_eq!(cache.get_user_by_name("legacy-user").unwrap().uid, 1234);
        assert_eq!(
            cache
                .get_user_by_provider_name("provider-a", "legacy-user")
                .unwrap()
                .gid,
            5678
        );
    }

    #[test]
    fn writable_schema_setup_adds_override_columns_to_existing_provider_tables() {
        let conn = Connection::open_in_memory().unwrap();
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
            CREATE TABLE provider_static_users (
                provider TEXT NOT NULL,
                name TEXT NOT NULL,
                uid INTEGER NOT NULL,
                gid INTEGER NOT NULL,
                PRIMARY KEY (provider, name)
            );
            CREATE TABLE provider_static_groups (
                provider TEXT NOT NULL,
                name TEXT NOT NULL,
                gid INTEGER NOT NULL,
                PRIMARY KEY (provider, name)
            );
            INSERT INTO provider_static_users (provider, name, uid, gid)
            VALUES ('provider-a', 'alice', 1234, 5678);
            INSERT INTO provider_static_groups (provider, name, gid)
            VALUES ('provider-a', 'group-id', 6000);",
        )
        .unwrap();
        ensure_schema(&conn).unwrap();
        let cache = StaticIdCache {
            conn: Some(conn),
            writable: true,
        };
        cache
            .set_provider_user_override(
                "provider-a",
                &StaticUser {
                    name: "alice".to_string(),
                    uid: 2345,
                    gid: 6789,
                },
            )
            .unwrap();
        cache
            .set_provider_group_override(
                "provider-a",
                &StaticGroup {
                    name: "group-id".to_string(),
                    gid: 7000,
                },
            )
            .unwrap();

        assert_eq!(
            cache
                .get_user_by_provider_name("provider-a", "alice")
                .map(|user| (user.uid, user.gid)),
            Some((2345, 6789))
        );
        assert_eq!(
            cache
                .get_group_by_provider_name("provider-a", "group-id")
                .map(|group| group.gid),
            Some(7000)
        );
    }
}
