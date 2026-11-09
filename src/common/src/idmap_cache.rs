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
);";

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
            conn.execute_batch(CREATE_TABLES)?;
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
}
