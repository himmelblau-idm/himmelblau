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
            if is_root {
                let migrate_conn =
                    Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
                ensure_static_users_schema(&migrate_conn)?;
            }
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

        if let Ok(mut stmt) = conn.prepare(
            "SELECT name, username, uid, gid, script_uid, script_gid, script_ran \
             FROM static_users WHERE name = ?1",
        ) {
            let mut rows = stmt.query([name]).ok()?;
            let row = rows.next().ok().flatten()?;

            return Some(StaticUser {
                name: row.get(0).ok()?,
                username: row.get(1).ok()?,
                uid: row.get(2).ok()?,
                gid: row.get(3).ok()?,
                script_uid: row.get(4).ok()?,
                script_gid: row.get(5).ok()?,
                script_ran: row.get::<_, i32>(6).unwrap_or(0) != 0,
            });
        }

        // Fallback for schemas that lack the new columns.
        if let Ok(mut stmt) =
            conn.prepare("SELECT name, username, uid, gid FROM static_users WHERE name = ?1")
        {
            let mut rows = stmt.query([name]).ok()?;
            let row = rows.next().ok().flatten()?;

            return Some(StaticUser {
                name: row.get(0).ok()?,
                username: row.get(1).ok()?,
                uid: row.get(2).ok()?,
                gid: row.get(3).ok()?,
                script_uid: None,
                script_gid: None,
                script_ran: false,
            });
        }

        let mut stmt = conn
            .prepare("SELECT name, uid, gid FROM static_users WHERE name = ?1")
            .ok()?;
        let mut rows = stmt.query([name]).ok()?;
        let row = rows.next().ok().flatten()?;

        Some(StaticUser {
            name: row.get(0).ok()?,
            username: None,
            uid: row.get(1).ok()?,
            gid: row.get(2).ok()?,
            script_uid: None,
            script_gid: None,
            script_ran: false,
        })
    }

    pub fn get_group_by_name(&self, name: &str) -> Option<StaticGroup> {
        self.conn.as_ref()?;
        let conn = self.conn.as_ref()?;

        let mut stmt = conn
            .prepare("SELECT name, gid FROM static_groups WHERE name = ?1")
            .ok()?;
        let mut rows = stmt.query([name]).ok()?;
        let row = rows.next().ok().flatten()?;

        Some(StaticGroup {
            name: row.get(0).ok()?,
            gid: row.get(1).ok()?,
        })
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
}
