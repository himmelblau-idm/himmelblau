/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

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
use crate::idprovider::interface::Id;
use rusqlite::{params, Connection, OpenFlags, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::unix_proto::NssUser;

#[derive(PartialEq)]
pub enum Mode {
    ReadOnly,
    ReadWrite,
}

pub struct NssCache {
    conn: Option<Connection>,
    writable: bool,
}

impl NssCache {
    pub fn new(db_path: &str, mode: &Mode) -> Result<Self> {
        let is_root = unsafe { libc::getuid() } == 0;
        let path = Path::new(db_path);
        let mut writable = false;

        if !path.exists() && is_root {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|_| rusqlite::Error::InvalidPath(parent.into()))?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
                    .map_err(|_| rusqlite::Error::InvalidPath(parent.into()))?;
            }
        }

        let conn = if path.exists() {
            if is_root && *mode == Mode::ReadWrite {
                writable = true;
                let conn = Connection::open(db_path)?;
                Self::add_display_name(&conn);
                Some(conn)
            } else {
                Some(Connection::open_with_flags(
                    db_path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY,
                )?)
            }
        } else if is_root && *mode == Mode::ReadWrite {
            writable = true;
            let conn = Connection::open(db_path)?;
            conn.execute(
                "CREATE TABLE IF NOT EXISTS nss_passwd (
                    name TEXT PRIMARY KEY,
                    uid INTEGER NOT NULL,
                    gid INTEGER NOT NULL,
                    gecos TEXT NOT NULL,
                    homedir TEXT NOT NULL,
                    shell TEXT NOT NULL,
                    last_updated INTEGER NOT NULL,
                    display_name TEXT
                 )",
                [],
            )?;
            fs::set_permissions(db_path, fs::Permissions::from_mode(0o644))
                .map_err(|_| rusqlite::Error::InvalidPath(db_path.into()))?;
            Some(conn)
        } else {
            None
        };

        Ok(NssCache { conn, writable })
    }

    fn add_display_name(conn: &Connection) {
        if conn
            .prepare("SELECT display_name FROM nss_passwd LIMIT 0")
            .is_err()
        {
            let _ = conn.execute("ALTER TABLE nss_passwd ADD COLUMN display_name TEXT", []);
        }
    }

    pub fn insert_user(&self, user: &NssUser) -> Result<()> {
        if let Some(conn) = &self.conn {
            if self.writable {
                let name = user
                    .canonical_name
                    .as_ref()
                    .map(|canonical| canonical.to_lowercase())
                    .unwrap_or_else(|| user.name.clone());
                let display_name = user.canonical_name.as_ref().map(|_| &user.name);
                if !user.cacheable {
                    // A lookup-only result must also invalidate older fallback rows.
                    conn.execute(
                        "DELETE FROM nss_passwd WHERE name = ?1 OR uid = ?2",
                        params![name, user.uid],
                    )?;
                    return Ok(());
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                let tx = conn.unchecked_transaction()?;
                tx.execute(
                    "DELETE FROM nss_passwd WHERE uid = ?1 AND name != ?2",
                    params![user.uid, name],
                )?;
                tx.execute(
                    "INSERT OR REPLACE INTO nss_passwd (name, uid, gid, gecos, homedir, shell, last_updated, display_name)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        name,
                        user.uid,
                        user.gid,
                        user.gecos,
                        user.homedir,
                        user.shell,
                        now,
                        display_name
                    ],
                )?;
                tx.commit()?;
            }
        }
        Ok(())
    }

    fn query_users(&self, filter: &str, params: &[&dyn rusqlite::ToSql]) -> Vec<(NssUser, i64)> {
        let Some(conn) = self.conn.as_ref() else {
            return Vec::new();
        };
        let columns = "name, uid, gid, gecos, homedir, shell, last_updated";
        let query = format!("SELECT {columns}, display_name FROM nss_passwd {filter}");
        let legacy_query = format!("SELECT {columns}, NULL FROM nss_passwd {filter}");
        let Ok(mut stmt) = conn
            .prepare(&query)
            .or_else(|_| conn.prepare(&legacy_query))
        else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map(params, |row| {
            let key: String = row.get(0)?;
            let display_name: Option<String> = row.get(7)?;
            let user = NssUser {
                canonical_name: display_name.as_ref().map(|_| key.clone()),
                name: display_name.unwrap_or(key),
                uid: row.get(1)?,
                gid: row.get(2)?,
                gecos: row.get(3)?,
                homedir: row.get(4)?,
                shell: row.get(5)?,
                cacheable: true,
            };
            Ok((user, row.get(6)?))
        }) else {
            return Vec::new();
        };
        let users: Vec<(NssUser, i64)> = rows.flatten().collect();
        users
    }

    /// Qualified names resolve only by canonical UPN; an unqualified name may be one user's display name.
    pub fn get_user(&self, id: &Id) -> Option<NssUser> {
        let (filter, key): (&str, &dyn rusqlite::ToSql) = match id {
            Id::Name(name) => ("WHERE name = ?1 COLLATE NOCASE", name),
            Id::Gid(uid) => ("WHERE uid = ?1", uid),
        };
        let oldest = oldest_fresh();
        let mut owners = self.query_users(filter, &[key]);
        if owners.is_empty() {
            let Id::Name(name) = id else {
                return None;
            };
            if name.contains('@') {
                return None;
            }
            owners = self.query_users("WHERE display_name = ?1 COLLATE NOCASE", &[name]);
            owners.retain(|(_, updated)| *updated >= oldest);
        }
        match owners.as_slice() {
            [(user, updated)] if *updated >= oldest => Some(user.clone()),
            _ => None,
        }
    }

    pub fn get_users(&self) -> Vec<NssUser> {
        let oldest = oldest_fresh();
        self.query_users("", &[])
            .into_iter()
            .filter(|(_, updated)| *updated >= oldest)
            .map(|(user, _)| user)
            .collect()
    }
}

fn oldest_fresh() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    now - 48 * 3600 // 48 hours
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::NssCache;
    use crate::idprovider::interface::Id;
    use crate::unix_proto::NssUser;
    use rusqlite::Connection;

    fn test_cache() -> NssCache {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE nss_passwd (
                name TEXT PRIMARY KEY, uid INTEGER, gid INTEGER, gecos TEXT,
                homedir TEXT, shell TEXT, last_updated INTEGER, display_name TEXT
            )",
        )
        .unwrap();
        NssCache {
            conn: Some(conn),
            writable: true,
        }
    }

    fn test_user() -> NssUser {
        NssUser {
            name: "user@example.com".to_string(),
            canonical_name: None,
            uid: 2000,
            gid: 2000,
            gecos: String::new(),
            homedir: "/home/user".to_string(),
            shell: "/bin/sh".to_string(),
            cacheable: false,
        }
    }

    #[test]
    fn lookup_only_user_does_not_enter_fallback_cache() {
        let cache = test_cache();
        let mut user = test_user();
        let id = Id::Name(user.name.clone());

        cache.insert_user(&user).unwrap();
        assert!(cache.get_user(&id).is_none());
        user.cacheable = true;
        cache.insert_user(&user).unwrap();
        assert!(cache.get_user(&id).is_some());
    }

    #[test]
    fn lookup_only_user_evicts_matching_fallback_rows() {
        for (name, uid) in [
            ("user@example.com", 2000),
            ("user@example.com", 3000),
            ("renamed@example.com", 2000),
        ] {
            let cache = test_cache();
            let mut user = test_user();
            user.cacheable = true;
            let cached_name = Id::Name(user.name.clone());
            let cached_uid = Id::Gid(user.uid);
            cache.insert_user(&user).unwrap();
            assert!(cache.get_user(&cached_name).is_some());
            assert!(cache.get_user(&cached_uid).is_some());

            let mut unrelated = test_user();
            unrelated.name = "unrelated@example.com".to_string();
            unrelated.uid = 4000;
            unrelated.gid = 4000;
            unrelated.cacheable = true;
            cache.insert_user(&unrelated).unwrap();

            user.name = name.to_string();
            user.uid = uid;
            user.cacheable = false;
            cache.insert_user(&user).unwrap();

            assert!(cache.get_user(&cached_name).is_none());
            assert!(cache.get_user(&cached_uid).is_none());
            assert!(cache.get_user(&Id::Name(user.name.clone())).is_none());
            assert!(cache.get_user(&Id::Gid(user.uid)).is_none());
            assert!(cache.get_user(&Id::Name(unrelated.name.clone())).is_some());
            assert!(cache.get_user(&Id::Gid(unrelated.uid)).is_some());
            let users = cache.get_users();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].name, unrelated.name);
        }
    }

    fn alias_user(canonical: &str, name: &str, uid: u32) -> NssUser {
        NssUser {
            name: name.to_string(),
            canonical_name: Some(canonical.to_string()),
            cacheable: true,
            uid,
            gid: uid,
            ..test_user()
        }
    }

    fn by_name(cache: &NssCache, name: &str) -> Option<NssUser> {
        cache.get_user(&Id::Name(name.to_string()))
    }

    #[test]
    fn display_name_resolves_only_unqualified_and_unambiguously() {
        let cache = test_cache();
        cache
            .insert_user(&alias_user("alice.long@contoso.com", "alice", 1000))
            .unwrap();
        let found = by_name(&cache, "alice").unwrap();
        assert_eq!(
            found.canonical_name.as_deref(),
            Some("alice.long@contoso.com")
        );
        assert!(by_name(&cache, "ALICE.long@contoso.com").is_some());
        assert!(by_name(&cache, "alice@contoso.com").is_none());

        cache
            .insert_user(&alias_user("alice.long@fabrikam.com", "alice", 1001))
            .unwrap();
        assert!(by_name(&cache, "alice").is_none());
        assert_eq!(cache.get_users().len(), 2);
    }

    #[test]
    fn canonical_identity_wins_over_a_display_name_even_when_expired() {
        let cache = test_cache();
        cache
            .insert_user(&alias_user("alice@contoso.com", "bob", 1001))
            .unwrap();
        cache
            .insert_user(&alias_user("bob", "bob@contoso.com", 1002))
            .unwrap();
        cache
            .conn
            .as_ref()
            .unwrap()
            .execute(
                "UPDATE nss_passwd SET last_updated = 0 WHERE name = 'bob'",
                [],
            )
            .unwrap();
        assert!(by_name(&cache, "bob").is_none());
        assert!(cache.get_user(&Id::Gid(1002)).is_none());
        assert_eq!(cache.get_users().len(), 1);
    }

    #[test]
    fn refresh_replaces_the_previous_owner_of_a_uid() {
        let cache = test_cache();
        cache
            .insert_user(&alias_user("old.upn@contoso.com", "alice", 1000))
            .unwrap();
        cache
            .insert_user(&alias_user("new.upn@contoso.com", "alice", 1000))
            .unwrap();
        assert!(by_name(&cache, "old.upn@contoso.com").is_none());
        let found = by_name(&cache, "alice").unwrap();
        assert_eq!(found.canonical_name.as_deref(), Some("new.upn@contoso.com"));
        assert_eq!(cache.get_users().len(), 1);
    }

    #[test]
    fn legacy_cache_is_readable_and_migrated() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE nss_passwd (
                name TEXT PRIMARY KEY, uid INTEGER, gid INTEGER, gecos TEXT,
                homedir TEXT, shell TEXT, last_updated INTEGER
            );
            INSERT INTO nss_passwd VALUES
                ('alice', 1000, 1000, '', '/home/alice', '/bin/sh', strftime('%s', 'now'));",
        )
        .unwrap();
        let mut cache = NssCache {
            conn: Some(conn),
            writable: false,
        };
        assert!(by_name(&cache, "alice").unwrap().canonical_name.is_none());
        assert_eq!(cache.get_users().len(), 1);

        cache.writable = true;
        NssCache::add_display_name(cache.conn.as_ref().unwrap());
        cache
            .insert_user(&alias_user(
                "alice.long@contoso.com",
                "alice@contoso.com",
                1000,
            ))
            .unwrap();
        assert_eq!(cache.get_users().len(), 1);
        assert!(by_name(&cache, "alice").is_none());
    }
}
