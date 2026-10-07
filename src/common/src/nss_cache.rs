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

        let mut conn = if path.exists() {
            if is_root && *mode == Mode::ReadWrite {
                writable = true;
                Some(Connection::open(db_path)?)
            } else {
                Some(Connection::open_with_flags(
                    db_path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY,
                )?)
            }
        } else if is_root && *mode == Mode::ReadWrite {
            writable = true;
            let conn = Connection::open(db_path)?;
            fs::set_permissions(db_path, fs::Permissions::from_mode(0o644))
                .map_err(|_| rusqlite::Error::InvalidPath(db_path.into()))?;
            Some(conn)
        } else {
            None
        };

        if writable {
            if let Some(conn) = conn.as_mut() {
                Self::initialize_schema(conn)?;
            }
        }

        Ok(NssCache { conn, writable })
    }

    fn initialize_schema(conn: &mut Connection) -> Result<()> {
        // Root NSS lookups also open the fallback cache for writing. Once the
        // schema is current, do not take a write lock just to read cached users.
        if conn
            .prepare("SELECT display_name FROM nss_passwd LIMIT 0")
            .is_ok()
            && conn
                .prepare("SELECT alias, name FROM nss_passwd_aliases LIMIT 0")
                .is_ok()
        {
            return Ok(());
        }
        let tx = conn.transaction()?;
        tx.execute(
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
        let has_display_name = {
            let mut stmt = tx.prepare("PRAGMA table_info(nss_passwd)")?;
            let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
            columns
                .collect::<Result<Vec<_>>>()?
                .iter()
                .any(|name| name == "display_name")
        };
        if !has_display_name {
            tx.execute("ALTER TABLE nss_passwd ADD COLUMN display_name TEXT", [])?;
        }
        // A lookup alias can belong to more than one account. Retain every
        // owner so ambiguous aliases fail closed rather than last-writer-wins.
        tx.execute(
            "CREATE TABLE IF NOT EXISTS nss_passwd_aliases (
                alias TEXT NOT NULL,
                name TEXT NOT NULL,
                PRIMARY KEY (alias, name)
             )",
            [],
        )?;
        tx.commit()
    }

    pub fn insert_user(&self, user: &NssUser) -> Result<()> {
        if let Some(conn) = &self.conn {
            if self.writable {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let cache_key = user
                    .canonical_name
                    .as_ref()
                    .map(|name| name.to_lowercase())
                    .unwrap_or_else(|| user.name.clone());
                let display_name = user.canonical_name.as_ref().map(|_| user.name.as_str());
                let tx = conn.unchecked_transaction()?;

                // The resolver assigns one owner per uid. A refreshed account
                // may have a new canonical UPN, so retire its previous keys and
                // alias ownership together, including pre-upgrade entries.
                tx.execute(
                    "DELETE FROM nss_passwd_aliases
                     WHERE name = ?2 OR name IN (SELECT name FROM nss_passwd WHERE uid = ?1)",
                    params![user.uid, cache_key],
                )?;
                tx.execute(
                    "DELETE FROM nss_passwd WHERE uid = ?1 AND name != ?2",
                    params![user.uid, cache_key],
                )?;
                tx.execute(
                    "INSERT OR REPLACE INTO nss_passwd
                     (name, uid, gid, gecos, homedir, shell, last_updated, display_name)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        cache_key,
                        user.uid,
                        user.gid,
                        user.gecos,
                        user.homedir,
                        user.shell,
                        now,
                        display_name
                    ],
                )?;
                for alias in &user.aliases {
                    tx.execute(
                        "INSERT OR IGNORE INTO nss_passwd_aliases (alias, name) VALUES (?1, ?2)",
                        params![alias.to_lowercase(), cache_key],
                    )?;
                }
                tx.commit()?;
            }
        }
        Ok(())
    }

    fn user_from_row(&self, row: &rusqlite::Row<'_>) -> Result<NssUser> {
        let cache_key: String = row.get(0)?;
        let display_name: Option<String> = row.get(7)?;
        let canonical_name = display_name.as_ref().map(|_| cache_key.clone());
        let aliases = self
            .conn
            .as_ref()
            .and_then(|conn| {
                let mut stmt = conn
                    .prepare("SELECT alias FROM nss_passwd_aliases WHERE name = ?1 ORDER BY alias")
                    .ok()?;
                let rows = stmt.query_map([&cache_key], |row| row.get(0)).ok()?;
                rows.collect::<Result<Vec<String>>>().ok()
            })
            .unwrap_or_default();
        Ok(NssUser {
            name: display_name.unwrap_or(cache_key),
            canonical_name,
            aliases,
            uid: row.get(1)?,
            gid: row.get(2)?,
            gecos: row.get(3)?,
            homedir: row.get(4)?,
            shell: row.get(5)?,
        })
    }

    pub fn get_user(&self, id: &Id) -> Option<NssUser> {
        let conn = self.conn.as_ref()?;
        let max_age_secs: i64 = 48 * 3600; // 48 hours
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let (column, param): (&str, &dyn rusqlite::ToSql) = match id {
            Id::Name(name) => ("name", name),
            Id::Gid(uid) => ("uid", uid),
        };
        let query = format!(
            "SELECT name, uid, gid, gecos, homedir, shell, last_updated, display_name
             FROM nss_passwd WHERE {column} = ?1 COLLATE NOCASE"
        );
        let legacy_query = query.replace("display_name", "NULL");
        let mut stmt = conn
            .prepare(&query)
            .or_else(|_| conn.prepare(&legacy_query))
            .ok()?;
        let mut rows = stmt.query([param]).ok()?;
        if let Some(row) = rows.next().ok()? {
            let last_updated: i64 = row.get(6).ok()?;
            // Canonical identities take precedence even if their cached entry
            // expired. Never let a different account's alias take over a UPN.
            if now - last_updated > max_age_secs {
                return None;
            }
            let user = self.user_from_row(row).ok()?;
            return if rows.next().ok()?.is_none() {
                Some(user)
            } else {
                None
            };
        }

        let Id::Name(name) = id else {
            return None;
        };
        let mut stmt = conn.prepare(
            "SELECT p.name, p.uid, p.gid, p.gecos, p.homedir, p.shell, p.last_updated, p.display_name
             FROM nss_passwd p JOIN nss_passwd_aliases a ON a.name = p.name
             WHERE a.alias = ?1 AND p.last_updated >= ?2",
        ).ok()?;
        let mut rows = stmt
            .query(params![name.to_lowercase(), now - max_age_secs])
            .ok()?;
        let user = self.user_from_row(rows.next().ok()??).ok()?;
        // More than one current owner means this alias is not safe to resolve.
        if rows.next().ok()?.is_some() {
            return None;
        }
        Some(user)
    }

    /// Fallback cache entries have no evidence that a qualified alias is not
    /// another user's real UPN. Only the daemon can verify that ambiguity.
    pub fn get_user_for_fallback(&self, id: &Id) -> Option<NssUser> {
        let user = self.get_user(id)?;
        if let Id::Name(name) = id {
            if name.contains('@')
                && !user
                    .canonical_name
                    .as_deref()
                    .is_some_and(|canonical| canonical.eq_ignore_ascii_case(name))
            {
                return None;
            }
        }
        Some(user)
    }

    pub fn get_users(&self) -> Vec<NssUser> {
        let mut users = Vec::new();
        let max_age_secs: i64 = 48 * 3600; // 48 hours
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if let Some(conn) = &self.conn {
            let mut stmt = match conn.prepare(
                "SELECT name, uid, gid, gecos, homedir, shell, last_updated, display_name FROM nss_passwd",
            ).or_else(|_| conn.prepare(
                "SELECT name, uid, gid, gecos, homedir, shell, last_updated, NULL FROM nss_passwd",
            )) {
                Ok(stmt) => stmt,
                Err(_) => return users,
            };

            let rows = stmt.query_map([], |row| {
                let last_updated: i64 = row.get(6)?;
                if now - last_updated <= max_age_secs {
                    self.user_from_row(row).map(Some)
                } else {
                    Ok(None)
                }
            });

            if let Ok(mapped_rows) = rows {
                for user in mapped_rows.flatten().flatten() {
                    users.push(user);
                }
            }
        }

        users
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> NssCache {
        let mut conn = Connection::open_in_memory().unwrap();
        NssCache::initialize_schema(&mut conn).unwrap();
        NssCache {
            conn: Some(conn),
            writable: true,
        }
    }

    fn user(canonical_name: &str, name: &str, uid: u32) -> NssUser {
        NssUser {
            name: name.to_string(),
            canonical_name: Some(canonical_name.to_string()),
            aliases: vec![name.to_string()],
            uid,
            gid: uid,
            gecos: "Test User".to_string(),
            homedir: "/home/test".to_string(),
            shell: "/bin/bash".to_string(),
        }
    }

    fn create_legacy_schema(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE nss_passwd (
                name TEXT PRIMARY KEY, uid INTEGER NOT NULL, gid INTEGER NOT NULL,
                gecos TEXT NOT NULL, homedir TEXT NOT NULL, shell TEXT NOT NULL,
                last_updated INTEGER NOT NULL
             );
             INSERT INTO nss_passwd VALUES
                ('alice', 1000, 1000, 'Test User', '/home/test', '/bin/bash', strftime('%s', 'now'));",
        ).unwrap();
    }

    #[test]
    fn fallback_cannot_substitute_a_qualified_alias_for_an_uncached_upn() {
        let cache = cache();
        for (canonical, alias, uid) in [
            ("alice@example.com", "bob@example.com", 1000),
            ("alice@secondary.com", "bob@secondary.com", 1001),
        ] {
            let mut alice = user(canonical, alias, uid);
            alice.aliases.push(format!("bare-{uid}"));
            cache.insert_user(&alice).unwrap();
            // Cache discovery sees the alias, but fallback cannot establish
            // whether another directory user owns the requested real UPN.
            assert_eq!(cache.get_user(&Id::Name(alias.into())).unwrap().uid, uid);
            assert!(cache
                .get_user_for_fallback(&Id::Name(alias.into()))
                .is_none());
            assert_eq!(
                cache
                    .get_user_for_fallback(&Id::Name(canonical.to_uppercase()))
                    .unwrap()
                    .uid,
                uid
            );
            assert_eq!(cache.get_user_for_fallback(&Id::Gid(uid)).unwrap().uid, uid);
            assert_eq!(
                cache
                    .get_user_for_fallback(&Id::Name(format!("bare-{uid}")))
                    .unwrap()
                    .uid,
                uid
            );
        }
        // Older NSS libraries stored display names without canonical metadata,
        // including qualified SAM names. Such rows cannot establish ownership.
        let mut legacy = user("unused@example.com", "legacy@example.com", 1003);
        legacy.canonical_name = None;
        legacy.aliases.clear();
        cache.insert_user(&legacy).unwrap();
        assert!(cache.get_user(&Id::Name(legacy.name.clone())).is_some());
        assert!(cache
            .get_user_for_fallback(&Id::Name(legacy.name))
            .is_none());
        assert_eq!(
            cache
                .get_user_for_fallback(&Id::Gid(legacy.uid))
                .unwrap()
                .uid,
            legacy.uid
        );
        let bob = user("bob@example.com", "robert", 1002);
        cache.insert_user(&bob).unwrap();
        assert_eq!(
            cache
                .get_user_for_fallback(&Id::Name("bob@example.com".into()))
                .unwrap()
                .uid,
            bob.uid
        );
    }

    #[test]
    fn old_and_migrated_caches_require_canonical_metadata_for_qualified_fallback() {
        for migrated in [false, true] {
            let mut conn = Connection::open_in_memory().unwrap();
            create_legacy_schema(&conn);
            conn.execute("UPDATE nss_passwd SET name = 'legacy@example.com'", [])
                .unwrap();
            if migrated {
                NssCache::initialize_schema(&mut conn).unwrap();
            }
            let cache = NssCache {
                conn: Some(conn),
                writable: false,
            };
            let id = Id::Name("legacy@example.com".into());
            assert!(cache.get_user(&id).is_some());
            assert!(cache.get_user_for_fallback(&id).is_none());
            assert_eq!(
                cache.get_user_for_fallback(&Id::Gid(1000)).unwrap().uid,
                1000
            );
        }
    }

    #[test]
    fn canonical_and_expanded_alias_survive_read_only_fallback() {
        let path = std::env::temp_dir().join(format!("himmelblau-nss-{}.db", uuid::Uuid::new_v4()));
        let mut conn = Connection::open(&path).unwrap();
        NssCache::initialize_schema(&mut conn).unwrap();
        let cache = NssCache {
            conn: Some(conn),
            writable: true,
        };
        let user = user("alice.long@contoso.com", "alice@contoso.com", 1000);
        cache.insert_user(&user).unwrap();
        drop(cache);
        let cache = NssCache::new(path.to_str().unwrap(), &Mode::ReadOnly).unwrap();

        for key in [
            "alice.long@contoso.com",
            "alice@contoso.com",
            "ALICE@CONTOSO.COM",
        ] {
            let found = cache.get_user(&Id::Name(key.to_string())).unwrap();
            assert_eq!(found.name, "alice@contoso.com");
            assert_eq!(
                found.canonical_name.as_deref(),
                Some("alice.long@contoso.com")
            );
            assert_eq!(found.uid, 1000);
        }
        assert_eq!(cache.get_user(&Id::Gid(1000)).unwrap().name, user.name);
        assert!(cache.get_user(&Id::Name("alice".to_string())).is_none());
        assert_eq!(cache.get_users().len(), 1);
        drop(cache);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn current_schema_does_not_require_a_write_lock() {
        let mut conn = Connection::open_in_memory().unwrap();
        NssCache::initialize_schema(&mut conn).unwrap();
        conn.pragma_update(None, "query_only", true).unwrap();
        NssCache::initialize_schema(&mut conn).unwrap();
    }

    #[test]
    fn identical_display_names_keep_separate_canonical_identities() {
        let cache = cache();
        let mut first = user("alice.long@contoso.com", "alice", 1000);
        first.aliases = vec!["alice@contoso.com".to_string()];
        let mut second = user("alice.long@fabrikam.com", "alice", 1001);
        second.aliases = vec!["alice@fabrikam.com".to_string()];
        cache.insert_user(&first).unwrap();
        cache.insert_user(&second).unwrap();

        for (key, uid) in [("alice@contoso.com", 1000), ("alice@fabrikam.com", 1001)] {
            let found = cache.get_user(&Id::Name(key.to_string())).unwrap();
            assert_eq!(found.name, "alice");
            assert_eq!(found.uid, uid);
        }
        assert_eq!(cache.get_users().len(), 2);
    }

    #[test]
    fn ambiguous_aliases_fail_closed_and_can_be_reassigned() {
        let cache = cache();
        let first = user("alice.one@contoso.com", "alice@contoso.com", 1000);
        let mut second = user("alice.two@contoso.com", "alice@contoso.com", 1001);
        cache.insert_user(&first).unwrap();
        cache.insert_user(&second).unwrap();
        let alias = Id::Name("alice@contoso.com".to_string());
        assert!(cache.get_user(&alias).is_none());
        assert_eq!(
            cache
                .get_user(&Id::Name(first.canonical_name.clone().unwrap()))
                .unwrap()
                .uid,
            1000
        );
        assert_eq!(
            cache
                .get_user(&Id::Name(second.canonical_name.clone().unwrap()))
                .unwrap()
                .uid,
            1001
        );

        second.aliases.clear();
        cache.insert_user(&second).unwrap();
        assert_eq!(cache.get_user(&alias).unwrap().uid, 1000);
    }

    #[test]
    fn canonical_identity_wins_over_alias_even_when_expired() {
        let cache = cache();
        let canonical = user("alice@contoso.com", "alice-local@contoso.com", 1000);
        let alias_owner = user("other@contoso.com", "alice@contoso.com", 1001);
        cache.insert_user(&canonical).unwrap();
        cache.insert_user(&alias_owner).unwrap();
        let id = Id::Name("alice@contoso.com".to_string());
        assert_eq!(cache.get_user(&id).unwrap().uid, 1000);

        cache
            .conn
            .as_ref()
            .unwrap()
            .execute(
                "UPDATE nss_passwd SET last_updated = 0 WHERE uid = 1000",
                [],
            )
            .unwrap();
        assert!(cache.get_user(&id).is_none());
    }

    #[test]
    fn refresh_removes_old_aliases_and_expiry_applies_to_every_lookup() {
        let cache = cache();
        let mut user = user("alice.long@contoso.com", "old@contoso.com", 1000);
        cache.insert_user(&user).unwrap();
        user.name = "new@contoso.com".to_string();
        user.aliases = vec![user.name.clone()];
        cache.insert_user(&user).unwrap();
        assert!(cache
            .get_user(&Id::Name("old@contoso.com".to_string()))
            .is_none());
        assert_eq!(
            cache.get_user(&Id::Name(user.name.clone())).unwrap().name,
            user.name
        );
        assert_eq!(cache.get_users().len(), 1);

        cache
            .conn
            .as_ref()
            .unwrap()
            .execute("UPDATE nss_passwd SET last_updated = 0", [])
            .unwrap();
        assert!(cache.get_user(&Id::Name(user.name)).is_none());
        assert!(cache
            .get_user(&Id::Name(user.canonical_name.unwrap()))
            .is_none());
        assert!(cache.get_user(&Id::Gid(1000)).is_none());
        assert!(cache.get_users().is_empty());
    }

    #[test]
    fn canonical_rename_replaces_uid_and_alias_ownership_atomically() {
        let cache = cache();
        let mut user = user("old.upn@contoso.com", "sam@contoso.com", 1000);
        user.aliases.push("old-alias@contoso.com".to_string());
        cache.insert_user(&user).unwrap();
        user.canonical_name = Some("new.upn@contoso.com".to_string());
        user.aliases = vec![user.name.clone()];
        cache.insert_user(&user).unwrap();

        for id in [
            Id::Gid(1000),
            Id::Name("sam@contoso.com".to_string()),
            Id::Name("new.upn@contoso.com".to_string()),
        ] {
            let found = cache.get_user(&id).unwrap();
            assert_eq!(found.uid, 1000);
            assert_eq!(found.name, "sam@contoso.com");
            assert_eq!(found.canonical_name.as_deref(), Some("new.upn@contoso.com"));
        }
        assert!(cache
            .get_user(&Id::Name("old.upn@contoso.com".to_string()))
            .is_none());
        assert!(cache
            .get_user(&Id::Name("old-alias@contoso.com".to_string()))
            .is_none());
        assert_eq!(cache.get_users().len(), 1);
        let old_alias_owners: u32 = cache
            .conn
            .as_ref()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM nss_passwd_aliases WHERE name = 'old.upn@contoso.com'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_alias_owners, 0);
    }

    #[test]
    fn legacy_read_only_cache_needs_no_migration() {
        let path = std::env::temp_dir().join(format!("himmelblau-nss-{}.db", uuid::Uuid::new_v4()));
        let conn = Connection::open(&path).unwrap();
        create_legacy_schema(&conn);
        drop(conn);
        let cache = NssCache::new(path.to_str().unwrap(), &Mode::ReadOnly).unwrap();
        let found = cache.get_user(&Id::Name("alice".to_string())).unwrap();
        assert_eq!(found.name, "alice");
        assert!(found.canonical_name.is_none());
        assert!(found.aliases.is_empty());
        assert_eq!(cache.get_user(&Id::Gid(1000)).unwrap().uid, 1000);
        assert_eq!(cache.get_users().len(), 1);
        assert!(cache.get_user(&Id::Name("missing".to_string())).is_none());
        assert!(cache
            .conn
            .as_ref()
            .unwrap()
            .prepare("SELECT display_name FROM nss_passwd")
            .is_err());
        drop(cache);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn migration_preserves_legacy_rows_and_refresh_deduplicates_them() {
        let mut conn = Connection::open_in_memory().unwrap();
        create_legacy_schema(&conn);
        NssCache::initialize_schema(&mut conn).unwrap();
        NssCache::initialize_schema(&mut conn).unwrap();
        let cache = NssCache {
            conn: Some(conn),
            writable: true,
        };
        assert_eq!(
            cache.get_user(&Id::Name("alice".to_string())).unwrap().uid,
            1000
        );
        cache
            .insert_user(&user("alice.long@contoso.com", "alice@contoso.com", 1000))
            .unwrap();
        assert_eq!(cache.get_users().len(), 1);
        assert!(cache.get_user(&Id::Name("alice".to_string())).is_none());
        assert_eq!(
            cache
                .get_user(&Id::Name("alice@contoso.com".to_string()))
                .unwrap()
                .uid,
            1000
        );
    }

    #[test]
    fn failed_alias_write_rolls_back_the_whole_refresh() {
        let cache = cache();
        let mut user = user("alice.long@contoso.com", "old@contoso.com", 1000);
        cache.insert_user(&user).unwrap();
        cache
            .conn
            .as_ref()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_alias BEFORE INSERT ON nss_passwd_aliases
             BEGIN SELECT RAISE(ABORT, 'test write failure'); END;",
            )
            .unwrap();
        user.canonical_name = Some("new.upn@contoso.com".to_string());
        user.name = "new@contoso.com".to_string();
        user.aliases = vec![user.name.clone()];
        assert!(cache.insert_user(&user).is_err());
        assert_eq!(
            cache
                .get_user(&Id::Name("old@contoso.com".to_string()))
                .unwrap()
                .name,
            "old@contoso.com"
        );
        assert!(cache.get_user(&Id::Name(user.name)).is_none());
        assert!(cache
            .get_user(&Id::Name(user.canonical_name.unwrap()))
            .is_none());
        assert_eq!(
            cache
                .get_user(&Id::Gid(1000))
                .unwrap()
                .canonical_name
                .as_deref(),
            Some("alice.long@contoso.com")
        );
        assert_eq!(cache.get_users().len(), 1);
    }
}
