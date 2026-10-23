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
use rusqlite::{params, Connection, OpenFlags, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(PartialEq)]
pub enum Mode {
    ReadOnly,
    ReadWrite,
}

pub struct MappedNameCache {
    conn: Option<Connection>,
    writable: bool,
}

impl MappedNameCache {
    pub fn new(db_path: &str, mode: &Mode) -> Result<Self> {
        Self::new_impl(db_path, mode, unsafe { libc::getuid() } == 0)
    }

    fn new_impl(db_path: &str, mode: &Mode, is_root: bool) -> Result<Self> {
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
                let (conn, can_write) =
                    Self::open_existing(|flags| Connection::open_with_flags(db_path, flags))?;
                writable = can_write;
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
                "CREATE TABLE IF NOT EXISTS mapping (
                        upn TEXT PRIMARY KEY,
                        mapped_name TEXT NOT NULL
                     )",
                [],
            )?;
            fs::set_permissions(db_path, fs::Permissions::from_mode(0o644))
                .map_err(|_| rusqlite::Error::InvalidPath(db_path.into()))?;
            Some(conn)
        } else {
            None
        };

        if writable {
            if let Some(conn) = &conn {
                // Migrate existing caches too. A read-only legacy cache remains usable
                // until a writer can install the case-insensitive lookup index.
                if let Err(e) = conn.execute(
                    "CREATE INDEX IF NOT EXISTS mapping_upn_lower ON mapping(lower(upn))",
                    [],
                ) {
                    warn!("Failed to index name mapping cache: {}", e);
                }
            }
        }
        Ok(MappedNameCache { conn, writable })
    }

    // A root NSS caller may be confined to read-only access by SELinux.
    fn open_existing(
        mut open: impl FnMut(OpenFlags) -> Result<Connection>,
    ) -> Result<(Connection, bool)> {
        match open(OpenFlags::SQLITE_OPEN_READ_WRITE) {
            Ok(conn) => Ok((conn, true)),
            Err(_) => open(OpenFlags::SQLITE_OPEN_READ_ONLY).map(|conn| (conn, false)),
        }
    }

    pub fn insert_mapping(&self, upn: &str, mapped_name: &str) -> Result<()> {
        if !upn.contains('@') || upn == mapped_name {
            return Ok(());
        }

        if let Some(conn) = &self.conn {
            if self.writable {
                conn.execute(
                    "INSERT OR REPLACE INTO mapping (upn, mapped_name) VALUES (?1, ?2)",
                    params![upn, mapped_name],
                )
                .map_err(|e| {
                    error!("Failed to insert name mapping for {}: {}", upn, e);
                    e
                })?;
            }
        }
        Ok(())
    }

    /// Cached name for a UPN, matched case-insensitively with an exact match first.
    pub fn lookup_mapped_name(&self, upn: &str) -> Option<String> {
        if !upn.contains('@') {
            return None;
        }
        let conn = self.conn.as_ref()?;
        conn.query_row(
            "SELECT mapped_name FROM mapping WHERE upn = ?1",
            params![upn],
            |row| row.get(0),
        )
        .ok()
        .or_else(|| {
            conn.query_row(
                "SELECT mapped_name FROM mapping WHERE lower(upn) = lower(?1) \
                 ORDER BY upn LIMIT 1",
                params![upn],
                |row| row.get(0),
            )
            .ok()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_cache(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE mapping (upn TEXT PRIMARY KEY, mapped_name TEXT NOT NULL);
            INSERT INTO mapping VALUES ('First.Last@example.com', 'First.Last');
            INSERT INTO mapping VALUES ('first.last@example.com', 'lowercase');",
        )
        .unwrap();
    }

    #[test]
    fn denied_write_open_preserves_readonly_cached_rename() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mapping.db");
        legacy_cache(&path);
        let mut attempts = Vec::new();
        let (conn, writable) = MappedNameCache::open_existing(|flags| {
            attempts.push(flags);
            if flags == OpenFlags::SQLITE_OPEN_READ_WRITE {
                Err(rusqlite::Error::InvalidPath(path.clone()))
            } else {
                Connection::open_with_flags(&path, flags)
            }
        })
        .unwrap();
        assert_eq!(
            attempts,
            vec![
                OpenFlags::SQLITE_OPEN_READ_WRITE,
                OpenFlags::SQLITE_OPEN_READ_ONLY
            ]
        );
        assert!(!writable);
        let cache = MappedNameCache {
            conn: Some(conn),
            writable,
        };
        assert_eq!(
            cache
                .lookup_mapped_name("first.last@example.com")
                .as_deref(),
            Some("lowercase")
        );
        cache
            .insert_mapping("first.last@example.com", "replacement")
            .unwrap();
        assert_eq!(
            cache
                .lookup_mapped_name("first.last@example.com")
                .as_deref(),
            Some("lowercase")
        );
        assert_eq!(
            cache
                .lookup_mapped_name("FIRST.LAST@EXAMPLE.COM")
                .as_deref(),
            Some("First.Last")
        );
    }

    #[test]
    fn exact_lookup_is_indexed_before_legacy_cache_migration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mapping.db");
        legacy_cache(&path);
        let cache = MappedNameCache::new(path.to_str().unwrap(), &Mode::ReadOnly).unwrap();
        let conn = cache.conn.as_ref().unwrap();
        let plan: String = conn
            .query_row(
                "EXPLAIN QUERY PLAN SELECT mapped_name FROM mapping WHERE upn = ?1",
                ["first.last@example.com"],
                |row| row.get(3),
            )
            .unwrap();
        assert!(plan.contains("SEARCH"), "{plan}");
        assert!(plan.contains("INDEX"), "{plan}");
        assert_eq!(
            cache
                .lookup_mapped_name("first.last@example.com")
                .as_deref(),
            Some("lowercase")
        );
    }

    #[test]
    fn writable_cache_migrates_casefolded_lookup_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mapping.db");
        legacy_cache(&path);
        let cache =
            MappedNameCache::new_impl(path.to_str().unwrap(), &Mode::ReadWrite, true).unwrap();
        let conn = cache.conn.as_ref().unwrap();
        let plan: String = conn.query_row(
            "EXPLAIN QUERY PLAN SELECT mapped_name FROM mapping WHERE lower(upn) = lower(?1) ORDER BY upn LIMIT 1",
            ["FIRST.LAST@EXAMPLE.COM"], |row| row.get(3)).unwrap();
        assert!(
            plan.contains("SEARCH") && plan.contains("mapping_upn_lower"),
            "{plan}"
        );
        assert_eq!(
            cache
                .lookup_mapped_name("FIRST.LAST@EXAMPLE.COM")
                .as_deref(),
            Some("First.Last")
        );
        assert_eq!(
            cache
                .lookup_mapped_name("first.last@example.com")
                .as_deref(),
            Some("lowercase")
        );
    }
}
