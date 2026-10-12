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

        Ok(MappedNameCache { conn, writable })
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

    /// Returns the cached name for a UPN, or `None` on a miss or a read error.
    /// UPNs are case-insensitive, so the key is matched regardless of case.
    pub fn lookup_mapped_name(&self, upn: &str) -> Option<String> {
        if !upn.contains('@') {
            return None;
        }
        let conn = self.conn.as_ref()?;
        conn.query_row(
            "SELECT mapped_name FROM mapping WHERE lower(upn) = lower(?1) LIMIT 1",
            params![upn],
            |row| row.get(0),
        )
        .ok()
    }
}
