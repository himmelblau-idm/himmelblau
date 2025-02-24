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
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO mapping (upn, mapped_name) VALUES (?1, ?2)",
                    params![upn, mapped_name],
                );
            }
        }
        Ok(())
    }

    pub fn get_mapped_name(&self, upn: &str) -> String {
        if self.conn.is_none() {
            return upn.to_string();
        }

        if !upn.contains('@') {
            return upn.to_string();
        }

        if let Some(conn) = &self.conn {
            let mut stmt = match conn.prepare("SELECT mapped_name FROM mapping WHERE upn = ?1") {
                Ok(stmt) => stmt,
                Err(_) => return upn.to_string(),
            };
            let mut rows = match stmt.query(params![upn]) {
                Ok(rows) => rows,
                Err(_) => return upn.to_string(),
            };
            if let Ok(Some(row)) = rows.next() {
                match row.get(0) {
                    Ok(mapped_name) => mapped_name,
                    Err(_) => upn.to_string(),
                }
            } else {
                upn.to_string()
            }
        } else {
            upn.to_string()
        }
    }
}
