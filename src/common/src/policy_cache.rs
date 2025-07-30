/*
   Unix Azure Entra ID implementation - Intune Compliance Cache
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

pub enum PolicyValue {
    Int(u32),
    Text(String),
}

pub struct PolicyCache {
    conn: Option<Connection>,
    writable: bool,
}

impl PolicyCache {
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
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS policies (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    is_number INTEGER NOT NULL
                );",
            )?;
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

    pub fn set(&self, key: &str, value: &PolicyValue) -> Result<()> {
        if !self.writable {
            return Ok(());
        }
        let conn = match &self.conn {
            Some(c) => c,
            None => return Ok(()),
        };

        let (val_str, is_number) = match value {
            PolicyValue::Int(num) => (num.to_string(), 1),
            PolicyValue::Text(ref s) => (s.clone(), 0),
        };

        conn.execute(
            "INSERT OR REPLACE INTO policies (key, value, is_number) VALUES (?1, ?2, ?3)",
            params![key, val_str, is_number],
        )?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<PolicyValue> {
        let conn = self.conn.as_ref()?;
        let mut stmt = conn
            .prepare("SELECT value, is_number FROM policies WHERE key = ?1")
            .ok()?;
        let mut rows = stmt.query([key]).ok()?;
        let row = rows.next().ok().flatten()?;
        let value: String = row.get(0).ok()?;
        let is_number: i32 = row.get(1).ok()?;

        if is_number == 1 {
            value.parse().ok().map(PolicyValue::Int)
        } else {
            Some(PolicyValue::Text(value))
        }
    }
}
