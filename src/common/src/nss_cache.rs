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
                "CREATE TABLE IF NOT EXISTS nss_passwd (
                    name TEXT PRIMARY KEY,
                    uid INTEGER NOT NULL,
                    gid INTEGER NOT NULL,
                    gecos TEXT NOT NULL,
                    homedir TEXT NOT NULL,
                    shell TEXT NOT NULL,
                    last_updated INTEGER NOT NULL
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

    pub fn insert_user(&self, user: &NssUser) -> Result<()> {
        if let Some(conn) = &self.conn {
            if self.writable {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                let _ = conn.execute(
                    "INSERT OR REPLACE INTO nss_passwd (name, uid, gid, gecos, homedir, shell, last_updated)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        user.name,
                        user.uid,
                        user.gid,
                        user.gecos,
                        user.homedir,
                        user.shell,
                        now
                    ],
                );
            }
        }
        Ok(())
    }

    pub fn get_user(&self, id: &Id) -> Option<NssUser> {
        self.conn.as_ref()?;

        let max_age_secs: i64 = 48 * 3600; // 48 hours
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let (query, param) = match id {
            Id::Name(n) => (
                "SELECT name, uid, gid, gecos, homedir, shell, last_updated
                FROM nss_passwd WHERE name = ?1",
                n as &dyn rusqlite::ToSql,
            ),
            Id::Gid(uid) => (
                "SELECT name, uid, gid, gecos, homedir, shell, last_updated
                FROM nss_passwd WHERE uid = ?1",
                uid as &dyn rusqlite::ToSql,
            ),
        };

        if let Some(conn) = &self.conn {
            let mut stmt = conn.prepare(query).ok()?;
            let mut rows = stmt.query([param]).ok()?;
            if let Ok(Some(row)) = rows.next() {
                let last_updated: i64 = row.get(6).ok()?;
                if now - last_updated > max_age_secs {
                    return None;
                }

                Some(NssUser {
                    name: row.get(0).ok()?,
                    uid: row.get(1).ok()?,
                    gid: row.get(2).ok()?,
                    gecos: row.get(3).ok()?,
                    homedir: row.get(4).ok()?,
                    shell: row.get(5).ok()?,
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn get_users(&self) -> Vec<NssUser> {
        let mut users = Vec::new();
        if self.conn.is_none() {
            return users;
        }

        let max_age_secs: i64 = 48 * 3600; // 48 hours
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if let Some(conn) = &self.conn {
            let mut stmt = match conn.prepare(
                "SELECT name, uid, gid, gecos, homedir, shell, last_updated FROM nss_passwd",
            ) {
                Ok(stmt) => stmt,
                Err(_) => return users,
            };

            let rows = stmt.query_map([], |row| {
                let last_updated: i64 = row.get(6)?;
                if now - last_updated <= max_age_secs {
                    Ok(Some(NssUser {
                        name: row.get(0)?,
                        uid: row.get(1)?,
                        gid: row.get(2)?,
                        gecos: row.get(3)?,
                        homedir: row.get(4)?,
                        shell: row.get(5)?,
                    }))
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
