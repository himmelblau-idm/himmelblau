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
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS static_users (
                    name TEXT PRIMARY KEY,
                    uid INTEGER NOT NULL,
                    gid INTEGER NOT NULL
                );
                 CREATE TABLE IF NOT EXISTS static_groups (
                    name TEXT PRIMARY KEY,
                    gid INTEGER NOT NULL
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

        Some(StaticUser {
            name: row.get(0).ok()?,
            uid: row.get(1).ok()?,
            gid: row.get(2).ok()?,
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
