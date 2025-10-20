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
use std::collections::HashMap;

pub struct UserMap {
    forward: HashMap<String, String>,
    reverse: HashMap<String, String>,
}

impl UserMap {
    pub fn new(user_map_file: &str) -> UserMap {
        let mut forward = HashMap::new();
        let mut reverse = HashMap::new();

        // User map lines are colon seperated.
        if let Ok(lines) = std::fs::read_to_string(user_map_file) {
            for line in lines.lines() {
                if line.trim_start().starts_with("#") || line.trim().is_empty() {
                    continue;
                }
                let mut it = line.splitn(2, ':');
                let local = it.next().map(str::trim).unwrap_or("").to_string();
                // The lowercase SPN names are because these are case-insensitive in Entra Id
                let upn = it.next().map(str::trim).unwrap_or("").to_lowercase();

                if local.is_empty() || upn.is_empty() {
                    continue;
                }
                if forward.contains_key(&local) {
                    continue;
                }
                if reverse.contains_key(&upn) {
                    continue;
                }

                forward.insert(local.clone(), upn.clone());
                reverse.insert(upn, local);
            }
        }

        UserMap { forward, reverse }
    }

    pub fn get_upn_from_local(&self, username: &str) -> Option<String> {
        self.forward.get(username).cloned()
    }

    pub fn get_local_from_upn(&self, upn: &str) -> Option<String> {
        self.reverse.get(upn).cloned()
    }

    pub fn get_id_overrides(&self) -> Vec<String> {
        self.forward.keys().cloned().collect()
    }
}
