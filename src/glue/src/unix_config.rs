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
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::unix_passwd::parse_etc_passwd;
use std::fs::File;
use std::io::Read;

pub trait KanidmUnixdConfig {
    fn map_cn_name(&self, account_id: &str) -> String;
}

impl KanidmUnixdConfig for HimmelblauConfig {
    fn map_cn_name(&self, account_id: &str) -> String {
        // Make sure this account_id isn't a local user
        let mut contents = vec![];
        if let Ok(mut file) = File::open("/etc/passwd") {
            let _ = file.read_to_end(&mut contents);
        }
        let local_users = parse_etc_passwd(contents.as_slice()).unwrap_or_default();
        if local_users
            .into_iter()
            .map(|u| u.name.to_string())
            .collect::<Vec<String>>()
            .contains(&account_id.to_string())
        {
            return account_id.to_string();
        }

        let domains = self.get_configured_domains();
        if self.get_cn_name_mapping() && !account_id.contains('@') && !domains.is_empty() {
            return format!("{}@{}", account_id, domains[0]);
        }
        account_id.to_string()
    }
}
