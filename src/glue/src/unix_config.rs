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
use himmelblau_unix_common::constants::{
    DEFAULT_CONN_TIMEOUT, DEFAULT_HELLO_PIN_MIN_LEN, DEFAULT_SOCK_PATH,
};
use himmelblau_unix_common::unix_passwd::parse_etc_passwd;
use std::fs::File;
use std::io::Read;

pub struct KanidmUnixdConfig {
    pub domains: Vec<String>,
    pub unix_sock_timeout: u64,
    pub sock_path: String,
    pub cn_name_mapping: bool,
    pub hello_pin_min_length: usize,
}

impl KanidmUnixdConfig {
    pub fn new() -> Self {
        KanidmUnixdConfig {
            domains: vec![],
            sock_path: DEFAULT_SOCK_PATH.to_string(),
            unix_sock_timeout: DEFAULT_CONN_TIMEOUT * 2,
            cn_name_mapping: false,
            hello_pin_min_length: DEFAULT_HELLO_PIN_MIN_LEN,
        }
    }

    pub fn read_options_from_optional_config(self, config_path: &str) -> Result<Self, String> {
        let config: HimmelblauConfig = HimmelblauConfig::new(Some(config_path))?;
        Ok(KanidmUnixdConfig {
            domains: config.get_configured_domains(),
            sock_path: config.get_socket_path(),
            unix_sock_timeout: config.get_connection_timeout() * 2,
            cn_name_mapping: config.get_cn_name_mapping(),
            hello_pin_min_length: config.get_hello_pin_min_length(),
        })
    }

    pub fn map_cn_name(&self, account_id: &str) -> String {
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

        if self.cn_name_mapping && !account_id.contains('@') && !self.domains.is_empty() {
            return format!("{}@{}", account_id, self.domains[0]);
        }
        account_id.to_string()
    }
}

impl Default for KanidmUnixdConfig {
    fn default() -> Self {
        Self::new()
    }
}
