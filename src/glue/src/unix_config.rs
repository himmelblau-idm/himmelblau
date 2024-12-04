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
use himmelblau_unix_common::config::{map_name_to_upn, HimmelblauConfig};
use himmelblau_unix_common::constants::{
    DEFAULT_CONN_TIMEOUT, DEFAULT_HELLO_PIN_MIN_LEN, DEFAULT_SOCK_PATH,
};

pub struct KanidmUnixdConfig {
    pub domains: Vec<String>,
    pub unix_sock_timeout: u64,
    pub sock_path: String,
    pub cn_name_mapping: bool,
    pub hello_pin_min_length: usize,
    name_mapping_script: Option<String>,
}

impl KanidmUnixdConfig {
    pub fn new() -> Self {
        KanidmUnixdConfig {
            domains: vec![],
            sock_path: DEFAULT_SOCK_PATH.to_string(),
            unix_sock_timeout: DEFAULT_CONN_TIMEOUT * 2,
            cn_name_mapping: false,
            hello_pin_min_length: DEFAULT_HELLO_PIN_MIN_LEN,
            name_mapping_script: None,
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
            name_mapping_script: config.get_name_mapping_script(),
        })
    }

    pub fn map_name_to_upn(&self, account_id: &str) -> String {
        map_name_to_upn(
            account_id,
            &self.name_mapping_script,
            self.cn_name_mapping,
            &self.domains,
        )
    }
}

impl Default for KanidmUnixdConfig {
    fn default() -> Self {
        Self::new()
    }
}
