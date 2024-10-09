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
use crate::unix_passwd::parse_etc_passwd;
use configparser::ini::Ini;
use std::fmt;
use std::fs::File;
use std::io::Error;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, error};

use crate::constants::{
    BROKER_APP_ID, CN_NAME_MAPPING, DEFAULT_AUTHORITY_HOST, DEFAULT_BROKER_SOCK_PATH,
    DEFAULT_CACHE_TIMEOUT, DEFAULT_CONFIG_PATH, DEFAULT_CONN_TIMEOUT, DEFAULT_DB_PATH,
    DEFAULT_HELLO_ENABLED, DEFAULT_HELLO_PIN_MIN_LEN, DEFAULT_HOME_ALIAS, DEFAULT_HOME_ATTR,
    DEFAULT_HOME_PREFIX, DEFAULT_HSM_PIN_PATH, DEFAULT_ID_ATTR_MAP, DEFAULT_ODC_PROVIDER,
    DEFAULT_SELINUX, DEFAULT_SFA_FALLBACK_ENABLED, DEFAULT_SHELL, DEFAULT_SOCK_PATH,
    DEFAULT_TASK_SOCK_PATH, DEFAULT_USE_ETC_SKEL, SERVER_CONFIG_PATH,
};
use crate::unix_config::{HomeAttr, HsmType};
use idmap::DEFAULT_IDMAP_RANGE;
use std::env;

#[derive(Debug, Copy, Clone)]
pub enum IdAttr {
    Uuid,
    Name,
}

pub fn split_username(username: &str) -> Option<(&str, &str)> {
    let tup: Vec<&str> = username.split('@').collect();
    if tup.len() == 2 {
        return Some((tup[0], tup[1]));
    }
    None
}

#[derive(Clone)]
pub struct HimmelblauConfig {
    config: Ini,
    filename: String,
}

fn str_to_home_attr(attrib: &str) -> HomeAttr {
    if attrib.to_lowercase() == "uuid" {
        return HomeAttr::Uuid;
    } else if attrib.to_lowercase() == "spn" {
        return HomeAttr::Spn;
    } else if attrib.to_lowercase() == "cn" {
        return HomeAttr::Cn;
    }
    HomeAttr::Uuid // Default to Uuid if the attrib can't be parsed
}

fn match_bool(val: Option<String>, default: bool) -> bool {
    match val {
        Some(val) => match val.to_lowercase().as_str() {
            "true" => true,
            "false" => false,
            "1" => true,
            "0" => false,
            _ => {
                error!("Unrecognized response for apply_policy '{}'", val);
                default
            }
        },
        None => default,
    }
}

impl HimmelblauConfig {
    pub fn new(config_path: Option<&str>) -> Result<HimmelblauConfig, String> {
        let mut sconfig = Ini::new();
        let mut filename: String = DEFAULT_CONFIG_PATH.to_string();
        if let Some(config_path) = config_path {
            filename = config_path.to_string();
        }
        let cfg_path: PathBuf = PathBuf::from(filename.clone());
        if cfg_path.exists() {
            match sconfig.load(filename.clone()) {
                Ok(l) => l,
                Err(e) => {
                    return Err(format!(
                        "failed to read config from {} - cannot start up: {} Quitting.",
                        filename.clone(),
                        e
                    ))
                }
            };
        }
        // Apply server generated config (generated during domain join)
        let srv_cfg_path: PathBuf = PathBuf::from(SERVER_CONFIG_PATH.to_string());
        if srv_cfg_path.exists() {
            if let Err(e) = sconfig.load_and_append(SERVER_CONFIG_PATH) {
                return Err(format!(
                    "failed to read config from {} - cannot start up: {} Quitting.",
                    SERVER_CONFIG_PATH, e
                ));
            }
        }
        Ok(HimmelblauConfig {
            config: sconfig,
            filename,
        })
    }

    pub fn get(&self, section: &str, option: &str) -> Option<String> {
        self.config.get(section, option)
    }

    pub fn get_home_prefix(&self, domain: Option<&str>) -> String {
        match domain {
            Some(domain) => match self.config.get(domain, "home_prefix") {
                Some(val) => val,
                None => match self.config.get("global", "home_prefix") {
                    Some(val) => val,
                    None => String::from(DEFAULT_HOME_PREFIX),
                },
            },
            None => match self.config.get("global", "home_prefix") {
                Some(val) => val,
                None => String::from(DEFAULT_HOME_PREFIX),
            },
        }
    }

    pub fn get_home_attr(&self, domain: Option<&str>) -> HomeAttr {
        match domain {
            Some(domain) => match self.config.get(domain, "home_attr") {
                Some(val) => str_to_home_attr(&val),
                None => match self.config.get("global", "home_attr") {
                    Some(val) => str_to_home_attr(&val),
                    None => DEFAULT_HOME_ATTR,
                },
            },
            None => match self.config.get("global", "home_attr") {
                Some(val) => str_to_home_attr(&val),
                None => DEFAULT_HOME_ATTR,
            },
        }
    }

    pub fn get_home_alias(&self, domain: Option<&str>) -> Option<HomeAttr> {
        match domain {
            Some(domain) => match self.config.get(domain, "home_alias") {
                Some(val) => Some(str_to_home_attr(&val)),
                None => match self.config.get("global", "home_alias") {
                    Some(val) => Some(str_to_home_attr(&val)),
                    None => DEFAULT_HOME_ALIAS,
                },
            },
            None => match self.config.get("global", "home_alias") {
                Some(val) => Some(str_to_home_attr(&val)),
                None => DEFAULT_HOME_ALIAS,
            },
        }
    }

    pub fn get_shell(&self, domain: Option<&str>) -> String {
        match domain {
            Some(domain) => match self.config.get(domain, "shell") {
                Some(val) => val,
                None => match self.config.get("global", "shell") {
                    Some(val) => val,
                    None => String::from(DEFAULT_SHELL),
                },
            },
            None => match self.config.get("global", "shell") {
                Some(val) => val,
                None => String::from(DEFAULT_SHELL),
            },
        }
    }

    pub fn get_odc_provider(&self, domain: &str) -> String {
        match self.config.get(domain, "odc_provider") {
            Some(val) => val,
            None => match self.config.get("global", "odc_provider") {
                Some(val) => val,
                None => String::from(DEFAULT_ODC_PROVIDER),
            },
        }
    }

    pub fn get_app_id(&self, domain: &str) -> String {
        match self.config.get(domain, "app_id") {
            Some(val) => val,
            None => {
                debug!("app_id unset, defaulting to MS Broker");
                String::from(BROKER_APP_ID)
            }
        }
    }

    pub fn get_idmap_range(&self, domain: &str) -> (u32, u32) {
        let default_range = DEFAULT_IDMAP_RANGE;
        match self.config.get(domain, "idmap_range") {
            Some(val) => {
                let vals: Vec<u32> = val
                    .split('-')
                    .map(|m| m.parse())
                    .collect::<Result<Vec<u32>, _>>()
                    .unwrap_or_else(|_| vec![default_range.0, default_range.1]);
                match vals.as_slice() {
                    [min, max] => (*min, *max),
                    _ => {
                        error!("Invalid range specified [{}] idmap_range = {}", domain, val);
                        default_range
                    }
                }
            }
            None => match self.config.get("global", "idmap_range") {
                Some(val) => {
                    let vals: Vec<u32> = val
                        .split('-')
                        .map(|m| m.parse())
                        .collect::<Result<Vec<u32>, _>>()
                        .unwrap_or_else(|_| vec![default_range.0, default_range.1]);
                    match vals.as_slice() {
                        [min, max] => (*min, *max),
                        _ => {
                            error!("Invalid range specified [global] idmap_range = {}", val);
                            default_range
                        }
                    }
                }
                None => {
                    error!(
                        "No idmap_range range specified in config, using {}-{}!",
                        DEFAULT_IDMAP_RANGE.0, DEFAULT_IDMAP_RANGE.1
                    );
                    default_range
                }
            },
        }
    }

    pub fn get_socket_path(&self) -> String {
        match self.config.get("global", "socket_path") {
            Some(val) => val,
            None => DEFAULT_SOCK_PATH.to_string(),
        }
    }

    pub fn get_task_socket_path(&self) -> String {
        match self.config.get("global", "task_socket_path") {
            Some(val) => val,
            None => DEFAULT_TASK_SOCK_PATH.to_string(),
        }
    }

    pub fn get_broker_socket_path(&self) -> String {
        match self.config.get("global", "broker_socket_path") {
            Some(val) => val,
            None => DEFAULT_BROKER_SOCK_PATH.to_string(),
        }
    }

    pub fn get_connection_timeout(&self) -> u64 {
        match self.config.get("global", "connection_timeout") {
            Some(val) => match val.parse::<u64>() {
                Ok(n) => n,
                Err(_) => {
                    error!("Failed parsing connection_timeout from config: {}", val);
                    DEFAULT_CONN_TIMEOUT
                }
            },
            None => DEFAULT_CONN_TIMEOUT,
        }
    }

    pub fn get_cache_timeout(&self) -> u64 {
        match self.config.get("global", "cache_timeout") {
            Some(val) => match val.parse::<u64>() {
                Ok(n) => n,
                Err(_) => {
                    error!("Failed parsing cache_timeout from config: {}", val);
                    DEFAULT_CACHE_TIMEOUT
                }
            },
            None => DEFAULT_CACHE_TIMEOUT,
        }
    }

    pub fn get_unix_sock_timeout(&self) -> u64 {
        self.get_connection_timeout() * 2
    }

    pub fn get_db_path(&self) -> String {
        match self.config.get("global", "db_path") {
            Some(val) => val,
            None => DEFAULT_DB_PATH.to_string(),
        }
    }

    pub fn get_hsm_type(&self) -> HsmType {
        match self.config.get("global", "hsm_type") {
            Some(val) => match val.to_lowercase().as_str() {
                "soft" => HsmType::Soft,
                "tmp" => HsmType::Tpm,
                _ => {
                    warn!("Invalid hsm_type configured, using default ...");
                    HsmType::default()
                }
            },
            None => {
                warn!("hsm_type not configured, using default ...");
                HsmType::default()
            }
        }
    }

    pub fn get_hsm_pin_path(&self) -> String {
        match env::var("HIMMELBLAU_HSM_PIN_PATH") {
            Ok(val) => val,
            Err(_e) => match self.config.get("global", "hsm_pin_path") {
                Some(val) => val,
                None => DEFAULT_HSM_PIN_PATH.to_string(),
            },
        }
    }

    pub fn get_apply_policy(&self) -> bool {
        match_bool(self.config.get("global", "apply_policy"), false)
    }

    pub fn get_pam_allow_groups(&self) -> Vec<String> {
        let mut pam_allow_groups = vec![];
        for section in self.config.sections() {
            pam_allow_groups.extend(match self.config.get(&section, "pam_allow_groups") {
                Some(val) => val.split(',').map(|s| s.trim().to_string()).collect(),
                None => vec![],
            });
        }
        pam_allow_groups
    }

    pub fn write(&self) -> Result<(), Error> {
        self.config.write(self.filename.clone())
    }

    pub fn write_server_config(&self) -> Result<(), Error> {
        let mut srv_conf = self.config.clone();
        srv_conf.remove_section("global");
        srv_conf.write(SERVER_CONFIG_PATH)
    }

    pub fn set(&mut self, section: &str, key: &str, value: &str) {
        self.config.set(section, key, Some(value.to_string()));
    }

    pub fn get_use_etc_skel(&self) -> bool {
        match_bool(
            self.config.get("global", "use_etc_skel"),
            DEFAULT_USE_ETC_SKEL,
        )
    }

    pub fn get_selinux(&self) -> bool {
        match_bool(self.config.get("global", "selinux"), DEFAULT_SELINUX)
    }

    pub fn get_configured_domains(&self) -> Vec<String> {
        let mut domains = match self.config.get("global", "domains") {
            Some(val) => val.split(',').map(|s| s.trim().to_string()).collect(),
            None => vec![],
        };
        let mut sections = self.config.sections();
        sections.retain(|s| s != "global");
        domains.extend(sections);
        domains.sort();
        domains.dedup();
        domains
    }

    pub fn get_config_file(&self) -> String {
        self.filename.clone()
    }

    pub fn get_enable_hello(&self) -> bool {
        match_bool(
            self.config.get("global", "enable_hello"),
            DEFAULT_HELLO_ENABLED,
        )
    }

    pub fn get_id_attr_map(&self) -> IdAttr {
        match self.config.get("global", "id_attr_map") {
            Some(id_attr_map) => match id_attr_map.to_lowercase().as_str() {
                "uuid" => IdAttr::Uuid,
                "name" => IdAttr::Name,
                _ => {
                    error!("Unrecognized id_attr_map choice: {}", id_attr_map);
                    DEFAULT_ID_ATTR_MAP
                }
            },
            None => DEFAULT_ID_ATTR_MAP,
        }
    }

    pub fn get_enable_sfa_fallback(&self) -> bool {
        match_bool(
            self.config.get("global", "enable_sfa_fallback"),
            DEFAULT_SFA_FALLBACK_ENABLED,
        )
    }

    pub fn get_debug(&self) -> bool {
        match_bool(self.config.get("global", "debug"), false)
    }

    pub fn get_cn_name_mapping(&self) -> bool {
        match_bool(
            self.config.get("global", "cn_name_mapping"),
            CN_NAME_MAPPING,
        )
    }

    pub fn get_hello_pin_min_length(&self) -> usize {
        match self.config.get("global", "hello_pin_min_length") {
            Some(val) => match val.parse::<usize>() {
                Ok(n) => n,
                Err(_) => {
                    error!("Failed parsing hello_pin_min_length from config: {}", val);
                    DEFAULT_HELLO_PIN_MIN_LEN
                }
            },
            None => DEFAULT_HELLO_PIN_MIN_LEN,
        }
    }

    pub fn get_authority_host(&self, domain: &str) -> String {
        match self.config.get(domain, "authority_host") {
            Some(val) => val,
            None => {
                debug!("authority_host unset, using defaults");
                String::from(DEFAULT_AUTHORITY_HOST)
            }
        }
    }

    pub fn get_tenant_id(&self, domain: &str) -> Option<String> {
        self.config.get(domain, "tenant_id")
    }

    pub fn get_graph_url(&self, domain: &str) -> Option<String> {
        self.config.get(domain, "graph_url")
    }

    pub fn get_local_groups(&self) -> Vec<String> {
        match self.config.get("global", "local_groups") {
            Some(val) => val.split(',').map(|s| s.to_string()).collect(),
            None => vec![],
        }
    }

    pub fn get_logon_script(&self) -> Option<String> {
        self.config.get("global", "logon_script")
    }

    pub fn get_logon_token_scopes(&self) -> Vec<String> {
        match self.config.get("global", "logon_token_scopes") {
            Some(scopes) => scopes.split(",").map(|s| s.to_string()).collect(),
            None => vec![],
        }
    }

    pub fn get_name_mapping_script(&self) -> Option<String> {
        self.config.get("global", "name_mapping_script")
    }

    pub fn map_upn_to_name(&self, account_id: &str) -> String {
        map_upn_to_name(
            account_id,
            &self.get_name_mapping_script(),
            self.get_cn_name_mapping(),
            &self.get_configured_domains(),
        )
    }

    pub fn map_name_to_upn(&self, account_id: &str) -> String {
        map_name_to_upn(
            account_id,
            &self.get_name_mapping_script(),
            self.get_cn_name_mapping(),
            &self.get_configured_domains(),
        )
    }
}

impl fmt::Debug for HimmelblauConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.config)
    }
}

// This function maps a upn to a local username. If cn name mapping is enabled,
// this will map to the CN. Otherwise it will attempt to map using the name
// mapping script. If no name mapping is enabled, it will respond with the
// supplied UPN (no name mapping).
pub fn map_upn_to_name(
    account_id: &str,
    name_mapping_script: &Option<String>,
    cn_name_mapping: bool,
    domains: &[String],
) -> String {
    // The name mapping script is expected to convert the input name to a UPN
    // if a name is supplied, or to a name if the UPN is supplied.
    if let Some(name_mapping_script) = &name_mapping_script {
        let output = Command::new(name_mapping_script).arg(account_id).output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    return String::from_utf8_lossy(&output.stdout).trim().to_string();
                } else {
                    eprintln!("Script execution failed with error: {:?}", output.status);
                }
            }
            Err(e) => {
                eprintln!("Failed to execute script: {}", e);
            }
        }
    }
    if cn_name_mapping && account_id.contains('@') && !domains.is_empty() {
        if let Some((cn, domain)) = split_username(account_id) {
            // We can only name map the default domain
            if domain == domains[0] {
                return cn.to_string();
            }
        }
    }
    account_id.to_string()
}

// This function attempts to convert a username to a valid UPN. On failure it
// will leave the name as-is, and respond with the original input. Himmelblau
// will reject the authentication attempt if the username isn't a valid UPN.
pub fn map_name_to_upn(
    account_id: &str,
    name_mapping_script: &Option<String>,
    cn_name_mapping: bool,
    domains: &[String],
) -> String {
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

    // The name mapping script is expected to convert the input name to a UPN
    // if a name is supplied, or to a name if the UPN is supplied.
    if !account_id.contains('@') {
        if let Some(name_mapping_script) = &name_mapping_script {
            let output = Command::new(name_mapping_script).arg(account_id).output();

            match output {
                Ok(output) => {
                    if output.status.success() {
                        return String::from_utf8_lossy(&output.stdout).trim().to_string();
                    } else {
                        eprintln!("Script execution failed with error: {:?}", output.status);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to execute script: {}", e);
                }
            }
        }
    }
    if cn_name_mapping && !account_id.contains('@') && !domains.is_empty() {
        return format!("{}@{}", account_id, domains[0]);
    }
    account_id.to_string()
}
