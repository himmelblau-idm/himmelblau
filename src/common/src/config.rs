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

use crate::constants::MAPPED_NAME_CACHE;
use crate::constants::{
    CN_NAME_MAPPING, DEFAULT_AUTHORITY_HOST, DEFAULT_BROKER_SOCK_PATH, DEFAULT_CACHE_TIMEOUT,
    DEFAULT_CONFIG_PATH, DEFAULT_CONN_TIMEOUT, DEFAULT_DB_PATH, DEFAULT_HELLO_ENABLED,
    DEFAULT_HELLO_PIN_MIN_LEN, DEFAULT_HELLO_PIN_RETRY_COUNT, DEFAULT_HOME_ALIAS,
    DEFAULT_HOME_ATTR, DEFAULT_HOME_PREFIX, DEFAULT_HSM_PIN_PATH, DEFAULT_ID_ATTR_MAP,
    DEFAULT_ODC_PROVIDER, DEFAULT_SELINUX, DEFAULT_SFA_FALLBACK_ENABLED, DEFAULT_SHELL,
    DEFAULT_SOCK_PATH, DEFAULT_TASK_SOCK_PATH, DEFAULT_USE_ETC_SKEL, SERVER_CONFIG_PATH,
};
use crate::mapping::{MappedNameCache, Mode};
use crate::unix_config::{HomeAttr, HsmType};
use himmelblau::error::MsalError;
use idmap::DEFAULT_IDMAP_RANGE;
use reqwest::Url;
use serde::Deserialize;
use std::env;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum IdAttr {
    Uuid,
    Name,
    Rfc2307,
}

pub fn split_username(username: &str) -> Option<(&str, &str)> {
    let tup: Vec<&str> = username.split('@').collect();
    if tup.len() == 2 {
        return Some((tup[0], tup[1]));
    }
    None
}

#[derive(Debug, Deserialize)]
struct FederationProvider {
    #[serde(rename = "tenantId")]
    tenant_id: String,
    authority_host: String,
    graph: String,
}

async fn request_federation_provider(
    odc_provider: &str,
    domain: &str,
) -> Result<(String, String, String), MsalError> {
    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

    let url = Url::parse_with_params(
        &format!("https://{}/odc/v2.1/federationProvider", odc_provider),
        &[("domain", domain)],
    )
    .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
    if resp.status().is_success() {
        let json_resp: FederationProvider = resp
            .json()
            .await
            .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
        debug!("Discovered tenant_id: {}", json_resp.tenant_id);
        debug!("Discovered authority_host: {}", json_resp.authority_host);
        debug!("Discovered graph: {}", json_resp.graph);
        Ok((
            json_resp.authority_host,
            json_resp.tenant_id,
            json_resp.graph,
        ))
    } else {
        Err(MsalError::RequestFailed(format!(
            "Federation Provider request failed: {}",
            resp.status(),
        )))
    }
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

    pub fn get_app_id(&self, domain: &str) -> Option<String> {
        self.config.get(domain, "app_id")
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
                "tpm" => HsmType::Tpm,
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

        let permitted_keys = [
            "authority_host",
            "tenant_id",
            "graph_url",
            "domain_aliases",
            "device_id",
            "intune_device_id",
        ];
        let mut keys_to_remove = Vec::new();
        for (section, keys) in srv_conf.get_map_ref() {
            for key in keys.keys() {
                if !permitted_keys.contains(&key.as_str()) {
                    keys_to_remove.push((section.to_string(), key.clone()));
                }
            }
        }
        for (section, key) in keys_to_remove {
            srv_conf.remove_key(&section, &key);
        }

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
        let domain = match self.config.get("global", "domain") {
            Some(val) => {
                info!("Mistyped `domain` parameter detected in himmelblau.conf. Did you mean `domains`?");
                val.split(',').map(|s| s.trim().to_string()).collect()
            }
            None => vec![],
        };
        domains.extend(domain);
        let mut sections = self.config.sections();
        sections.retain(|s| s != "global");
        for section in sections {
            if !domains.contains(&section) {
                domains.push(section);
            }
        }
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
                "rfc2307" => IdAttr::Rfc2307,
                _ => {
                    error!("Unrecognized id_attr_map choice: {}", id_attr_map);
                    DEFAULT_ID_ATTR_MAP
                }
            },
            None => DEFAULT_ID_ATTR_MAP,
        }
    }

    pub fn get_rfc2307_group_fallback_map(&self) -> Option<IdAttr> {
        self.config
            .get("global", "rfc2307_group_fallback_map")
            .and_then(|id_attr_map| match id_attr_map.to_lowercase().as_str() {
                "uuid" => Some(IdAttr::Uuid),
                "name" => Some(IdAttr::Name),
                _ => None,
            })
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

    pub fn get_hello_pin_retry_count(&self) -> u32 {
        match self.config.get("global", "hello_pin_retry_count") {
            Some(val) => match val.parse::<u32>() {
                Ok(n) => n,
                Err(_) => {
                    error!("Failed parsing hello_pin_retry_count from config: {}", val);
                    DEFAULT_HELLO_PIN_RETRY_COUNT
                }
            },
            None => DEFAULT_HELLO_PIN_RETRY_COUNT,
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

    pub fn get_logon_token_app_id(&self, domain: &str) -> Option<String> {
        self.config.get(domain, "logon_token_app_id")
    }

    pub fn get_intune_device_id(&self, domain: &str) -> Option<String> {
        self.config.get(domain, "intune_device_id")
    }

    pub fn get_enable_experimental_mfa(&self) -> bool {
        match_bool(self.config.get("global", "enable_experimental_mfa"), true)
    }

    pub fn get_enable_experimental_passwordless_fido(&self) -> bool {
        match_bool(
            self.config
                .get("global", "enable_experimental_passwordless_fido"),
            false,
        )
    }

    pub async fn get_primary_domain_from_alias(&mut self, alias: &str) -> Option<String> {
        let domains = self.get_configured_domains();

        // Attempt to short-circut the request by checking if the alias is
        // already configured.
        for domain in &domains {
            let domain_aliases = match self.config.get(domain, "domain_aliases") {
                Some(aliases) => aliases.split(",").map(|s| s.to_string()).collect(),
                None => vec![],
            };
            if domain_aliases.contains(&alias.to_string()) {
                return Some(domain.to_string());
            }
        }

        let mut modified_config = false;

        // We don't recognize this alias, so now we need to search for it the
        // hard way by checking for matching tenant id's.
        let (_, alias_tenant_id, _) =
            match request_federation_provider(DEFAULT_ODC_PROVIDER, alias).await {
                Ok(resp) => resp,
                Err(e) => {
                    error!(
                        "Failed matching alias '{}' to a configured tenant: {:?}",
                        alias, e
                    );
                    return None;
                }
            };
        for domain in domains {
            let tenant_id = match self.get_tenant_id(&domain) {
                Some(tenant_id) => tenant_id,
                None => {
                    let (authority_host, tenant_id, graph_url) =
                        match request_federation_provider(&self.get_odc_provider(&domain), &domain)
                            .await
                        {
                            Ok(resp) => resp,
                            Err(e) => {
                                error!("Failed sending federation provider request: {:?}", e);
                                continue;
                            }
                        };
                    self.set(&domain, "authority_host", &authority_host);
                    self.set(&domain, "tenant_id", &tenant_id);
                    self.set(&domain, "graph_url", &graph_url);
                    modified_config = true;
                    tenant_id
                }
            };
            if tenant_id == alias_tenant_id {
                let mut domain_aliases = match self.config.get(&domain, "domain_aliases") {
                    Some(aliases) => aliases.split(",").map(|s| s.to_string()).collect(),
                    None => vec![],
                };
                domain_aliases.push(alias.to_string());
                self.set(&domain, "domain_aliases", &domain_aliases.join(","));
                let _ = self.write_server_config();
                return Some(domain);
            }
        }

        error!("Failed matching alias '{}' to a configured tenant", alias);
        if modified_config {
            let _ = self.write_server_config();
        }
        None
    }

    pub fn get_name_mapping_script(&self) -> Option<String> {
        self.config.get("global", "name_mapping_script")
    }

    /// This function attempts to convert a username to a valid UPN. On failure it
    /// will leave the name as-is, and respond with the original input. Himmelblau
    /// will reject the authentication attempt if the username isn't a valid UPN.
    pub fn map_name_to_upn(&self, account_id: &str) -> String {
        let name_mapping_script = self.get_name_mapping_script();
        let cn_name_mapping = self.get_cn_name_mapping();
        let domains = self.get_configured_domains();

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
                let name_cache = MappedNameCache::new(MAPPED_NAME_CACHE, &Mode::ReadWrite).ok();

                let output = Command::new(name_mapping_script).arg(account_id).output();

                match output {
                    Ok(output) => {
                        if output.status.success() {
                            let upn = String::from_utf8_lossy(&output.stdout).trim().to_string();
                            if let Some(name_cache) = &name_cache {
                                // Failing to insert a name map is not a critical failure.
                                let _ = name_cache.insert_mapping(&upn, account_id);
                            }
                            return upn;
                        } else {
                            error!("Script execution failed with error: {:?}", output.status);
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to execute script `{}` from `{}`: {}",
                            name_mapping_script,
                            env::current_dir()
                                .unwrap_or_else(|e| {
                                    error!("No working dir: {:?}", e);
                                    String::new().into()
                                })
                                .display(),
                            e
                        );
                    }
                }
            }
        }
        if cn_name_mapping && !account_id.contains('@') && !domains.is_empty() {
            return format!("{}@{}", account_id, domains[0]);
        }
        account_id.to_string()
    }

    /// This function maps a UPN to a mapped name. If a mapping script is
    /// configured, it will use the mapping cache to obtain the mapped name.
    /// If a mapping script is not configured, but upn to cn mapping is
    /// enabled, it will map the upn to the cn. Otherwise it will return the
    /// name unchanged.
    pub fn map_upn_to_name(&self, upn: &str) -> String {
        if !upn.contains('@') {
            // This isn't a upn, just return the input unchanged
            return upn.to_string();
        }

        let res;
        if self.get_name_mapping_script().is_some() {
            if let Ok(name_mapping_cache) = MappedNameCache::new(MAPPED_NAME_CACHE, &Mode::ReadOnly)
            {
                res = name_mapping_cache.get_mapped_name(upn);
            } else {
                res = upn.to_string();
            }
        } else if self.get_cn_name_mapping() {
            res = upn.split('@').next().unwrap_or(upn).to_string();
        } else {
            res = upn.to_string();
        }
        res
    }
}

impl fmt::Debug for HimmelblauConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

    // Helper function to create temporary configuration files
    fn create_temp_config(contents: &str) -> String {
        let file_path = format!("/tmp/himmelblau_test_config_{}.ini", uuid::Uuid::new_v4());
        fs::write(&file_path, contents).expect("Failed to write temporary config file");
        file_path
    }

    #[test]
    fn test_get_home_prefix() {
        let config_data = r#"
        [global]
        home_prefix = /home/global

        [example.com]
        home_prefix = /home/example
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_home_prefix(Some("example.com")), "/home/example");
        assert_eq!(config.get_home_prefix(None), "/home/global");
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(
            config_empty.get_home_prefix(Some("unknown.com")),
            DEFAULT_HOME_PREFIX
        );
    }

    #[test]
    fn test_get_shell() {
        let config_data = r#"
        [global]
        shell = /bin/bash

        [example.com]
        shell = /bin/zsh
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_shell(Some("example.com")), "/bin/zsh");
        assert_eq!(config.get_shell(None), "/bin/bash");
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_shell(Some("unknown.com")), DEFAULT_SHELL);
    }

    #[test]
    fn test_get_connection_timeout() {
        let config_data = r#"
        [global]
        connection_timeout = 45
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_connection_timeout(), 45);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_connection_timeout(), 30);
    }

    #[test]
    fn test_get_idmap_range() {
        let config_data = r#"
        [global]
        idmap_range = 1000-2000

        [example.com]
        idmap_range = 5000-6000
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_idmap_range("example.com"), (5000, 6000));
        assert_eq!(config.get_idmap_range("unknown.com"), (1000, 2000));
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_idmap_range("any.com"), DEFAULT_IDMAP_RANGE);
    }

    #[test]
    fn test_get_broker_socket_path() {
        let config_data = r#"
        [global]
        broker_socket_path = /var/run/broker.sock
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_broker_socket_path(), "/var/run/broker.sock");
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(
            config_empty.get_broker_socket_path(),
            DEFAULT_BROKER_SOCK_PATH
        );
    }

    #[test]
    fn test_get_pam_allow_groups() {
        let config_data = r#"
        [example.com]
        pam_allow_groups = 2eb4e6a2-f55d-4cf4-8e62-978f9f4a828d,f791d7c2-66cd-4f67-a195-72c6faf3c3b5

        [global]
        pam_allow_groups = 825d1f7e-c4cd-4fc2-aeeb-1f92357f8da6,0149b437-fbaa-4419-bf46-f9a9f9a3438c
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let mut groups = config.get_pam_allow_groups();
        groups.sort();
        let mut expected_groups: Vec<String> = vec![
            "2eb4e6a2-f55d-4cf4-8e62-978f9f4a828d".to_string(),
            "f791d7c2-66cd-4f67-a195-72c6faf3c3b5".to_string(),
            "825d1f7e-c4cd-4fc2-aeeb-1f92357f8da6".to_string(),
            "0149b437-fbaa-4419-bf46-f9a9f9a3438c".to_string(),
        ];
        expected_groups.sort();

        assert_eq!(groups, expected_groups);
    }

    #[test]
    fn test_get_hsm_pin_path_env_override() {
        env::set_var("HIMMELBLAU_HSM_PIN_PATH", "/custom/pin/path");

        let config_data = r#"
        [global]
        hsm_pin_path = /etc/hsm/default_pin
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_hsm_pin_path(), "/custom/pin/path");

        env::remove_var("HIMMELBLAU_HSM_PIN_PATH");
    }

    #[test]
    fn test_get_apply_policy() {
        let config_data = r#"
        [global]
        apply_policy = true
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_apply_policy(), true);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_apply_policy(), false);
    }

    #[test]
    fn test_get_home_attr() {
        let config_data = r#"
        [global]
        home_attr = cn

        [example.com]
        home_attr = spn
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_home_attr(None), HomeAttr::Cn);
        assert_eq!(config.get_home_attr(Some("example.com")), HomeAttr::Spn);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_home_attr(None), HomeAttr::Uuid);
    }

    #[test]
    fn test_get_home_alias() {
        let config_data = r#"
        [global]
        home_alias = cn

        [example.com]
        home_alias = uuid
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_home_alias(None), Some(HomeAttr::Cn));
        assert_eq!(
            config.get_home_alias(Some("example.com")),
            Some(HomeAttr::Uuid)
        );
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(
            config_empty.get_home_alias(Some("unknown.com")),
            Some(HomeAttr::Spn)
        );
    }

    #[test]
    fn test_get_odc_provider() {
        let config_data = r#"
        [global]
        odc_provider = suse.com

        [example.com]
        odc_provider = odc.officeapps.live.com
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_odc_provider("unknown.com"), "suse.com");
        assert_eq!(
            config.get_odc_provider("example.com"),
            "odc.officeapps.live.com"
        );
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(
            config_empty.get_odc_provider("unknown.com"),
            DEFAULT_ODC_PROVIDER
        );
    }

    #[test]
    fn test_get_app_id() {
        let config_data = r#"
        [example.com]
        app_id = 70fee399-7cd8-42f9-a0ea-1e12ea308908
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_app_id("unknown.com"), None);
        assert_eq!(
            config.get_app_id("example.com"),
            Some("70fee399-7cd8-42f9-a0ea-1e12ea308908".to_string())
        );
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_app_id("example.com"), None);
    }

    #[test]
    fn test_get_socket_path() {
        let config_data = r#"
        [global]
        socket_path = /var/run/socket_path.sock
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_socket_path(), "/var/run/socket_path.sock");
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_socket_path(), DEFAULT_SOCK_PATH);
    }

    #[test]
    fn test_get_task_socket_path() {
        let config_data = r#"
        [global]
        task_socket_path = /var/run/task_socket.sock
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_task_socket_path(), "/var/run/task_socket.sock");
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_task_socket_path(), DEFAULT_TASK_SOCK_PATH);
    }

    #[test]
    fn test_get_cache_timeout() {
        let config_data = r#"
        [global]
        cache_timeout = 120
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_cache_timeout(), 120);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_cache_timeout(), DEFAULT_CACHE_TIMEOUT);
    }

    #[test]
    fn test_get_unix_sock_timeout() {
        let config_data = r#"
        [global]
        connection_timeout = 15
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_unix_sock_timeout(), 30);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(
            config_empty.get_unix_sock_timeout(),
            DEFAULT_CONN_TIMEOUT * 2
        );
    }

    #[test]
    fn test_get_db_path() {
        let config_data = r#"
        [global]
        db_path = /var/db/himmelblau.db
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_db_path(), "/var/db/himmelblau.db");
    }

    #[test]
    fn test_get_hsm_type() {
        let (config_data, default, alt) = if HsmType::default() == HsmType::Soft {
            (
                r#"
                    [global]
                    hsm_type = tpm
                "#,
                HsmType::Soft,
                HsmType::Tpm,
            )
        } else {
            (
                r#"
                    [global]
                    hsm_type = soft
                "#,
                HsmType::Tpm,
                HsmType::Soft,
            )
        };

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_hsm_type(), alt);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_hsm_type(), default);
    }

    #[test]
    fn test_get_use_etc_skel() {
        let config_data = r#"
        [global]
        use_etc_skel = true
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_use_etc_skel(), true);

        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_use_etc_skel(), false);
    }

    #[test]
    fn test_get_configured_domains() {
        let config_data = r#"
        [global]
        domains = example.com,test.com

        [alpha.com]
        [test.com]
        [example2.com]
        [example.com]
        [test2.com]
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let mut domains = config.get_configured_domains();
        // The order from `domains` must always be preserved (specifically, we
        // care about the placement of the first domain only).
        assert_eq!(domains[..2], vec!["example.com", "test.com"]);

        // The order of the remaining domains is irrelevant.
        domains.sort();
        assert_eq!(
            domains,
            vec![
                "alpha.com",
                "example.com",
                "example2.com",
                "test.com",
                "test2.com"
            ]
        );
    }

    #[test]
    fn test_get_enable_hello() {
        let config_data = r#"
        [global]
        enable_hello = false
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_enable_hello(), false);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_enable_hello(), DEFAULT_HELLO_ENABLED);
    }

    #[test]
    fn test_get_enable_experimental_mfa() {
        let config_data = r#"
        [global]
        enable_experimental_mfa = false
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_enable_experimental_mfa(), false);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_enable_experimental_mfa(), true);
    }

    #[test]
    fn test_get_enable_experimental_passwordless_fido() {
        let config_data = r#"
        [global]
        enable_experimental_passwordless_fido = true
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        // Test when explicitly set to true
        assert_eq!(config.get_enable_experimental_passwordless_fido(), true);

        // Test fallback default (false) when config is missing
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(
            config_empty.get_enable_experimental_passwordless_fido(),
            false
        );
    }

    #[test]
    fn test_get_debug() {
        let config_data = r#"
        [global]
        debug = true
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_debug(), true);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_debug(), false);
    }

    #[test]
    fn test_get_cn_name_mapping() {
        let config_data = r#"
        [global]
        cn_name_mapping = false
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_cn_name_mapping(), false);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_cn_name_mapping(), CN_NAME_MAPPING);
    }

    #[test]
    fn test_get_authority_host() {
        let config_data = r#"
        [example.com]
        authority_host = https://login.suse.com
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(
            config.get_authority_host("example.com"),
            "https://login.suse.com"
        );
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(
            config_empty.get_authority_host("example.com"),
            DEFAULT_AUTHORITY_HOST
        );
    }

    #[test]
    fn test_get_graph_url() {
        let config_data = r#"
        [example.com]
        graph_url = https://graph.suse.com
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(
            config.get_graph_url("example.com"),
            Some("https://graph.suse.com".to_string())
        );
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_graph_url("example.com"), None);
    }

    #[test]
    fn test_get_selinux() {
        let config_data = r#"
        [global]
        selinux = true
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_selinux(), true);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_selinux(), DEFAULT_SELINUX);
    }

    #[test]
    fn test_get_id_attr_map() {
        let config_data = r#"
        [global]
        id_attr_map = uuid
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_id_attr_map(), IdAttr::Uuid);

        // Default fallback for unknown value
        let config_invalid = r#"
        [global]
        id_attr_map = invalid_value
        "#;
        let temp_file_invalid = create_temp_config(config_invalid);
        let config_invalid = HimmelblauConfig::new(Some(&temp_file_invalid)).unwrap();
        assert_eq!(config_invalid.get_id_attr_map(), DEFAULT_ID_ATTR_MAP);

        let config_missing = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_missing.get_id_attr_map(), DEFAULT_ID_ATTR_MAP);
    }

    #[test]
    fn test_get_hello_pin_min_length() {
        let config_data = r#"
        [global]
        hello_pin_min_length = 8
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_hello_pin_min_length(), 8);
        let config_invalid = r#"
        [global]
        hello_pin_min_length = invalid_value
        "#;
        let temp_file_invalid = create_temp_config(config_invalid);
        let config_invalid = HimmelblauConfig::new(Some(&temp_file_invalid)).unwrap();
        assert_eq!(
            config_invalid.get_hello_pin_min_length(),
            DEFAULT_HELLO_PIN_MIN_LEN
        );
        let config_missing = HimmelblauConfig::new(None).unwrap();
        assert_eq!(
            config_missing.get_hello_pin_min_length(),
            DEFAULT_HELLO_PIN_MIN_LEN
        );
    }

    #[test]
    fn test_get_tenant_id() {
        let config_data = r#"
        [example.com]
        tenant_id = example-tenant-id
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(
            config.get_tenant_id("example.com"),
            Some("example-tenant-id".to_string())
        );
        assert_eq!(config.get_tenant_id("nonexistent.com"), None);
        let config_missing = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_missing.get_tenant_id("example.com"), None);
    }

    #[test]
    fn test_get_local_groups() {
        let config_data = r#"
        [global]
        local_groups = group1,group2,group3
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let expected_groups = vec![
            "group1".to_string(),
            "group2".to_string(),
            "group3".to_string(),
        ];
        assert_eq!(config.get_local_groups(), expected_groups);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_local_groups(), Vec::<String>::new());
    }

    #[test]
    fn test_get_logon_script() {
        let config_data = r#"
        [global]
        logon_script = /path/to/logon/script
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(
            config.get_logon_script(),
            Some("/path/to/logon/script".to_string())
        );
        let config_missing = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_missing.get_logon_script(), None);
    }

    #[test]
    fn test_get_intune_device_id() {
        let config_data = r#"
        [example.com]
        intune_device_id = 123e4567-e89b-12d3-a456-426614174000
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(
            config.get_intune_device_id("example.com"),
            Some("123e4567-e89b-12d3-a456-426614174000".to_string())
        );

        // Test missing domain
        assert_eq!(config.get_intune_device_id("missing.com"), None);
        let config_missing = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_missing.get_intune_device_id("example.com"), None);
    }

    #[test]
    fn test_get_logon_token_scopes() {
        let config_data = r#"
        [global]
        logon_token_scopes = scope1,scope2,scope3
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let expected_scopes = vec![
            "scope1".to_string(),
            "scope2".to_string(),
            "scope3".to_string(),
        ];
        assert_eq!(config.get_logon_token_scopes(), expected_scopes);
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_logon_token_scopes(), Vec::<String>::new());
    }

    #[test]
    fn test_get_logon_token_app_id() {
        let config_data = r#"
        [example.com]
        logon_token_app_id = 544e695f-5d78-442e-b14e-e114e95e640c
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(
            config.get_logon_token_app_id("example.com"),
            Some("544e695f-5d78-442e-b14e-e114e95e640c".to_string())
        );

        // Test missing domain
        assert_eq!(config.get_logon_token_app_id("missing.com"), None);

        // Test empty configuration
        let config_empty = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_empty.get_logon_token_app_id("example.com"), None);
    }

    #[test]
    fn test_str_to_home_attr() {
        assert_eq!(str_to_home_attr("uuid"), HomeAttr::Uuid);
        assert_eq!(str_to_home_attr("spn"), HomeAttr::Spn);
        assert_eq!(str_to_home_attr("cn"), HomeAttr::Cn);
        assert_eq!(str_to_home_attr("invalid"), HomeAttr::Uuid); // Default fallback
    }

    #[test]
    fn test_split_username() {
        assert_eq!(
            split_username("user@example.com"),
            Some(("user", "example.com"))
        );
        assert_eq!(split_username("invalid_username"), None);
    }

    #[test]
    fn test_get_name_mapping_script() {
        let config_data = r#"
        [global]
        name_mapping_script = /path/to/name_mapping_script
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(
            config.get_name_mapping_script(),
            Some("/path/to/name_mapping_script".to_string())
        );

        let config_missing = HimmelblauConfig::new(None).unwrap();
        assert_eq!(config_missing.get_name_mapping_script(), None);
    }

    #[test]
    fn test_map_name_to_upn_script_execution_success() {
        let config_data = r#"
        [global]
        name_mapping_script = ../../scripts/test_script_echo.sh
        domains = example.com
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let account_id = "user";
        let expected_output = "user";

        assert_eq!(
            config.map_name_to_upn(account_id),
            expected_output.to_string()
        );
    }

    #[test]
    fn test_map_name_to_upn_local_user() {
        // Simulate a local user in /etc/passwd
        let account_id = "localuser";

        let config_data = r#"
        [global]
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        // Simulating presence of local user
        assert_eq!(config.map_name_to_upn(account_id), account_id.to_string());
    }

    #[test]
    fn test_map_name_to_upn_add_domain() {
        let config_data = r#"
        [global]
        cn_to_upn_mapping = true
        domains = example.com
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let account_id = "user";
        let expected_output = "user@example.com";

        assert_eq!(
            config.map_name_to_upn(account_id),
            expected_output.to_string()
        );
    }

    #[test]
    fn test_map_name_to_upn_no_mapping() {
        let config_data = r#"
        [global]
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let account_id = "user";

        assert_eq!(config.map_name_to_upn(account_id), account_id.to_string());
    }
}
