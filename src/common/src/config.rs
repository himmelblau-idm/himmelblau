use anyhow::{anyhow, Result};
use configparser::ini::Ini;
use std::fmt;
use std::io::Error;
use std::path::PathBuf;
use tracing::{debug, error};

use crate::constants::{
    DEFAULT_APP_ID, DEFAULT_AUTHORITY_HOST, DEFAULT_CACHE_TIMEOUT, DEFAULT_CONN_TIMEOUT,
    DEFAULT_DB_PATH, DEFAULT_GRAPH, DEFAULT_HOME_ALIAS, DEFAULT_HOME_ATTR, DEFAULT_HOME_PREFIX,
    DEFAULT_IDMAP_RANGE, DEFAULT_ODC_PROVIDER, DEFAULT_SELINUX, DEFAULT_SHELL, DEFAULT_SOCK_PATH,
    DEFAULT_TASK_SOCK_PATH, DEFAULT_TPM_TCTI_NAME, DEFAULT_USE_ETC_SKEL,
};
use crate::unix_config::{HomeAttr, TpmPolicy};
use msal::misc::request_federation_provider;

pub fn split_username(username: &str) -> Option<(&str, &str)> {
    let tup: Vec<&str> = username.split('@').collect();
    if tup.len() == 2 {
        return Some((tup[0], tup[1]));
    }
    None
}

pub struct HimmelblauConfig {
    config: Ini,
    filename: String,
}

fn str_to_home_attr(attrib: &str) -> HomeAttr {
    if attrib.to_lowercase() == "uuid" {
        return HomeAttr::Uuid;
    } else if attrib.to_lowercase() == "spn" {
        return HomeAttr::Spn;
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

struct FederationProvider {
    odc_provider: String,
    domain: String,
    tenant_id: Option<String>,
    authority_host: Option<String>,
    graph: Option<String>,
}

impl FederationProvider {
    fn new(odc_provider: &str, domain: &str) -> Self {
        FederationProvider {
            odc_provider: odc_provider.to_string(),
            domain: domain.to_string(),
            tenant_id: None,
            authority_host: None,
            graph: None,
        }
    }

    async fn set(&mut self) -> Result<()> {
        let (authority_host, tenant_id, graph) =
            request_federation_provider(&self.odc_provider, &self.domain).await?;
        self.tenant_id = Some(tenant_id);
        self.authority_host = Some(authority_host);
        self.graph = Some(graph);
        Ok(())
    }

    async fn get_tenant_id(&mut self) -> Result<String> {
        if self.tenant_id.is_none() {
            self.set().await?;
        }
        match &self.tenant_id {
            Some(tenant_id) => Ok(tenant_id.to_string()),
            None => Err(anyhow!("Failed fetching tenant_id")),
        }
    }

    async fn get_authority_host(&mut self) -> Result<String> {
        if self.authority_host.is_none() {
            self.set().await?;
        }
        match &self.authority_host {
            Some(authority_host) => Ok(authority_host.to_string()),
            None => Err(anyhow!("Failed fetching authority_host")),
        }
    }

    async fn get_graph(&mut self) -> Result<String> {
        if self.graph.is_none() {
            self.set().await?;
        }
        match &self.graph {
            Some(graph) => Ok(graph.to_string()),
            None => Err(anyhow!("Failed fetching graph")),
        }
    }
}

impl HimmelblauConfig {
    pub fn new(config_path: &str) -> Result<HimmelblauConfig, String> {
        let mut sconfig = Ini::new();
        let cfg_path: PathBuf = PathBuf::from(config_path);
        if cfg_path.exists() {
            match sconfig.load(config_path) {
                Ok(l) => l,
                Err(e) => {
                    return Err(format!(
                        "failed to read config from {} - cannot start up: {} Quitting.",
                        config_path, e
                    ))
                }
            };
        } else {
            return Err(format!(
                "config missing from {} - cannot start up. Quitting.",
                config_path
            ));
        }
        Ok(HimmelblauConfig {
            config: sconfig,
            filename: config_path.to_string(),
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

    fn get_odc_provider(&self, domain: &str) -> String {
        match self.config.get(domain, "odc_provider") {
            Some(val) => val,
            None => match self.config.get("global", "odc_provider") {
                Some(val) => val,
                None => String::from(DEFAULT_ODC_PROVIDER),
            },
        }
    }

    pub async fn get_tenant_id_authority_and_graph(
        &self,
        domain: &str,
    ) -> Result<(String, String, String)> {
        let mut federation_provider =
            FederationProvider::new(&self.get_odc_provider(domain), domain);
        let tenant_id = match self.config.get(domain, "tenant_id") {
            Some(val) => val,
            None => match self.config.get("global", "tenant_id") {
                Some(val) => val,
                None => match federation_provider.get_tenant_id().await {
                    Ok(val) => val,
                    Err(e) => return Err(anyhow!("Failed fetching tenant_id: {}", e)),
                },
            },
        };
        let authority_host = match self.config.get(domain, "authority_host") {
            Some(val) => val,
            None => match self.config.get("global", "authority_host") {
                Some(val) => val,
                None => match federation_provider.get_authority_host().await {
                    Ok(val) => val,
                    Err(_) => String::from(DEFAULT_AUTHORITY_HOST),
                },
            },
        };
        let graph = match self.config.get(domain, "graph") {
            Some(val) => val,
            None => match self.config.get("global", "graph") {
                Some(val) => val,
                None => match federation_provider.get_graph().await {
                    Ok(val) => val,
                    Err(_) => String::from(DEFAULT_GRAPH),
                },
            },
        };
        Ok((authority_host, tenant_id, graph))
    }

    pub fn get_app_id(&self, domain: &str) -> String {
        match self.config.get(domain, "app_id") {
            Some(val) => val,
            None => match self.config.get("global", "app_id") {
                Some(val) => val,
                None => {
                    debug!("app_id unset, defaulting to Intune Portal for Linux");
                    String::from(DEFAULT_APP_ID)
                }
            },
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

    pub fn get_db_path(&self) -> String {
        match self.config.get("global", "db_path") {
            Some(val) => val,
            None => DEFAULT_DB_PATH.to_string(),
        }
    }

    pub fn get_tpm_policy(&self) -> TpmPolicy {
        match self.config.get("global", "tpm_policy") {
            Some(val) => match val.as_str() {
                "ignore" => TpmPolicy::Ignore,
                "if_possible" => TpmPolicy::IfPossible(DEFAULT_TPM_TCTI_NAME.to_string()),
                "required" => TpmPolicy::Required(DEFAULT_TPM_TCTI_NAME.to_string()),
                _ => TpmPolicy::Ignore,
            },
            None => TpmPolicy::Ignore,
        }
    }

    pub fn get_apply_policy(&self) -> bool {
        match_bool(self.config.get("global", "apply_policy"), false)
    }

    pub fn get_pam_allow_groups(&self) -> Vec<String> {
        match self.config.get("global", "pam_allow_groups") {
            Some(val) => val.split(',').map(|s| s.trim().to_string()).collect(),
            None => vec![],
        }
    }

    pub fn write(&self) -> Result<(), Error> {
        self.config.write(self.filename.clone())
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

    pub fn get_config_file(&self) -> String {
        self.filename.clone()
    }
}

impl fmt::Debug for HimmelblauConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.config)
    }
}
