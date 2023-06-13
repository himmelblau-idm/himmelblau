use configparser::ini::Ini;
use std::path::PathBuf;
use log::{debug, error};

use msal::misc::request_tenant_id_and_authority;
use crate::constants::{DEFAULT_HOMEDIR, DEFAULT_SHELL, DEFAULT_ODC_PROVIDER,
    DEFAULT_APP_ID, DEFAULT_IDMAP_RANGE, DEFAULT_AUTHORITY_HOST};

pub fn split_username(username: &str) -> Option<(&str, &str)> {
    let tup: Vec<&str> = username.split('@').collect();
    if tup.len() == 2 {
        return Some((tup[0], tup[1]));
    }
    None
}

pub struct HimmelblauConfig {
    config: Ini
}

impl HimmelblauConfig {
    pub fn new(config_path: &str) -> Result<HimmelblauConfig, String> {
        let mut sconfig = Ini::new();
        let cfg_path: PathBuf = PathBuf::from(config_path);
        if cfg_path.exists() {
            match sconfig.load(config_path) {
                Ok(l) => l,
                Err(e) => return Err(format!("failed to read config from {} - cannot start up: {} Quitting.",
                                              config_path, e)),
            };
        } else {
            return Err(format!("config missing from {} - cannot start up. Quitting.",
                               config_path));
        }
        Ok(HimmelblauConfig {
            config: sconfig
        })
    }

    pub fn get(&self, section: &str, option: &str) -> Option<String> {
        self.config.get(section, option)
    }

    pub fn get_homedir(&self, username: &str, uid: u32, sam: &str, domain: &str) -> String {
        let homedir = match self.config.get(domain, "homedir") {
            Some(val) => val,
            None => match self.config.get("global", "homedir") {
                Some(val) => val,
                None => String::from(DEFAULT_HOMEDIR),
            }
        };
        homedir.replace("%f", username).replace("%U", &uid.to_string()).replace("%u", sam).replace("%d", domain)
    }

    pub fn get_shell(&self, domain: &str) -> String {
        match self.config.get(domain, "shell") {
            Some(val) => val,
            None => match self.config.get("global", "shell") {
                Some(val) => val,
                None => String::from(DEFAULT_SHELL),
            }
        }
    }

    fn get_odc_provider(&self, domain: &str) -> String {
        match self.config.get(domain, "odc_provider") {
            Some(val) => val,
            None => {
                match self.config.get("global", "odc_provider") {
                    Some(val) => val,
                    None => String::from(DEFAULT_ODC_PROVIDER),
                }
            }
        }
    }

    async fn get_tenant_id_and_authority(&self, domain: &str) -> (String, String) {
        let odc_provider = self.get_odc_provider(domain);
        let req = request_tenant_id_and_authority(&odc_provider, domain).await;
        let tenant_id = match self.config.get(domain, "tenant_id") {
            Some(val) => val,
            None => {
                match self.config.get("global", "tenant_id") {
                    Some(val) => val,
                    None => {
                        let tenant_id_req = req.as_ref();
                        String::from(match tenant_id_req {
                            Ok(val) => val,
                            Err(e) => panic!("Failed fetching tenant_id: {}", e),
                        }.1.clone())
                    },
                }
            }
        };
        let authority_host = match self.config.get(domain, "authority_host") {
            Some(val) => val,
            None => {
                match self.config.get("global", "authority_host") {
                    Some(val) => val,
                    None => {
                        let authority_host_req = req.as_ref();
                        match authority_host_req {
                            Ok(val) => val.0.clone(),
                            Err(_e) => String::from(DEFAULT_AUTHORITY_HOST),
                        }
                    }
                }
            }
        };
        (authority_host, tenant_id)
    }

    pub async fn get_authority_url(&self, domain: &str) -> (String, String) {
        let (authority_host, tenant_id) = self.get_tenant_id_and_authority(domain).await;
        let authority_url = format!("https://{}/{}", authority_host, tenant_id);
        (tenant_id, authority_url)
    }

    pub fn get_app_id(&self, domain: &str) -> String {
        match self.config.get(domain, "app_id") {
            Some(val) => String::from(val),
            None => match self.config.get("global", "app_id") {
                Some(val) => String::from(val),
                None => {
                    debug!("app_id unset, defaulting to Intune Portal for Linux");
                    String::from(DEFAULT_APP_ID)
                }
            }
        }
    }

    pub fn get_idmap_range(&self, domain: &str) -> (u32, u32) {
        let default_range = DEFAULT_IDMAP_RANGE;
        match self.config.get(domain, "idmap_range") {
            Some(val) => {
                let vals: Vec<u32> = val.split('-').map(|m| m.parse().unwrap()).collect();
                match vals.as_slice() {
                    [min, max] => (*min, *max),
                    _ => {
                        error!("Invalid range specified [{}] idmap_range = {}", domain, val);
                        default_range
                    }
                }
            },
            None => {
                match self.config.get("global", "idmap_range") {
                    Some(val) => {
                        let vals: Vec<u32> = val.split('-').map(|m| m.parse().unwrap()).collect();
                        match vals.as_slice() {
                            [min, max] => (*min, *max),
                            _ => {
                                error!("Invalid range specified [global] idmap_range = {}", val);
                                default_range
                            }
                        }
                    },
                    None => {
                        error!("No idmap_range range specified in config, using {}-{}!",
                               DEFAULT_IDMAP_RANGE.0, DEFAULT_IDMAP_RANGE.1);
                        default_range
                    },
                }
            },
        }
    }
}
