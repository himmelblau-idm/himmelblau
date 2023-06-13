use configparser::ini::Ini;
use std::path::PathBuf;
use log::{debug, error};

use msal::misc::request_tenant_id;

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
                None => String::from("/home/%f"),
            }
        };
        homedir.replace("%f", username).replace("%U", &uid.to_string()).replace("%u", sam).replace("%d", domain)
    }

    pub fn get_shell(&self, domain: &str) -> String {
        match self.config.get(domain, "shell") {
            Some(val) => val,
            None => match self.config.get("global", "shell") {
                Some(val) => val,
                None => String::from("/bin/bash"),
            }
        }
    }

    pub async fn get_tenant_id(&self, domain: &str) -> Option<String> {
        match self.config.get(domain, "tenant_id") {
            Some(val) => Some(val),
            None => {
                match self.config.get("global", "tenant_id") {
                    Some(val) => Some(val),
                    None => {
                        /* It's ok to panic here if no tenant id is found,
                         * since we need to terminate the connection at this
                         * point. If we panic here, either the network is down,
                         * or the specified domain is invalid. */
                        Some(request_tenant_id(domain).await.unwrap())
                    }
                }
            }
        }
    }

    pub async fn get_authority_url(&self, domain: &str, authority: Option<&str>) -> Option<(String, String)> {
        let tenant_id = match self.get_tenant_id(domain).await {
            Some(val) => val,
            None => return None,
        };
        let authority_url = match authority {
            Some(val) => format!("{}/{}", val, tenant_id),
            None => format!("https://login.microsoftonline.com/{}", tenant_id),
        };
        Some((tenant_id, authority_url))
    }

    pub fn get_app_id(&self, domain: &str) -> String {
        match self.config.get(domain, "app_id") {
            Some(val) => String::from(val),
            None => match self.config.get("global", "app_id") {
                Some(val) => String::from(val),
                None => {
                    debug!("app_id unset, defaulting to Intune Portal for Linux");
                    String::from("b743a22d-6705-4147-8670-d92fa515ee2b")
                }
            }
        }
    }

    pub fn get_idmap_range(&self, domain: &str) -> (u32, u32) {
        let default_range = (1000000, 6999999);
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
                        error!("No idmap_range range specified in config, using 1000000-6999999!");
                        default_range
                    },
                }
            },
        }
    }
}
