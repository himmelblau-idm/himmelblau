use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::{DEFAULT_CONN_TIMEOUT, DEFAULT_SOCK_PATH};
use std::process::Command;

pub struct KanidmUnixdConfig {
    pub domains: Vec<String>,
    pub unix_sock_timeout: u64,
    pub sock_path: String,
    pub cn_name_mapping: bool,
    name_mapping_script: Option<String>,
}

impl KanidmUnixdConfig {
    pub fn new() -> Self {
        KanidmUnixdConfig {
            domains: vec![],
            sock_path: DEFAULT_SOCK_PATH.to_string(),
            unix_sock_timeout: DEFAULT_CONN_TIMEOUT * 2,
            cn_name_mapping: false,
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
            name_mapping_script: config.get_name_mapping_script(),
        })
    }

    pub fn map_logon_name(&self, account_id: &str) -> String {
        if let Some(name_mapping_script) = &self.name_mapping_script {
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
