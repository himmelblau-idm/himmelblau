use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::{DEFAULT_CONN_TIMEOUT, DEFAULT_SOCK_PATH};

pub struct KanidmUnixdConfig {
    pub unix_sock_timeout: u64,
    pub sock_path: String,
}

impl KanidmUnixdConfig {
    pub fn new() -> Self {
        KanidmUnixdConfig {
            sock_path: DEFAULT_SOCK_PATH.to_string(),
            unix_sock_timeout: DEFAULT_CONN_TIMEOUT * 2,
        }
    }

    pub fn read_options_from_optional_config(self, config_path: &str) -> Result<Self, String> {
        let config: HimmelblauConfig = HimmelblauConfig::new(Some(config_path))?;
        Ok(KanidmUnixdConfig {
            sock_path: config.get_socket_path(),
            unix_sock_timeout: config.get_connection_timeout() * 2,
        })
    }
}

impl Default for KanidmUnixdConfig {
    fn default() -> Self {
        Self::new()
    }
}
