use configparser::ini::Ini;
use std::path::{PathBuf};

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
}
