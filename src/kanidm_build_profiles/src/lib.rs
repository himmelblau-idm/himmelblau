pub const DEFAULT_CONFIG_PATH: &str = "/etc/himmelblau/himmelblau.conf";

pub fn apply_profile() {
    println!(
        "cargo:rustc-env=KANIDM_CLIENT_CONFIG_PATH={}",
        DEFAULT_CONFIG_PATH
    );
}
