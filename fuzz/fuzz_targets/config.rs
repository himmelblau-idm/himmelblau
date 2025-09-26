//! Fuzz the Himmelblau config reader & helpers.
//!
//! This harness:
//!  - Generates randomized himmelblau.conf content (global + 0..3 domain sections).
//!  - Exercises documented options exposed via getters in `config.rs`.
//!  - Calls additional helpers like `split_username`, `map_name_to_upn`, `map_upn_to_name`.
//!  - Ensures no panics and no infinite loops on arbitrary input.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

use himmelblau_unix_common::config::{split_username, HimmelblauConfig};

// ---------- Fuzzer input model ----------

#[derive(Debug, Arbitrary)]
struct FInput {
    // Raw config body fuzz (may contain invalid UTF-8; we write lossily)
    raw_cfg: Vec<u8>,

    // Structured fields to construct a well-formed INI with all options
    // (used in addition to raw_cfg to reach deep parsing states).
    use_structured: bool,

    // Global section
    debug: bool,
    selinux: bool,
    apply_policy: bool,
    enable_hello: bool,
    enable_sfa_fallback: bool,
    enable_experimental_mfa: bool,
    enable_experimental_passwordless_fido: bool,
    enable_experimental_intune_custom_compliance: bool,

    connection_timeout: u64,
    cache_timeout: u64,
    unix_sock_timeout: u64,

    home_prefix: Stringish,
    home_attr: HomeAttrPick,
    home_alias: Option<HomeAttrPick>,
    shell: Stringish,

    socket_path: Stringish,
    task_socket_path: Stringish,
    broker_socket_path: Stringish,

    db_path: Stringish,
    policies_db_path: Stringish,

    tpm_tcti_name: Option<Stringish>,
    hsm_pin_path: Option<Stringish>,

    hello_pin_min_length: u8,
    hello_pin_retry_count: u8,
    hello_pin_prompt: Stringish,
    entra_id_password_prompt: Stringish,

    cn_name_mapping: Stringish,
    name_mapping_script: Option<Stringish>,

    // app/scopes for logon token
    app_id: Option<Stringish>,
    logon_token_app_id: Option<Stringish>,
    logon_token_scopes: Vec<Stringish>,

    // groups
    pam_allow_groups: Vec<Stringish>,
    sudo_groups: Vec<Stringish>,
    local_sudo_group: Stringish,
    local_groups: Vec<Stringish>,

    // ODC/authority host (per domain)
    odc_provider: Stringish,

    // Domain specs
    domains: Vec<DomainSpec>,
}

#[derive(Debug, Arbitrary, Clone)]
struct DomainSpec {
    name: Stringish, // primary domain name
    idmap_lo: u32,
    idmap_hi: u32,
    // domain-specific overrides
    home_prefix: Option<Stringish>,
    home_attr: Option<HomeAttrPick>,
    home_alias: Option<HomeAttrPick>,
    shell: Option<Stringish>,
    app_id: Option<Stringish>,
    logon_token_app_id: Option<Stringish>,
    intune_device_id: Option<Stringish>,
    graph_url: Option<Stringish>,
    tenant_id: Option<Stringish>,
}

#[derive(Debug, Arbitrary, Clone)]
struct Stringish(Vec<u8>);

impl fmt::Display for Stringish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = String::from_utf8_lossy(&self.0);
        write!(f, "{}", s)
    }
}

#[derive(Debug, Arbitrary, Clone, Copy)]
enum HomeAttrPick {
    Uuid,
    Spn,
}

// ---------- Helper: write a structured INI touching every option ----------

fn write_structured_ini(path: &Path, fi: &FInput) -> std::io::Result<()> {
    let mut f = File::create(path)?;

    // --- [global] ---
    writeln!(f, "[global]")?;
    writeln!(f, "debug = {}", fi.debug)?;
    writeln!(f, "selinux = {}", fi.selinux)?;
    writeln!(f, "apply_policy = {}", fi.apply_policy)?;
    writeln!(f, "enable_hello = {}", fi.enable_hello)?;
    writeln!(f, "enable_sfa_fallback = {}", fi.enable_sfa_fallback)?;
    writeln!(
        f,
        "enable_experimental_mfa = {}",
        fi.enable_experimental_mfa
    )?;
    writeln!(
        f,
        "enable_experimental_passwordless_fido = {}",
        fi.enable_experimental_passwordless_fido
    )?;
    writeln!(
        f,
        "enable_experimental_intune_custom_compliance = {}",
        fi.enable_experimental_intune_custom_compliance
    )?;

    writeln!(f, "connection_timeout = {}", fi.connection_timeout)?;
    writeln!(f, "cache_timeout = {}", fi.cache_timeout)?;
    writeln!(f, "unix_sock_timeout = {}", fi.unix_sock_timeout)?;

    writeln!(f, "home_prefix = {}", fi.home_prefix)?;
    writeln!(
        f,
        "home_attr = {}",
        match fi.home_attr {
            HomeAttrPick::Uuid => "uuid",
            HomeAttrPick::Spn => "spn",
        }
    )?;
    if let Some(alias) = fi.home_alias {
        writeln!(
            f,
            "home_alias = {}",
            match alias {
                HomeAttrPick::Uuid => "uuid",
                HomeAttrPick::Spn => "spn",
            }
        )?;
    }
    writeln!(f, "shell = {}", fi.shell)?;

    writeln!(f, "socket_path = {}", fi.socket_path)?;
    writeln!(f, "task_socket_path = {}", fi.task_socket_path)?;
    writeln!(f, "broker_socket_path = {}", fi.broker_socket_path)?;

    writeln!(f, "db_path = {}", fi.db_path)?;
    writeln!(f, "policies_db_path = {}", fi.policies_db_path)?;

    if let Some(t) = &fi.tpm_tcti_name {
        writeln!(f, "tpm_tcti_name = {}", t)?;
    }
    if let Some(p) = &fi.hsm_pin_path {
        writeln!(f, "hsm_pin_path = {}", p)?;
    }

    // Hello/Password prompts and constraints
    writeln!(f, "hello_pin_min_length = {}", fi.hello_pin_min_length)?;
    writeln!(f, "hello_pin_retry_count = {}", fi.hello_pin_retry_count)?;
    writeln!(f, "hello_pin_prompt = {}", fi.hello_pin_prompt)?;
    writeln!(
        f,
        "entra_id_password_prompt = {}",
        fi.entra_id_password_prompt
    )?;

    // Name mapping
    writeln!(f, "cn_name_mapping = {}", fi.cn_name_mapping)?;
    if let Some(nm) = &fi.name_mapping_script {
        writeln!(f, "name_mapping_script = {}", nm)?;
    }

    // Token/App
    if let Some(app) = &fi.app_id {
        writeln!(f, "app_id = {}", app)?;
    }
    if let Some(app) = &fi.logon_token_app_id {
        writeln!(f, "logon_token_app_id = {}", app)?;
    }
    if !fi.logon_token_scopes.is_empty() {
        let scopes = fi
            .logon_token_scopes
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(",");
        writeln!(f, "logon_token_scopes = {}", scopes)?;
    }

    // Groups
    if !fi.pam_allow_groups.is_empty() {
        let s = fi
            .pam_allow_groups
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");
        writeln!(f, "pam_allow_groups = {}", s)?;
    }
    if !fi.sudo_groups.is_empty() {
        let s = fi
            .sudo_groups
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");
        writeln!(f, "sudo_groups = {}", s)?;
    }
    writeln!(f, "local_sudo_group = {}", fi.local_sudo_group)?;
    if !fi.local_groups.is_empty() {
        let s = fi
            .local_groups
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");
        writeln!(f, "local_groups = {}", s)?;
    }

    // ODC / authority host
    writeln!(f, "odc_provider = {}", fi.odc_provider)?;

    // Domains (and required top-level `domains=` + per-domain sections)
    let domain_names: Vec<String> = fi.domains.iter().map(|d| d.name.to_string()).collect();
    if !domain_names.is_empty() {
        writeln!(f, "domains = {}", domain_names.join(","))?;
    }
    for d in &fi.domains {
        writeln!(f, "\n[{}]", d.name)?;
        writeln!(f, "idmap_range = {}-{}", d.idmap_lo, d.idmap_hi)?;
        if let Some(v) = &d.home_prefix {
            writeln!(f, "home_prefix = {}", v)?;
        }
        if let Some(v) = d.home_attr {
            writeln!(
                f,
                "home_attr = {}",
                match v {
                    HomeAttrPick::Uuid => "uuid",
                    HomeAttrPick::Spn => "spn",
                }
            )?;
        }
        if let Some(v) = d.home_alias {
            writeln!(
                f,
                "home_alias = {}",
                match v {
                    HomeAttrPick::Uuid => "uuid",
                    HomeAttrPick::Spn => "spn",
                }
            )?;
        }
        if let Some(v) = &d.shell {
            writeln!(f, "shell = {}", v)?;
        }
        if let Some(v) = &d.app_id {
            writeln!(f, "app_id = {}", v)?;
        }
        if let Some(v) = &d.logon_token_app_id {
            writeln!(f, "logon_token_app_id = {}", v)?;
        }
        if let Some(v) = &d.intune_device_id {
            writeln!(f, "intune_device_id = {}", v)?;
        }
        if let Some(v) = &d.graph_url {
            writeln!(f, "graph_url = {}", v)?;
        }
        if let Some(v) = &d.tenant_id {
            writeln!(f, "tenant_id = {}", v)?;
        }
    }

    Ok(())
}

// ---------- Exercise getters & helpers safely ----------

fn exercise_config(cfg: &HimmelblauConfig) {
    // Global, no panics expected
    let _ = cfg.get_debug();
    let _ = cfg.get_selinux();
    let _ = cfg.get_apply_policy();
    let _ = cfg.get_enable_hello();
    let _ = cfg.get_enable_sfa_fallback();
    let _ = cfg.get_enable_experimental_mfa();
    let _ = cfg.get_enable_experimental_passwordless_fido();
    let _ = cfg.get_enable_experimental_intune_custom_compliance();

    let _ = cfg.get_connection_timeout();
    let _ = cfg.get_cache_timeout();
    let _ = cfg.get_unix_sock_timeout();

    let _ = cfg.get_home_prefix(None);
    let _ = cfg.get_home_attr(None);
    let _ = cfg.get_home_alias(None);
    let _ = cfg.get_shell(None);

    let _ = cfg.get_socket_path();
    let _ = cfg.get_task_socket_path();
    let _ = cfg.get_broker_socket_path();

    let _ = cfg.get_db_path();
    let _ = cfg.get_policies_db_path();

    let _ = cfg.get_hsm_type();
    let _ = cfg.get_hsm_pin_path();
    let _ = cfg.get_tpm_tcti_name();

    let _ = cfg.get_hello_pin_min_length();
    let _ = cfg.get_hello_pin_retry_count();
    let _ = cfg.get_hello_pin_prompt();
    let _ = cfg.get_entra_id_password_prompt();

    let _ = cfg.get_cn_name_mapping();
    let _ = cfg.get_name_mapping_script();

    let _ = cfg.get_logon_token_scopes();

    let _ = cfg.get_pam_allow_groups();
    let _ = cfg.get_sudo_groups();
    let _ = cfg.get_local_sudo_group();
    let _ = cfg.get_local_groups();

    let _ = cfg.get_odc_provider("global");
    let _ = cfg.get_id_attr_map();
    let _ = cfg.get_rfc2307_group_fallback_map();

    // Configured domains & per-domain getters
    let domains = cfg.get_configured_domains();
    for d in &domains {
        let name = d.as_str();
        let _ = cfg.get_home_prefix(Some(name));
        let _ = cfg.get_home_attr(Some(name));
        let _ = cfg.get_home_alias(Some(name));
        let _ = cfg.get_shell(Some(name));
        let _ = cfg.get_odc_provider(name);
        let _ = cfg.get_app_id(name);
        let _ = cfg.get_idmap_range(name);
        let _ = cfg.get_graph_url(name);
        let _ = cfg.get_logon_token_app_id(name);
        let _ = cfg.get_intune_device_id(name);
        let _ = cfg.get_tenant_id(name);
        // authority_host may be derived from odc/graph/tenant; exercise it if present
        let _ = cfg.get_authority_host(name);
    }

    // Additional helpers
    let _ = cfg.get_config_file();
    if let Some(primary) = cfg.get_primary_domain_from_alias_simple("alias.example.com") {
        // round-trip mapping using helpers
        let _ = cfg.map_upn_to_name("alice@example.com");
        let _ = cfg.map_upn_to_name(&format!("alice@{primary}"));
    } else {
        let _ = cfg.map_upn_to_name("bob@example.com");
    }

    // Exercise split_username with some tricky inputs
    let _ = split_username("user@example.com");
    let _ = split_username("user@");
    let _ = split_username("@example.com");
    let _ = split_username("user@example@bad");
}

// ---------- The libFuzzer target ----------

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // If data is tiny, still try a minimal config (avoid excessive I/O)
    let fi = FInput::arbitrary(&mut u).unwrap_or_else(|_| FInput {
        raw_cfg: vec![],
        use_structured: true,
        debug: false,
        selinux: false,
        apply_policy: false,
        enable_hello: false,
        enable_sfa_fallback: false,
        enable_experimental_mfa: false,
        enable_experimental_passwordless_fido: false,
        enable_experimental_intune_custom_compliance: false,
        connection_timeout: 0,
        cache_timeout: 0,
        unix_sock_timeout: 0,
        home_prefix: Stringish(b"/home".to_vec()),
        home_attr: HomeAttrPick::Uuid,
        home_alias: None,
        shell: Stringish(b"/bin/sh".to_vec()),
        socket_path: Stringish(b"/run/himmelblaud.sock".to_vec()),
        task_socket_path: Stringish(b"/run/himmelblaud-tasks.sock".to_vec()),
        broker_socket_path: Stringish(b"/run/himmelblau-broker.sock".to_vec()),
        db_path: Stringish(b"/var/lib/himmelblau/db.sqlite".to_vec()),
        policies_db_path: Stringish(b"/var/lib/himmelblau/policies.sqlite".to_vec()),
        tpm_tcti_name: None,
        hsm_pin_path: None,
        hello_pin_min_length: 6,
        hello_pin_retry_count: 3,
        hello_pin_prompt: Stringish(b"Enter PIN".to_vec()),
        entra_id_password_prompt: Stringish(b"Password".to_vec()),
        cn_name_mapping: Stringish(b"displayName".to_vec()),
        name_mapping_script: None,
        app_id: None,
        logon_token_app_id: None,
        logon_token_scopes: vec![],
        pam_allow_groups: vec![],
        sudo_groups: vec![],
        local_sudo_group: Stringish(b"sudo".to_vec()),
        local_groups: vec![],
        odc_provider: Stringish(b"https://login.microsoftonline.com".to_vec()),
        domains: vec![],
    });

    // Temp workspace
    let tmp = match TempDir::new() {
        Ok(t) => t,
        Err(_) => return,
    };
    let cfg_path = tmp.path().join("himmelblau.conf");

    // Two paths to reach edge cases:
    //  1) Write raw bytes lossily (INI parser error paths)
    //  2) Write structured, touching all options
    if !fi.raw_cfg.is_empty() {
        let _ = fs::write(&cfg_path, String::from_utf8_lossy(&fi.raw_cfg).as_bytes());
        if let Ok(cfg) = HimmelblauConfig::new(Some(cfg_path.to_string_lossy().as_ref())) {
            exercise_config(&cfg);
        }
    }

    // Structured pass
    if fi.use_structured {
        let _ = write_structured_ini(&cfg_path, &fi);
        if let Ok(cfg) = HimmelblauConfig::new(Some(cfg_path.to_string_lossy().as_ref())) {
            exercise_config(&cfg);

            // Touch write paths (don’t assert, just ensure no panic)
            let _ = cfg.write();
        }
    }
});
