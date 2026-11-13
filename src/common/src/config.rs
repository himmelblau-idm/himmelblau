use crate::constants::DEFAULT_HELLO_TOTP_ENABLED;
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
use crate::i18n::tr;
use crate::unix_passwd::parse_etc_passwd;
use configparser::ini::Ini;
use oauth2::url;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::io::{self, Error};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use tracing::{debug, error};

use crate::constants::{
    CN_NAME_MAPPING, DEFAULT_ALLOW_REMOTE_HELLO, DEFAULT_AUTHORITY_HOST, DEFAULT_BROKER_SOCK_PATH,
    DEFAULT_CACHE_TIMEOUT, DEFAULT_CONFIG_PATH, DEFAULT_CONN_TIMEOUT,
    DEFAULT_CONSOLE_PASSWORD_ONLY, DEFAULT_DB_PATH, DEFAULT_FIDO_TIMEOUT, DEFAULT_HELLO_ENABLED,
    DEFAULT_HELLO_PIN_MIN_LEN, DEFAULT_HELLO_PIN_RETRY_COUNT, DEFAULT_HOME_ALIAS,
    DEFAULT_HOME_ATTR, DEFAULT_HOME_PREFIX, DEFAULT_HSM_PIN_PATH, DEFAULT_ID_ATTR_MAP,
    DEFAULT_JOIN_TYPE, DEFAULT_LOCAL_GROUPS_RECONCILE_INTERVAL, DEFAULT_LOGON_SCRIPT_TIMEOUT,
    DEFAULT_MFA_POLL_PROMPT_SERVICES, DEFAULT_ODC_PROVIDER, DEFAULT_OFFLINE_BREAKGLASS_TTL,
    DEFAULT_ORCHESTRATOR_SOCK_PATH, DEFAULT_PASSWORD_ONLY_REMOTE_SERVICES_DENY_LIST,
    DEFAULT_POLICIES_DB_DIR, DEFAULT_REQUEST_TIMEOUT, DEFAULT_SELINUX,
    DEFAULT_SFA_FALLBACK_ENABLED, DEFAULT_SHELL, DEFAULT_SOCK_PATH, DEFAULT_TASK_SOCK_PATH,
    DEFAULT_TPM_TCTI_NAME, DEFAULT_USER_MAP_FILE, DEFAULT_USE_ETC_SKEL, MAPPED_NAME_CACHE,
    NSS_IGNORE_EXACT, NSS_IGNORE_PREFIX, RUNTIME_CONFIG_PATH, SERVER_CONFIG_PATH,
    VENDOR_CONFIG_PATH,
};
use crate::mapping::{MappedNameCache, Mode};
use crate::unix_config::{HomeAttr, HsmType};
use himmelblau::auth::IpVersion;
use himmelblau::error::MsalError;
use idmap::{DEFAULT_IDMAP_RANGE, DEFAULT_SUBID_RANGE};
use reqwest::Url;
use serde::de;
use serde::{Deserialize, Deserializer};
use std::env;
use std::time::Duration;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum IdAttr {
    Uuid,
    Name,
    Rfc2307,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum JoinType {
    Join,
    Register,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum IpVersionSelection {
    Both,
    Ipv4Only,
    Ipv6Only,
}

/// Which supplementary groups NSS initgroups publishes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InitgroupsMode {
    /// Only groups that resolve to an NSS name.
    Named,
    /// Every cached group GID, including ones getgrgid cannot name.
    Full,
}

impl From<JoinType> for u32 {
    fn from(val: JoinType) -> Self {
        // Microsoft Entra ID enrollment join types:
        // 0 = Device Join (standard join)
        // 4 = Device Registration (register only)
        match val {
            JoinType::Join => 0,     // Device Join
            JoinType::Register => 4, // Device Registration
        }
    }
}

/// Keys discovered at runtime and persisted in the server cache.
const SERVER_CACHE_KEYS: [&str; 6] = [
    "authority_host",
    "tenant_id",
    "graph_url",
    "domain_aliases",
    "device_id",
    "intune_device_id",
];

/// Section name prefix of a `[tenant.<label>]` provider stanza.
pub const TENANT_SECTION_PREFIX: &str = "tenant.";

/// Global keys that define a provider in configs without tenant stanzas.
const LEGACY_PROVIDER_KEYS: [&str; 3] = ["domain", "domains", "oidc_issuer_url"];

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProviderKind {
    Entra,
    Oidc,
}

/// Provider keys of a `[tenant.<label>]` section. Other keys are
/// domain-specific options read through the getters.
#[derive(Deserialize)]
struct TenantStanza {
    #[serde(default, deserialize_with = "de_optional_string")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "de_optional_string")]
    oidc_issuer_url: Option<String>,
    #[serde(default, deserialize_with = "de_bool")]
    default: bool,
}

/// An identity provider served by the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    /// The `<label>` of `[tenant.<label>]`, or the domain in legacy configs.
    pub label: String,
    /// The section holding the provider's admin settings.
    pub section: String,
    pub kind: ProviderKind,
    /// Settings/storage key: an Entra domain or an issuer-derived OIDC key.
    pub domain: String,
    pub default: bool,
}

impl ProviderConfig {
    pub(crate) fn oidc_tenant_id(&self, config: &HimmelblauConfig) -> Option<uuid::Uuid> {
        if self.kind != ProviderKind::Oidc {
            return None;
        }
        let issuer = config.get_oidc_issuer_url(Some(&self.domain))?;
        Some(oidc_tenant_id(&issuer))
    }

    pub(crate) fn scopes_oidc_accounts(&self) -> bool {
        self.kind == ProviderKind::Oidc && self.section.starts_with(TENANT_SECTION_PREFIX)
    }

    pub(crate) fn local_account_name(&self, account: &str) -> String {
        if self.scopes_oidc_accounts() {
            format!("{account}@{}", self.label)
        } else {
            account.to_string()
        }
    }

    pub(crate) fn upstream_account_name(&self, account: &str) -> Option<String> {
        let qualified = if self.section.starts_with(TENANT_SECTION_PREFIX) {
            account
                .rsplit_once('@')
                .filter(|(_, suffix)| suffix.eq_ignore_ascii_case(&self.label))
                .map(|(name, _)| name)
        } else {
            None
        };
        let account = qualified.unwrap_or(account);
        if account.is_empty() || account.starts_with('@') || account.ends_with('@') {
            return None;
        }
        if self.kind == ProviderKind::Entra && qualified.is_some() && !account.contains('@') {
            Some(format!("{account}@{}", self.domain))
        } else {
            Some(account.to_string())
        }
    }
}

#[derive(Debug, Default)]
pub struct ValidationReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

pub fn split_username(username: &str) -> Option<(&str, &str)> {
    let tup: Vec<&str> = username.split('@').collect();
    if tup.len() == 2 {
        return Some((tup[0], tup[1]));
    }
    None
}

/// Parse a TTL string into seconds.
///
/// Returns an `Option<u64>` representing the number of seconds parsed from the TTL string,
/// or `None` if parsing fails.
///
/// Supported suffixes:
/// - 'm' for minutes
/// - 'h' for hours
/// - 'd' for days
///
/// If no suffix is provided, the value is treated as seconds.
pub fn parse_ttl_to_seconds(ttl_str: &str) -> Option<u64> {
    let ttl_str = ttl_str.trim().to_lowercase();

    // Directly check if last character is alphabetic and extract suffix
    let (num_part, suffix) = match ttl_str.chars().last() {
        Some(last_char) if last_char.is_ascii_alphabetic() => {
            (&ttl_str[..ttl_str.len() - 1], last_char)
        }
        Some(_) => (ttl_str.as_str(), 's'),
        None => {
            error!("TTL string is empty");
            return None;
        }
    };

    let number: u64 = match num_part.parse() {
        Ok(number) => number,
        Err(e) => {
            error!("Invalid TTL number: {}", e);
            return None;
        }
    };

    let seconds = match suffix {
        's' => number,
        'm' => number * 60,
        'h' => number * 3600,
        'd' => number * 86400,
        _ => {
            error!("Invalid TTL unit '{}'", suffix);
            return None;
        }
    };

    Some(seconds)
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
    request_timeout_secs: u64,
) -> Result<(String, String, String), MsalError> {
    let request_timeout = Duration::from_secs(request_timeout_secs);
    let connect_timeout = std::cmp::min(request_timeout / 2, Duration::from_secs(3));
    let client = reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .build()
        .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

    let url = Url::parse_with_params(
        &format!("https://{}/odc/v2.1/federationProvider", odc_provider),
        [("domain", domain)],
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
    /// Admin configuration from the config hierarchy and drop-ins.
    config: Ini,
    /// Values discovered at runtime, see `SERVER_CACHE_KEYS`.
    cache: Ini,
    cache_path: PathBuf,
    filename: String,
    effective_config_paths: Vec<PathBuf>,
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

fn parse_bool(val: &str) -> Option<bool> {
    match val.trim().to_lowercase().as_str() {
        "true" | "yes" | "on" | "t" | "y" | "1" => Some(true),
        "false" | "no" | "off" | "f" | "n" | "0" => Some(false),
        _ => None,
    }
}

fn match_bool(key: &str, val: Option<String>, default: bool) -> bool {
    match val {
        Some(val) => parse_bool(&val).unwrap_or_else(|| {
            error!(key, value = %val, default, "Unrecognized boolean value, using default");
            default
        }),
        None => default,
    }
}

fn de_bool<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    let val = String::deserialize(deserializer)?;
    parse_bool(&val)
        .ok_or_else(|| de::Error::invalid_value(de::Unexpected::Str(&val), &"a boolean"))
}

fn de_optional_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

fn parse_range(val: &str) -> Option<(u32, u32)> {
    match val
        .split('-')
        .map(|m| m.trim().parse())
        .collect::<Result<Vec<u32>, _>>()
    {
        Ok(vals) => match vals.as_slice() {
            [min, max] if min <= max => Some((*min, *max)),
            _ => None,
        },
        Err(_) => None,
    }
}

fn resolve_home_prefix(path: &Path) -> io::Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let mut resolved = PathBuf::new();
    let mut has_missing_component = false;

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => resolved.push(prefix.as_os_str()),
            Component::RootDir => resolved.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) if has_missing_component => resolved.push(name),
            Component::Normal(name) => {
                let candidate = resolved.join(name);
                match fs::canonicalize(&candidate) {
                    Ok(canonical) => resolved = canonical,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        match fs::symlink_metadata(&candidate) {
                            Ok(_) => return Err(error),
                            Err(metadata_error)
                                if metadata_error.kind() == io::ErrorKind::NotFound =>
                            {
                                resolved = candidate;
                                has_missing_component = true;
                            }
                            Err(metadata_error) => return Err(metadata_error),
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }

    Ok(resolved)
}

fn ranges_overlap(a: (u32, u32), b: (u32, u32)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}

fn split_list(val: &str) -> impl Iterator<Item = String> + '_ {
    val.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Normalize an OIDC issuer URL, rejecting values that are not plain https URLs.
fn parse_issuer_url(val: &str) -> Result<Option<String>, String> {
    let s = val.trim();
    let s = s
        .strip_suffix("/.well-known/openid-configuration")
        .unwrap_or(s);
    if s.is_empty() {
        Ok(None)
    } else if !s.starts_with("https://") {
        Err("OIDC issuer URL must use https://".to_string())
    } else if s.contains('?') || s.contains('#') {
        Err("OIDC issuer URL must not contain query or fragment".to_string())
    } else if url::Url::parse(s).is_err() {
        Err("OIDC issuer URL is not a valid URL".to_string())
    } else {
        Ok(Some(s.to_string()))
    }
}

pub(crate) fn oidc_tenant_id(issuer: &str) -> uuid::Uuid {
    uuid::Uuid::new_v5(
        &uuid::uuid!("e669513b-1345-4853-96a7-596243184319"),
        issuer.as_bytes(),
    )
}

fn path_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("failed to inspect {}: {}", path.display(), error)),
    }
}

fn symlink_points_to_dev_null(path: &Path) -> bool {
    matches!(fs::read_link(path), Ok(target) if target == Path::new("/dev/null"))
}

fn is_mask(path: &Path) -> Result<bool, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {}: {}", path.display(), error))?;

    if metadata.file_type().is_symlink() {
        return Ok(symlink_points_to_dev_null(path));
    }

    Ok(metadata.is_file() && metadata.len() == 0)
}

fn drop_in_dir(config_path: &Path) -> PathBuf {
    let mut path = config_path.as_os_str().to_os_string();
    path.push(".d");
    PathBuf::from(path)
}

fn collect_drop_ins(config_paths: &[PathBuf]) -> Result<BTreeMap<OsString, PathBuf>, String> {
    let mut drop_ins = BTreeMap::new();

    for config_path in config_paths {
        let directory = drop_in_dir(config_path);
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "failed to read drop-in directory {}: {}",
                    directory.display(),
                    error
                ))
            }
        };

        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "failed to read drop-in directory {}: {}",
                    directory.display(),
                    error
                )
            })?;
            let path = entry.path();
            if path.extension() != Some(OsStr::new("conf")) {
                continue;
            }

            let file_type = entry.file_type().map_err(|error| {
                format!("failed to inspect drop-in {}: {}", path.display(), error)
            })?;
            let is_config_file = file_type.is_file()
                || (file_type.is_symlink()
                    && (symlink_points_to_dev_null(&path)
                        || fs::metadata(&path)
                            .map(|metadata| metadata.is_file())
                            .unwrap_or(false)));
            if is_config_file {
                drop_ins.insert(entry.file_name(), path);
            }
        }
    }

    Ok(drop_ins)
}

fn load_config_file(config: &mut Ini, path: &Path) -> Result<(), String> {
    let filename = path
        .to_str()
        .ok_or_else(|| format!("configuration path is not valid UTF-8: {}", path.display()))?;
    config
        .load_and_append(filename)
        .map(|_| ())
        .map_err(|error| {
            format!(
                "failed to read config from {} - cannot start up: {} Quitting.",
                path.display(),
                error
            )
        })
}

fn load_config_hierarchy(
    config: &mut Ini,
    config_paths: &[PathBuf],
) -> Result<Vec<PathBuf>, String> {
    let mut effective_config_paths = Vec::new();
    let mut main_config = None;
    for path in config_paths {
        if path_exists(path)? {
            main_config = Some(path);
        }
    }

    if let Some(path) = main_config {
        effective_config_paths.push(path.clone());
        if !is_mask(path)? {
            load_config_file(config, path)?;
        }
    }

    for path in collect_drop_ins(config_paths)?.values() {
        effective_config_paths.push(path.clone());
        if !is_mask(path)? {
            load_config_file(config, path)?;
        }
    }

    Ok(effective_config_paths)
}

impl HimmelblauConfig {
    #[cfg(test)]
    #[allow(clippy::expect_used)]
    pub(crate) fn from_test_config(input: &str) -> Self {
        let mut config = Ini::new();
        config
            .read(input.to_string())
            .expect("Invalid test configuration");
        Self {
            config,
            cache: Ini::new(),
            cache_path: PathBuf::new(),
            filename: String::new(),
            effective_config_paths: Vec::new(),
        }
    }

    pub fn new(config_path: Option<&str>) -> Result<HimmelblauConfig, String> {
        Self::load(config_path, Path::new(SERVER_CONFIG_PATH))
    }

    pub(crate) fn load(
        config_path: Option<&str>,
        cache_path: &Path,
    ) -> Result<HimmelblauConfig, String> {
        let mut sconfig = Ini::new();
        let mut filename: String = DEFAULT_CONFIG_PATH.to_string();
        if let Some(config_path) = config_path {
            filename = config_path.to_string();
        }
        let cfg_path: PathBuf = PathBuf::from(filename.clone());
        let config_paths = if filename == DEFAULT_CONFIG_PATH {
            vec![
                PathBuf::from(VENDOR_CONFIG_PATH),
                PathBuf::from(RUNTIME_CONFIG_PATH),
                cfg_path,
            ]
        } else {
            vec![cfg_path]
        };
        let effective_config_paths = load_config_hierarchy(&mut sconfig, &config_paths)?;

        let mut cache = Ini::new();
        if cache_path.exists() {
            load_config_file(&mut cache, cache_path)?;
        }
        Ok(HimmelblauConfig {
            config: sconfig,
            cache,
            cache_path: cache_path.to_path_buf(),
            filename,
            effective_config_paths,
        })
    }

    pub(crate) fn reload(&self) -> Result<Self, String> {
        Self::load(Some(&self.filename), &self.cache_path)
    }

    pub fn get(&self, section: &str, option: &str) -> Option<String> {
        if SERVER_CACHE_KEYS.contains(&option) {
            if let Some(val) = self.cache.get(section, option) {
                return Some(val);
            }
        }
        self.config.get(section, option)
    }

    /// Read `key` for `domain`. Discovered keys come from the server cache
    /// first, then from the admin section that configures `domain`.
    fn domain_value(&self, domain: &str, key: &str) -> Option<String> {
        let provider = self.provider_for_domain(domain);
        let canonical = provider.as_ref().map_or(domain, |p| p.domain.as_str());
        if SERVER_CACHE_KEYS.contains(&key) {
            if let Some(val) = self.cache.get(canonical, key) {
                return Some(val);
            }
        }
        self.config.get(&self.section_for_domain(domain), key)
    }

    fn domain_or_global_value(&self, domain: Option<&str>, key: &str) -> Option<String> {
        domain
            .and_then(|domain| self.domain_value(domain, key))
            .or_else(|| self.config.get("global", key))
    }

    fn section_for_domain(&self, domain: &str) -> String {
        self.provider_for_domain(domain)
            .map(|p| p.section)
            .unwrap_or_else(|| domain.to_string())
    }

    pub fn get_home_prefix(&self, domain: Option<&str>) -> String {
        self.domain_or_global_value(domain, "home_prefix")
            .unwrap_or_else(|| String::from(DEFAULT_HOME_PREFIX))
    }

    pub fn get_home_attr(&self, domain: Option<&str>) -> HomeAttr {
        match self.domain_or_global_value(domain, "home_attr") {
            Some(val) => str_to_home_attr(&val),
            None => DEFAULT_HOME_ATTR,
        }
    }

    pub fn get_home_alias(&self, domain: Option<&str>) -> Option<HomeAttr> {
        match self.domain_or_global_value(domain, "home_alias") {
            Some(val) => Some(str_to_home_attr(&val)),
            None => DEFAULT_HOME_ALIAS,
        }
    }

    pub fn get_shell(&self, domain: Option<&str>) -> String {
        self.domain_or_global_value(domain, "shell")
            .unwrap_or_else(|| String::from(DEFAULT_SHELL))
    }

    pub fn get_odc_provider(&self, domain: &str) -> String {
        self.domain_or_global_value(Some(domain), "odc_provider")
            .unwrap_or_else(|| String::from(DEFAULT_ODC_PROVIDER))
    }

    pub fn get_idmap_range(&self, domain: &str) -> (u32, u32) {
        let (source, val) = match self.domain_value(domain, "idmap_range") {
            Some(val) => (domain, val),
            None => match self.config.get("global", "idmap_range") {
                Some(val) => ("global", val),
                None => {
                    warn!(
                        min = DEFAULT_IDMAP_RANGE.0,
                        max = DEFAULT_IDMAP_RANGE.1,
                        "No idmap_range configured, using the default"
                    );
                    return DEFAULT_IDMAP_RANGE;
                }
            },
        };
        parse_range(&val).unwrap_or_else(|| {
            error!(
                section = source,
                value = %val,
                "Invalid idmap_range, using the default"
            );
            DEFAULT_IDMAP_RANGE
        })
    }

    pub fn get_unix_sock_timeout(&self) -> u64 {
        self.get_connection_timeout().saturating_mul(2)
    }

    /// Get the subordinate ID range for container support (podman, etc.)
    /// Returns the configured range, or the default range if not configured.
    pub fn get_subid_range(&self) -> (u32, u32) {
        let default_range = DEFAULT_SUBID_RANGE;
        match self.config.get("global", "subid_range") {
            Some(val) => {
                let vals: Vec<u32> = val
                    .split('-')
                    .map(|m| m.parse())
                    .collect::<Result<Vec<u32>, _>>()
                    .unwrap_or_else(|_| vec![default_range.0, default_range.1]);
                match vals.as_slice() {
                    [min, max] => (*min, *max),
                    _ => {
                        error!("Invalid range specified [global] subid_range = {}", val);
                        default_range
                    }
                }
            }
            None => default_range,
        }
    }

    pub fn get_authority_host(&self, domain: &str) -> String {
        match self.domain_or_global_value(Some(domain), "authority_host") {
            Some(val) => val,
            None => {
                debug!("authority_host unset, using defaults");
                String::from(DEFAULT_AUTHORITY_HOST)
            }
        }
    }

    /// Resolve a user's configured domain (including a known alias) before
    /// selecting its authority. OIDC accounts use the configured issuer host,
    /// regardless of whether their account-name claim contains a domain.
    pub fn get_authority_host_for_account(&self, account_id: &str) -> Option<String> {
        let provider = self.provider_for_account(account_id)?;
        if provider.kind == ProviderKind::Oidc {
            let issuer = self.get_oidc_issuer_url(Some(&provider.domain))?;
            let issuer = url::Url::parse(&issuer).ok()?;
            return issuer.host_str().map(str::to_string);
        }
        Some(self.get_authority_host(&provider.domain))
    }

    /// Broker environments are endpoint authorities, so preserve an OIDC issuer's
    /// nondefault port. FIDO RP IDs continue to use the hostname-only accessor.
    pub fn get_broker_environment_for_account(&self, account_id: &str) -> Option<String> {
        let provider = self.provider_for_account(account_id)?;
        if provider.kind == ProviderKind::Oidc {
            let issuer = self.get_oidc_issuer_url(Some(&provider.domain))?;
            let issuer = url::Url::parse(&issuer).ok()?;
            issuer.host_str()?;
            return Some(issuer[url::Position::BeforeHost..url::Position::AfterPort].to_string());
        }
        self.get_authority_host_for_account(account_id)
    }

    pub fn get_tenant_id(&self, domain: &str) -> Option<String> {
        self.domain_value(domain, "tenant_id")
    }

    pub fn get_graph_url(&self, domain: &str) -> Option<String> {
        self.domain_value(domain, "graph_url")
    }

    pub fn get_app_id(&self, domain: &str) -> Option<String> {
        self.domain_or_global_value(Some(domain), "app_id")
    }

    pub fn get_logon_token_app_id(&self, domain: &str) -> Option<String> {
        self.domain_or_global_value(Some(domain), "logon_token_app_id")
    }

    pub fn get_policies_db_path(&self) -> String {
        match self.config.get("global", "policies_db_path") {
            Some(val) => val,
            None => DEFAULT_POLICIES_DB_DIR.to_string(),
        }
    }

    pub fn get_hsm_type(&self) -> HsmType {
        match self.config.get("global", "hsm_type") {
            Some(val) => match val.to_lowercase().as_str() {
                "soft" | "tpm_bound_soft_if_possible" => HsmType::Soft,
                "tpm_if_possible" => HsmType::TpmIfPossible,
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

    pub fn get_join_type(&self) -> JoinType {
        match self.config.get("global", "join_type") {
            Some(val) => match val.to_lowercase().as_str() {
                "join" => JoinType::Join,
                "register" => JoinType::Register,
                _ => {
                    error!("Unrecognized join_type choice: {}", val);
                    DEFAULT_JOIN_TYPE
                }
            },
            None => DEFAULT_JOIN_TYPE,
        }
    }

    /// Whether user discovery and enrollment auth request the Microsoft Intune
    /// resource instead of the Microsoft Intune Enrollment resource.
    pub fn get_use_intune_auth_resource(&self) -> bool {
        self.get_apply_policy() || self.get_intune_auth_resource()
    }

    pub fn write(&self) -> Result<(), Error> {
        self.config.write(self.filename.clone())
    }

    pub fn reload_server_cache(&mut self) -> Result<(), String> {
        let mut cache = Ini::new();
        if self.cache_path.exists() {
            load_config_file(&mut cache, &self.cache_path)?;
        }
        self.cache = cache;
        Ok(())
    }

    pub fn write_server_config(&self) -> Result<(), Error> {
        let mut srv_conf = self.cache.clone();
        srv_conf.remove_section("global");

        let mut keys_to_remove = Vec::new();
        for (section, keys) in srv_conf.get_map_ref() {
            for key in keys.keys() {
                if !SERVER_CACHE_KEYS.contains(&key.as_str()) {
                    keys_to_remove.push((section.to_string(), key.clone()));
                }
            }
        }
        for (section, key) in keys_to_remove {
            srv_conf.remove_key(&section, &key);
        }

        srv_conf.write(&self.cache_path)
    }

    /// Discovered keys go to the server cache, everything else to the admin
    /// configuration held in memory.
    pub fn set(&mut self, section: &str, key: &str, value: &str) {
        if SERVER_CACHE_KEYS.contains(&key) {
            self.cache.set(section, key, Some(value.to_string()));
        } else {
            self.config.set(section, key, Some(value.to_string()));
        }
    }

    fn tenant_sections(&self) -> Vec<String> {
        let mut sections: Vec<String> = self
            .config
            .sections()
            .into_iter()
            .filter(|s| s.starts_with(TENANT_SECTION_PREFIX))
            .collect();
        sections.sort();
        sections
    }

    fn legacy_sections(&self) -> Vec<String> {
        self.config
            .sections()
            .into_iter()
            .filter(|s| {
                s != "global" && s != "offline_breakglass" && !s.starts_with(TENANT_SECTION_PREFIX)
            })
            .collect()
    }

    fn legacy_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = ["domains", "domain"]
            .iter()
            .filter_map(|key| self.config.get("global", key))
            .flat_map(|val| split_list(&val).collect::<Vec<_>>())
            .collect();
        for section in self.legacy_sections() {
            if !domains.contains(&section) {
                domains.push(section);
            }
        }
        domains
    }

    fn legacy_entra_domains(&self) -> Vec<String> {
        self.legacy_domains()
            .into_iter()
            .filter(|d| d != "oidc")
            .collect()
    }

    fn legacy_providers(&self) -> Vec<ProviderConfig> {
        let issuer = self.config.get("global", "oidc_issuer_url");
        if matches!(issuer.as_deref().map(parse_issuer_url), Some(Ok(Some(_)))) {
            return vec![ProviderConfig {
                label: "oidc".to_string(),
                section: "oidc".to_string(),
                kind: ProviderKind::Oidc,
                domain: "oidc".to_string(),
                default: true,
            }];
        }
        self.legacy_entra_domains()
            .into_iter()
            .take(1)
            .map(|domain| ProviderConfig {
                label: domain.clone(),
                section: domain.clone(),
                kind: ProviderKind::Entra,
                domain,
                default: true,
            })
            .collect()
    }

    fn tenant_stanza(&self, section: &str) -> Result<TenantStanza, de::value::Error> {
        let entries = self
            .config
            .get_map_ref()
            .get(section)
            .into_iter()
            .flatten()
            .filter_map(|(key, val)| val.clone().map(|val| (key.clone(), val)));
        TenantStanza::deserialize(de::value::MapDeserializer::new(entries))
    }

    /// Parse the configured identity providers.
    ///
    /// Each `[tenant.<label>]` section defines one provider. Configs without
    /// tenant sections define at most one provider through `[global] domain`
    /// or `[global] oidc_issuer_url`.
    pub fn parse_providers(&self) -> Result<Vec<ProviderConfig>, Vec<String>> {
        let tenant_sections = self.tenant_sections();
        if tenant_sections.is_empty() {
            return Ok(self.legacy_providers());
        }

        let mut errors = vec![];
        let mut legacy: Vec<String> = LEGACY_PROVIDER_KEYS
            .iter()
            .filter(|key| {
                self.config
                    .get("global", key)
                    .is_some_and(|v| !v.trim().is_empty())
            })
            .map(|key| format!("[global] {}", key))
            .collect();
        legacy.extend(self.legacy_sections().iter().map(|s| format!("[{}]", s)));
        if !legacy.is_empty() {
            errors.push(format!(
                "{} cannot be combined with [{}<label>] sections",
                legacy.join(", "),
                TENANT_SECTION_PREFIX
            ));
        }

        let mut providers = vec![];
        for section in tenant_sections {
            let label = section[TENANT_SECTION_PREFIX.len()..].to_string();
            if label.is_empty() {
                errors.push(format!("[{}] requires a label", section));
                continue;
            }
            if label.contains('@') || label.chars().any(|c| c.is_whitespace() || c.is_control()) {
                errors.push(format!(
                    "[{}] label must not contain @ or whitespace",
                    section
                ));
                continue;
            }
            if self
                .config
                .get_map_ref()
                .get(&section)
                .is_some_and(|values| values.contains_key("type"))
            {
                errors.push(format!(
                    "[{}] type is inferred from domain or oidc_issuer_url; remove type",
                    section
                ));
                continue;
            }
            let stanza = match self.tenant_stanza(&section) {
                Ok(stanza) => stanza,
                Err(e) => {
                    errors.push(format!("[{}] {}", section, e));
                    continue;
                }
            };
            let (kind, domain) = match (stanza.domain, stanza.oidc_issuer_url) {
                (Some(domain), None) => {
                    let domain = domain.trim().to_string();
                    if domain.is_empty() {
                        errors.push(format!("[{}] requires a domain", section));
                        continue;
                    }
                    if domain.contains(',') {
                        errors.push(format!(
                            "[{}] domain must be a single domain; Entra aliases are discovered automatically",
                            section
                        ));
                        continue;
                    }
                    if domain.contains(['@', '/', ':']) || domain.chars().any(char::is_whitespace) {
                        errors.push(format!("[{}] requires a domain name", section));
                        continue;
                    }
                    (ProviderKind::Entra, domain)
                }
                (None, Some(url)) => match parse_issuer_url(&url) {
                    Ok(Some(issuer)) => (
                        ProviderKind::Oidc,
                        format!("oidc:{}", oidc_tenant_id(&issuer)),
                    ),
                    Ok(None) => {
                        errors.push(format!("[{}] OIDC issuer URL is empty", section));
                        continue;
                    }
                    Err(error) => {
                        errors.push(format!("[{}] {}", section, error));
                        continue;
                    }
                },
                (Some(_), Some(_)) => {
                    errors.push(format!("[{}] domain and oidc_issuer_url select different protocols; configure exactly one", section));
                    continue;
                }
                (None, None) => {
                    errors.push(format!("[{}] requires domain or oidc_issuer_url", section));
                    continue;
                }
            };
            providers.push(ProviderConfig {
                label,
                section,
                kind,
                domain,
                default: stanza.default,
            });
        }

        if errors.is_empty() {
            Ok(providers)
        } else {
            Err(errors)
        }
    }

    /// The provider serving names without a domain: the only provider, or
    /// the one marked `default = true`.
    pub fn default_provider(&self) -> Option<ProviderConfig> {
        let providers = self.parse_providers().ok()?;
        if providers.len() == 1 {
            return providers.into_iter().next();
        }
        providers.into_iter().find(|p| p.default)
    }

    /// Resolve storage/settings keys and known Entra domain aliases.
    pub fn provider_for_domain(&self, domain: &str) -> Option<ProviderConfig> {
        let providers = self.parse_providers().ok()?;
        let mut matches = providers.into_iter().filter(|p| {
            p.domain.eq_ignore_ascii_case(domain)
                || self
                    .domain_aliases_for(p)
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(domain))
        });
        let provider = matches.next()?;
        matches.next().is_none().then_some(provider)
    }

    /// An explicit final label selects a provider; bare names use the default.
    pub fn provider_for_account(&self, account: &str) -> Option<ProviderConfig> {
        if account.is_empty() || account.starts_with('@') || account.ends_with('@') {
            return None;
        }
        if let Some((name, suffix)) = account.rsplit_once('@') {
            let providers = self.parse_providers().ok()?;
            if let Some(provider) = providers.iter().find(|p| {
                p.section.starts_with(TENANT_SECTION_PREFIX) && p.label.eq_ignore_ascii_case(suffix)
            }) {
                if self.routing_name_conflicts(provider, suffix) {
                    return None;
                }
                if provider.kind == ProviderKind::Entra && name.contains('@') {
                    let (_, domain) = split_username(name)?;
                    if self.provider_for_domain(domain).as_ref() != Some(provider) {
                        return None;
                    }
                }
                provider.upstream_account_name(account)?;
                return Some(provider.clone());
            }
        }
        if let Some((name, domain)) = split_username(account) {
            if name.is_empty() || domain.is_empty() {
                return None;
            }
            if let Some(provider) = self
                .provider_for_domain(domain)
                .filter(|p| p.kind == ProviderKind::Entra)
            {
                return Some(provider);
            }
            // Legacy OIDC configurations accept the issuer's account-name claim.
            return self
                .default_provider()
                .filter(|p| p.kind == ProviderKind::Oidc && p.section == "oidc");
        }
        if account.contains('@') {
            return None;
        }
        self.default_provider()
    }

    pub fn canonical_account_name(&self, account: &str) -> Option<String> {
        let provider = self.provider_for_account(account)?;
        Some(provider.local_account_name(&provider.upstream_account_name(account)?))
    }

    pub(crate) fn provider_for_token(
        &self,
        token: &crate::idprovider::interface::UserToken,
    ) -> Option<ProviderConfig> {
        if let Some(tenant) = token.tenant_id {
            if let Some(provider) = self
                .parse_providers()
                .ok()?
                .into_iter()
                .find(|p| p.oidc_tenant_id(self) == Some(tenant))
            {
                return Some(provider);
            }
        }
        let provider = self
            .provider_for_account(&token.spn)
            .filter(|p| p.kind == ProviderKind::Entra && token.oidc_account_id.is_none())?;
        if let Some(tenant) = token.tenant_id {
            let expected = self.get_tenant_id(&provider.domain)?;
            if !expected.eq_ignore_ascii_case(&tenant.to_string()) {
                return None;
            }
        }
        Some(provider)
    }

    pub fn provider_for_gid(&self, gid: u32) -> Option<ProviderConfig> {
        self.parse_providers().ok()?.into_iter().find(|p| {
            let (min, max) = self.get_idmap_range(&p.domain);
            (min..=max).contains(&gid)
        })
    }

    /// Another Entra provider already bound to `tenant_id`.
    pub fn provider_sharing_tenant(&self, domain: &str, tenant_id: &str) -> Option<ProviderConfig> {
        self.parse_providers().ok()?.into_iter().find(|p| {
            p.kind == ProviderKind::Entra
                && !p.domain.eq_ignore_ascii_case(domain)
                && self
                    .get_tenant_id(&p.domain)
                    .is_some_and(|id| id.eq_ignore_ascii_case(tenant_id))
        })
    }

    /// Discover an alias only when its tenant ID matches a configured Entra provider.
    pub async fn discover_provider_for_domain(&self, alias: &str) -> Option<ProviderConfig> {
        let providers: Vec<_> = self
            .parse_providers()
            .ok()?
            .into_iter()
            .filter(|p| p.kind == ProviderKind::Entra)
            .collect();
        if providers.is_empty() {
            return None;
        }
        let (_, alias_tenant, _) =
            request_federation_provider(DEFAULT_ODC_PROVIDER, alias, self.get_request_timeout())
                .await
                .ok()?;
        let mut tenants = Vec::new();
        for provider in providers {
            let tenant = match self.get_tenant_id(&provider.domain) {
                Some(tenant) => tenant,
                None => {
                    let Ok((_, tenant, _)) = request_federation_provider(
                        &self.get_odc_provider(&provider.domain),
                        &provider.domain,
                        self.get_request_timeout(),
                    )
                    .await
                    else {
                        continue;
                    };
                    tenant
                }
            };
            tenants.push((provider, tenant));
        }
        Self::match_discovered_tenant(tenants, &alias_tenant)
    }

    fn match_discovered_tenant(
        tenants: impl IntoIterator<Item = (ProviderConfig, String)>,
        tenant_id: &str,
    ) -> Option<ProviderConfig> {
        let mut matches = tenants.into_iter().filter_map(|(provider, tenant)| {
            (provider.kind == ProviderKind::Entra && tenant.eq_ignore_ascii_case(tenant_id))
                .then_some(provider)
        });
        let provider = matches.next()?;
        matches.next().is_none().then_some(provider)
    }

    fn routing_name_conflicts(&self, provider: &ProviderConfig, name: &str) -> bool {
        self.parse_providers().is_ok_and(|providers| {
            providers
                .iter()
                .any(|p| p != provider && self.provider_claims_name(p, name))
        })
    }

    fn provider_claims_name(&self, provider: &ProviderConfig, name: &str) -> bool {
        provider.label.eq_ignore_ascii_case(name)
            || provider.domain.eq_ignore_ascii_case(name)
            || self
                .domain_aliases_for(provider)
                .iter()
                .any(|a| a.eq_ignore_ascii_case(name))
    }

    pub(crate) fn routing_name_is_known(&self, name: &str) -> bool {
        self.parse_providers()
            .is_ok_and(|providers| providers.iter().any(|p| self.provider_claims_name(p, name)))
    }

    pub(crate) fn record_domain_alias(&mut self, provider: &ProviderConfig, alias: &str) -> bool {
        if provider.kind != ProviderKind::Entra {
            return false;
        }
        if self.routing_name_conflicts(provider, alias) {
            error!(provider = %provider.label, alias, "Discovered alias conflicts with a configured provider");
            return false;
        }
        let mut aliases = self.domain_aliases_for(provider);
        if !aliases.iter().any(|a| a.eq_ignore_ascii_case(alias)) {
            aliases.push(alias.to_lowercase());
            self.set(&provider.domain, "domain_aliases", &aliases.join(","));
            if let Err(error) = self.write_server_config() {
                error!(?error, "Failed to write the server cache");
            }
        }
        true
    }

    /// Check the provider configuration. The daemon refuses to start when
    /// errors are reported.
    pub fn validate(&self) -> ValidationReport {
        let mut report = ValidationReport::default();
        let providers = match self.parse_providers() {
            Ok(providers) if providers.is_empty() => {
                report.errors.push(format!(
                    "No provider is configured, set [global] domain or add a [{}<label>] section",
                    TENANT_SECTION_PREFIX
                ));
                return report;
            }
            Ok(providers) => providers,
            Err(errors) => {
                report.errors = errors;
                return report;
            }
        };
        for (section, values) in self.config.get_map_ref() {
            if values.contains_key("domain_aliases") {
                report.errors.push(format!(
                    "[{}] domain_aliases is internal discovery metadata; remove it from administrator configuration",
                    section
                ));
            }
        }

        if self.tenant_sections().is_empty() {
            self.validate_legacy(&mut report);
        } else {
            self.validate_tenants(&providers, &mut report);
        }
        self.validate_id_ranges(&providers, &mut report);
        report
    }

    fn validate_legacy(&self, report: &mut ValidationReport) {
        let domains = self.legacy_entra_domains();
        if self.get_oidc_issuer_url(None).is_some() {
            if let Some(domain) = domains.first() {
                report.warnings.push(format!(
                    "Both oidc_issuer_url and Entra ID domain '{}' are configured, the domain is ignored",
                    domain
                ));
            }
        } else if domains.len() > 1 {
            report.warnings.push(format!(
                "Only one domain is supported in [global], using '{}' and ignoring: {}. Configure a [{}<label>] section per tenant instead",
                domains[0],
                domains[1..].join(", "),
                TENANT_SECTION_PREFIX
            ));
        }
    }

    fn validate_tenants(&self, providers: &[ProviderConfig], report: &mut ValidationReport) {
        let mut names: BTreeMap<String, &str> = BTreeMap::new();
        let mut tenant_ids: BTreeMap<String, &str> = BTreeMap::new();
        let mut issuers: BTreeMap<String, &str> = BTreeMap::new();
        for p in providers {
            let section = p.section.as_str();
            let aliases = self.domain_aliases_for(p);
            for name in [p.label.clone(), p.domain.clone()]
                .into_iter()
                .chain(aliases)
            {
                match names.insert(name.to_lowercase(), section) {
                    Some(other) if other != section => report.errors.push(format!(
                        "[{}] and [{}] both claim the domain {}",
                        other, section, name
                    )),
                    _ => {}
                }
            }

            if providers.len() > 1 && self.config.get(section, "idmap_range").is_none() {
                report.errors.push(format!(
                    "[{}] requires an idmap_range when several tenants are configured",
                    section
                ));
            }
            if let Some(val) = self.config.get(section, "idmap_range") {
                if parse_range(&val).is_none() {
                    report
                        .errors
                        .push(format!("[{}] idmap_range = {} is invalid", section, val));
                }
            }

            if p.kind == ProviderKind::Entra {
                if let Some(tenant_id) = self.get_tenant_id(&p.domain) {
                    if let Some(other) = tenant_ids.insert(tenant_id.to_lowercase(), section) {
                        report.errors.push(format!(
                            "[{}] and [{}] share the tenant {}; configure one provider per Entra tenant",
                            other, section, tenant_id
                        ));
                    }
                }
            }
            if p.kind == ProviderKind::Oidc
                && p.get_app_id(self).is_none_or(|id| id.trim().is_empty())
            {
                report
                    .errors
                    .push(format!("[{}] OIDC provider requires app_id", section));
            }

            if let Some(issuer) = self
                .config
                .get(section, "oidc_issuer_url")
                .and_then(|url| parse_issuer_url(&url).ok().flatten())
            {
                if let Some(other) =
                    issuers.insert(issuer.trim_end_matches('/').to_string(), section)
                {
                    report.errors.push(format!(
                        "[{}] and [{}] share the OIDC issuer {}",
                        other, section, issuer
                    ));
                }
            }
        }

        let defaults: Vec<&str> = providers
            .iter()
            .filter(|p| p.default)
            .map(|p| p.section.as_str())
            .collect();
        if defaults.len() > 1 {
            report.errors.push(format!(
                "Only one tenant can set default = true, found: {}",
                defaults.join(", ")
            ));
        } else if defaults.is_empty() && providers.len() > 1 {
            report
                .errors
                .push("One tenant must set default = true when several are configured".to_string());
        }

        if providers.len() > 1 && self.get_id_attr_map() == IdAttr::Rfc2307 {
            report
                .errors
                .push("id_attr_map = rfc2307 supports a single tenant only".to_string());
        }
        let mut cn_home_prefixes = Vec::new();
        for provider in providers {
            if !self.provider_uses_cn_home_name(provider) {
                continue;
            }
            let prefix = provider.get_home_prefix(self);
            match resolve_home_prefix(Path::new(&prefix)) {
                Ok(path) => cn_home_prefixes.push((provider, path)),
                Err(error) => report.errors.push(format!(
                    "[{}] cannot resolve home_prefix {:?}: {}",
                    provider.section, prefix, error
                )),
            }
        }
        for (index, (provider, prefix)) in cn_home_prefixes.iter().enumerate() {
            for (other, other_prefix) in &cn_home_prefixes[index + 1..] {
                if prefix == other_prefix {
                    report.errors.push(format!(
                        "[{}] and [{}] require distinct home_prefix values for CN home names",
                        provider.section, other.section
                    ));
                }
            }
        }
    }

    fn provider_uses_cn_home_name(&self, provider: &ProviderConfig) -> bool {
        let home_attr = provider.get_home_attr(self);
        let home_alias = provider.get_home_alias(self);
        let oidc_strips_spn_suffix = !provider.scopes_oidc_accounts()
            && provider.kind == ProviderKind::Oidc
            && provider.get_oidc_account_id_strip_at_suffix(self);

        home_attr == HomeAttr::Cn
            || home_alias == Some(HomeAttr::Cn)
            || (oidc_strips_spn_suffix
                && (home_attr == HomeAttr::Spn || home_alias == Some(HomeAttr::Spn)))
    }

    fn validate_id_ranges(&self, providers: &[ProviderConfig], report: &mut ValidationReport) {
        let ranges: Vec<(String, (u32, u32))> = providers
            .iter()
            .map(|p| (p.domain.clone(), self.get_idmap_range(&p.domain)))
            .collect();

        let subid_range = self.get_subid_range();
        for (idx, (name, range)) in ranges.iter().enumerate() {
            if ranges_overlap(*range, subid_range) {
                report.errors.push(format!(
                    "idmap_range ({}-{}) of {} overlaps with subid_range ({}-{})",
                    range.0, range.1, name, subid_range.0, subid_range.1
                ));
            }
            for (other_name, other_range) in &ranges[idx + 1..] {
                if ranges_overlap(*range, *other_range) {
                    report.errors.push(format!(
                        "idmap_range ({}-{}) of {} overlaps with idmap_range ({}-{}) of {}",
                        range.0, range.1, name, other_range.0, other_range.1, other_name
                    ));
                }
            }
        }
    }

    /// Storage/settings keys of the providers served by this configuration.
    pub fn get_configured_domains(&self) -> Vec<String> {
        self.parse_providers()
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.domain)
            .collect()
    }

    pub fn get_configured_entra_domains(&self) -> Vec<String> {
        self.parse_providers()
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.kind == ProviderKind::Entra)
            .map(|p| p.domain)
            .collect()
    }

    /// The domain of the default provider when it is an Entra ID tenant.
    /// Legacy configs use the first configured domain.
    pub fn get_configured_entra_domain(&self) -> Option<String> {
        self.default_provider()
            .filter(|p| p.kind == ProviderKind::Entra)
            .map(|p| p.domain)
    }

    pub fn get_config_file(&self) -> String {
        self.filename.clone()
    }

    pub fn get_effective_config_paths(&self) -> &[PathBuf] {
        &self.effective_config_paths
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

    pub fn get_password_only_remote_services_deny_list(&self) -> Vec<String> {
        match self
            .config
            .get("global", "password_only_remote_services_deny_list")
        {
            Some(val) => val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            None => DEFAULT_PASSWORD_ONLY_REMOTE_SERVICES_DENY_LIST
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    pub fn get_intune_device_id(&self, domain: &str) -> Option<String> {
        let domain = self
            .get_primary_domain_from_alias_simple(domain)
            .unwrap_or(domain.to_string());
        self.domain_value(&domain, "intune_device_id")
    }

    /// Entra sign-in aliases discovered and persisted by the daemon.
    fn domain_aliases_for(&self, provider: &ProviderConfig) -> Vec<String> {
        if provider.kind != ProviderKind::Entra {
            return Vec::new();
        }
        let mut aliases: Vec<_> = self
            .cache
            .get(&provider.domain, "domain_aliases")
            .iter()
            .flat_map(|value| split_list(value))
            .map(|alias| alias.to_lowercase())
            .collect();
        aliases.sort();
        aliases.dedup();
        aliases
    }

    pub fn get_primary_domain_from_alias_simple(&self, alias: &str) -> Option<String> {
        self.provider_for_domain(alias).map(|p| p.domain)
    }

    pub async fn domains_are_aliases(&self, domain1: &str, domain2: &str) -> bool {
        let first = match self.provider_for_domain(domain1) {
            Some(provider) => Some(provider),
            None => self.discover_provider_for_domain(domain1).await,
        };
        let second = match self.provider_for_domain(domain2) {
            Some(provider) => Some(provider),
            None => self.discover_provider_for_domain(domain2).await,
        };
        matches!((first, second), (Some(a), Some(b)) if a.domain == b.domain)
    }

    /// Convert a login name to a UPN, or `None` if it cannot be a directory user
    /// (empty, or a known local-only name). Callers treat `None` as user-unknown
    /// and must not look it up against Entra. See himmelblau-idm/himmelblau#1392.
    pub fn map_name_to_upn(&self, account_id: &str) -> Option<String> {
        self.map_name_to_upn_impl(account_id, "/etc/passwd")
    }

    /// Inner impl with an injectable passwd path for hermetic unit tests.
    fn map_name_to_upn_impl(&self, account_id: &str, passwd_path: &str) -> Option<String> {
        let name_mapping_script = self.get_name_mapping_script();
        let cn_name_mapping = self.get_cn_name_mapping();
        let domain = self.get_configured_entra_domain();

        if account_id.trim().is_empty() {
            return None;
        }

        // Make sure this account_id isn't a local user
        let mut contents = vec![];
        if let Ok(mut file) = File::open(passwd_path) {
            let _ = file.read_to_end(&mut contents);
        }
        let local_users = parse_etc_passwd(contents.as_slice()).unwrap_or_default();
        if local_users
            .into_iter()
            .map(|u| u.name.to_string())
            .collect::<Vec<String>>()
            .contains(&account_id.to_string())
        {
            return Some(account_id.to_string());
        }

        // Local-only names probed by systemd/GDM at boot; never directory users.
        if NSS_IGNORE_EXACT.contains(&account_id)
            || NSS_IGNORE_PREFIX
                .iter()
                .any(|prefix| account_id.starts_with(prefix))
        {
            return None;
        }

        // Empty script output signals "not a directory user" -> None.
        if !account_id.contains('@') {
            if let Some(name_mapping_script) = &name_mapping_script {
                let name_cache = MappedNameCache::new(MAPPED_NAME_CACHE, &Mode::ReadWrite).ok();

                let output = Command::new(name_mapping_script).arg(account_id).output();

                match output {
                    Ok(output) => {
                        if output.status.success() {
                            let upn = String::from_utf8_lossy(&output.stdout).trim().to_string();
                            if upn.is_empty() {
                                return None;
                            }
                            if let Some(name_cache) = &name_cache {
                                // Failing to insert a name map is not a critical failure.
                                if let Err(e) = name_cache.insert_mapping(&upn, account_id) {
                                    error!(
                                        "Failed to cache name mapping for {} as {}: {}",
                                        account_id, upn, e
                                    );
                                }
                            }
                            return Some(upn);
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
        if cn_name_mapping && !account_id.contains('@') {
            if let Some(domain) = domain {
                return Some(format!("{}@{}", account_id, domain));
            }
        }
        Some(
            self.canonical_account_name(account_id)
                .unwrap_or_else(|| account_id.to_string()),
        )
    }

    /// This function maps a UPN to a mapped name. If a mapping script is
    /// configured, it will use the mapping cache to obtain the mapped name.
    /// If a mapping script is not configured, but upn to cn mapping is
    /// enabled, it will map the upn to the cn. Otherwise it will return the
    /// name unchanged.
    pub fn map_upn_to_name(&self, upn: &str) -> String {
        if let Some((name, domain)) = split_username(upn) {
            let primary = self
                .get_configured_entra_domain()
                .unwrap_or_default()
                .to_lowercase();
            let res;
            if self.get_name_mapping_script().is_some() {
                if let Ok(name_mapping_cache) =
                    MappedNameCache::new(MAPPED_NAME_CACHE, &Mode::ReadOnly)
                {
                    res = name_mapping_cache.get_mapped_name(upn);
                } else {
                    res = upn.to_string();
                }
            // Only perform cn name mapping for the primary domain
            } else if self.get_cn_name_mapping() && domain.eq_ignore_ascii_case(&primary) {
                res = name.to_string();
            } else {
                res = upn.to_string();
            }
            res
        } else {
            // This isn't a upn, just return the input unchanged
            upn.to_string()
        }
    }

    pub fn get_sudo_groups(&self) -> Vec<String> {
        let mut sudo_groups: Vec<String> = vec![];
        for section in self.config.sections() {
            sudo_groups.extend(match self.config.get(&section, "sudo_groups") {
                Some(val) => val.split(',').map(|s| s.trim().to_string()).collect(),
                None => vec![],
            });
        }
        sudo_groups
    }

    pub fn get_oidc_issuer_url(&self, domain: Option<&str>) -> Option<String> {
        let val = self.domain_or_global_value(domain, "oidc_issuer_url")?;
        parse_issuer_url(&val).unwrap_or_else(|e| {
            error!(error = %e, "Ignoring oidc_issuer_url");
            None
        })
    }

    pub fn pam_allow_groups_for_provider(&self, provider: &ProviderConfig) -> Vec<String> {
        if self.tenant_sections().is_empty() {
            return self.get_pam_allow_groups();
        }
        self.domain_or_global_value(Some(&provider.domain), "pam_allow_groups")
            .map(|v| split_list(&v).collect())
            .unwrap_or_default()
    }

    pub fn sudo_groups_for_provider(&self, provider: &ProviderConfig) -> Vec<String> {
        if self.tenant_sections().is_empty() {
            return self.get_sudo_groups();
        }
        self.domain_or_global_value(Some(&provider.domain), "sudo_groups")
            .map(|v| split_list(&v).collect())
            .unwrap_or_default()
    }
}

// Generated getter methods from XML parameter definitions.
include!(concat!(env!("OUT_DIR"), "/config_gen.rs"));

impl HimmelblauConfig {
    pub fn get_ip_versions(&self) -> Vec<IpVersion> {
        match self.get_ip_version() {
            IpVersionSelection::Ipv4Only => vec![IpVersion::V4],
            IpVersionSelection::Ipv6Only => vec![IpVersion::V6],
            IpVersionSelection::Both => vec![IpVersion::V4, IpVersion::V6],
        }
    }
}

impl fmt::Debug for HimmelblauConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HimmelblauConfig")
            .field("config", &self.config)
            .field("cache", &self.cache)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    // Helper function to create temporary configuration files
    fn create_temp_config(contents: &str) -> String {
        let file_path = format!("/tmp/himmelblau_test_config_{}.ini", uuid::Uuid::new_v4());
        fs::write(&file_path, contents).expect("Failed to write temporary config file");
        file_path
    }

    // Throwaway passwd file so map_name_to_upn_impl can be tested hermetically.
    fn create_temp_passwd(contents: &str) -> String {
        let file_path = format!("/tmp/himmelblau_test_passwd_{}", uuid::Uuid::new_v4());
        fs::write(&file_path, contents).expect("Failed to write temporary passwd file");
        file_path
    }

    // Helper function to create an empty config (to test defaults without system config interference)
    fn create_empty_config() -> HimmelblauConfig {
        let temp_file = create_temp_config("");
        HimmelblauConfig::new(Some(&temp_file)).unwrap()
    }

    #[cfg(unix)]
    fn write_temp_config(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).expect("Failed to create config directory");
        fs::write(path, contents).expect("Failed to write temporary config file");
    }

    #[cfg(unix)]
    #[test]
    fn test_load_config_hierarchy_precedence_and_masking() {
        let root = env::temp_dir().join(format!(
            "himmelblau_test_config_hierarchy_{}",
            uuid::Uuid::new_v4()
        ));
        let vendor = root.join("usr/lib/himmelblau/himmelblau.conf");
        let runtime = root.join("run/himmelblau/himmelblau.conf");
        let local = root.join("etc/himmelblau/himmelblau.conf");

        write_temp_config(
            &vendor,
            "[global]\nvalue = vendor-main\nmain_only = ignored\n",
        );
        write_temp_config(&runtime, "[global]\nvalue = runtime-main\n");

        let mut main_config = Ini::new();
        let effective_config_paths = load_config_hierarchy(
            &mut main_config,
            &[vendor.clone(), runtime.clone(), local.clone()],
        )
        .unwrap();
        assert_eq!(effective_config_paths, vec![runtime.clone()]);
        assert_eq!(
            main_config.get("global", "value").as_deref(),
            Some("runtime-main")
        );
        assert_eq!(main_config.get("global", "main_only"), None);

        write_temp_config(&local, "");

        write_temp_config(
            &drop_in_dir(&vendor).join("10-masked.conf"),
            "[global]\nmasked = no\n",
        );
        let masked_drop_in = drop_in_dir(&local).join("10-masked.conf");
        fs::create_dir_all(masked_drop_in.parent().unwrap())
            .expect("Failed to create local drop-in directory");
        symlink("/dev/null", masked_drop_in).expect("Failed to create drop-in mask");

        write_temp_config(
            &drop_in_dir(&local).join("20-local.conf"),
            "[global]\nvalue = local-drop-in\nlocal_only = retained\n",
        );
        write_temp_config(
            &drop_in_dir(&vendor).join("30-late.conf"),
            "[global]\nvalue = vendor-late\n",
        );
        write_temp_config(
            &drop_in_dir(&runtime).join("30-late.conf"),
            "[global]\nvalue = runtime-late\n",
        );
        let linked_drop_in = root.join("linked.conf");
        write_temp_config(&linked_drop_in, "[global]\nlinked = loaded\n");
        symlink(linked_drop_in, drop_in_dir(&vendor).join("35-linked.conf"))
            .expect("Failed to create regular-file drop-in symlink");

        let directory_target = root.join("directory-target");
        fs::create_dir_all(&directory_target).expect("Failed to create symlink target directory");
        symlink(
            directory_target,
            drop_in_dir(&vendor).join("36-directory.conf"),
        )
        .expect("Failed to create directory drop-in symlink");
        symlink(
            root.join("missing.conf"),
            drop_in_dir(&vendor).join("37-broken.conf"),
        )
        .expect("Failed to create broken drop-in symlink");

        write_temp_config(
            &drop_in_dir(&local).join("40-ignored.ini"),
            "[global]\nvalue = wrong-suffix\n",
        );
        write_temp_config(
            &drop_in_dir(&local).join("50-nested.conf.d/60-ignored.conf"),
            "[global]\nvalue = nested\n",
        );

        let mut config = Ini::new();
        let _effective_config_paths =
            load_config_hierarchy(&mut config, &[vendor, runtime, local]).unwrap();

        assert_eq!(
            config.get("global", "value").as_deref(),
            Some("runtime-late")
        );
        assert_eq!(
            config.get("global", "local_only").as_deref(),
            Some("retained")
        );
        assert_eq!(config.get("global", "main_only"), None);
        assert_eq!(config.get("global", "masked"), None);
        assert_eq!(config.get("global", "linked").as_deref(), Some("loaded"));

        fs::remove_dir_all(root).expect("Failed to remove config hierarchy");
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_connection_timeout(), 30);
    }

    #[test]
    fn test_get_request_timeout() {
        let config_data = r#"
        [global]
        request_timeout = 15
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_request_timeout(), 15);
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_request_timeout(), DEFAULT_REQUEST_TIMEOUT);
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
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_idmap_range("any.com"), DEFAULT_IDMAP_RANGE);
    }

    #[test]
    fn test_get_subid_range() {
        let config_data = r#"
        [global]
        subid_range = 100000-999999
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_subid_range(), (100000, 999999));

        // When not configured, use the default range
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_subid_range(), DEFAULT_SUBID_RANGE);
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
        let config_empty = create_empty_config();
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
    fn test_get_join_type() {
        let config_data = r#"
        [global]
        join_type = register
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_join_type(), JoinType::Register);
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_join_type(), JoinType::Join);

        let config_data = r#"
        [global]
        join_type = join
        "#;
        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_join_type(), JoinType::Join);
    }

    #[test]
    fn test_get_ip_version() {
        let config_data = r#"
        [global]
        ip_version = ipv4-only
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_ip_version(), IpVersionSelection::Ipv4Only);
        assert_eq!(config.get_ip_versions(), vec![IpVersion::V4]);

        let config_data = r#"
        [global]
        ip_version = ipv6-only
        "#;
        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_ip_version(), IpVersionSelection::Ipv6Only);
        assert_eq!(config.get_ip_versions(), vec![IpVersion::V6]);

        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_ip_version(), IpVersionSelection::Both);
        assert_eq!(config_empty.get_initgroups_mode(), InitgroupsMode::Named);
        assert_eq!(
            config_empty.get_ip_versions(),
            vec![IpVersion::V4, IpVersion::V6]
        );
    }

    #[test]
    fn test_get_initgroups_mode() {
        let named = r#"
        [global]
        initgroups_mode = named
        "#;
        let temp_file = create_temp_config(named);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_initgroups_mode(), InitgroupsMode::Named);

        let full = r#"
        [global]
        initgroups_mode = full
        "#;
        let temp_file = create_temp_config(full);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_initgroups_mode(), InitgroupsMode::Full);

        let invalid = r#"
        [global]
        initgroups_mode = debug
        "#;
        let temp_file = create_temp_config(invalid);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_initgroups_mode(), InitgroupsMode::Named);
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
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_apply_policy(), false);
    }

    #[test]
    fn test_get_intune_auth_resource() {
        let config_data = r#"
        [global]
        intune_auth_resource = true
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_intune_auth_resource(), true);
        assert_eq!(config.get_apply_policy(), false);
        assert_eq!(config.get_use_intune_auth_resource(), true);
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_intune_auth_resource(), false);
        assert_eq!(config_empty.get_use_intune_auth_resource(), false);

        let apply_policy_data = r#"
        [global]
        apply_policy = true
        "#;

        let apply_policy_file = create_temp_config(apply_policy_data);
        let apply_policy = HimmelblauConfig::new(Some(&apply_policy_file)).unwrap();

        assert_eq!(apply_policy.get_intune_auth_resource(), false);
        assert_eq!(apply_policy.get_use_intune_auth_resource(), true);
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
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

        let config_empty = create_empty_config();
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

        assert_eq!(config.get_configured_domains(), vec!["example.com"]);
    }

    #[test]
    fn test_get_configured_entra_domain() {
        // The first entry of `domains` is used
        let temp_file = create_temp_config(
            r#"
        [global]
        domains = example.com,test.com

        [test.com]
        [example.com]
        "#,
        );
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(
            config.get_configured_entra_domain(),
            Some("example.com".to_string())
        );

        // The oidc section is never an Entra domain
        let temp_file = create_temp_config(
            r#"
        [global]
        oidc_issuer_url = https://issuer.example.com

        [oidc]
        "#,
        );
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_configured_entra_domain(), None);

        // A blank domain option is not a domain
        let temp_file = create_temp_config(
            r#"
        [global]
        domain =
        oidc_issuer_url = https://issuer.example.com

        [oidc]
        "#,
        );
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_configured_entra_domain(), None);

        // Only the served domain is returned.
        let temp_file = create_temp_config(
            r#"
        [global]
        domains = example.com,test.com
        "#,
        );
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_configured_entra_domains(), vec!["example.com"]);

        // No configuration at all
        let temp_file = create_temp_config("[global]\n");
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_configured_entra_domain(), None);
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
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_enable_hello(), DEFAULT_HELLO_ENABLED);
    }

    #[test]
    fn test_get_enable_passwordless() {
        let config_data = r#"
        [global]
        enable_passwordless = false
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_enable_passwordless(), false);

        // Test that default is true (backward compat)
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_enable_passwordless(), true);
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_cn_name_mapping(), CN_NAME_MAPPING);
    }

    #[test]
    fn test_get_authority_host() {
        let config_data = r#"
        [example.com]
        authority_host = login.suse.com
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_authority_host("example.com"), "login.suse.com");
        let config_empty = create_empty_config();
        assert_eq!(
            config_empty.get_authority_host("example.com"),
            DEFAULT_AUTHORITY_HOST
        );
    }

    #[test]
    fn test_get_authority_host_for_account_resolves_aliases() {
        let config = load_with_cache(
            "[global]\ndomains = example.com\n[example.com]\nauthority_host = login.microsoftonline.us\n",
            "[example.com]\ndomain_aliases = first.example.com, ALIAS.example.com  , third.example.com\n",
        );
        assert_eq!(
            config.get_authority_host_for_account("alice@alias.example.com"),
            Some("login.microsoftonline.us".to_string())
        );
        assert_eq!(
            config.get_authority_host_for_account("alice"),
            Some("login.microsoftonline.us".to_string())
        );
    }

    #[test]
    fn test_get_authority_host_for_oidc_accounts_uses_issuer() {
        let temp_file = create_temp_config(
            "[global]\noidc_issuer_url = https://id.example.org/realms/example/.well-known/openid-configuration\n",
        );
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        for account in ["alice", "alice@unrelated.example.com"] {
            assert_eq!(
                config.get_authority_host_for_account(account),
                Some("id.example.org".to_string())
            );
        }
    }

    #[test]
    fn test_broker_environment_preserves_oidc_ports() {
        for (issuer, environment, host) in [
            (
                "https://id.example.org:8443/realm",
                "id.example.org:8443",
                "id.example.org",
            ),
            (
                "https://id.example.org/realm",
                "id.example.org",
                "id.example.org",
            ),
            ("https://[::1]:8443/realm", "[::1]:8443", "[::1]"),
        ] {
            let contents = format!("[global]\noidc_issuer_url = {issuer}\n");
            let temp_file = create_temp_config(&contents);
            let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
            for account in ["alice", "alice@other.example"] {
                assert_eq!(
                    config.get_broker_environment_for_account(account),
                    Some(environment.to_string())
                );
                assert_eq!(
                    config.get_authority_host_for_account(account),
                    Some(host.to_string())
                );
            }
        }
    }

    #[test]
    fn test_broker_environment_preserves_entra_alias_authority() {
        let config = load_with_cache(
            "[global]\ndomains = example.com\n[example.com]\nauthority_host = login.microsoftonline.us\n",
            "[example.com]\ndomain_aliases = alias.example.com\n",
        );
        assert_eq!(
            config.get_broker_environment_for_account("alice@alias.example.com"),
            Some("login.microsoftonline.us".to_string())
        );
        assert_eq!(
            config.get_broker_environment_for_account("alice"),
            Some("login.microsoftonline.us".to_string())
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
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_graph_url("example.com"), None);
    }

    #[test]
    fn test_get_oidc_device_authorization_endpoint() {
        let config_data = r#"
        [global]
        oidc_device_authorization_endpoint = https://idp.example.com/device/code
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(
            config.get_oidc_device_authorization_endpoint(None),
            Some("https://idp.example.com/device/code".to_string())
        );

        let config_empty = create_empty_config();
        assert_eq!(
            config_empty.get_oidc_device_authorization_endpoint(None),
            None
        );
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
        let config_empty = create_empty_config();
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

        let config_missing = create_empty_config();
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
        let config_missing = create_empty_config();
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
        let config_missing = create_empty_config();
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
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_local_groups(), Vec::<String>::new());
    }

    #[test]
    fn test_get_local_groups_reconcile_interval() {
        let config_data = r#"
        [global]
        local_groups_reconcile_interval = 0
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_local_groups_reconcile_interval(), 0);
        let config_empty = create_empty_config();
        assert_eq!(
            config_empty.get_local_groups_reconcile_interval(),
            DEFAULT_LOCAL_GROUPS_RECONCILE_INTERVAL
        );
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
        let config_missing = create_empty_config();
        assert_eq!(config_missing.get_logon_script(), None);
    }

    #[test]
    fn test_get_logon_script_timeout() {
        let config_data = r#"
        [global]
        logon_script_timeout = 120
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_logon_script_timeout(), 120);
        let config_empty = create_empty_config();
        assert_eq!(
            config_empty.get_logon_script_timeout(),
            DEFAULT_LOGON_SCRIPT_TIMEOUT
        );
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
        let config_missing = create_empty_config();
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
        let config_empty = create_empty_config();
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
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_logon_token_app_id("example.com"), None);
    }

    #[test]
    fn test_get_mfa_method() {
        let config_data = r#"
        [global]
        mfa_method = TwoWayVoiceMobile
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        // Test when MFA method is set
        assert_eq!(
            config.get_mfa_method(),
            Some("TwoWayVoiceMobile".to_string())
        );

        // Test when config is missing (should return None)
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_mfa_method(), None);

        // Test with different MFA method
        let config_data_sms = r#"
        [global]
        mfa_method = OneWaySMS
        "#;
        let temp_file_sms = create_temp_config(config_data_sms);
        let config_sms = HimmelblauConfig::new(Some(&temp_file_sms)).unwrap();
        assert_eq!(config_sms.get_mfa_method(), Some("OneWaySMS".to_string()));
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

        let config_missing = create_empty_config();
        assert_eq!(config_missing.get_name_mapping_script(), None);
    }

    const PASSWD_MINIMAL: &str = "root:x:0:0:root:/root:/bin/bash\n";

    #[test]
    fn test_map_name_to_upn_script_execution_success() {
        let config = HimmelblauConfig::new(Some(&create_temp_config(
            r#"
        [global]
        name_mapping_script = ../../scripts/test_script_echo.sh
        domains = example.com
        "#,
        )))
        .unwrap();
        let passwd = create_temp_passwd(PASSWD_MINIMAL);
        assert_eq!(
            config.map_name_to_upn_impl("user", &passwd),
            Some("user".to_string())
        );
    }

    #[test]
    fn test_map_name_to_upn_local_user() {
        let config = HimmelblauConfig::new(Some(&create_temp_config(
            r#"
        [global]
        domains = example.com
        "#,
        )))
        .unwrap();
        let passwd = create_temp_passwd(&format!(
            "{}localuser:x:1000:1000::/home/localuser:/bin/bash\n",
            PASSWD_MINIMAL
        ));
        assert_eq!(
            config.map_name_to_upn_impl("localuser", &passwd),
            Some("localuser".to_string())
        );
    }

    #[test]
    fn test_map_name_to_upn_local_user_wins_over_ignore_list() {
        let config = HimmelblauConfig::new(Some(&create_temp_config(
            r#"
        [global]
        domains = example.com
        "#,
        )))
        .unwrap();
        let passwd = create_temp_passwd(&format!(
            "{}systemd-coredump:x:999:999::/run/systemd:/usr/sbin/nologin\n",
            PASSWD_MINIMAL
        ));
        assert_eq!(
            config.map_name_to_upn_impl("systemd-coredump", &passwd),
            Some("systemd-coredump".to_string())
        );
    }

    #[test]
    fn test_map_name_to_upn_add_domain() {
        let config = HimmelblauConfig::new(Some(&create_temp_config(
            r#"
        [global]
        cn_to_upn_mapping = true
        domains = example.com
        "#,
        )))
        .unwrap();
        let passwd = create_temp_passwd(PASSWD_MINIMAL);
        assert_eq!(
            config.map_name_to_upn_impl("user", &passwd),
            Some("user@example.com".to_string())
        );
    }

    #[test]
    fn test_map_name_to_upn_empty_is_none() {
        let config = HimmelblauConfig::new(Some(&create_temp_config(
            r#"
        [global]
        domains = example.com
        "#,
        )))
        .unwrap();
        let passwd = create_temp_passwd(PASSWD_MINIMAL);
        assert_eq!(config.map_name_to_upn_impl("", &passwd), None);
        assert_eq!(config.map_name_to_upn_impl("   ", &passwd), None);
    }

    #[test]
    fn test_map_name_to_upn_ignored_names_are_none() {
        let config = HimmelblauConfig::new(Some(&create_temp_config(
            r#"
        [global]
        domains = example.com
        "#,
        )))
        .unwrap();
        let passwd = create_temp_passwd(PASSWD_MINIMAL);
        for name in [
            "gdm",
            "sssd",
            "systemd-coredump",
            "gnome-initial-setup",
            "gdm-greeter",
            "gdm-greeter-2",
            "gdm-greeter-9",
            "pam_unix_non_existent",
            "pam_unix_non_existent:",
        ] {
            assert_eq!(
                config.map_name_to_upn_impl(name, &passwd),
                None,
                "{name} should be None"
            );
        }
    }

    #[test]
    fn test_map_name_to_upn_prefix_does_not_overmatch() {
        // A real user whose name merely starts with "gdm" must NOT be ignored.
        let config = HimmelblauConfig::new(Some(&create_temp_config(
            r#"
        [global]
        domains = example.com
        "#,
        )))
        .unwrap();
        let passwd = create_temp_passwd(PASSWD_MINIMAL);
        assert_eq!(
            config.map_name_to_upn_impl("gdmitrij.popov", &passwd),
            Some("gdmitrij.popov@example.com".to_string())
        );
    }

    #[test]
    fn test_map_name_to_upn_no_mapping() {
        let config = HimmelblauConfig::new(Some(&create_temp_config(
            r#"
        [global]
        "#,
        )))
        .unwrap();
        let passwd = create_temp_passwd(PASSWD_MINIMAL);
        assert_eq!(
            config.map_name_to_upn_impl("user", &passwd),
            Some("user".to_string())
        );
    }

    #[test]
    fn test_get_local_sudo_group() {
        let config_data = r#"
        [global]
        local_sudo_group = wheel
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let group = config.get_local_sudo_group();

        assert_eq!(group, "wheel");

        let empty_config = create_empty_config();

        let default_group = empty_config.get_local_sudo_group();

        assert_eq!(default_group, "sudo")
    }

    #[test]
    fn test_get_sudo_groups() {
        let config_data = r#"
        [example.com]
        sudo_groups = 2eb4e6a2-f55d-4cf4-8e62-978f9f4a828d,f791d7c2-66cd-4f67-a195-72c6faf3c3b5

        [global]
        sudo_groups = 825d1f7e-c4cd-4fc2-aeeb-1f92357f8da6,0149b437-fbaa-4419-bf46-f9a9f9a3438c
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let mut groups = config.get_sudo_groups();
        groups.sort();
        let mut expected_groups: Vec<String> = vec![
            "825d1f7e-c4cd-4fc2-aeeb-1f92357f8da6".to_string(),
            "0149b437-fbaa-4419-bf46-f9a9f9a3438c".to_string(),
            "2eb4e6a2-f55d-4cf4-8e62-978f9f4a828d".to_string(),
            "f791d7c2-66cd-4f67-a195-72c6faf3c3b5".to_string(),
        ];
        expected_groups.sort();

        assert_eq!(groups, expected_groups);
    }

    #[test]
    fn test_user_map_file() {
        let config_data = r#"
        [global]
        "#;
        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_user_map_file(), DEFAULT_USER_MAP_FILE);

        let config_data = r#"
        [global]
        user_map_file = /path/to/user_map
        "#;
        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_user_map_file(), "/path/to/user_map");
    }

    #[test]
    fn test_get_offline_breakglass_enabled() {
        // Explicitly disabled
        let config_data = r#"
        [offline_breakglass]
        enabled = false
        "#;
        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_offline_breakglass_enabled(), false);

        // Explicitly enabled
        let config_data = r#"
        [offline_breakglass]
        enabled = true
        "#;
        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_offline_breakglass_enabled(), true);

        // Missing value → default (false)
        let config_data = r#"
        [offline_breakglass]
        "#;
        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_offline_breakglass_enabled(), false);
    }

    #[test]
    fn test_get_offline_breakglass_ttl() {
        // TTL with hours
        let config_data = r#"
        [offline_breakglass]
        ttl = 2h
        "#;
        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_offline_breakglass_ttl(), 7200);

        // TTL with minutes
        let config_data = r#"
        [offline_breakglass]
        ttl = 30m
        "#;
        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(config.get_offline_breakglass_ttl(), 1800);

        // Invalid TTL → fallback to default
        let config_data = r#"
        [offline_breakglass]
        ttl = nonsense
        "#;
        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(
            config.get_offline_breakglass_ttl(),
            DEFAULT_OFFLINE_BREAKGLASS_TTL
        );

        // Missing → default
        let config_data = r#"
        [offline_breakglass]
        "#;
        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();
        assert_eq!(
            config.get_offline_breakglass_ttl(),
            DEFAULT_OFFLINE_BREAKGLASS_TTL
        );
    }

    #[test]
    fn test_get_password_only_remote_services_deny_list_comma_separated() {
        let config_data = r#"
        [global]
        password_only_remote_services_deny_list = ssh,telnet,ftp
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let result = config.get_password_only_remote_services_deny_list();
        assert_eq!(result, vec!["ssh", "telnet", "ftp"]);
    }

    #[test]
    fn test_get_password_only_remote_services_deny_list_whitespace_trimming() {
        let config_data = r#"
        [global]
        password_only_remote_services_deny_list = ssh , telnet,  ftp  ,vnc
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let result = config.get_password_only_remote_services_deny_list();
        assert_eq!(result, vec!["ssh", "telnet", "ftp", "vnc"]);
    }

    #[test]
    fn test_get_password_only_remote_services_deny_list_empty_string() {
        let config_data = r#"
        [global]
        password_only_remote_services_deny_list =
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let result = config.get_password_only_remote_services_deny_list();
        // Empty string should be filtered out to prevent matching all services
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_get_password_only_remote_services_deny_list_default_value() {
        let config_data = r#"
        [global]
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let result = config.get_password_only_remote_services_deny_list();
        // Should return the default list parsed from DEFAULT_PASSWORD_ONLY_REMOTE_SERVICES_DENY_LIST
        let expected: Vec<String> = DEFAULT_PASSWORD_ONLY_REMOTE_SERVICES_DENY_LIST
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(result, expected);
        // Verify default contains expected services
        assert!(result.contains(&"ssh".to_string()));
        assert!(result.contains(&"telnet".to_string()));
    }

    #[test]
    fn test_get_password_only_remote_services_deny_list_case_sensitivity() {
        // Values are stored as-is (case-sensitive). The caller (himmelblau.rs)
        // may apply case-insensitive matching, but the config parser preserves case.
        let config_data = r#"
        [global]
        password_only_remote_services_deny_list = SSH,Telnet,FTP
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let result = config.get_password_only_remote_services_deny_list();
        assert_eq!(result, vec!["SSH", "Telnet", "FTP"]);
        // Case is preserved - these are not lowercased
        assert!(result.contains(&"SSH".to_string()));
        assert!(!result.contains(&"ssh".to_string()));
    }

    #[test]
    fn test_get_password_only_remote_services_deny_list_single_value() {
        let config_data = r#"
        [global]
        password_only_remote_services_deny_list = ssh
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let result = config.get_password_only_remote_services_deny_list();
        assert_eq!(result, vec!["ssh"]);
    }

    #[test]
    fn test_get_mfa_poll_prompt_services_default_value() {
        let config = create_empty_config();

        let result = config.get_mfa_poll_prompt_services();
        let expected: Vec<String> = DEFAULT_MFA_POLL_PROMPT_SERVICES
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(result, expected);
        assert!(result.contains(&"ssh".to_string()));
        assert!(result.contains(&"cockpit".to_string()));
    }

    #[test]
    fn test_get_mfa_poll_prompt_services_comma_separated() {
        let config_data = r#"
        [global]
        mfa_poll_prompt_services = ssh,cockpit,custom
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let result = config.get_mfa_poll_prompt_services();
        assert_eq!(result, vec!["ssh", "cockpit", "custom"]);
    }

    #[test]
    fn test_get_mfa_poll_prompt_services_whitespace_trimming() {
        let config_data = r#"
        [global]
        mfa_poll_prompt_services = ssh , cockpit,  custom
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let result = config.get_mfa_poll_prompt_services();
        assert_eq!(result, vec!["ssh", "cockpit", "custom"]);
    }

    #[test]
    fn test_get_mfa_poll_prompt_services_empty_string() {
        let config_data = r#"
        [global]
        mfa_poll_prompt_services =
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let result = config.get_mfa_poll_prompt_services();
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_get_canonicalize_user_services_default_value() {
        // PAM_USER is never rewritten unless services are explicitly listed.
        let config = create_empty_config();

        let result = config.get_canonicalize_user_services();
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_get_canonicalize_user_services_comma_separated() {
        let config_data = r#"
        [global]
        canonicalize_user_services = gdm-password , login
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        let result = config.get_canonicalize_user_services();
        assert_eq!(result, vec!["gdm-password", "login"]);
    }

    // Tests for parse_ttl_to_seconds()

    #[test]
    fn test_parse_ttl_seconds() {
        assert_eq!(parse_ttl_to_seconds("10"), Some(10));
        assert_eq!(parse_ttl_to_seconds("10s"), Some(10));
        assert_eq!(parse_ttl_to_seconds("10S"), Some(10));
        assert_eq!(parse_ttl_to_seconds("0s"), Some(0));
        assert_eq!(parse_ttl_to_seconds("1"), Some(1));
    }

    #[test]
    fn test_parse_ttl_minutes() {
        assert_eq!(parse_ttl_to_seconds("1m"), Some(60));
        assert_eq!(parse_ttl_to_seconds("5m"), Some(300));
        assert_eq!(parse_ttl_to_seconds("30M"), Some(1800));
    }

    #[test]
    fn test_parse_ttl_hours() {
        assert_eq!(parse_ttl_to_seconds("1h"), Some(3600));
        assert_eq!(parse_ttl_to_seconds("2h"), Some(7200));
        assert_eq!(parse_ttl_to_seconds("24H"), Some(86400));
    }

    #[test]
    fn test_parse_ttl_days() {
        assert_eq!(parse_ttl_to_seconds("1d"), Some(86400));
        assert_eq!(parse_ttl_to_seconds("7d"), Some(604800));
        assert_eq!(parse_ttl_to_seconds("30D"), Some(2592000));
    }

    #[test]
    fn test_parse_ttl_whitespace() {
        assert_eq!(parse_ttl_to_seconds("  10s  "), Some(10));
        assert_eq!(parse_ttl_to_seconds("\t5m\n"), Some(300));
    }

    #[test]
    fn test_parse_ttl_invalid() {
        // Empty string
        assert_eq!(parse_ttl_to_seconds(""), None);
        // Invalid suffix
        assert_eq!(parse_ttl_to_seconds("10x"), None);
        assert_eq!(parse_ttl_to_seconds("10w"), None);
        // Non-numeric
        assert_eq!(parse_ttl_to_seconds("abc"), None);
        assert_eq!(parse_ttl_to_seconds("tenm"), None);
        // Negative (parse as u64 fails)
        assert_eq!(parse_ttl_to_seconds("-10s"), None);
        // Floating point
        assert_eq!(parse_ttl_to_seconds("1.5h"), None);
    }

    // Tests for split_username()

    #[test]
    fn test_split_username_valid() {
        assert_eq!(
            split_username("user@example.com"),
            Some(("user", "example.com"))
        );
        assert_eq!(
            split_username("alice@contoso.onmicrosoft.com"),
            Some(("alice", "contoso.onmicrosoft.com"))
        );
    }

    #[test]
    fn test_split_username_no_at() {
        assert_eq!(split_username("username"), None);
        assert_eq!(split_username(""), None);
    }

    #[test]
    fn test_split_username_multiple_at() {
        // More than one @ returns None (len != 2)
        assert_eq!(split_username("user@domain@extra"), None);
    }

    #[test]
    fn test_get_fido_timeout() {
        let config_data = r#"
        [global]
        fido_timeout = 60
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_fido_timeout(), 60);
        let config_empty = create_empty_config();
        assert_eq!(config_empty.get_fido_timeout(), 25);
    }

    #[test]
    fn test_get_fido_prompt() {
        let config_data = r#"
        [global]
        fido_prompt = Insert key now.
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_fido_prompt(), "Insert key now.");
        let config_empty = create_empty_config();
        assert_eq!(
            config_empty.get_fido_prompt(),
            "Please insert your security key."
        );
    }

    #[test]
    fn test_get_fido_presence_prompt() {
        let config_data = r#"
        [global]
        fido_presence_prompt = Touch key now.
        "#;

        let temp_file = create_temp_config(config_data);
        let config = HimmelblauConfig::new(Some(&temp_file)).unwrap();

        assert_eq!(config.get_fido_presence_prompt(), "Touch key now.");
        let config_empty = create_empty_config();
        assert_eq!(
            config_empty.get_fido_presence_prompt(),
            "Please touch your security key."
        );
    }

    #[test]
    fn test_split_username_edge_cases() {
        // Empty parts are still valid splits
        assert_eq!(split_username("@domain"), Some(("", "domain")));
        assert_eq!(split_username("user@"), Some(("user", "")));
        // Just @ sign
        assert_eq!(split_username("@"), Some(("", "")));
    }

    #[allow(clippy::unwrap_used)]
    fn load_with_cache(config: &str, cache: &str) -> HimmelblauConfig {
        let config_file = create_temp_config(config);
        let cache_file = create_temp_config(cache);
        HimmelblauConfig::load(Some(&config_file), Path::new(&cache_file)).unwrap()
    }

    fn assert_rejected(config: &str, cache: &str, expected: &str) {
        let report = load_with_cache(config, cache).validate();
        assert!(
            report.errors.iter().any(|e| e.contains(expected)),
            "expected an error containing {:?} for {:?}, got {:?}",
            expected,
            config,
            report.errors
        );
    }

    const TWO_TENANTS: &str = r#"
        [tenant.contoso]
        domain = contoso.com
        default = yes
        idmap_range = 200000-1000000
        home_prefix = /home/contoso/

        [tenant.fabrikam]
        oidc_issuer_url = https://login.fabrikam.com/.well-known/openid-configuration
        app_id = linux-login
        idmap_range = 1000001-2000000
        "#;

    #[test]
    fn test_parse_bool() {
        for val in ["true", "Yes", "ON", "t", "y", "1", " true "] {
            assert_eq!(parse_bool(val), Some(true), "{}", val);
        }
        for val in ["false", "No", "OFF", "f", "n", "0"] {
            assert_eq!(parse_bool(val), Some(false), "{}", val);
        }
        for val in ["", "maybe", "2", "enabled"] {
            assert_eq!(parse_bool(val), None, "{}", val);
        }
        assert!(match_bool("apply_policy", Some("maybe".to_string()), true));
        assert!(!match_bool("apply_policy", Some("off".to_string()), true));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_legacy_domain_is_the_single_provider() {
        let config = load_with_cache("[global]\ndomain = contoso.com\n", "");
        assert_eq!(
            config.parse_providers().unwrap(),
            vec![ProviderConfig {
                label: "contoso.com".to_string(),
                section: "contoso.com".to_string(),
                kind: ProviderKind::Entra,
                domain: "contoso.com".to_string(),
                default: true,
            }]
        );
        let report = config.validate();
        assert!(report.is_ok() && report.warnings.is_empty(), "{:?}", report);
    }

    #[test]
    fn test_legacy_multiple_domains_use_the_first() {
        let config = load_with_cache("[global]\ndomains = contoso.com,fabrikam.com\n", "");
        assert_eq!(
            config.default_provider().map(|p| p.domain),
            Some("contoso.com".to_string())
        );
        let report = config.validate();
        assert!(report.is_ok(), "{:?}", report);
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("ignoring: fabrikam.com"));
        assert!(config.provider_for_domain("fabrikam.com").is_none());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_legacy_oidc_takes_precedence_over_domain() {
        let config = load_with_cache(
            "[global]\ndomain = contoso.com\noidc_issuer_url = https://issuer.example.com\n",
            "",
        );
        let provider = config.default_provider().unwrap();
        assert_eq!(provider.kind, ProviderKind::Oidc);
        assert_eq!(provider.domain, "oidc");
        let report = config.validate();
        assert!(report.is_ok(), "{:?}", report);
        assert!(report.warnings[0].contains("'contoso.com'"));

        // An invalid issuer leaves the domain as the provider
        let config = load_with_cache(
            "[global]\ndomain = contoso.com\noidc_issuer_url = http://issuer.example.com\n",
            "",
        );
        assert_eq!(
            config.default_provider().map(|p| p.kind),
            Some(ProviderKind::Entra)
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_tenant_sections_define_providers() {
        let config = load_with_cache(TWO_TENANTS, "[contoso.com]\ndomain_aliases=contoso.org\n");
        let report = config.validate();
        assert!(report.is_ok() && report.warnings.is_empty(), "{:?}", report);

        let providers = config.parse_providers().unwrap();
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0].label, "contoso");
        assert_eq!(providers[0].section, "tenant.contoso");
        assert_eq!(providers[0].kind, ProviderKind::Entra);
        assert!(providers[0].default);
        assert_eq!(providers[1].kind, ProviderKind::Oidc);
        assert!(!providers[1].default);

        assert_eq!(config.default_provider().unwrap().label, "contoso");
        assert_eq!(
            config.get_configured_domains(),
            vec!["contoso.com".to_string(), providers[1].domain.clone()]
        );
        assert_eq!(config.get_configured_entra_domains(), vec!["contoso.com"]);
        assert_eq!(
            config.get_configured_entra_domain(),
            Some("contoso.com".to_string())
        );

        // Domain-specific options resolve through the tenant section
        assert_eq!(
            config.get_home_prefix(Some("CONTOSO.com")),
            "/home/contoso/"
        );
        assert_eq!(
            config.get_home_prefix(Some(&providers[1].domain)),
            DEFAULT_HOME_PREFIX
        );
        assert_eq!(
            config.get_idmap_range(&providers[1].domain),
            (1000001, 2000000)
        );
        assert_eq!(
            config.get_primary_domain_from_alias_simple("Contoso.org"),
            Some("contoso.com".to_string())
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn tenant_domain_spelling_is_preserved_for_cache_keys() {
        let mut config =
            HimmelblauConfig::from_test_config("[tenant.contoso]\ndomain = Contoso.COM\n");
        let provider = config.parse_providers().unwrap().remove(0);

        assert_eq!(provider.domain, "Contoso.COM");
        config.set(&provider.domain, "tenant_id", "tenant-id");
        assert_eq!(
            config.get_tenant_id("contoso.com"),
            Some("tenant-id".to_string())
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn renaming_entra_label_preserves_identity_and_provider_settings() {
        let input = "[tenant.work]\ndomain=contoso.com\nidmap_range=200000-300000\n\
                     home_prefix=/home/work/\nshell=/bin/zsh\n";
        let mut original = HimmelblauConfig::from_test_config(input);
        original.set("contoso.com", "tenant_id", "tenant-id");
        original.set("contoso.com", "device_id", "device-id");
        let mut renamed =
            HimmelblauConfig::from_test_config(&input.replace("[tenant.work]", "[tenant.office]"));
        renamed.cache = original.cache.clone();

        assert!(original.validate().is_ok());
        assert!(renamed.validate().is_ok());
        let before = original.provider_for_account("alice@contoso.com").unwrap();
        let after = renamed.provider_for_account("alice@contoso.com").unwrap();
        assert_ne!(before.label, after.label);
        assert_ne!(before.section, after.section);
        assert_eq!(before.domain, after.domain);
        assert_eq!(before.kind, after.kind);
        assert_eq!(
            renamed.get_tenant_id(&after.domain),
            Some("tenant-id".into())
        );
        assert_eq!(
            renamed.domain_value(&after.domain, "device_id"),
            Some("device-id".into())
        );
        assert_eq!(
            before.get_idmap_range(&original),
            after.get_idmap_range(&renamed)
        );
        assert_eq!(
            before.get_home_prefix(&original),
            after.get_home_prefix(&renamed)
        );
        assert_eq!(before.get_shell(&original), after.get_shell(&renamed));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_single_tenant_section_is_the_default() {
        let config = load_with_cache("[tenant.contoso]\ndomain = contoso.com\n", "");
        assert!(config.validate().is_ok());
        assert_eq!(config.default_provider().unwrap().label, "contoso");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn provider_lookup_and_settings_are_scoped() {
        let config = config_for_provider_test();
        assert!(config.validate().is_ok());
        let entra = config.provider_for_account("alice@CONTOSO.ORG").unwrap();
        let oidc = config.provider_for_account("bob@fabrikam").unwrap();
        assert_eq!(entra.label, "contoso");
        assert_eq!(config.provider_for_account("alice").unwrap(), entra);
        assert_eq!(entra.get_home_prefix(&config), "/home/contoso/");
        assert_eq!(oidc.get_shell(&config), "/bin/zsh");
        assert_eq!(oidc.get_oidc_account_id_claims(&config), vec!["email"]);
        assert_eq!(oidc.get_pam_allow_groups(&config), vec!["engineers"]);
        assert!(entra.get_pam_allow_groups(&config).is_empty());
        assert_eq!(config.provider_for_gid(1000001).unwrap(), oidc);
        assert!(config.provider_for_gid(2000001).is_none());
        for account in [
            "",
            "@contoso.com",
            "alice@",
            "alice@a@b",
            "alice@unknown.com",
        ] {
            assert!(config.provider_for_account(account).is_none(), "{account}");
        }
        assert_eq!(config.map_upn_to_name("alice@contoso.com"), "alice");
        assert_eq!(
            config.map_upn_to_name("alice@contoso.org"),
            "alice@contoso.org"
        );
        assert_eq!(
            config.map_upn_to_name("alice@fabrikam.com"),
            "alice@fabrikam.com"
        );
    }

    fn config_for_provider_test() -> HimmelblauConfig {
        let mut config = HimmelblauConfig::from_test_config(&format!(
            "[global]\nshell = /bin/bash\ncn_name_mapping = true\n{TWO_TENANTS}\nshell = /bin/zsh\noidc_account_id_claims = email\npam_allow_groups = engineers\n"
        ));
        config.set("contoso.com", "domain_aliases", "contoso.org");
        config
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn discovered_alias_requires_a_unique_configured_entra_tenant() {
        let config = HimmelblauConfig::from_test_config(TWO_TENANTS);
        let providers = config.parse_providers().unwrap();
        let entra = providers[0].clone();
        let oidc = providers[1].clone();
        let tenants = vec![
            (entra.clone(), "tenant-A".to_string()),
            (oidc, "tenant-B".to_string()),
        ];
        assert_eq!(
            HimmelblauConfig::match_discovered_tenant(tenants.clone(), "TENANT-a"),
            Some(entra.clone())
        );
        for tenant_id in ["unconfigured", "tenant-B"] {
            assert!(
                HimmelblauConfig::match_discovered_tenant(tenants.clone(), tenant_id).is_none()
            );
        }
        let duplicate = vec![
            (entra.clone(), "tenant-A".to_string()),
            (entra, "tenant-A".to_string()),
        ];
        assert!(HimmelblauConfig::match_discovered_tenant(duplicate, "tenant-A").is_none());
    }

    #[test]
    fn oidc_stanzas_require_client_ids_and_distinct_normalized_issuers() {
        let mut config =
            HimmelblauConfig::from_test_config("[tenant.a]\noidc_issuer_url=https://id.example\n");
        assert!(config
            .validate()
            .errors
            .iter()
            .any(|e| e.contains("requires app_id")));
        config.set("global", "app_id", "linux");
        assert!(config.validate().is_ok());

        config.set("tenant.a", "default", "true");
        config.set("tenant.a", "idmap_range", "200000-300000");
        config.set("tenant.b", "idmap_range", "300001-400000");
        for issuer in [
            "https://id.example/",
            "https://id.example/.well-known/openid-configuration",
        ] {
            config.set("tenant.b", "oidc_issuer_url", issuer);
            assert!(config
                .validate()
                .errors
                .iter()
                .any(|e| e.contains("share the OIDC issuer")));
        }
        config.set("tenant.b", "oidc_issuer_url", "https://other.example");
        assert!(config.validate().is_ok());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn oidc_protocol_and_storage_identity_come_from_the_issuer() {
        let input = "[global]\napp_id=linux\n\
                     [tenant.first]\noidc_issuer_url=https://id.example/realms/first\n\
                     default=true\nidmap_range=200000-300000\nshell=/bin/zsh\n\
                     [tenant.second]\noidc_issuer_url=https://id.example/realms/second\n\
                     idmap_range=300001-400000\n";
        let config = HimmelblauConfig::from_test_config(input);
        assert!(config.validate().is_ok());
        let first = config.provider_for_account("alice@first").unwrap();
        let second = config.provider_for_account("alice@second").unwrap();
        assert_eq!(first.kind, ProviderKind::Oidc);
        assert_ne!(first.domain, second.domain);
        assert_eq!(first.get_shell(&config), "/bin/zsh");
        let renamed = HimmelblauConfig::from_test_config(
            &input.replace("[tenant.first]", "[tenant.renamed]"),
        );
        let after = renamed.provider_for_account("alice@renamed").unwrap();
        assert_eq!(first.domain, after.domain);
        assert_eq!(
            first.oidc_tenant_id(&config),
            after.oidc_tenant_id(&renamed)
        );
        for (extra, expected) in [
            ("domain=example.org", "configure exactly one"),
            ("type=oidc", "type is inferred"),
        ] {
            assert_rejected(
                &format!("[tenant.a]\noidc_issuer_url=https://id.example\n{extra}\n"),
                "",
                expected,
            );
        }
        for (issuer, expected) in [
            ("", "OIDC issuer URL is empty"),
            ("http://id.example", "must use https://"),
            ("https://", "not a valid URL"),
            ("https://id.example?query=1", "query or fragment"),
        ] {
            assert_rejected(
                &format!("[tenant.a]\noidc_issuer_url={issuer}\n"),
                "",
                expected,
            );
        }
    }

    #[test]
    fn test_tenant_section_parse_errors() {
        for (config, expected) in [
            ("[tenant.]\ndomain = contoso.com\n", "requires a label"),
            (
                "[tenant.contoso]\ntype = saml\ndomain = contoso.com\n",
                "type is inferred",
            ),
            ("[tenant.contoso]\n", "requires domain or oidc_issuer_url"),
            ("[tenant.contoso]\ndomain =\n", "requires a domain"),
            (
                "[tenant.contoso]\ndomain = contoso.com,contoso.org\n",
                "aliases are discovered automatically",
            ),
            (
                "[tenant.contoso]\ndomain = contoso.com\ndefault = maybe\n",
                "expected a boolean",
            ),
            (
                "[global]\ndomain = contoso.com\n[tenant.contoso]\ndomain = contoso.com\n",
                "[global] domain cannot be combined",
            ),
            (
                "[contoso.com]\n[tenant.contoso]\ndomain = contoso.com\n",
                "[contoso.com] cannot be combined",
            ),
        ] {
            assert!(load_with_cache(config, "").parse_providers().is_err());
            assert_rejected(config, "", expected);
        }
    }

    #[test]
    fn test_tenant_section_validation_errors() {
        let tenants = |a: &str, b: &str| {
            format!(
                "[tenant.a]\ndefault = true\n{}\n[tenant.b]\n{}\n",
                a.replace(';', "\n"),
                b.replace(';', "\n")
            )
        };
        let range_a = "idmap_range = 200000-300000";
        let range_b = "idmap_range = 300001-400000";
        for (config, cache, expected) in [
            (
                tenants(
                    &format!("domain = contoso.com;{}", range_a),
                    &format!("domain = CONTOSO.com;{}", range_b),
                ),
                "",
                "both claim the domain",
            ),
            (
                tenants(
                    &format!("domain = contoso.com;{}", range_a),
                    &format!("domain = fabrikam.com;{}", range_b),
                ),
                "[contoso.com]\ndomain_aliases = fabrikam.com\n",
                "both claim the domain fabrikam.com",
            ),
            (
                tenants(
                    &format!("domain = contoso.com;{}", range_a),
                    "domain = fabrikam.com",
                ),
                "",
                "[tenant.b] requires an idmap_range",
            ),
            (
                "[tenant.a]\ndomain = contoso.com\nidmap_range = 5-x\n".to_string(),
                "",
                "idmap_range = 5-x is invalid",
            ),
            (
                "[tenant.a]\ndomain = contoso.com\nidmap_range = 400000-300000\n".to_string(),
                "",
                "idmap_range = 400000-300000 is invalid",
            ),
            (
                tenants(
                    &format!("domain = contoso.com;{}", range_a),
                    &format!("domain = fabrikam.com;default = true;{}", range_b),
                ),
                "",
                "Only one tenant can set default = true",
            ),
            (
                format!(
                    "[tenant.a]\ndomain = contoso.com\n{}\n[tenant.b]\ndomain = fabrikam.com\n{}\n",
                    range_a, range_b
                ),
                "",
                "One tenant must set default = true",
            ),
            (
                tenants(
                    &format!("domain = contoso.com;{}", range_a),
                    &format!("domain = fabrikam.com;{}", range_b),
                ),
                "[contoso.com]\ntenant_id = 1111\n[fabrikam.com]\ntenant_id = 1111\n",
                "share the tenant 1111",
            ),
            (
                format!(
                    "[global]\nid_attr_map = rfc2307\n{}",
                    tenants(
                        &format!("domain = contoso.com;{}", range_a),
                        &format!("domain = fabrikam.com;{}", range_b),
                    )
                ),
                "",
                "rfc2307 supports a single tenant",
            ),
            (
                "[tenant.a]\n".to_string(),
                "",
                "requires domain or oidc_issuer_url",
            ),
            (
                "[tenant.a]\noidc_issuer_url = http://issuer.example.com\n".to_string(),
                "",
                "must use https://",
            ),
            (
                "[tenant.a]\ndomain = contoso.com\noidc_issuer_url = https://issuer.example.com\n"
                    .to_string(),
                "",
                "configure exactly one",
            ),
            (
                tenants(
                    &format!("domain = contoso.com;{}", range_a),
                    "domain = fabrikam.com;idmap_range = 250000-350000",
                ),
                "",
                "of contoso.com overlaps with idmap_range (250000-350000) of fabrikam.com",
            ),
            (
                "[tenant.a]\ndomain = contoso.com\nidmap_range = 2100000000-2100000100\n"
                    .to_string(),
                "",
                "of contoso.com overlaps with subid_range",
            ),
            (
                "[global]\ndomain = contoso.com\nidmap_range = 2100000000-2100000100\n".to_string(),
                "",
                "of contoso.com overlaps with subid_range",
            ),
            (
                "[global]\ndebug = true\n".to_string(),
                "",
                "No provider is configured",
            ),
        ] {
            assert_rejected(&config, cache, expected);
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn provider_sharing_tenant_finds_other_entra_providers() {
        let mut config = HimmelblauConfig::from_test_config(
            "[tenant.a]\ndomain = contoso.com\ndefault = true\nidmap_range = 200000-300000\n\
             [tenant.b]\ndomain = fabrikam.com\nidmap_range = 300001-400000\n",
        );
        assert!(config
            .provider_sharing_tenant("fabrikam.com", "1111")
            .is_none());
        config.set("contoso.com", "tenant_id", "AAAA");
        assert_eq!(
            config
                .provider_sharing_tenant("FABRIKAM.com", "aaaa")
                .unwrap()
                .section,
            "tenant.a"
        );
        assert!(config
            .provider_sharing_tenant("contoso.com", "aaaa")
            .is_none());
        assert!(config
            .provider_sharing_tenant("fabrikam.com", "bbbb")
            .is_none());
    }

    #[test]
    fn qualified_oidc_spn_homes_are_distinct_from_entra_cn_homes() {
        let config = HimmelblauConfig::from_test_config(
            "[tenant.oidc]\ndefault = true\n\
             oidc_issuer_url = https://issuer.example\napp_id = linux\n\
             oidc_account_id_strip_at_suffix = true\nidmap_range = 200000-300000\n\
             home_prefix = /home/\n\
             [tenant.entra]\ndomain = entra.example\nidmap_range = 300001-400000\n\
             home_attr = cn\nhome_prefix = /home/\n",
        );

        let report = config.validate();
        assert!(report.is_ok(), "{:?}", report.errors);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn explicit_labels_preserve_upstream_names_and_default_routing() {
        let config = HimmelblauConfig::from_test_config(TWO_TENANTS);
        for (login, label, upstream, canonical) in [
            ("alice", "contoso", "alice", "alice"),
            (
                "alice@contoso",
                "contoso",
                "alice@contoso.com",
                "alice@contoso.com",
            ),
            (
                "alice@contoso.com",
                "contoso",
                "alice@contoso.com",
                "alice@contoso.com",
            ),
            ("alice@fabrikam", "fabrikam", "alice", "alice@fabrikam"),
            (
                "alice@example.org@FABRIKAM",
                "fabrikam",
                "alice@example.org",
                "alice@example.org@fabrikam",
            ),
        ] {
            let provider = config.provider_for_account(login).unwrap();
            assert_eq!(provider.label, label);
            assert_eq!(
                provider.upstream_account_name(login).as_deref(),
                Some(upstream)
            );
            assert_eq!(
                config.canonical_account_name(login).as_deref(),
                Some(canonical)
            );
        }
        for login in [
            "@fabrikam",
            "alice@@fabrikam",
            "alice@",
            "alice@unknown",
            "alice@fabrikam.com@contoso",
        ] {
            assert!(config.provider_for_account(login).is_none(), "{login}");
        }
        let oidc_default = HimmelblauConfig::from_test_config(
            &TWO_TENANTS
                .replace("default = yes", "default = no\n")
                .replace(
                    "[tenant.fabrikam]",
                    "[tenant.fabrikam]\ndefault = true\noidc_account_id_strip_at_suffix = true",
                ),
        );
        assert!(oidc_default.validate().is_ok());
        assert_eq!(
            oidc_default.canonical_account_name("alice").as_deref(),
            Some("alice@fabrikam")
        );
        let legacy = HimmelblauConfig::from_test_config(
            "[global]\noidc_issuer_url=https://issuer.example\n",
        );
        assert_eq!(
            legacy
                .canonical_account_name("alice@example.org")
                .as_deref(),
            Some("alice@example.org")
        );
    }

    #[test]
    fn labels_cannot_shadow_other_providers_or_contain_separators() {
        for label in ["contoso.com", "contoso.org"] {
            let input = TWO_TENANTS.replace("[tenant.fabrikam]", &format!("[tenant.{label}]"));
            assert_rejected(
                &input,
                "[contoso.com]\ndomain_aliases=contoso.org\n",
                "both claim the domain",
            );
        }
        for label in ["a@b", "two words"] {
            assert_rejected(
                &format!("[tenant.{label}]\ndomain=example.com\n"),
                "",
                "label must not contain",
            );
        }
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::unwrap_used)]
    fn cn_home_prefix_collisions_use_resolved_paths_and_report_resolution_errors() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!(".test-home-prefix-{}", uuid::Uuid::new_v4()));
        let shared = root.join("shared");
        let alias = root.join("alias");
        let broken = root.join("broken");
        fs::create_dir_all(&shared).unwrap();
        symlink(&shared, &alias).unwrap();
        symlink(root.join("missing"), &broken).unwrap();

        let config_for = |first: &Path, second: &Path| {
            HimmelblauConfig::from_test_config(&format!(
                "[tenant.a]\ndomain = a.example\ndefault = true\n\
                 idmap_range = 200000-300000\nhome_attr = cn\nhome_prefix = {}/\n\
                 [tenant.b]\ndomain = b.example\nidmap_range = 300001-400000\n\
                 home_attr = cn\nhome_prefix = {}/\n",
                first.display(),
                second.display()
            ))
        };
        let normalized_paths_rejected = config_for(&shared, &shared.join("."))
            .validate()
            .errors
            .iter()
            .any(|error| error.contains("require distinct home_prefix"));
        let symlinked_paths_rejected = config_for(&shared, &alias)
            .validate()
            .errors
            .iter()
            .any(|error| error.contains("require distinct home_prefix"));
        let broken_symlink_rejected = config_for(&broken, &shared)
            .validate()
            .errors
            .iter()
            .any(|error| error.contains("cannot resolve home_prefix"));

        fs::remove_dir_all(&root).unwrap();
        assert!(normalized_paths_rejected);
        assert!(symlinked_paths_rejected);
        assert!(broken_symlink_rejected);
    }

    #[test]
    fn administrator_aliases_are_rejected_and_cannot_route_accounts() {
        for input in [
            "[global]\ndomain=example.com\ndomain_aliases=alias.example\n",
            "[global]\ndomain=example.com\n[example.com]\ndomain_aliases=alias.example\n",
            "[tenant.work]\ndomain=example.com\ndomain_aliases=alias.example\n",
        ] {
            let config = HimmelblauConfig::from_test_config(input);
            assert!(config
                .validate()
                .errors
                .iter()
                .any(|e| e.contains("internal discovery metadata")));
            assert!(config.provider_for_account("alice@alias.example").is_none());
            assert!(config.provider_for_account("alice@example.com").is_some());
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn verified_aliases_survive_restart_and_oidc_cache_aliases_are_ignored() {
        let mut config = HimmelblauConfig::from_test_config(TWO_TENANTS);
        config.cache_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!(".test-verified-alias-{}.ini", uuid::Uuid::new_v4()));
        let entra = config.provider_for_account("alice@contoso.com").unwrap();
        let provider = HimmelblauConfig::match_discovered_tenant(
            [(entra.clone(), "tenant-id".to_string())],
            "tenant-id",
        )
        .unwrap();
        assert!(config.record_domain_alias(&provider, "SIGN-IN.example"));
        let mut restarted = HimmelblauConfig::from_test_config(TWO_TENANTS);
        restarted.cache_path = config.cache_path.clone();
        restarted.reload_server_cache().unwrap();
        assert_eq!(
            restarted.provider_for_account("alice@sign-in.example"),
            Some(entra)
        );
        assert!(restarted.validate().is_ok());
        let oidc = restarted.provider_for_account("alice@fabrikam").unwrap();
        restarted.set(&oidc.domain, "domain_aliases", "oidc-alias.example");
        assert!(restarted
            .provider_for_account("alice@oidc-alias.example")
            .is_none());
        assert!(!restarted.record_domain_alias(&oidc, "another.example"));
        fs::write(&config.cache_path, "[invalid section").unwrap();
        assert!(restarted.reload_server_cache().is_err());
        fs::remove_file(config.cache_path).unwrap();
    }

    #[test]
    fn test_server_cache_layer() {
        let config = load_with_cache(
            r#"
            [global]
            domain = contoso.com

            [contoso.com]
            authority_host = admin.example.com
            "#,
            r#"
            [contoso.com]
            authority_host = cache.example.com
            domain_aliases = contoso.org,contoso.net

            [stale.com]
            tenant_id = 2222
            "#,
        );
        // Cache sections never define providers
        assert_eq!(config.get_configured_domains(), vec!["contoso.com"]);
        assert_eq!(
            config.get_primary_domain_from_alias_simple("stale.com"),
            None
        );
        // Discovered values take precedence
        assert_eq!(
            config.get_authority_host("contoso.com"),
            "cache.example.com"
        );
        // Persisted aliases resolve without discovery.
        for alias in ["contoso.org", "CONTOSO.net"] {
            assert_eq!(
                config.get_primary_domain_from_alias_simple(alias),
                Some("contoso.com".to_string())
            );
        }

        // Tenant sections read the cache through their domain
        let config = load_with_cache(
            "[tenant.contoso]\ndomain = contoso.com\n",
            "[contoso.com]\ntenant_id = 1111\n",
        );
        assert_eq!(
            config.get_tenant_id("contoso.com"),
            Some("1111".to_string())
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_write_server_config_only_writes_discovered_keys() {
        let config_file =
            create_temp_config("[global]\ndomain = contoso.com\n[contoso.com]\nshell = /bin/zsh\n");
        let cache_file = create_temp_config("");
        let mut config =
            HimmelblauConfig::load(Some(&config_file), Path::new(&cache_file)).unwrap();
        config.set("contoso.com", "tenant_id", "1111");
        config.set("contoso.com", "home_prefix", "/srv/home/");
        config.write_server_config().unwrap();

        let written = fs::read_to_string(&cache_file).unwrap();
        assert!(written.contains("tenant_id"));
        assert!(!written.contains("shell"));
        assert!(!written.contains("home_prefix"));
        assert_eq!(config.get_home_prefix(Some("contoso.com")), "/srv/home/");

        let reloaded = HimmelblauConfig::load(Some(&config_file), Path::new(&cache_file)).unwrap();
        assert_eq!(
            reloaded.get_tenant_id("contoso.com"),
            Some("1111".to_string())
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn reload_server_cache_updates_aliases_without_changing_provider_settings() {
        let mut config = HimmelblauConfig::from_test_config(TWO_TENANTS);
        config.cache_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!(".test-server-cache-{}.ini", uuid::Uuid::new_v4()));
        assert!(config
            .provider_for_account("alice@discovered.example")
            .is_none());
        fs::write(
            &config.cache_path,
            "[contoso.com]\ndomain_aliases=discovered.example\nhome_prefix=/ignored/\n\
             [stale.example]\ntenant_id=stale\n",
        )
        .unwrap();
        config.reload_server_cache().unwrap();
        let provider = config
            .provider_for_account("alice@discovered.example")
            .unwrap();
        assert_eq!(provider.domain, "contoso.com");
        assert_eq!(provider.get_home_prefix(&config), "/home/contoso/");
        assert!(config.provider_for_domain("stale.example").is_none());

        fs::remove_file(&config.cache_path).unwrap();
        config.reload_server_cache().unwrap();
        assert!(config
            .provider_for_account("alice@discovered.example")
            .is_none());
    }
}
