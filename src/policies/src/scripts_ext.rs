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
use crate::cse::CSE;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use himmelblau::intune::{ComplianceState, IntuneStatus, PolicyStatus};
use himmelblau_unix_common::{
    config::HimmelblauConfig,
    systemd_api::{Systemd, TransientUnit, UnitManager, Variant},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::fs;
use tokio::process::Command;
use tracing::{debug, error};

fn policy_unit_name(policy_id: &str) -> Result<String> {
    if policy_id.is_empty()
        || policy_id.len() > 200
        || !policy_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        bail!("Invalid Intune policy ID: {:?}", policy_id);
    }
    Ok(format!("himmelblaud-policy@{}", policy_id))
}

fn calendar_schedule(frequency: &str) -> Result<&'static str> {
    match frequency {
        "15" => Ok("*-*-* *:00/15:00"),
        "30" => Ok("*-*-* *:00/30:00"),
        "60" => Ok("*-*-* *:00:00"),
        "120" => Ok("*-*-* 00/2:00:00"),
        "180" => Ok("*-*-* 00/3:00:00"),
        "360" => Ok("*-*-* 00/6:00:00"),
        "720" => Ok("*-*-* 00/12:00:00"),
        "1440" => Ok("*-*-* 00:00:00"),
        "10080" => Ok("Sun *-*-* 00:00:00"),
        _ => bail!("Unknown script application frequency '{}'", frequency),
    }
}

async fn user_id(username: &str) -> Result<u32> {
    let mut command = Command::new("id");
    command
        .args(["-u", "--", username])
        .env_remove("SYSTEMD_ACTIVATION_UNIT");
    let output = command_output(command)
        .await
        .with_context(|| format!("Failed to resolve policy execution user {}", username))?;
    let uid = std::str::from_utf8(&output.stdout)
        .context("Non-UTF-8 policy execution UID")?
        .trim()
        .parse::<u32>()
        .context("Invalid policy execution UID")?;
    if uid == libc::uid_t::MAX {
        bail!("Invalid policy execution UID");
    }
    Ok(uid)
}

fn retry_wrapper(script_path: &str, retries: u32) -> String {
    let script_path = format!("'{}'", script_path.replace('\'', "'\\''"));
    format!(
        r#"#!/bin/bash
retries={retries}
attempts=0
while [ $attempts -le $retries ]; do
    {script_path}
    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        exit 0
    fi
    attempts=$((attempts+1))
done
exit $exit_code
"#
    )
}

async fn write_atomic(path: &Path, contents: &str, mode: u32) -> Result<()> {
    let parent = path.parent().context("File has no parent directory")?;
    let file = NamedTempFile::new_in(parent)
        .with_context(|| format!("Failed to create temporary file in {}", parent.display()))?;
    fs::write(file.path(), contents).await?;
    fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode)).await?;
    file.persist(path)
        .with_context(|| format!("Failed to install {}", path.display()))?;
    Ok(())
}

async fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("Failed to remove {}", path.display())),
    }
}

async fn command_output(mut command: Command) -> Result<Output> {
    let program = command
        .as_std()
        .get_program()
        .to_string_lossy()
        .into_owned();
    let output = tokio::time::timeout(Duration::from_secs(30), command.kill_on_drop(true).output())
        .await
        .with_context(|| format!("Timed out waiting for {}", program))?
        .with_context(|| format!("Failed to execute {}", program))?;
    if !output.status.success() {
        bail!(
            "{} failed ({}): {}",
            program,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct ScriptPolicy {
    policy_id: String,
    execution_uid: u32,
    frequency: String,
    retries: u32,
    script: String,
}

impl ScriptPolicy {
    fn validate(&self) -> Result<()> {
        policy_unit_name(&self.policy_id)?;
        calendar_schedule(&self.frequency)?;
        if self.execution_uid == u32::MAX {
            bail!("Invalid policy execution UID");
        }
        Ok(())
    }

    fn definition_path(&self, cache_dir: &Path) -> PathBuf {
        cache_dir.join(format!("policy_{}.json", self.policy_id))
    }

    async fn load(path: &Path) -> Result<Option<Self>> {
        match fs::read_to_string(path).await {
            Ok(data) => {
                let policy: Self = serde_json::from_str(&data)?;
                policy.validate()?;
                Ok(Some(policy))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
        }
    }

    async fn save(&self, cache_dir: &Path) -> Result<()> {
        self.validate()?;
        fs::create_dir_all(cache_dir).await?;
        write_atomic(
            &self.definition_path(cache_dir),
            &serde_json::to_string(self)?,
            0o600,
        )
        .await
    }

    async fn materialize(&self, cache_dir: &Path) -> Result<()> {
        self.validate()?;
        let script_dir = cache_dir.join("bin");
        fs::create_dir_all(&script_dir).await?;
        let script_path = script_dir.join(format!("policy_{}_script.sh", self.policy_id));
        write_atomic(&script_path, &self.script, 0o755).await?;
        write_atomic(
            &script_dir.join(format!("policy_{}_wrapper.sh", self.policy_id)),
            &retry_wrapper(
                script_path.to_str().context("Non-UTF-8 script path")?,
                self.retries,
            ),
            0o755,
        )
        .await
    }

    fn unit_settings_changed(&self, previous: &Self) -> bool {
        self.execution_uid != previous.execution_uid || self.frequency != previous.frequency
    }
}

async fn stop_policy(systemd: &dyn UnitManager, unit: &str) -> Result<()> {
    for suffix in ["timer", "service"] {
        systemd.stop_unit(&format!("{}.{}", unit, suffix)).await?;
    }
    Ok(())
}

async fn retire_policy(systemd: &dyn UnitManager, unit: &str) -> Result<()> {
    stop_policy(systemd, unit).await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while systemd.unit_exists(&format!("{}.timer", unit)).await?
            || systemd.unit_exists(&format!("{}.service", unit)).await?
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    })
    .await
    .with_context(|| format!("Timed out waiting for {} to be collected", unit))?
}

fn policy_units(
    policy: &ScriptPolicy,
    cache_dir: &Path,
    create_service: bool,
) -> Result<(TransientUnit, Vec<TransientUnit>)> {
    policy.validate()?;
    let unit = policy_unit_name(&policy.policy_id)?;
    let description = format!("Himmelblau Configuration Policy {}", policy.policy_id);
    let timer = TransientUnit {
        name: format!("{}.timer", unit),
        properties: vec![
            ("Description", description.clone().into()),
            ("CollectMode", "inactive-or-failed".into()),
            (
                "TimersCalendar",
                Variant::new(vec![("OnCalendar", calendar_schedule(&policy.frequency)?)]),
            ),
            ("AccuracyUSec", 1_000_000u64.into()),
            ("Persistent", false.into()),
        ],
    };
    let mut auxiliary = Vec::new();
    if create_service {
        let script_dir = cache_dir.join("bin");
        let wrapper = script_dir.join(format!("policy_{}_wrapper.sh", policy.policy_id));
        if !wrapper.is_absolute() {
            bail!("Policy cache path must be absolute");
        }
        let path = std::env::var("PATH").context("PATH is required to run policy scripts")?;
        let executable = wrapper
            .to_str()
            .context("Non-UTF-8 wrapper path")?
            .to_string();
        let argv = vec![executable.replace('$', "$$")];
        auxiliary.push(TransientUnit {
            name: format!("{}.service", unit),
            properties: vec![
                ("Description", description.into()),
                ("CollectMode", "inactive-or-failed".into()),
                ("Type", "oneshot".into()),
                ("User", policy.execution_uid.to_string().into()),
                ("WorkingDirectory", "~".into()),
                ("CacheDirectory", Variant::new(vec!["himmelblau-policies"])),
                ("TimeoutStartUSec", u64::MAX.into()),
                ("KillMode", "control-group".into()),
                ("Environment", Variant::new(vec![format!("PATH={}", path)])),
                ("ExecStart", Variant::new(vec![(executable, argv, false)])),
            ],
        });
    }
    Ok((timer, auxiliary))
}

async fn ensure_policy(
    systemd: &dyn UnitManager,
    policy: &ScriptPolicy,
    cache_dir: &Path,
) -> Result<()> {
    let unit = policy_unit_name(&policy.policy_id)?;
    let timer_exists = systemd.unit_exists(&format!("{}.timer", unit)).await?;
    let service_exists = systemd.unit_exists(&format!("{}.service", unit)).await?;
    if timer_exists && service_exists {
        return Ok(());
    }
    if timer_exists {
        // Recreate an orphaned timer with its missing service, without running the script now.
        retire_policy(systemd, &unit).await?;
    }
    let (timer, auxiliary) = policy_units(policy, cache_dir, !service_exists)?;
    systemd.start_transient(timer, auxiliary).await?;
    debug!(unit = %unit, "Created missing transient configuration policy units");
    Ok(())
}

async fn restore_policies(
    cache_dir: &Path,
    legacy_cron_dir: &Path,
    systemd: &dyn UnitManager,
) -> Result<()> {
    let mut entries = match fs::read_dir(cache_dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context("Failed to read configuration policy definitions"),
    };
    let mut failures = 0;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("policy_") || !name.ends_with(".json") {
            continue;
        }
        let path = entry.path();
        let result = async {
            if !entry.file_type().await?.is_file() {
                bail!("Policy definition is not a regular file");
            }
            let policy = ScriptPolicy::load(&path)
                .await?
                .context("Policy definition disappeared during startup")?;
            if policy.definition_path(cache_dir) != path {
                bail!("Policy definition ID does not match its filename");
            }
            remove_if_exists(&legacy_cron_dir.join(format!("policy_{}", policy.policy_id))).await?;
            policy.materialize(cache_dir).await?;
            ensure_policy(systemd, &policy, cache_dir).await
        }
        .await;
        if let Err(e) = result {
            error!(path = %path.display(), error = %format!("{e:#}"), "Failed to restore configuration policy");
            failures += 1;
        }
    }
    if failures > 0 {
        bail!("Failed to restore {} configuration policies", failures);
    }
    Ok(())
}

pub async fn restore_configuration_policies(config: &HimmelblauConfig) -> Result<()> {
    restore_policies(
        Path::new(&config.get_policies_db_path()),
        Path::new("/etc/cron.d"),
        &Systemd::default(),
    )
    .await
}

/// A simple persistent cache mapping usernames to the set of applied policy IDs.
#[derive(Serialize, Deserialize, Default)]
pub struct PolicyCache {
    pub user_policies: HashMap<String, HashSet<String>>,
}

impl PolicyCache {
    /// Loads the cache from the given file path. If the file does not exist, returns an empty cache.
    pub async fn load(path: &PathBuf) -> Result<Self> {
        match fs::read_to_string(path).await {
            Ok(data) => Ok(serde_json::from_str(&data)?),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(PolicyCache::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Saves the cache to the given file path.
    pub async fn save(&self, path: &PathBuf) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        write_atomic(path, &data, 0o600).await
    }

    /// Returns the set of applied policy IDs for the specified user.
    pub fn get_for_user(&self, username: &str) -> HashSet<String> {
        self.user_policies
            .get(username)
            .cloned()
            .unwrap_or_default()
    }

    /// Updates the cache for the given user.
    pub fn update_for_user(&mut self, username: &str, applied_policy_ids: HashSet<String>) {
        self.user_policies
            .insert(username.to_string(), applied_policy_ids);
    }
}

pub struct ScriptsCSE {
    username: String,
    config: HimmelblauConfig,
}

#[async_trait]
impl CSE for ScriptsCSE {
    fn new(config: &HimmelblauConfig, username: &str) -> Self {
        ScriptsCSE {
            username: username.to_string(),
            config: config.clone(),
        }
    }

    async fn process_group_policy(&self, policies: &mut IntuneStatus) -> Result<bool> {
        let cache_dir = PathBuf::from(self.config.get_policies_db_path());
        fs::create_dir_all(&cache_dir).await?;
        let systemd = Systemd::default();
        // Generate the persistent cache path.
        let cache_path_str = self
            .cache_path()
            .await
            .map_err(|e| anyhow!("Failed to determine cache path: {}", e))?;
        let cache_path = PathBuf::from(cache_path_str);
        // Load the existing cache.
        let mut cache = PolicyCache::load(&cache_path)
            .await
            .map_err(|e| anyhow!("Failed to load policy cache: {}", e))?;
        let cached_policy_ids = cache.get_for_user(&self.username);
        let mut tracked_policy_ids = cached_policy_ids.clone();
        // Collect new policy IDs from the changed policies.
        let new_policy_ids: HashSet<String> = policies
            .policy_statuses
            .iter()
            .filter(|p| {
                p.details
                    .iter()
                    .any(|d| d.setting_definition_item_id == "linux_customconfig_script")
            })
            .map(|p| p.policy_id.clone())
            .collect();

        // Remove policies that were applied before but are not in the new set.
        for old_policy in cached_policy_ids.difference(&new_policy_ids) {
            let unit = policy_unit_name(old_policy)?;
            remove_if_exists(&cache_dir.join(format!("policy_{}.json", old_policy))).await?;
            stop_policy(&systemd, &unit).await?;
            let cron_file = format!("/etc/cron.d/policy_{}", old_policy);
            remove_if_exists(Path::new(&cron_file)).await?;
            for kind in ["script", "wrapper"] {
                remove_if_exists(
                    &cache_dir
                        .join("bin")
                        .join(format!("policy_{}_{}.sh", old_policy, kind)),
                )
                .await?;
            }
            tracked_policy_ids.remove(old_policy);
            cache.update_for_user(&self.username, tracked_policy_ids.clone());
            cache.save(&cache_path).await?;
        }

        // Process and apply the changed policies.
        for policy in policies.policy_statuses.iter_mut() {
            let detail_ids: Vec<&str> = policy
                .details
                .iter()
                .map(|d| d.setting_definition_item_id.as_str())
                .collect();
            debug!(
                policy_id = %policy.policy_id,
                ?detail_ids,
                "ScriptsCSE: inspecting policy details"
            );
            // Validate this is a scripts policy
            if policy
                .details
                .iter()
                .any(|d| d.setting_definition_item_id == "linux_customconfig_script")
            {
                debug!(
                    policy_id = %policy.policy_id,
                    "ScriptsCSE: matched scripts policy, applying"
                );
                let result = async {
                    policy_unit_name(&policy.policy_id)?;
                    // Track the definition before creating units, even if a later policy fails.
                    if tracked_policy_ids.insert(policy.policy_id.clone()) {
                        cache.update_for_user(&self.username, tracked_policy_ids.clone());
                        cache.save(&cache_path).await?;
                    }
                    self.apply_policy(policy, &systemd).await
                }
                .await;
                if let Err(e) = result {
                    for detail in &mut policy.details {
                        if detail
                            .setting_definition_item_id
                            .starts_with("linux_customconfig_")
                        {
                            detail.set_status(
                                Some("Error".to_string()),
                                Some(format!("{e:#}")),
                                &ComplianceState::Error,
                            );
                        }
                    }
                    return Err(e);
                }
            } else {
                debug!(
                    policy_id = %policy.policy_id,
                    "ScriptsCSE: not a scripts policy, skipping"
                );
            }
        }

        // Update and save the cache.
        cache.update_for_user(&self.username, new_policy_ids);
        cache
            .save(&cache_path)
            .await
            .map_err(|e| anyhow!("Failed to save policy cache: {}", e))?;

        Ok(true)
    }
}

impl ScriptsCSE {
    async fn cache_path(&self) -> Result<String> {
        let db_path = self.config.get_policies_db_path();
        let mut path = PathBuf::from(db_path);
        // Append a filename, e.g., "cache_<username>_scripts.json"
        path.push(format!("cache_{}_scripts.json", self.username));
        path.to_str()
            .map(|s| s.to_string())
            .ok_or(anyhow!("Failed to convert cache path to string"))
    }

    async fn apply_policy(
        &self,
        policy: &mut PolicyStatus,
        systemd: &dyn UnitManager,
    ) -> Result<()> {
        let unit = policy_unit_name(&policy.policy_id)?;
        let mut execution_uid = 0;
        let mut frequency = "60".to_string();
        let mut retries = 0;
        let mut script_b64: Option<String> = None;

        // Process each setting.
        for detail in &policy.details {
            match detail.setting_definition_item_id.as_str() {
                "linux_customconfig_executioncontext" => match detail.expected_value.as_str() {
                    "root" => {
                        execution_uid = 0;
                    }
                    "user" => {
                        execution_uid = user_id(&self.username).await?;
                    }
                    _ => {
                        return Err(anyhow!(
                            "Unrecognized execution context '{}'",
                            detail.expected_value
                        ))
                    }
                },
                "linux_customconfig_executionfrequency" => {
                    frequency = detail.expected_value.clone();
                }
                "linux_customconfig_executionretries" => {
                    if let Ok(val) = detail.expected_value.parse::<u32>() {
                        retries = val;
                    } else {
                        return Err(anyhow!("Failed to parse script execution retries"));
                    }
                }
                "linux_customconfig_script" => {
                    script_b64 = Some(detail.expected_value.clone());
                }
                _ => {}
            }
        }

        let script_b64 = match script_b64 {
            Some(val) => val,
            // This isn't a script policy, nothing to do
            None => return Ok(()),
        };
        let script_bytes = STANDARD
            .decode(script_b64)
            .map_err(|e| anyhow!("Failed to decode script: {}", e))?;
        let definition = ScriptPolicy {
            policy_id: policy.policy_id.clone(),
            execution_uid,
            frequency,
            retries,
            script: String::from_utf8(script_bytes).context("Failed to convert script to UTF-8")?,
        };
        definition.validate()?;
        let cache_dir = PathBuf::from(self.config.get_policies_db_path());
        let previous = ScriptPolicy::load(&definition.definition_path(&cache_dir)).await?;
        let replace_units = match previous {
            Some(previous) => definition.unit_settings_changed(&previous),
            None => true,
        };
        if replace_units {
            retire_policy(systemd, &unit).await?;
        }
        definition.save(&cache_dir).await?;
        remove_if_exists(Path::new(&format!(
            "/etc/cron.d/policy_{}",
            policy.policy_id
        )))
        .await?;
        definition.materialize(&cache_dir).await?;
        ensure_policy(systemd, &definition, &cache_dir).await?;

        for detail in &mut policy.details {
            if matches!(
                detail.setting_definition_item_id.as_str(),
                "linux_customconfig_executioncontext"
                    | "linux_customconfig_executionfrequency"
                    | "linux_customconfig_executionretries"
                    | "linux_customconfig_script"
            ) {
                detail.actual_value = detail.expected_value.clone();
                detail.new_compliance_state = "Compliant".to_string();
            }
        }

        debug!(
            "Installed script policy {} for user {}, enforced via transient timer {}.timer.",
            &policy.policy_id, &self.username, &unit
        );

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::tempdir;

    #[derive(Default)]
    struct FakeState {
        units: HashSet<String>,
        starts: Vec<(TransientUnit, Vec<TransientUnit>)>,
        stops: Vec<String>,
        fail_query: bool,
    }

    #[derive(Default)]
    struct FakeSystemd {
        state: Mutex<FakeState>,
    }

    #[async_trait]
    impl UnitManager for FakeSystemd {
        async fn unit_exists(&self, name: &str) -> Result<bool> {
            let state = self.state.lock().unwrap();
            if state.fail_query {
                bail!("Unit query failed");
            }
            Ok(state.units.contains(name))
        }

        async fn stop_unit(&self, name: &str) -> Result<()> {
            let mut state = self.state.lock().unwrap();
            if state.units.remove(name) {
                state.stops.push(name.to_string());
            }
            Ok(())
        }

        async fn start_transient(
            &self,
            unit: TransientUnit,
            auxiliary: Vec<TransientUnit>,
        ) -> Result<()> {
            let mut state = self.state.lock().unwrap();
            if state.units.contains(&unit.name)
                || auxiliary
                    .iter()
                    .any(|unit| state.units.contains(&unit.name))
            {
                bail!("Unit already exists");
            }
            state.units.insert(unit.name.clone());
            state
                .units
                .extend(auxiliary.iter().map(|unit| unit.name.clone()));
            state.starts.push((unit, auxiliary));
            Ok(())
        }
    }

    fn property<'a>(unit: &'a TransientUnit, name: &str) -> &'a Variant<'static> {
        &unit
            .properties
            .iter()
            .find(|(key, _)| *key == name)
            .unwrap()
            .1
    }

    fn policy() -> ScriptPolicy {
        ScriptPolicy {
            policy_id: "test".to_string(),
            execution_uid: 12345,
            frequency: "30".to_string(),
            retries: 2,
            script: "#!/bin/sh\nexit 0\n".to_string(),
        }
    }

    #[test]
    fn schedules_preserve_calendar_boundaries() {
        for (frequency, calendar) in [
            ("15", "*-*-* *:00/15:00"),
            ("30", "*-*-* *:00/30:00"),
            ("60", "*-*-* *:00:00"),
            ("120", "*-*-* 00/2:00:00"),
            ("180", "*-*-* 00/3:00:00"),
            ("360", "*-*-* 00/6:00:00"),
            ("720", "*-*-* 00/12:00:00"),
            ("1440", "*-*-* 00:00:00"),
            ("10080", "Sun *-*-* 00:00:00"),
        ] {
            assert_eq!(calendar_schedule(frequency).unwrap(), calendar);
        }
        assert!(calendar_schedule("unknown").is_err());
    }

    #[test]
    fn policy_ids_cannot_escape_the_unit_name() {
        assert_eq!(
            policy_unit_name("0123-4567").unwrap(),
            "himmelblaud-policy@0123-4567"
        );
        for id in ["", "../other", "x/y", "x\nUser=root", "x%y", "x@y"] {
            assert!(policy_unit_name(id).is_err(), "{id:?}");
        }
    }

    #[test]
    fn transient_properties_preserve_settings_and_literal_paths() {
        let cache_dir = Path::new("/path with spaces/100%/\"cache\":$literal");
        let (timer, auxiliary) = policy_units(&policy(), cache_dir, true).unwrap();
        assert_eq!(timer.name, "himmelblaud-policy@test.timer");
        let calendars: Vec<(String, String)> = property(&timer, "TimersCalendar")
            .try_clone()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(
            calendars,
            vec![("OnCalendar".to_string(), "*-*-* *:00/30:00".to_string())]
        );
        assert!(!bool::try_from(property(&timer, "Persistent")).unwrap());
        assert_eq!(
            u64::try_from(property(&timer, "AccuracyUSec")).unwrap(),
            1_000_000
        );
        assert_eq!(auxiliary.len(), 1);
        let service = &auxiliary[0];
        assert_eq!(service.name, "himmelblaud-policy@test.service");
        assert_eq!(
            <&str>::try_from(property(service, "User")).unwrap(),
            "12345"
        );
        assert_eq!(
            u64::try_from(property(service, "TimeoutStartUSec")).unwrap(),
            u64::MAX
        );
        let directories: Vec<String> = property(service, "CacheDirectory")
            .try_clone()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(directories, ["himmelblau-policies"]);
        assert!(!service.properties.iter().any(|(name, _)| matches!(
            *name,
            "RuntimeDirectory" | "RuntimeDirectoryMode" | "BindPaths" | "BindReadOnlyPaths"
        )));
        let commands: Vec<(String, Vec<String>, bool)> = property(service, "ExecStart")
            .try_clone()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(commands.len(), 1);
        let wrapper = cache_dir.join("bin/policy_test_wrapper.sh");
        assert_eq!(commands[0].0, wrapper.to_str().unwrap());
        assert_eq!(commands[0].1, vec![commands[0].0.replace('$', "$$")]);
        assert!(!commands[0].2);

        let (timer, auxiliary) = policy_units(&policy(), cache_dir, false).unwrap();
        assert_eq!(timer.name, "himmelblaud-policy@test.timer");
        assert!(auxiliary.is_empty());
    }

    #[tokio::test]
    async fn startup_recreates_units_without_restarting_existing_ones() {
        let root = tempdir().unwrap();
        let cache = root.path().join("cache");
        let cron = root.path().join("cron");
        fs::create_dir(&cron).await.unwrap();
        fs::write(cron.join("policy_test"), "legacy cron job")
            .await
            .unwrap();
        let policy = policy();
        policy.save(&cache).await.unwrap();
        let systemd = FakeSystemd::default();

        restore_policies(&cache, &cron, &systemd).await.unwrap();
        assert!(systemd
            .unit_exists("himmelblaud-policy@test.timer")
            .await
            .unwrap());
        assert!(systemd
            .unit_exists("himmelblaud-policy@test.service")
            .await
            .unwrap());
        assert!(!cron.join("policy_test").exists());
        assert_eq!(
            ScriptPolicy::load(&policy.definition_path(&cache))
                .await
                .unwrap(),
            Some(policy.clone())
        );
        assert_eq!(
            fs::metadata(policy.definition_path(&cache))
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let script = cache.join("bin/policy_test_script.sh");
        fs::remove_file(&script).await.unwrap();
        restore_policies(&cache, &cron, &systemd).await.unwrap();
        assert_eq!(fs::read_to_string(&script).await.unwrap(), policy.script);
        let state = systemd.state.lock().unwrap();
        assert_eq!(state.starts.len(), 1);
        assert!(state.stops.is_empty());
    }

    #[tokio::test]
    async fn startup_repairs_either_missing_half_without_running_the_script() {
        for existing in ["timer", "service"] {
            let root = tempdir().unwrap();
            let cache = root.path().join("cache");
            let cron = root.path().join("cron");
            policy().save(&cache).await.unwrap();
            let systemd = FakeSystemd::default();
            let name = format!("himmelblaud-policy@test.{}", existing);
            systemd.state.lock().unwrap().units.insert(name);

            restore_policies(&cache, &cron, &systemd).await.unwrap();
            let state = systemd.state.lock().unwrap();
            assert!(state.units.contains("himmelblaud-policy@test.timer"));
            assert!(state.units.contains("himmelblaud-policy@test.service"));
            assert_eq!(state.starts.len(), 1);
            let (timer, auxiliary) = &state.starts[0];
            assert_eq!(timer.name, "himmelblaud-policy@test.timer");
            if existing == "service" {
                assert!(auxiliary.is_empty());
                assert!(state.stops.is_empty());
            } else {
                assert_eq!(state.stops, vec!["himmelblaud-policy@test.timer"]);
                assert_eq!(auxiliary.len(), 1);
                assert_eq!(auxiliary[0].name, "himmelblaud-policy@test.service");
            }
        }
    }

    #[tokio::test]
    async fn startup_reports_bad_definitions_and_restores_the_others() {
        let root = tempdir().unwrap();
        let cache = root.path().join("cache");
        let cron = root.path().join("cron");
        policy().save(&cache).await.unwrap();
        fs::write(cache.join("policy_broken.json"), "invalid json")
            .await
            .unwrap();
        let systemd = FakeSystemd::default();
        assert!(restore_policies(&cache, &cron, &systemd).await.is_err());
        assert!(systemd
            .unit_exists("himmelblaud-policy@test.timer")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn a_failed_unit_query_never_looks_like_a_missing_unit() {
        let root = tempdir().unwrap();
        let cache = root.path().join("cache");
        policy().save(&cache).await.unwrap();
        let systemd = FakeSystemd::default();
        systemd.state.lock().unwrap().fail_query = true;
        assert!(
            restore_policies(&cache, &root.path().join("cron"), &systemd)
                .await
                .is_err()
        );
        assert!(systemd.state.lock().unwrap().starts.is_empty());
    }

    #[test]
    fn only_execution_user_or_schedule_changes_require_new_units() {
        let old = policy();
        let mut new = old.clone();
        new.script = "new script".to_string();
        new.retries += 1;
        assert!(!new.unit_settings_changed(&old));
        new.execution_uid += 1;
        assert!(new.unit_settings_changed(&old));
        new.execution_uid = old.execution_uid;
        new.frequency = "60".to_string();
        assert!(new.unit_settings_changed(&old));
    }

    #[tokio::test]
    async fn execution_users_are_resolved_to_numeric_ids() {
        assert_eq!(user_id("root").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn directly_executed_cached_wrapper_retries_the_script() {
        let dir = tempdir().unwrap();
        let cache = dir.path().join("cache 'quoted' $literal");
        let counter = dir.path().join("attempts");
        let mut policy = policy();
        policy.script =
            "#!/bin/sh\necho attempt >> \"$COUNTER\"\n[ \"$(wc -l < \"$COUNTER\")\" -ge 3 ]\n"
                .to_string();
        policy.retries = 4;
        policy.materialize(&cache).await.unwrap();
        let (_, auxiliary) = policy_units(&policy, &cache, true).unwrap();
        let commands: Vec<(String, Vec<String>, bool)> = property(&auxiliary[0], "ExecStart")
            .try_clone()
            .unwrap()
            .downcast()
            .unwrap();
        let output = Command::new(&commands[0].0)
            .env("COUNTER", &counter)
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            fs::read_to_string(&counter).await.unwrap().lines().count(),
            3
        );
    }

    #[tokio::test]
    async fn cache_and_removal_errors_are_not_silenced() {
        let dir = tempdir().unwrap();
        assert!(PolicyCache::load(&dir.path().to_path_buf()).await.is_err());
        assert!(remove_if_exists(dir.path()).await.is_err());
        assert!(remove_if_exists(&dir.path().join("absent")).await.is_ok());
    }
}
