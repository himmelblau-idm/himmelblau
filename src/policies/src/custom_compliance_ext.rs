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
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use himmelblau::intune::{ComplianceState, IntuneStatus, PolicyStatus};
use himmelblau_unix_common::{
    config::HimmelblauConfig,
    systemd_api::{Systemd, TransientUnit, UnitOutput, Variant},
};
use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempPath};
use tokio::sync::Mutex;
use tracing::{debug, error};

const SCRIPT_TIMEOUT: Duration = Duration::from_secs(60);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(75);
const COMPLIANCE_UNIT: &str = "himmelblaud-tasks-compliance.service";
const CAP_DAC_READ_SEARCH_MASK: u64 = 1 << 2;
static COMPLIANCE_UNIT_LOCK: Mutex<()> = Mutex::const_new(());

fn compliance_unit(
    script_path: &Path,
    has_shebang: bool,
    systemd_version: u32,
) -> Result<TransientUnit> {
    if systemd_version < 239 {
        anyhow::bail!("Systemd 239 or newer is required for compliance scripts");
    }
    let path = script_path
        .to_str()
        .context("Compliance script path is not UTF-8")?;
    if !script_path.is_absolute() {
        anyhow::bail!("Compliance script path must be absolute");
    }
    let executable = if has_shebang { path } else { "/bin/sh" }.to_string();
    let mut argv = vec![executable.replace('$', "$$")];
    if !has_shebang {
        argv.push(path.replace('$', "$$"));
    }
    let mut environment = Vec::new();
    for name in ["PATH", "LOCALE_ARCHIVE", "TZDIR"] {
        match std::env::var(name) {
            Ok(value) => environment.push(format!("{}={}", name, value)),
            Err(std::env::VarError::NotPresent) if name != "PATH" => {}
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("Failed to read script environment {}", name));
            }
        }
    }
    let mut unit = TransientUnit {
        name: COMPLIANCE_UNIT.to_string(),
        properties: vec![
            ("Description", "Himmelblau Custom Compliance".into()),
            ("Type", "oneshot".into()),
            ("User", "root".into()),
            ("CollectMode", "inactive-or-failed".into()),
            (
                "TimeoutStartUSec",
                (SCRIPT_TIMEOUT.as_secs() * 1_000_000).into(),
            ),
            ("TimeoutStopUSec", 5_000_000u64.into()),
            ("KillMode", "control-group".into()),
            ("SendSIGKILL", true.into()),
            ("NoNewPrivileges", true.into()),
            ("PrivateTmp", true.into()),
            ("PrivateDevices", true.into()),
            ("ProtectSystem", "strict".into()),
            ("ProtectKernelTunables", true.into()),
            ("ProtectKernelModules", true.into()),
            ("ProtectControlGroups", true.into()),
            ("MemoryDenyWriteExecute", true.into()),
            // The policy cache is packaged as mode 0600, so loading the script needs search bypass.
            ("CapabilityBoundingSet", CAP_DAC_READ_SEARCH_MASK.into()),
            (
                "InaccessiblePaths",
                // Without CAP_SYS_ADMIN, mokutil must fall back to efivarfs.
                Variant::new(vec!["-/sys/firmware/efi/mok-variables"]),
            ),
            ("Environment", Variant::new(environment)),
            // Ignore script exit codes, but not a unit startup failure or timeout.
            ("ExecStart", Variant::new(vec![(executable, argv, true)])),
        ],
    };
    if systemd_version >= 242 {
        unit.properties.push(("ProtectHostname", true.into()));
    }
    if systemd_version >= 244 {
        unit.properties.push(("ProtectKernelLogs", true.into()));
    }
    if systemd_version >= 245 {
        unit.properties.push(("ProtectClock", true.into()));
    }
    Ok(unit)
}

fn prepare_script(script: &[u8], directory: &Path) -> Result<(TempPath, bool)> {
    let (contents, has_shebang) = match std::str::from_utf8(script) {
        Ok(text) => {
            let normalized = text.replace("\r\n", "\n");
            let shebang = normalized.starts_with("#!");
            (normalized.into_bytes(), shebang)
        }
        Err(_) => (script.to_vec(), false),
    };

    // The tasks daemon has PrivateTmp: the new unit cannot see its /tmp.
    std::fs::create_dir_all(directory).context("Failed to create policy script directory")?;
    let mut file = NamedTempFile::new_in(directory).context("Failed to create temp file")?;
    file.write_all(&contents)
        .context("Failed to write script")?;
    file.flush().context("Failed to flush script")?;
    file.as_file()
        .set_permissions(Permissions::from_mode(0o500))?;

    // Close the writable descriptor before PID 1 executes the script (ETXTBSY).
    Ok((file.into_temp_path(), has_shebang))
}

async fn execute_script(script: Vec<u8>, directory: PathBuf) -> Result<String> {
    let _guard = COMPLIANCE_UNIT_LOCK.lock().await;
    let systemd = Systemd::default();
    let version = systemd.version().await?;
    let (temp_path, has_shebang) =
        tokio::task::spawn_blocking(move || prepare_script(&script, &directory))
            .await
            .context("Compliance script preparation failed")??;
    let unit = compliance_unit(&temp_path, has_shebang, version)?;
    let started = Instant::now();
    let outcome = systemd.run_with_output(unit, CLIENT_TIMEOUT).await;
    let cleanup = temp_path
        .close()
        .context("Failed to remove temporary compliance script");
    let output = match (outcome, cleanup) {
        (Ok(output), Ok(())) => output,
        (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
        (Err(error), Err(cleanup)) => {
            return Err(error.context(format!("Script cleanup also failed: {cleanup:#}")));
        }
    };
    debug!(
        job_result = %output.job_result,
        service_result = %output.service_result,
        elapsed_ms = started.elapsed().as_millis(),
        stdout_len = output.stdout.len(),
        stderr_len = output.stderr.len(),
        "Custom compliance unit finished"
    );
    script_output(&output)
}

fn script_output(output: &UnitOutput) -> Result<String> {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.success() {
        anyhow::bail!(
            "{COMPLIANCE_UNIT} failed (job: {}, service: {}): {}",
            output.job_result,
            output.service_result,
            stderr
        );
    }
    if !stderr.is_empty() {
        debug!(stderr = %stderr, "Custom compliance script stderr");
    }
    if stdout.is_empty() {
        if stderr.is_empty() {
            anyhow::bail!("No output returned from script");
        } else {
            anyhow::bail!("Script returned no stdout: {}", stderr);
        }
    }
    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&stdout)
        .context("Output is not well-formed json")?;
    Ok(stdout)
}

pub struct CustomComplianceCSE {
    script_directory: PathBuf,
}

#[async_trait]
impl CSE for CustomComplianceCSE {
    fn new(config: &HimmelblauConfig, _username: &str) -> Self {
        Self {
            script_directory: PathBuf::from(config.get_policies_db_path()).join("bin"),
        }
    }

    /// Process a group of policies. For deleted policies, no action is taken.
    /// For changed policies, run compliance checks and return an error if any check fails.
    async fn process_group_policy(&self, policies: &mut IntuneStatus) -> Result<bool> {
        debug!(
            num_policies = policies.policy_statuses.len(),
            "CustomComplianceCSE: checking policies for custom compliance"
        );
        for policy in policies.policy_statuses.iter_mut() {
            let detail_ids: Vec<&str> = policy
                .details
                .iter()
                .map(|d| d.setting_definition_item_id.as_str())
                .collect();
            debug!(
                policy_id = %policy.policy_id,
                ?detail_ids,
                "CustomComplianceCSE: inspecting policy details"
            );
            if policy.details.iter().any(|detail| {
                detail.setting_definition_item_id == "linux_customcompliance_discoveryscript"
            }) {
                debug!(
                    policy_id = %policy.policy_id,
                    "CustomComplianceCSE: matched custom compliance policy, applying"
                );
                self.apply_compliance(policy).await;
            } else {
                debug!(
                    policy_id = %policy.policy_id,
                    "CustomComplianceCSE: not a custom compliance policy, skipping"
                );
            }
        }
        Ok(true)
    }
}

impl CustomComplianceCSE {
    async fn apply_compliance(&self, policy: &mut PolicyStatus) {
        let script_detail = policy
            .details
            .iter_mut()
            .find(|d| d.setting_definition_item_id == "linux_customcompliance_discoveryscript");
        let Some(detail) = script_detail else {
            debug!(
                policy_id = %policy.policy_id,
                "CustomComplianceCSE: no discovery script detail found in policy"
            );
            return;
        };
        debug!(
            policy_id = %policy.policy_id,
            expected_value_len = detail.expected_value.len(),
            "CustomComplianceCSE: found discovery script, decoding and executing"
        );
        let decoded = (|| -> Result<Vec<u8>> {
            let decoded = STANDARD
                .decode(detail.expected_value.clone())
                .map_err(|e| anyhow!("Failed to decode CSE: {}", e))?;
            if let Ok(script) = std::str::from_utf8(&decoded) {
                debug!(
                    policy_id = %policy.policy_id,
                    script = %script,
                    "CustomComplianceCSE: decoded discovery CSE content"
                );
            } else {
                debug!(
                    policy_id = %policy.policy_id,
                    len = decoded.len(),
                    "CustomComplianceCSE: decoded binary discovery CSE content"
                );
            }
            Ok(decoded)
        })();
        let result = match decoded {
            Ok(decoded) => execute_script(decoded, self.script_directory.clone()).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(output) => {
                debug!(
                    policy_id = %policy.policy_id,
                    output = %output,
                    "CustomComplianceCSE: script executed successfully"
                );
                detail.set_status(
                    Some("Unknown".to_string()),
                    Some(output),
                    &ComplianceState::Unknown,
                );
            }
            Err(e) => {
                error!(
                    policy_id = %policy.policy_id,
                    error = %format!("{e:#}"),
                    "CustomComplianceCSE: script execution failed"
                );
                detail.set_status(
                    Some("Error".to_string()),
                    Some(format!("{e:#}")),
                    &ComplianceState::Error,
                );
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn property<'a>(unit: &'a TransientUnit, name: &str) -> &'a Variant<'static> {
        &unit
            .properties
            .iter()
            .find(|(key, _)| *key == name)
            .expect("property")
            .1
    }

    #[test]
    fn sandbox_properties_are_gated_for_older_systemd_versions() {
        for version in [239, 241, 242, 243, 244, 245, 257] {
            let unit = compliance_unit(Path::new("/shared/script"), true, version).expect("unit");
            for (name, minimum) in [
                ("ProtectHostname", 242),
                ("ProtectKernelLogs", 244),
                ("ProtectClock", 245),
            ] {
                assert_eq!(
                    unit.properties.iter().any(|(key, _)| *key == name),
                    version >= minimum,
                    "{name} on systemd {version}"
                );
            }
        }
        assert!(compliance_unit(Path::new("/shared/script"), true, 238).is_err());
    }

    #[test]
    fn discovery_uses_the_fixed_unit_and_native_execution_properties() {
        let path = Path::new("/shared/${literal}/script with spaces");
        for shebang in [false, true] {
            let unit = compliance_unit(path, shebang, 257).expect("unit");
            assert_eq!(unit.name, COMPLIANCE_UNIT);
            assert_eq!(
                <&str>::try_from(property(&unit, "Type")).expect("type"),
                "oneshot"
            );
            assert_eq!(
                u64::try_from(property(&unit, "TimeoutStartUSec")).expect("timeout"),
                60_000_000
            );
            assert_eq!(
                u64::try_from(property(&unit, "TimeoutStopUSec")).expect("timeout"),
                5_000_000
            );
            assert_eq!(
                <&str>::try_from(property(&unit, "KillMode")).expect("kill mode"),
                "control-group"
            );
            let commands: Vec<(String, Vec<String>, bool)> = property(&unit, "ExecStart")
                .try_clone()
                .expect("clone")
                .downcast()
                .expect("commands");
            assert_eq!(commands.len(), 1);
            assert!(commands[0].2);
            assert_eq!(
                commands[0].0,
                if shebang {
                    path.to_str().expect("path")
                } else {
                    "/bin/sh"
                }
            );
            assert_eq!(
                commands[0].1.last().expect("script argument"),
                "/shared/$${literal}/script with spaces"
            );
        }
    }

    #[test]
    fn discovery_tempfile_is_shared_executable_and_normalized() {
        let dir = tempdir().expect("tempdir");
        let (path, shebang) =
            prepare_script(b"#!/bin/sh\r\necho '{}'\r\n", dir.path()).expect("prepare");
        assert!(shebang);
        assert_eq!(path.parent(), Some(dir.path()));
        assert_eq!(
            fs::read(&path).expect("contents"),
            b"#!/bin/sh\necho '{}'\n"
        );
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o500
        );
        let name = path.to_path_buf();
        path.close().expect("cleanup");
        assert!(!name.exists());
    }

    #[test]
    fn unit_failure_is_not_reported_as_successful_json() {
        let output = UnitOutput {
            job_result: "failed".to_string(),
            service_result: "timeout".to_string(),
            stdout: b"{}".to_vec(),
            stderr: b"unit timed out".to_vec(),
        };
        let error = script_output(&output).expect_err("unit failure");
        assert!(error.to_string().contains("unit timed out"));
    }

    #[test]
    fn output_must_be_a_json_object() {
        let mut output = UnitOutput {
            job_result: "done".to_string(),
            service_result: "success".to_string(),
            stdout: b"{\"ok\":true}\n".to_vec(),
            stderr: Vec::new(),
        };
        assert_eq!(
            script_output(&output).expect("json").trim(),
            "{\"ok\":true}"
        );
        for stdout in ["[]", "invalid", ""] {
            output.stdout = stdout.as_bytes().to_vec();
            assert!(script_output(&output).is_err());
        }
    }
}
