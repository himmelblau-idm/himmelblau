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
use himmelblau_unix_common::config::HimmelblauConfig;
use std::fs::{self, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::NamedTempFile;
use tracing::{debug, error};

fn execute_script(script: &[u8]) -> Result<String> {
    // Check if the content is valid UTF-8 text and, if so, whether it
    // starts with a shebang.  When a shebang is present the file is
    // executed directly (the kernel honours the interpreter line);
    // otherwise it is run via /bin/sh.
    let (contents, has_shebang) = match std::str::from_utf8(script) {
        Ok(text) => {
            // Normalize Windows line endings for text content
            let normalized = text.replace("\r\n", "\n");
            let shebang = normalized.starts_with("#!");
            (normalized.into_bytes(), shebang)
        }
        Err(_) => (script.to_vec(), false),
    };

    // Create a temporary file
    let mut file = NamedTempFile::new().context("Failed to create temp file")?;

    // Write the script contents
    file.write_all(&contents)
        .context("Failed to write script to temp file")?;

    // Make it executable
    let mut perms: Permissions = file.as_file().metadata()?.permissions();
    perms.set_mode(0o500);
    file.as_file().set_permissions(perms)?;

    // Execute: directly if it has a shebang, via /bin/sh otherwise
    let output = if has_shebang {
        Command::new(file.path())
            .output()
            .context("Failed to execute script directly")?
    } else {
        Command::new("/bin/sh")
            .arg(file.path())
            .output()
            .context("Failed to execute script via /bin/sh")?
    };

    // Capture the path before dropping
    let path = file.path().to_path_buf();

    // Close and remove the file
    drop(file);

    // Manually delete the file in case it wasn’t removed by drop
    let _ = fs::remove_file(&path);

    // Ignores exit codes as the scripts might be of dubious quality, only check stdout
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    debug!(
        exit_code = ?output.status.code(),
        stdout_len = stdout.len(),
        stderr_len = stderr.len(),
        "Custom compliance script execution finished"
    );
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

    // Validate that the output is well-formed JSON
    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&stdout)
        .context("Output is not well-formed json")?;

    Ok(stdout)
}

pub struct CustomComplianceCSE {}

#[async_trait]
impl CSE for CustomComplianceCSE {
    fn new(_config: &HimmelblauConfig, _username: &str) -> Self {
        Self {}
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
            // Validate this is a compliance policy
            if policy.details.iter().any(|detail| {
                let id = &detail.setting_definition_item_id;
                id == "linux_customcompliance_discoveryscript"
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
    /// Applies the compliance checks for a given policy.
    ///
    /// Finds the discovery script detail, decodes and executes it, then
    /// sets the status on that detail. On error, sets an error status
    /// instead of aborting the entire policy evaluation.
    async fn apply_compliance(&self, policy: &mut PolicyStatus) {
        // Find the discovery script detail
        let script_detail = policy.details.iter_mut().find(|d| {
            d.setting_definition_item_id == "linux_customcompliance_discoveryscript"
        });

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

        // Decode and execute the script
        let result = (|| -> Result<String> {
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
            execute_script(&decoded)
        })();

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
