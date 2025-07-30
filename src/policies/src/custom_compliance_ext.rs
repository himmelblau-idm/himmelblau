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

fn execute_script(script: &str) -> Result<String> {
    // Create a temporary file
    let mut file = NamedTempFile::new().context("Failed to create temp file")?;

    // Write the script contents
    file.write_all(script.as_bytes())
        .context("Failed to write script to temp file")?;

    // Make it executable
    let mut perms: Permissions = file.as_file().metadata()?.permissions();
    perms.set_mode(0o700);
    file.as_file().set_permissions(perms)?;

    // Execute the script
    let output = Command::new(file.path())
        .output()
        .context("Failed to execute script")?;

    // Capture the path before dropping
    let path = file.path().to_path_buf();

    // Close and remove the file
    drop(file);

    // Manually delete the file in case it wasn’t removed by drop
    let _ = fs::remove_file(&path);

    if !output.status.success() {
        anyhow::bail!(
            "Script failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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
        for policy in policies.policy_statuses.iter_mut() {
            // Validate this is a compliance policy
            if policy.details.iter().any(|detail| {
                let id = &detail.setting_definition_item_id;
                id == "linux_customcompliance_discoveryscript"
            }) {
                self.apply_compliance(policy).await?;
            }
        }
        Ok(true)
    }
}

impl CustomComplianceCSE {
    /// Applies the compliance checks for a given policy.
    ///
    /// If any check fails, an error is returned with details on the failure.
    async fn apply_compliance(&self, policy: &mut PolicyStatus) -> Result<()> {
        for policy_detail in policy.details.iter_mut() {
            let script = String::from_utf8(
                STANDARD
                    .decode(policy_detail.expected_value.clone())
                    .map_err(|e| anyhow!("Failed to decode script: {}", e))?,
            )
            .map_err(|e| anyhow!("Failed to decode script: {}", e))?;
            let output = execute_script(&script)?;
            policy_detail.set_status(
                Some("Unknown".to_string()),
                Some(output),
                &ComplianceState::Unknown,
            );
        }
        Ok(())
    }
}
