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
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use himmelblau::intune::IntuneStatus;
use himmelblau_unix_common::config::HimmelblauConfig;
use os_release::OsRelease;
use semver::Version;
use tokio::fs;
use tokio::process::Command;

pub async fn is_disk_encrypted() -> bool {
    // Check for LUKS encryption using `lsblk`
    if let Ok(output) = Command::new("lsblk")
        .arg("-o")
        .arg("NAME,FSTYPE")
        .output()
        .await
    {
        if let Ok(output_str) = String::from_utf8(output.stdout) {
            if output_str.contains("crypt") {
                return true;
            }
        }
    }

    // Check for entries in `/etc/crypttab`
    if let Ok(crypttab) = fs::read_to_string("/etc/crypttab").await {
        if !crypttab.trim().is_empty() {
            return true;
        }
    }

    // Check for mapped encrypted volumes in `/dev/mapper`
    if let Ok(entries) = fs::read_dir("/dev/mapper").await {
        let mut entries = entries;
        while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
            if let Some(name_str) = entry.file_name().to_str() {
                if name_str.contains("crypt") {
                    return true;
                }
            }
        }
    }

    // Check for `dm-crypt` devices using `lsblk`
    if let Ok(output) = Command::new("lsblk")
        .arg("-o")
        .arg("NAME,TYPE,MOUNTPOINT")
        .output()
        .await
    {
        if let Ok(output_str) = String::from_utf8(output.stdout) {
            if output_str.contains("dm-crypt") {
                return true;
            }
        }
    }

    // No disk encryption detected
    false
}

fn normalize_version(version: &str) -> String {
    let parts: Vec<&str> = version.split('.').collect();
    match parts.len() {
        0 => version.to_string(), // Shouldn't happen.
        1 => format!("{}.0.0", version),
        2 => format!("{}.0", version),
        _ => version.to_string(),
    }
}

pub struct ComplianceCSE {
    config: HimmelblauConfig,
}

#[async_trait]
impl CSE for ComplianceCSE {
    fn new(config: &HimmelblauConfig, _username: &str) -> Self {
        ComplianceCSE {
            config: config.clone(),
        }
    }

    /// Process a group of policies. For deleted policies, no action is taken.
    /// For changed policies, run compliance checks and return an error if any check fails.
    async fn process_group_policy(&self, policies: &mut IntuneStatus) -> Result<bool> {
        self.apply_compliance(policies).await?;
        Ok(true)
    }
}

impl ComplianceCSE {
    /// Applies the compliance checks for a given policy.
    ///
    /// If any check fails, an error is returned with details on the failure.
    async fn apply_compliance(&self, policy: &mut IntuneStatus) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();

        let os_release = OsRelease::new()?;
        let system_distro = os_release.id;
        let system_version_str = normalize_version(&os_release.version_id);
        let system_version = Version::parse(&system_version_str).map_err(|e| {
            anyhow!(
                "Failed to parse system version '{}' as semver: {}",
                system_version_str,
                e
            )
        })?;

        for setting in policy.policy_statuses.iter_mut() {
            for details in setting.details.iter_mut() {
                match details.setting_definition_item_id.as_str() {
                    "linux_distribution_alloweddistros_item_$type" => {
                        if details.expected_value != system_distro {
                            errors.push(format!(
                                "Distribution compliance failed: system distro '{}' is not '{}'",
                                system_distro, details.expected_value
                            ));
                        } else {
                            details.new_compliance_state = "Compliant".to_string();
                        }
                        details.actual_value = system_distro.clone();
                    }
                    "linux_distribution_alloweddistros_item_minimumversion" => {
                        let min_semver = Version::parse(&details.expected_value).map_err(|e| {
                            anyhow!(
                                "Failed to parse minimum version '{}' as semver: {}",
                                details.expected_value,
                                e
                            )
                        })?;
                        if system_version < min_semver {
                            errors.push(format!(
                                "Version compliance failed: system version '{}' is less than minimum '{}'",
                                system_version, min_semver
                            ));
                        } else {
                            details.new_compliance_state = "Compliant".to_string();
                        }
                        details.actual_value = system_version_str.clone();
                    }
                    "linux_distribution_alloweddistros_item_maximumversion" => {
                        let max_semver = Version::parse(&details.expected_value).map_err(|e| {
                            anyhow!(
                                "Failed to parse maximum version '{}' as semver: {}",
                                details.expected_value,
                                e
                            )
                        })?;
                        if system_version > max_semver {
                            errors.push(format!(
                                "Version compliance failed: system version '{}' is greater than maximum '{}'",
                                system_version, max_semver
                            ));
                        } else {
                            details.new_compliance_state = "Compliant".to_string();
                        }
                        details.actual_value = system_version_str.clone();
                    }
                    "linux_deviceencryption_required" => {
                        let is_disk_encrypted = is_disk_encrypted().await;
                        if details.expected_value.to_lowercase() == "true" && !is_disk_encrypted {
                            errors.push("Device encryption compliance failed: encryption likely not enabled".to_string());
                        } else {
                            details.new_compliance_state = "Compliant".to_string();
                        }
                        details.actual_value = is_disk_encrypted.to_string();
                    }
                    "linux_passwordpolicy_minimumlength" => {
                        let system_min_length = self.config.get_hello_pin_min_length();
                        if let Ok(min_length) = details.expected_value.parse::<u32>() {
                            if system_min_length < min_length as usize {
                                errors.push(format!(
                                    "Password policy compliance failed: system minimum length {} is less than required {}",
                                    system_min_length, min_length
                                ));
                            } else {
                                details.new_compliance_state = "Compliant".to_string();
                            }
                        } else {
                            errors
                                .push("Failed to read minimum password length policy".to_string());
                        }
                        details.actual_value = system_min_length.to_string();
                    }
                    unknown => {
                        errors.push(format!("Unrecognized compliance option '{}'", unknown));
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow!("Compliance check failures: {}", errors.join("; ")))
        }
    }
}
