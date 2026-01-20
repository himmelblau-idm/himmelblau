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
use himmelblau::intune::{IntuneStatus, PolicyStatus};
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::POLICY_CACHE;
use himmelblau_unix_common::policy_cache::{PolicyCache, PolicyValue};
use os_release::OsRelease;
use semver::Version;
use tokio::fs;
use tokio::process::Command;
use tracing::debug;

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
    let parts: Vec<String> = version
        .split('.')
        .map(|p| {
            let stripped = p.trim_start_matches('0');
            if stripped.is_empty() {
                "0".to_string()
            } else {
                stripped.to_string()
            }
        })
        .collect();

    match parts.len() {
        0 => "0.0.0".to_string(), // fallback
        1 => format!("{}.0.0", parts[0]),
        2 => format!("{}.{}.0", parts[0], parts[1]),
        _ => format!("{}.{}.{}", parts[0], parts[1], parts[2]),
    }
}

pub struct ComplianceCSE {}

#[async_trait]
impl CSE for ComplianceCSE {
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
                id.starts_with("linux_distribution_")
                    || id.starts_with("linux_deviceencryption_")
                    || id.starts_with("linux_passwordpolicy_")
            }) {
                self.apply_compliance(policy).await?;
            }
        }
        Ok(true)
    }
}

impl ComplianceCSE {
    /// Applies the compliance checks for a given policy.
    ///
    /// If any check fails, an error is returned with details on the failure.
    async fn apply_compliance(&self, policy: &mut PolicyStatus) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();

        let os_release =
            OsRelease::new().map_err(|e| anyhow!("Failed to read /etc/os-release: {}", e))?;
        let system_distro = os_release.id;
        let system_version_str = normalize_version(&os_release.version_id);
        let system_version = Version::parse(&system_version_str).map_err(|e| {
            anyhow!(
                "Failed to parse system version '{}' as semver: {}",
                system_version_str,
                e
            )
        })?;
        let policy_cache = PolicyCache::new(POLICY_CACHE, true)?;

        for details in policy.details.iter_mut() {
            match details.setting_definition_item_id.as_str() {
                "linux_distribution_alloweddistros_item_$type" => {
                    if details.expected_value != system_distro {
                        errors.push(format!(
                            "Distribution compliance failed: system distro '{}' is not '{}'",
                            system_distro, details.expected_value
                        ));
                    } else {
                        details.new_compliance_state = "Compliant".to_string();
                        debug!("Distribution compliance passed: {}", system_distro);
                    }
                    details.actual_value = system_distro.clone();
                }
                "linux_distribution_alloweddistros_item_minimumversion" => {
                    // Skip check if no minimum version is specified
                    if details.expected_value.is_empty() {
                        details.new_compliance_state = "Compliant".to_string();
                        details.actual_value = os_release.version_id.clone();
                        debug!("Minimum version compliance skipped: no minimum specified");
                    } else {
                        let min_semver = Version::parse(&normalize_version(
                            &details.expected_value,
                        ))
                        .map_err(|e| {
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
                            debug!(
                                "Minimum version compliance passed: {}",
                                os_release.version_id
                            );
                        }
                        details.actual_value = os_release.version_id.clone();
                    }
                }
                "linux_distribution_alloweddistros_item_maximumversion" => {
                    // Skip check if no maximum version is specified
                    if details.expected_value.is_empty() {
                        details.new_compliance_state = "Compliant".to_string();
                        details.actual_value = os_release.version_id.clone();
                        debug!("Maximum version compliance skipped: no maximum specified");
                    } else {
                        let max_semver = Version::parse(&normalize_version(
                            &details.expected_value,
                        ))
                        .map_err(|e| {
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
                            debug!(
                                "Maximum version compliance passed: {}",
                                os_release.version_id
                            );
                        }
                        details.actual_value = os_release.version_id.clone();
                    }
                }
                "linux_deviceencryption_required" => {
                    let is_disk_encrypted = is_disk_encrypted().await;
                    if details.expected_value.to_lowercase() == "true" && !is_disk_encrypted {
                        errors.push(
                            "Device encryption compliance failed: encryption likely not enabled"
                                .to_string(),
                        );
                    } else {
                        details.new_compliance_state = "Compliant".to_string();
                        debug!(
                            "Device encryption compliance passed, encrypted?: {}",
                            is_disk_encrypted
                        );
                    }
                    details.actual_value = is_disk_encrypted.to_string();
                }
                "linux_passwordpolicy_minimumlength" => {
                    if let Ok(min_length) = details.expected_value.parse::<u32>() {
                        match policy_cache.set(
                            details.setting_definition_item_id.as_str(),
                            &PolicyValue::Int(min_length),
                        ) {
                            Ok(_) => {
                                details.actual_value = details.expected_value.clone();
                                details.new_compliance_state = "Compliant".to_string();
                                debug!(
                                    "Password policy compliance passed, min length: {}",
                                    min_length
                                );
                            }
                            Err(e) => {
                                errors.push(format!(
                                    "Failed to set minimum password length policy: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        errors.push("Failed to read minimum password length policy".to_string());
                    }
                }
                "linux_passwordpolicy_minimumdigits" => {
                    if let Ok(min_digits) = details.expected_value.parse::<u32>() {
                        match policy_cache.set(
                            details.setting_definition_item_id.as_str(),
                            &PolicyValue::Int(min_digits),
                        ) {
                            Ok(_) => {
                                details.actual_value = details.expected_value.clone();
                                details.new_compliance_state = "Compliant".to_string();
                                debug!(
                                    "Password policy compliance passed, min digits: {}",
                                    min_digits
                                );
                            }
                            Err(e) => {
                                errors.push(format!(
                                    "Failed to set minimum password digits policy: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        errors.push("Failed to read minimum password digits policy".to_string());
                    }
                }
                "linux_passwordpolicy_minimumlowercase" => {
                    if let Ok(min_lowercase) = details.expected_value.parse::<u32>() {
                        match policy_cache.set(
                            details.setting_definition_item_id.as_str(),
                            &PolicyValue::Int(min_lowercase),
                        ) {
                            Ok(_) => {
                                details.actual_value = details.expected_value.clone();
                                details.new_compliance_state = "Compliant".to_string();
                                debug!(
                                    "Password policy compliance passed, min lowercase: {}",
                                    min_lowercase
                                );
                            }
                            Err(e) => {
                                errors.push(format!(
                                    "Failed to set minimum password lowercase policy: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        errors.push("Failed to read minimum password lowercase policy".to_string());
                    }
                }
                "linux_passwordpolicy_minimumsymbols" => {
                    if let Ok(min_symbols) = details.expected_value.parse::<u32>() {
                        match policy_cache.set(
                            details.setting_definition_item_id.as_str(),
                            &PolicyValue::Int(min_symbols),
                        ) {
                            Ok(_) => {
                                details.actual_value = details.expected_value.clone();
                                details.new_compliance_state = "Compliant".to_string();
                                debug!(
                                    "Password policy compliance passed, min symbols: {}",
                                    min_symbols
                                );
                            }
                            Err(e) => {
                                errors.push(format!(
                                    "Failed to set minimum password symbols policy: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        errors.push("Failed to read minimum password symbols policy".to_string());
                    }
                }
                "linux_passwordpolicy_minimumuppercase" => {
                    if let Ok(min_uppercase) = details.expected_value.parse::<u32>() {
                        match policy_cache.set(
                            details.setting_definition_item_id.as_str(),
                            &PolicyValue::Int(min_uppercase),
                        ) {
                            Ok(_) => {
                                details.actual_value = details.expected_value.clone();
                                details.new_compliance_state = "Compliant".to_string();
                                debug!(
                                    "Password policy compliance compliance passed, min uppercase: {}",
                                    min_uppercase
                                );
                            }
                            Err(e) => {
                                errors.push(format!(
                                    "Failed to set minimum password uppercase policy: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        errors.push("Failed to read minimum password uppercase policy".to_string());
                    }
                }
                unknown => {
                    errors.push(format!("Unrecognized compliance option '{}'", unknown));
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
