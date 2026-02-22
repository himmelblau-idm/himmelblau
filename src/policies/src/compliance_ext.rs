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
use himmelblau::intune::{IntuneStatus, PolicyDetails, PolicyStatus};
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::POLICY_CACHE;
use himmelblau_unix_common::policy_cache::{PolicyCache, PolicyValue};
use os_release::OsRelease;
use semver::Version;
use std::collections::HashMap;
use tokio::fs;
use tokio::process::Command;
use tracing::{debug, warn};

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
    /// For changed policies, run compliance checks and report status.
    async fn process_group_policy(&self, policies: &mut IntuneStatus) -> Result<bool> {
        let mut errors = vec![];
        debug!(
            num_policies = policies.policy_statuses.len(),
            "ComplianceCSE: checking policies for compliance settings"
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
                "ComplianceCSE: inspecting policy details"
            );
            // Validate this is a compliance policy
            if policy.details.iter().any(|detail| {
                let id = &detail.setting_definition_item_id;
                id.starts_with("linux_distribution_")
                    || id.starts_with("linux_deviceencryption_")
                    || id.starts_with("linux_passwordpolicy_")
            }) {
                if let Err(e) = self.apply_compliance(policy).await {
                    errors.push(format!(
                        "Policy {}: {}",
                        policy.policy_id, e
                    ));
                }
            }
        }
        if errors.is_empty() {
            Ok(true)
        } else {
            Err(anyhow!("Compliance processing errors: {}", errors.join("; ")))
        }
    }
}

/// Extract the distro group index from a CSP path.
///
/// Expected format: `<provider>/Distribution/AllowedDistros/<index>/<setting>`
/// e.g., `"com.microsoft.manage.LinuxMdm/Distribution/AllowedDistros/1/$type"` → `"1"`
fn extract_distro_index(csp_path: &str) -> Option<&str> {
    let parts: Vec<&str> = csp_path.split('/').collect();
    if parts.len() >= 5 && parts[1] == "Distribution" && parts[2] == "AllowedDistros" {
        Some(parts[3])
    } else {
        None
    }
}

impl ComplianceCSE {
    /// Applies the compliance checks for a given policy.
    ///
    /// Sets actual_value and new_compliance_state for each policy detail.
    /// NonCompliant findings are NOT errors — they are valid compliance states
    /// reported back to Intune. Only genuine processing failures (cache errors,
    /// parse failures) are treated as errors.
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

        // Handle distribution compliance with proper grouping
        // (groups by CSP path index)
        Self::apply_distribution_compliance(
            &mut policy.details,
            &system_distro,
            &os_release.version_id,
            &system_version,
        );

        // Handle non-distribution compliance settings
        for details in policy.details.iter_mut() {
            match details.setting_definition_item_id.as_str() {
                // Distribution settings are handled above
                s if s.starts_with("linux_distribution_") => continue,
                "linux_deviceencryption_required" => {
                    let is_disk_encrypted = is_disk_encrypted().await;
                    details.actual_value = is_disk_encrypted.to_string();
                    if details.expected_value.to_lowercase() != "true" || is_disk_encrypted {
                        details.new_compliance_state = "Compliant".to_string();
                        debug!(
                            "Device encryption compliance passed, encrypted?: {}",
                            is_disk_encrypted
                        );
                    } else {
                        debug!("Device encryption compliance: encryption not enabled");
                    }
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
                                    "Password policy compliance passed, min uppercase: {}",
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
                    warn!("Unrecognized compliance option '{}'", unknown);
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow!("Compliance check failures: {}", errors.join("; ")))
        }
    }

    /// Handle distribution compliance with proper grouping by CSP path index. There might be
    /// multiple distribution groups (e.g., AllowedDistros/1/*, AllowedDistros/2/*) in the same
    /// policy, and we shouldn't return NonCompliant for settings that don't match the system distro
    /// if another group does match. The logic is:
    ///
    /// This allows enrolling with policy enforcement and CA:
    /// - Settings are grouped by their CSP path distro index (e.g., AllowedDistros/1/*, AllowedDistros/2/*)
    /// - If any group matches the system distro, matching groups are evaluated normally
    ///   and non-matching groups are marked as "not applicable" (Compliant)
    /// - If no group matches, all $type entries get NonCompliant and version entries
    ///   get "not applicable" (Compliant)
    fn apply_distribution_compliance(
        details: &mut [PolicyDetails],
        system_distro: &str,
        version_id: &str,
        system_version: &Version,
    ) {
        // Group distribution settings by CSP path distro index
        let mut distro_groups: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, detail) in details.iter().enumerate() {
            if detail
                .setting_definition_item_id
                .starts_with("linux_distribution_")
            {
                if let Some(index) = extract_distro_index(&detail.csp_path) {
                    distro_groups
                        .entry(index.to_string())
                        .or_default()
                        .push(i);
                }
            }
        }

        if distro_groups.is_empty() {
            return;
        }

        // Check if any group has a matching distro
        let has_matching_distro = distro_groups.values().any(|indices| {
            indices.iter().any(|&i| {
                details[i].setting_definition_item_id
                    == "linux_distribution_alloweddistros_item_$type"
                    && details[i]
                        .expected_value
                        .eq_ignore_ascii_case(system_distro)
            })
        });

        debug!(
            num_distro_groups = distro_groups.len(),
            has_matching_distro, system_distro,
            "Distribution compliance: grouped settings"
        );

        // Process each distro group
        for indices in distro_groups.values() {
            let group_matches = indices.iter().any(|&i| {
                details[i].setting_definition_item_id
                    == "linux_distribution_alloweddistros_item_$type"
                    && details[i]
                        .expected_value
                        .eq_ignore_ascii_case(system_distro)
            });

            for &i in indices {
                if group_matches {
                    // This distro group matches — evaluate normally
                    Self::evaluate_distro_detail(
                        &mut details[i],
                        system_distro,
                        version_id,
                        system_version,
                    );
                } else if has_matching_distro {
                    // Not applicable: another distro group matches the system
                    debug!(
                        "Distribution rule not applicable: {} = {}",
                        details[i].setting_definition_item_id, details[i].expected_value
                    );
                    details[i].actual_value = "".to_string();
                    details[i].new_compliance_state = "Compliant".to_string();
                    details[i].old_compliance_state = "Compliant".to_string();
                } else {
                    // Unsupported: no distro group matches at all
                    if details[i].setting_definition_item_id
                        == "linux_distribution_alloweddistros_item_$type"
                    {
                        // Report the actual distro as NonCompliant
                        details[i].actual_value = system_distro.to_string();
                        // Stays as default NonCompliant
                    } else {
                        // Version constraints for unsupported distro: not applicable
                        details[i].actual_value = "".to_string();
                        details[i].new_compliance_state = "Compliant".to_string();
                        details[i].old_compliance_state = "Compliant".to_string();
                    }
                }
            }
        }
    }

    /// Evaluate a single distribution detail for a matching distro group.
    fn evaluate_distro_detail(
        detail: &mut PolicyDetails,
        system_distro: &str,
        version_id: &str,
        system_version: &Version,
    ) {
        match detail.setting_definition_item_id.as_str() {
            "linux_distribution_alloweddistros_item_$type" => {
                detail.actual_value = system_distro.to_string();
                if detail.expected_value.eq_ignore_ascii_case(system_distro) {
                    detail.new_compliance_state = "Compliant".to_string();
                    debug!("Distribution compliance passed: {}", system_distro);
                } else {
                    detail.new_compliance_state = "NonCompliant".to_string();
                    debug!(
                        "Distribution compliance: system distro '{}' is not '{}'",
                        system_distro, detail.expected_value
                    );
                }
            }
            "linux_distribution_alloweddistros_item_minimumversion" => {
                detail.actual_value = version_id.to_string();
                if detail.expected_value.is_empty() {
                    detail.new_compliance_state = "Compliant".to_string();
                    debug!("Minimum version compliance skipped: no minimum specified");
                } else {
                    match Version::parse(&normalize_version(&detail.expected_value)) {
                        Ok(min_ver) => {
                            if system_version >= &min_ver {
                                detail.new_compliance_state = "Compliant".to_string();
                                debug!(
                                    "Minimum version compliance passed: {} >= {}",
                                    version_id, min_ver
                                );
                            } else {
                                detail.actual_value = system_version.to_string();
                                detail.new_compliance_state = "NonCompliant".to_string();
                                debug!(
                                    "Minimum version compliance failed: {} < {}",
                                    system_version, min_ver
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to parse min version '{}': {}",
                                detail.expected_value, e
                            );
                            detail.new_compliance_state = "Error".to_string();
                        }
                    }
                }
            }
            "linux_distribution_alloweddistros_item_maximumversion" => {
                detail.actual_value = version_id.to_string();
                if detail.expected_value.is_empty() {
                    detail.new_compliance_state = "Compliant".to_string();
                    debug!("Maximum version compliance skipped: no maximum specified");
                } else {
                    match Version::parse(&normalize_version(&detail.expected_value)) {
                        Ok(max_ver) => {
                            if system_version <= &max_ver {
                                detail.new_compliance_state = "Compliant".to_string();
                                debug!(
                                    "Maximum version compliance passed: {} <= {}",
                                    version_id, max_ver
                                );
                            } else {
                                detail.actual_value = system_version.to_string();
                                detail.new_compliance_state = "NonCompliant".to_string();
                                debug!(
                                    "Maximum version compliance failed: {} > {}",
                                    system_version, max_ver
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to parse max version '{}': {}",
                                detail.expected_value, e
                            );
                            detail.new_compliance_state = "Error".to_string();
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
