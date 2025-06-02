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
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use himmelblau::intune::{IntuneStatus, PolicyStatus};
use himmelblau_unix_common::config::HimmelblauConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::debug;

/// A simple persistent cache mapping usernames to the set of applied policy IDs.
#[derive(Serialize, Deserialize, Default)]
pub struct PolicyCache {
    pub user_policies: HashMap<String, HashSet<String>>,
}

impl PolicyCache {
    /// Loads the cache from the given file path. If the file does not exist, returns an empty cache.
    pub async fn load(path: &PathBuf) -> Result<Self> {
        if let Ok(data) = fs::read_to_string(path).await {
            let cache = serde_json::from_str(&data)?;
            Ok(cache)
        } else {
            Ok(PolicyCache::default())
        }
    }

    /// Saves the cache to the given file path.
    pub async fn save(&self, path: &PathBuf) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data).await?;
        Ok(())
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
        // Collect new policy IDs from the changed policies.
        let new_policy_ids: HashSet<String> = policies
            .policy_statuses
            .iter()
            .map(|p| p.policy_id.clone())
            .collect();

        // Remove policies that were applied before but are not in the new set.
        for old_policy in cached_policy_ids.difference(&new_policy_ids) {
            let script_path = self
                .script_path()
                .await
                .map_err(|e| anyhow!("Failed to determine script path: {}", e))?;
            let cron_file = format!("/etc/cron.d/policy_{}", old_policy);
            let script_file = format!("{}/policy_{}_script.sh", script_path, old_policy);
            let wrapper_file = format!("{}/policy_{}_wrapper.sh", script_path, old_policy);
            let _ = fs::remove_file(&cron_file).await;
            let _ = fs::remove_file(&script_file).await;
            let _ = fs::remove_file(&wrapper_file).await;
        }

        // Process and apply the changed policies.
        for policy in policies.policy_statuses.iter_mut() {
            // Validate this is a scripts policy
            if policy
                .details
                .iter()
                .any(|d| d.setting_definition_item_id == "linux_customconfig_script")
            {
                self.apply_policy(policy).await?;
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
    async fn script_path(&self) -> Result<String> {
        let db_path = self.config.get_db_path();
        let mut cache_path = PathBuf::from(db_path);
        cache_path.pop();
        cache_path.push("bin");
        let script_path = cache_path
            .to_str()
            .ok_or(anyhow!("Failed to convert to string"))
            .map(|val| val.to_string())?;
        fs::create_dir_all(script_path.clone())
            .await
            .map_err(|e| anyhow!("Failed to create script path {}: {}", script_path, e))?;
        Ok(script_path)
    }

    async fn cache_path(&self) -> Result<String> {
        let db_path = self.config.get_db_path();
        let mut path = PathBuf::from(db_path);
        path.pop();
        // Append a filename, e.g., "cache_<username>_scripts.json"
        path.push(format!("cache_{}_scripts.json", self.username));
        path.to_str()
            .map(|s| s.to_string())
            .ok_or(anyhow!("Failed to convert cache path to string"))
    }

    async fn apply_policy(&self, policy: &mut PolicyStatus) -> Result<()> {
        let mut execution_context = "root".to_string();
        let mut frequency = "1hour".to_string();
        let mut retries = 0;
        let mut script_b64: Option<String> = None;

        // Process each setting.
        for detail in policy.details.iter_mut() {
            match detail.setting_definition_item_id.as_str() {
                "linux_customconfig_executioncontext" => match detail.expected_value.as_str() {
                    "root" => {
                        execution_context = detail.expected_value.clone();
                        detail.actual_value = detail.expected_value.clone();
                        detail.new_compliance_state = "Compliant".to_string();
                    }
                    "user" => {
                        execution_context = self.username.to_string();
                        detail.actual_value = detail.expected_value.clone();
                        detail.new_compliance_state = "Compliant".to_string();
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
                    detail.actual_value = detail.expected_value.clone();
                    detail.new_compliance_state = "Compliant".to_string();
                }
                "linux_customconfig_executionretries" => {
                    if let Ok(val) = detail.expected_value.parse::<u32>() {
                        retries = val;
                        detail.actual_value = detail.expected_value.clone();
                        detail.new_compliance_state = "Compliant".to_string();
                    } else {
                        return Err(anyhow!("Failed to parse script execution retries"));
                    }
                }
                "linux_customconfig_script" => {
                    script_b64 = Some(detail.expected_value.clone());
                    detail.actual_value = detail.expected_value.clone();
                    detail.new_compliance_state = "Compliant".to_string();
                }
                _ => {}
            }
        }

        let script_directory = self
            .script_path()
            .await
            .map_err(|e| anyhow!("Failed to determine script path: {}", e))?;

        let script_b64 = match script_b64 {
            Some(val) => val,
            // This isn't a script policy, nothing to do
            None => return Ok(()),
        };
        let script_bytes = STANDARD
            .decode(script_b64)
            .map_err(|e| anyhow!("Failed to decode script: {}", e))?;
        let script_content = String::from_utf8(script_bytes)
            .map_err(|e| anyhow!("Failed to convert script to utf8 string: {}", e))?;

        let script_file_path =
            format!("{}/policy_{}_script.sh", script_directory, policy.policy_id);
        let mut script_file = fs::File::create(&script_file_path)
            .await
            .map_err(|e| anyhow!("Failed to create script file: {}", e))?;
        script_file
            .write_all(script_content.as_bytes())
            .await
            .map_err(|e| anyhow!("Failed to write script to file: {}", e))?;
        Command::new("chmod")
            .arg("+x")
            .arg(&script_file_path)
            .output()
            .await
            .map_err(|e| anyhow!("Failed to set script permissions: {}", e))?;

        let wrapper_script_path = format!(
            "{}/policy_{}_wrapper.sh",
            script_directory, policy.policy_id
        );
        let wrapper_script = format!(
            r#"#!/bin/bash
# Wrapper script for policy execution with retry logic.
retries={}
attempts=0
while [ $attempts -le $retries ]; do
    {}
    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        exit 0
    fi
    attempts=$((attempts+1))
done
exit $exit_code
"#,
            retries, script_file_path
        );
        let mut wrapper_script_file =
            fs::File::create(&wrapper_script_path).await.map_err(|e| {
                anyhow!(
                    "Failed to create wrapper file {}: {}",
                    wrapper_script_path,
                    e
                )
            })?;
        wrapper_script_file
            .write_all(wrapper_script.as_bytes())
            .await
            .map_err(|e| anyhow!("Failed to write wrapper script to file: {}", e))?;
        Command::new("chmod")
            .arg("+x")
            .arg(&wrapper_script_path)
            .output()
            .await
            .map_err(|e| anyhow!("Failed to set wrapper script permissions: {}", e))?;

        let cron_schedule = match frequency.as_str() {
            "15" => "*/15 * * * *",  // Every 15 minutes
            "30" => "*/30 * * * *",  // Every 30 minutes
            "60" => "0 * * * *",     // At the top of every hour
            "120" => "0 */2 * * *",  // Every 2 hours at minute 0
            "180" => "0 */3 * * *",  // Every 3 hours at minute 0
            "360" => "0 */6 * * *",  // Every 6 hours at minute 0
            "720" => "0 */12 * * *", // Every 12 hours at minute 0
            "1440" => "0 0 * * *",   // Every day at midnight
            "10080" => "0 0 * * 0",  // Every week on Sunday at midnight
            _ => {
                return Err(anyhow!(
                    "Unknown script application frequency '{}' for policy {}.",
                    frequency,
                    policy.policy_id
                ))
            }
        };

        let cron_job_line = format!(
            "{} {} {}\n",
            cron_schedule, execution_context, wrapper_script_path
        );

        let cron_file_path = format!("/etc/cron.d/policy_{}", policy.policy_id);
        let mut cron_file = fs::File::create(&cron_file_path)
            .await
            .map_err(|e| anyhow!("Failed to create cron file: {}", e))?;
        cron_file
            .write_all(cron_job_line.as_bytes())
            .await
            .map_err(|e| anyhow!("Failed to write cron job to file: {}", e))?;

        Command::new("chmod")
            .arg("644")
            .arg(&cron_file_path)
            .output()
            .await
            .map_err(|e| anyhow!("Failed to set cron file permissions: {}", e))?;

        debug!(
            "Installed script policy to {} for user {}, enforced via cron {}.",
            &wrapper_script_path, &self.username, &cron_file_path
        );

        Ok(())
    }
}
