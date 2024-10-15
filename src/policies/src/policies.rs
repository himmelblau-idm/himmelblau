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
use crate::chromium_ext::ChromiumUserCSE;
use crate::cse::CSE;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use regex::Regex;
use reqwest::header;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::error;

pub trait PolicySetting: Send + Sync {
    fn enabled(&self) -> bool;
    fn class_type(&self) -> PolicyType;
    fn key(&self) -> String;
    fn value(&self) -> Option<ValueType>;
    fn get_compare_pattern(&self) -> String;
}

#[async_trait]
pub trait Policy: Send + Sync {
    fn get_id(&self) -> String;
    fn get_name(&self) -> String;
    async fn load_policy_settings(&mut self, graph_url: &str, access_token: &str) -> Result<bool>;
    fn list_policy_settings(&self, pattern: Regex) -> Result<Vec<Arc<dyn PolicySetting>>>;
    fn clone(&self) -> Arc<dyn Policy>;
}

#[derive(Deserialize, Clone)]
struct ConfigurationPolicy {
    id: String,
    name: String,
    #[serde(skip)]
    policy_definitions: Option<Vec<Arc<dyn PolicySetting>>>,
}

#[async_trait]
impl Policy for ConfigurationPolicy {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    async fn load_policy_settings(&mut self, graph_url: &str, access_token: &str) -> Result<bool> {
        let settings: Vec<ConfigurationPolicySetting> =
            list_config_policy_settings(graph_url, access_token, &self.id).await?;
        let mut res: Vec<Arc<dyn PolicySetting>> = vec![];
        for setting in settings {
            res.push(Arc::new(setting));
        }
        self.policy_definitions = Some(res);
        Ok(true)
    }

    fn list_policy_settings(&self, pattern: Regex) -> Result<Vec<Arc<dyn PolicySetting>>> {
        match &self.policy_definitions {
            Some(policy_definitions) => {
                let mut res: Vec<Arc<dyn PolicySetting>> = vec![];
                for policy_definition in policy_definitions {
                    if pattern.is_match(&policy_definition.get_compare_pattern()) {
                        res.push(policy_definition.clone());
                    }
                }
                Ok(res)
            }
            None => Err(anyhow!("Policy Definitions were not loaded")),
        }
    }

    fn clone(&self) -> Arc<dyn Policy> {
        Arc::new(ConfigurationPolicy {
            id: self.id.clone(),
            name: self.name.clone(),
            policy_definitions: self.policy_definitions.clone(),
        })
    }
}

#[derive(Deserialize)]
struct ConfigurationPolicies {
    value: Vec<ConfigurationPolicy>,
}

async fn list_configuration_policies(
    graph_url: &str,
    access_token: &str,
) -> Result<Vec<ConfigurationPolicy>> {
    let url = &format!(
        "{}/beta/deviceManagement/configurationPolicies?$select=name,id",
        graph_url
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        Ok(resp.json::<ConfigurationPolicies>().await?.value)
    } else {
        Err(anyhow!(resp.status()))
    }
}

#[derive(Debug, Deserialize)]
struct GroupPolicyConfiguration {
    id: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct GroupPolicyConfigurations {
    value: Vec<GroupPolicyConfiguration>,
}

async fn list_group_policy_configurations(
    graph_url: &str,
    access_token: &str,
    policy_id: &str,
) -> Result<Vec<GroupPolicyConfiguration>> {
    let url = &format!(
        "{}/beta/deviceManagement/groupPolicyConfigurations/{}/definitionValues",
        graph_url, policy_id
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        Ok(resp.json::<GroupPolicyConfigurations>().await?.value)
    } else {
        Err(anyhow!(resp.status()))
    }
}

#[derive(Debug, Deserialize, Clone)]
struct GroupPolicyDefinition {
    #[serde(skip)]
    enabled: bool,
    #[serde(rename = "classType")]
    class_type: String,
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(rename = "categoryPath")]
    category_path: String,
    #[serde(skip)]
    value: PresentationValue,
}

impl PolicySetting for GroupPolicyDefinition {
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn class_type(&self) -> PolicyType {
        if self.class_type == "user" {
            PolicyType::User
        } else if self.class_type == "device" {
            PolicyType::Device
        } else {
            PolicyType::Unknown
        }
    }

    fn key(&self) -> String {
        self.display_name.clone()
    }

    fn value(&self) -> Option<ValueType> {
        match &self.value.value {
            Some(value) => Some(value.clone()),
            None => self.value.values.as_ref().cloned(),
        }
    }

    fn get_compare_pattern(&self) -> String {
        self.category_path.clone()
    }
}

async fn get_group_policy_definition(
    graph_url: &str,
    access_token: &str,
    policy_id: &str,
    def_id: &str,
) -> Result<GroupPolicyDefinition> {
    let url = &format!(
        "{}/beta/deviceManagement/groupPolicyConfigurations/{}/definitionValues/{}/definition",
        graph_url, policy_id, def_id
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        Ok(resp.json::<GroupPolicyDefinition>().await?)
    } else {
        Err(anyhow!(resp.status()))
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum ValueType {
    Text(String),
    Decimal(i64),
    Boolean(bool),
    MultiText(Vec<String>),
    List(Vec<PresentationValueList>),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PresentationValueList {
    name: String,
    value: Option<String>,
}

#[derive(Default, Debug, Deserialize, Clone)]
struct PresentationValue {
    value: Option<ValueType>,
    values: Option<ValueType>,
}

#[derive(Debug, Deserialize)]
struct PresentationValues {
    value: Option<Vec<PresentationValue>>,
}

async fn get_group_policy_values(
    graph_url: &str,
    access_token: &str,
    policy_id: &str,
    definition_id: &str,
) -> Result<PresentationValue> {
    let url = &format!("{}/beta/deviceManagement/groupPolicyConfigurations/{}/definitionValues/{}/presentationValues", graph_url, policy_id, definition_id);
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        match resp.json::<PresentationValues>().await?.value {
            Some(value) => {
                // There should be exactly one value
                if value.len() != 1 {
                    Err(anyhow!("The wrong number of values were returned"))
                } else {
                    Ok(value[0].clone())
                }
            }
            None => Err(anyhow!("No values were returned")),
        }
    } else {
        Err(anyhow!(resp.status()))
    }
}

#[derive(Deserialize, Clone)]
pub struct GroupPolicy {
    id: String,
    #[serde(rename = "displayName")]
    name: String,
    #[serde(skip)]
    policy_definitions: Option<Vec<Arc<dyn PolicySetting>>>,
}

#[async_trait]
impl Policy for GroupPolicy {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    async fn load_policy_settings(&mut self, graph_url: &str, access_token: &str) -> Result<bool> {
        let mut res: Vec<Arc<dyn PolicySetting>> = vec![];
        let definition_values =
            list_group_policy_configurations(graph_url, access_token, &self.id).await?;
        for definition_value in definition_values {
            let mut definition = get_group_policy_definition(
                graph_url,
                access_token,
                &self.id,
                &definition_value.id,
            )
            .await?;
            definition.enabled = definition_value.enabled;
            match get_group_policy_values(graph_url, access_token, &self.id, &definition_value.id)
                .await
            {
                Ok(val) => {
                    definition.value = val;
                    res.push(Arc::new(definition));
                }
                Err(e) => {
                    error!(
                        "Failed fetching presentation value for {}: {}",
                        definition_value.id, e
                    );
                }
            };
        }
        self.policy_definitions = Some(res);
        Ok(true)
    }

    fn list_policy_settings(&self, pattern: Regex) -> Result<Vec<Arc<dyn PolicySetting>>> {
        match &self.policy_definitions {
            Some(policy_definitions) => {
                let mut res: Vec<Arc<dyn PolicySetting>> = vec![];
                for policy_definition in policy_definitions {
                    if pattern.is_match(&policy_definition.get_compare_pattern()) {
                        res.push(policy_definition.clone());
                    }
                }
                Ok(res)
            }
            None => Err(anyhow!("Policy Definitions were not loaded")),
        }
    }

    fn clone(&self) -> Arc<dyn Policy> {
        Arc::new(GroupPolicy {
            id: self.id.clone(),
            name: self.name.clone(),
            policy_definitions: self.policy_definitions.clone(),
        })
    }
}

#[derive(Deserialize)]
struct GroupPolicies {
    value: Vec<GroupPolicy>,
}

async fn list_group_policies(graph_url: &str, access_token: &str) -> Result<Vec<GroupPolicy>> {
    let url = &format!(
        "{}/beta/deviceManagement/groupPolicyConfigurations?$select=displayName,id",
        graph_url
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        Ok(resp.json::<GroupPolicies>().await?.value)
    } else {
        Err(anyhow!(resp.status()))
    }
}

#[derive(PartialEq)]
enum ObjectType {
    User,
    Group,
    Device,
}

#[derive(PartialEq)]
pub enum PolicyType {
    User,
    Device,
    Unknown,
}

#[derive(Debug, Deserialize)]
struct DirectoryObject {
    #[serde(rename = "@odata.type")]
    odata_type: String,
}

#[derive(Debug, Deserialize)]
struct DirectoryObjectsResponse {
    value: Vec<DirectoryObject>,
}

#[derive(Serialize, Deserialize)]
struct DirectoryObjectsRequest {
    ids: Vec<String>,
    types: Vec<String>,
}

async fn get_object_type_by_id(
    graph_url: &str,
    access_token: &str,
    id: &str,
) -> Result<ObjectType> {
    let url = &format!("{}/v1.0/directoryObjects/getByIds", graph_url);
    let client = reqwest::Client::new();

    let json_payload = serde_json::to_string(&DirectoryObjectsRequest {
        ids: vec![id.to_string()],
        types: vec![
            "user".to_string(),
            "group".to_string(),
            "device".to_string(),
        ],
    })?;

    let resp = client
        .post(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json_payload)
        .send()
        .await?;
    if resp.status().is_success() {
        let objs = resp.json::<DirectoryObjectsResponse>().await?.value;
        if objs.len() == 1 {
            if objs[0].odata_type == "#microsoft.graph.user" {
                Ok(ObjectType::User)
            } else if objs[0].odata_type == "#microsoft.graph.group" {
                Ok(ObjectType::Group)
            } else if objs[0].odata_type == "#microsoft.graph.device" {
                Ok(ObjectType::Device)
            } else {
                Err(anyhow!("Unrecognized object type {}", objs[0].odata_type))
            }
        } else {
            Err(anyhow!("Failed finding exactly one object with id {}", id))
        }
    } else {
        Err(anyhow!(resp.status()))
    }
}

#[derive(Serialize, Deserialize)]
struct MemberGroupsRequest {
    #[serde(rename = "groupIds")]
    group_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MemberGroupsResponse {
    value: Vec<String>,
}

async fn id_memberof_group(
    graph_url: &str,
    access_token: &str,
    id: &str,
    group_id: &str,
) -> Result<bool> {
    let url = &format!(
        "{}/v1.0/directoryObjects/{}/checkMemberGroups",
        graph_url, id
    );
    let client = reqwest::Client::new();

    let json_payload = serde_json::to_string(&MemberGroupsRequest {
        group_ids: vec![group_id.to_string()],
    })?;

    let resp = client
        .post(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json_payload)
        .send()
        .await?;
    if resp.status().is_success() {
        Ok(resp
            .json::<MemberGroupsResponse>()
            .await?
            .value
            .contains(&group_id.to_string()))
    } else {
        Err(anyhow!(resp.status()))
    }
}

#[derive(Debug, Deserialize)]
struct GroupPolicyAssignmentTarget {
    #[serde(rename = "@odata.type")]
    odata_type: String,
    #[serde(rename = "deviceAndAppManagementAssignmentFilterId")]
    filter_id: Option<String>,
    /* #[serde(rename = "deviceAndAppManagementAssignmentFilterType")]
    filter_type: String,*/
    #[serde(rename = "groupId")]
    group_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GroupPolicyAssignment {
    target: GroupPolicyAssignmentTarget,
}

#[derive(Debug, Deserialize)]
struct GroupPolicyAssignments {
    value: Vec<GroupPolicyAssignment>,
}

async fn parse_assignments(
    graph_url: &str,
    access_token: &str,
    id: &str,
    policy_id: &str,
    assignments: Vec<GroupPolicyAssignment>,
) -> Result<bool> {
    let mut assigned = false;
    let mut excluded = false;
    let id_typ = get_object_type_by_id(graph_url, access_token, id).await?;
    for rule in assignments {
        if rule.target.filter_id.is_some() {
            error!(
                "TODO: Device filters have not been implemented, GPO {} will be disabled",
                policy_id
            );
            return Ok(false);
        }
        match rule.target.odata_type.as_str() {
            "#microsoft.graph.allLicensedUsersAssignmentTarget" => {
                if id_typ == ObjectType::User {
                    assigned = true;
                }
            }
            "#microsoft.graph.allDevicesAssignmentTarget" => {
                if id_typ == ObjectType::Device {
                    assigned = true;
                }
            }
            "#microsoft.graph.groupAssignmentTarget" => {
                if id_typ != ObjectType::Device {
                    match rule.target.group_id {
                        Some(group_id) => {
                            let member_of =
                                id_memberof_group(graph_url, access_token, id, &group_id).await?;
                            if member_of {
                                assigned = true;
                            }
                        }
                        None => error!("GPO {}: groupAssignmentTarget missing group id", policy_id),
                    }
                }
            }
            "#microsoft.graph.exclusionGroupAssignmentTarget" => {
                if id_typ != ObjectType::Device {
                    match rule.target.group_id {
                        Some(group_id) => {
                            let member_of =
                                id_memberof_group(graph_url, access_token, id, &group_id).await?;
                            if member_of {
                                excluded = true;
                            }
                        }
                        None => error!("GPO {}: groupAssignmentTarget missing group id", policy_id),
                    }
                }
            }
            target => {
                error!("GPO {}: unrecognized rule target \"{}\"", policy_id, target);
            }
        }
    }
    if assigned && !excluded {
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn get_gpo_assigned(
    graph_url: &str,
    access_token: &str,
    id: &str,
    policy_id: &str,
) -> Result<bool> {
    let url = &format!(
        "{}/beta/deviceManagement/groupPolicyConfigurations/{}/assignments",
        graph_url, policy_id
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        let assignments = resp.json::<GroupPolicyAssignments>().await?.value;
        parse_assignments(graph_url, access_token, id, policy_id, assignments).await
    } else {
        Err(anyhow!(resp.status()))
    }
}

async fn get_config_policy_assigned(
    graph_url: &str,
    access_token: &str,
    id: &str,
    policy_id: &str,
) -> Result<bool> {
    let url = &format!(
        "{}/beta/deviceManagement/configurationPolicies/{}/assignments",
        graph_url, policy_id
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        let assignments = resp.json::<GroupPolicyAssignments>().await?.value;
        parse_assignments(graph_url, access_token, id, policy_id, assignments).await
    } else {
        Err(anyhow!(resp.status()))
    }
}

#[derive(Debug, Deserialize)]
struct SimpleSettingValue {
    value: String,
}

#[derive(Debug, Deserialize)]
struct ChoiceSettingValue {
    value: String,
}

#[derive(Debug, Deserialize)]
struct SettingInstance {
    #[serde(rename = "settingDefinitionId")]
    setting_definition_id: String,
    #[serde(rename = "simpleSettingValue", default)]
    simple_value: Option<SimpleSettingValue>,
    #[serde(rename = "choiceSettingValue", default)]
    choice_value: Option<ChoiceSettingValue>,
}

#[derive(Debug, Deserialize)]
struct ConfigurationPolicySetting {
    #[serde(rename = "settingInstance")]
    setting_instance: SettingInstance,
}

impl PolicySetting for ConfigurationPolicySetting {
    fn enabled(&self) -> bool {
        // Configuration Policies can't be disabled, so this is always true
        true
    }

    fn class_type(&self) -> PolicyType {
        let user = match Regex::new(r"^user_") {
            Ok(user) => user,
            Err(_e) => return PolicyType::Unknown,
        };
        let device = match Regex::new(r"^device_") {
            Ok(device) => device,
            Err(_e) => return PolicyType::Unknown,
        };
        if user.is_match(&self.setting_instance.setting_definition_id) {
            PolicyType::User
        } else if device.is_match(&self.setting_instance.setting_definition_id) {
            PolicyType::Device
        } else {
            PolicyType::Unknown
        }
    }

    fn key(&self) -> String {
        self.setting_instance.setting_definition_id.to_string()
    }

    fn value(&self) -> Option<ValueType> {
        match &self.setting_instance.simple_value {
            Some(val) => Some(ValueType::Text(val.value.to_string())),
            None => self
                .setting_instance
                .choice_value
                .as_ref()
                .map(|val| ValueType::Text(val.value.to_string())),
        }
    }

    fn get_compare_pattern(&self) -> String {
        self.setting_instance.setting_definition_id.to_string()
    }
}

#[derive(Debug, Deserialize)]
struct ConfigurationPoliciesSettings {
    value: Vec<ConfigurationPolicySetting>,
}

async fn list_config_policy_settings(
    graph_url: &str,
    access_token: &str,
    policy_id: &str,
) -> Result<Vec<ConfigurationPolicySetting>> {
    let url = &format!(
        "{}/beta/deviceManagement/configurationPolicies/{}/settings",
        graph_url, policy_id
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        Ok(resp.json::<ConfigurationPoliciesSettings>().await?.value)
    } else {
        Err(anyhow!(resp.status()))
    }
}

/* get_gpo_list
 * Get the full list of Group Policy Objects for a given id (user or device).
 *
 * graph_url        The microsoft graph URL
 * access_token     An authenticated token for reading the graph
 * id               The ID of the user/group/device to list policies for
 */
async fn get_gpo_list(
    graph_url: &str,
    access_token: &str,
    id: &str,
) -> Result<Vec<Arc<dyn Policy>>> {
    let mut res: Vec<Arc<dyn Policy>> = vec![];
    let config_policy_list = list_configuration_policies(graph_url, access_token).await?;
    for mut policy in config_policy_list {
        // Check assignments and whether this policy applies
        let assigned = get_config_policy_assigned(graph_url, access_token, id, &policy.id).await?;
        if assigned {
            // Only load policy defs if we know we'll be using them
            policy.load_policy_settings(graph_url, access_token).await?;
            res.push(Arc::new(policy));
        }
    }
    let group_policy_list = list_group_policies(graph_url, access_token).await?;
    for mut gpo in group_policy_list {
        // Check assignments and whether this policy applies
        let assigned = get_gpo_assigned(graph_url, access_token, id, &gpo.id).await?;
        if assigned {
            // Only load policy defs if we know we'll be using them
            gpo.load_policy_settings(graph_url, access_token).await?;
            res.push(Arc::new(gpo));
        }
    }
    Ok(res)
}

pub async fn apply_group_policy(graph_url: &str, access_token: &str, id: &str) -> Result<bool> {
    let changed_gpos = get_gpo_list(graph_url, access_token, id).await?;

    /* TODO: Keep track of applied gpos, then unapply them when they disappear */
    let del_gpos: Vec<Arc<dyn Policy>> = vec![];

    let obj_type = get_object_type_by_id(graph_url, access_token, id).await?;
    let mut gp_extensions: Vec<Arc<dyn CSE>> = vec![];
    if obj_type == ObjectType::User {
        gp_extensions.push(Arc::new(ChromiumUserCSE::new(graph_url, access_token, id)));
    } else if obj_type == ObjectType::Device {
        /* TODO: Machine policy extensions go here */
    }

    for ext in gp_extensions {
        let cdel_gpos: Vec<Arc<dyn Policy>> = del_gpos.to_vec();
        let cchanged_gpos: Vec<Arc<dyn Policy>> = changed_gpos.to_vec();
        ext.process_group_policy(cdel_gpos, cchanged_gpos).await?;
    }

    Ok(true)
}
