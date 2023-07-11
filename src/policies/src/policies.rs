use reqwest::header;
use serde::{Serialize, Deserialize};
use anyhow::{anyhow, Result};
use tracing::{debug, error};
use std::sync::Arc;

pub trait Policy: Send + Sync {
    fn get_id(&self) -> &str;
    fn get_name(&self) -> &str;
}

#[derive(Deserialize)]
struct ConfigurationPolicy {
    id: String,
    name: String,
}

impl Policy for ConfigurationPolicy {
    fn get_id(&self) -> &str {
        &self.id
    }

    fn get_name(&self) -> &str {
        &self.name
    }
}

#[derive(Deserialize)]
struct ConfigurationPolicies {
    value: Vec<ConfigurationPolicy>,
}

async fn list_configuration_policies(graph_url: &str, access_token: &str) -> Result<Vec<ConfigurationPolicy>> {
    let url = &format!("{}/beta/deviceManagement/configurationPolicies?$select=name,id", graph_url);
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
pub struct GroupPolicy {
    id: String,
    #[serde(rename = "displayName")]
    name: String,
}

impl Policy for GroupPolicy {
    fn get_id(&self) -> &str {
        &self.id
    }

    fn get_name(&self) -> &str {
        &self.name
    }
}

#[derive(Deserialize)]
struct GroupPolicies {
    value: Vec<GroupPolicy>,
}

async fn list_group_policies(graph_url: &str, access_token: &str) -> Result<Vec<GroupPolicy>> {
    let url = &format!("{}/beta/deviceManagement/groupPolicyConfigurations?$select=displayName,id", graph_url);
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

async fn get_object_type_by_id(graph_url: &str, access_token: &str, id: &str) -> Result<ObjectType> {
    let url = &format!("{}/v1.0/directoryObjects/getByIds", graph_url);
    let client = reqwest::Client::new();

    let json_payload = serde_json::to_string(&DirectoryObjectsRequest {
        ids: vec![id.to_string()],
        types: vec!["user".to_string(),
                    "group".to_string(),
                    "device".to_string()],
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

async fn id_memberof_group(graph_url: &str, access_token: &str, id: &str, group_id: &str) -> Result<bool> {
    let url = &format!("{}/v1.0/directoryObjects/{}/checkMemberGroups", graph_url, id);
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
        Ok(resp.json::<MemberGroupsResponse>().await?.value.contains(&group_id.to_string()))
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

async fn parse_assignments(graph_url: &str, access_token: &str, id: &str, policy_id: &str, assignments: Vec<GroupPolicyAssignment>) -> Result<bool> {
    let mut assigned = false;
    let mut excluded = false;
    let id_typ = get_object_type_by_id(graph_url, access_token, id).await?;
    for rule in assignments {
        match rule.target.filter_id {
            Some(_) => {
                error!("TODO: Device filters have not been implemented, GPO {} will be disabled", policy_id);
                return Ok(false);
            }
            None => {}
        }
        match rule.target.odata_type.as_str() {
            "#microsoft.graph.allLicensedUsersAssignmentTarget" => {
                if id_typ == ObjectType::User {
                    assigned = true;
                }
            },
            "#microsoft.graph.allDevicesAssignmentTarget" => {
                if id_typ == ObjectType::Device {
                    assigned = true;
                }
            },
            "#microsoft.graph.groupAssignmentTarget" => {
                if id_typ != ObjectType::Device {
                    match rule.target.group_id {
                        Some(group_id) => {
                            let member_of = id_memberof_group(graph_url, access_token, id, &group_id).await?;
                            if member_of {
                                assigned = true;
                            }
                        },
                        None => error!("GPO {}: groupAssignmentTarget missing group id", policy_id),
                    }
                }
            },
            "#microsoft.graph.exclusionGroupAssignmentTarget" => {
                if id_typ != ObjectType::Device {
                    match rule.target.group_id {
                        Some(group_id) => {
                            let member_of = id_memberof_group(graph_url, access_token, id, &group_id).await?;
                            if member_of {
                                excluded = true;
                            }
                        },
                        None => error!("GPO {}: groupAssignmentTarget missing group id", policy_id),
                    }
                }
            },
            &_ => todo!(),
        }
    }
    if assigned && !excluded {
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn get_gpo_assigned(graph_url: &str, access_token: &str, id: &str, policy_id: &str) -> Result<bool> {
    let url = &format!("{}/beta/deviceManagement/groupPolicyConfigurations/{}/assignments", graph_url, policy_id);
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

async fn get_config_policy_assigned(graph_url: &str, access_token: &str, id: &str, policy_id: &str) -> Result<bool> {
    let url = &format!("{}/beta/deviceManagement/configurationPolicies/{}/assignments", graph_url, policy_id);
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

/* get_gpo_list
 * Get the full list of Group Policy Objects for a given id (user or device).
 *
 * graph_url        The microsoft graph URL
 * access_token     An authenticated token for reading the graph
 * id               The ID of the user/group/device to list policies for
 */
async fn get_gpo_list(graph_url: &str, access_token: &str, id: &str) -> Result<Vec<Arc<dyn Policy>>> {
    let mut res: Vec<Arc<dyn Policy>> = vec![];
    let config_policy_list = list_configuration_policies(&graph_url, access_token).await?;
    for policy in config_policy_list {
        // Check assignments and whether this policy applies
        let assigned = get_config_policy_assigned(graph_url, access_token, id, &policy.id).await?;
        if assigned {
            res.push(Arc::new(policy));
        }
    }
    let group_policy_list = list_group_policies(&graph_url, access_token).await?;
    for gpo in group_policy_list {
        // Check assignments and whether this policy applies
        let assigned = get_gpo_assigned(graph_url, access_token, id, &gpo.id).await?;
        if assigned {
            res.push(Arc::new(gpo));
        }
    }
    Ok(res)
}

pub async fn apply_group_policy(graph_url: &str, access_token: &str, id: &str) -> Result<bool> {
    let changed_gpos = get_gpo_list(graph_url, access_token, id).await?;

    /* TODO: Keep track of applied gpos, then unapply them when they disappear */

    for gpo in changed_gpos {
        debug!("Applying policy {}", gpo.get_name());
        /* TODO: Fetch each GPOs policy and apply it */
    }

    Ok(true)
}
