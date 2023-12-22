use anyhow::{anyhow, Result};
use reqwest::header;
use serde::Deserialize;
use serde_json::{json, to_string_pretty};
use tracing::debug;

#[derive(Debug, Deserialize)]
pub struct DirectoryObject {
    #[serde(rename = "@odata.type")]
    odata_type: String,
    id: String,
    description: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "securityIdentifier")]
    security_identifier: Option<String>,
}

impl DirectoryObject {
    pub fn get(&self, key: &str) -> Option<&String> {
        match key {
            "id" => Some(&self.id),
            "description" => self.description.as_ref(),
            /* Azure only provides an ID if we lack the GroupMember.Read.All
             * permission, in which case just use the ID as the displayName. */
            "display_name" => match &self.display_name {
                Some(val) => Some(val),
                None => Some(&self.id),
            },
            "security_identifier" => self.security_identifier.as_ref(),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct DirectoryObjects {
    value: Vec<DirectoryObject>,
}

pub async fn request_user_groups(
    graph_url: &str,
    access_token: &str,
) -> Result<Vec<DirectoryObject>> {
    let url = &format!("{}/v1.0/me/memberOf", graph_url);
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    let mut res: Vec<DirectoryObject> = Vec::new();
    if resp.status().is_success() {
        let json_resp: DirectoryObjects = resp.json().await?;
        for entry in json_resp.value {
            if entry.odata_type == "#microsoft.graph.group" {
                res.push(entry)
            }
        }
        Ok(res)
    } else {
        Err(anyhow!(resp.status()))
    }
}

#[derive(Debug, Deserialize)]
pub struct UserObject {
    #[serde(rename = "displayName")]
    pub displayname: String,
    #[serde(rename = "userPrincipalName")]
    pub upn: String,
    pub id: String,
}

pub async fn request_user(graph_url: &str, access_token: &str, upn: &str) -> Result<UserObject> {
    let url = &format!("{}/v1.0/users/{}", graph_url, upn);
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        let json_resp: UserObject = resp.json().await?;
        Ok(json_resp)
    } else {
        Err(anyhow!(resp.status()))
    }
}

pub async fn assign_device_to_user(
    graph_url: &str,
    access_token: &str,
    device_id: &str,
    upn: &str,
) -> Result<()> {
    let url = &format!(
        "{}/v1.0/devices/{}/registeredOwners/$ref",
        graph_url, device_id
    );
    let user_obj = request_user(graph_url, access_token, upn).await?;
    let payload = json!({
        "@odata.id": format!("{}/v1.0/directoryObjects/{}", graph_url, user_obj.id),
    });
    match to_string_pretty(&payload) {
        Ok(pretty) => {
            debug!("POST {}: {}", url, pretty);
        }
        Err(_e) => {}
    };
    let client = reqwest::Client::new();
    let resp = client
        .post(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&payload)
        .send()
        .await?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(anyhow!(resp.status()))
    }
}
