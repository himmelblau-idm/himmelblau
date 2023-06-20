use reqwest::{Url, header};
use serde::Deserialize;
use anyhow::{anyhow, Result};
use log::debug;

#[derive(Debug, Deserialize)]
struct FederationProvider {
    #[serde(rename = "tenantId")]
    tenant_id: String,
    authority_host: String,
    graph: String,
}

pub async fn request_federation_provider(odc_provider: &str, domain: &str) -> Result<(String, String, String)> {
    let url = Url::parse_with_params(
        &format!("https://{}/odc/v2.1/federationProvider", odc_provider),
        &[("domain", domain)],
    )?;

    let resp = reqwest::get(url).await?;
    if resp.status().is_success() {
        let json_resp: FederationProvider = resp.json().await?;
        debug!("Discovered tenant_id: {}", json_resp.tenant_id);
        debug!("Discovered authority_host: {}", json_resp.authority_host);
        debug!("Discovered graph: {}", json_resp.graph);
        Ok((json_resp.authority_host, json_resp.tenant_id, json_resp.graph))
    } else {
        Err(anyhow!(resp.status()))
    }
}

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

pub async fn request_user_groups(graph_url: &str, access_token: &str) -> Result<Vec<DirectoryObject>> {
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
