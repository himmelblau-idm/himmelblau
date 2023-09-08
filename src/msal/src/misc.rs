use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use reqwest::{header, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_string_pretty};
use tracing::debug;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct FederationProvider {
    #[serde(rename = "tenantId")]
    tenant_id: String,
    authority_host: String,
    graph: String,
}

pub async fn request_federation_provider(
    odc_provider: &str,
    domain: &str,
) -> Result<(String, String, String)> {
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
        Ok((
            json_resp.authority_host,
            json_resp.tenant_id,
            json_resp.graph,
        ))
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

#[derive(Debug, Deserialize, Clone)]
pub struct Application {
    #[serde(rename = "appId")]
    pub app_id: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    pub id: Option<String>,
    #[serde(rename = "keyCredentials")]
    pub key_creds: Option<Vec<KeyCredential>>,
}

#[derive(Debug, Deserialize)]
struct ApplicationList {
    value: Vec<Application>,
}

pub async fn list_applications(graph_url: &str, access_token: &str) -> Result<Vec<Application>> {
    let url = &format!("{}/v1.0/applications", graph_url);
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        let json_resp: ApplicationList = resp.json().await?;
        Ok(json_resp.value)
    } else {
        Err(anyhow!(resp.status()))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyCredential {
    #[serde(rename = "customKeyIdentifier")]
    custom_key_identifier: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "endDateTime")]
    end_date_time: Option<String>,
    key: Option<String>,
    #[serde(rename = "keyId")]
    key_id: String,
    #[serde(rename = "startDateTime")]
    start_date_time: String,
    r#type: String,
    usage: String,
}

pub async fn get_application(
    graph_url: &str,
    access_token: &str,
    app_id: &str,
) -> Result<Application> {
    let url = Url::parse_with_params(
        &format!("{}/v1.0/applications", graph_url,),
        &[
            ("$select", "keyCredentials,id"),
            ("$filter", format!("appId eq '{}'", app_id).as_str()),
        ],
    )?;
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        let json_resp: ApplicationList = resp.json().await?;
        match json_resp.value.first() {
            Some(app) => Ok(app.clone()),
            None => Err(anyhow!("Application {} not found", app_id)),
        }
    } else {
        Err(anyhow!(resp.status()))
    }
}

pub async fn add_application_certificate(
    graph_url: &str,
    access_token: &str,
    app_id: &str,
    cert: &str,
    desc: &str,
) -> Result<()> {
    let app = get_application(graph_url, access_token, app_id).await?;
    let app_id = match &app.id {
        Some(id) => id.clone(),
        None => return Err(anyhow!("Application {} missing id", app_id)),
    };
    let url = &format!("{}/v1.0/applications/{}", graph_url, app_id);
    let mut key_creds = match app.key_creds {
        Some(key_creds) => key_creds,
        None => Vec::<KeyCredential>::new(),
    };
    key_creds.push(KeyCredential {
        custom_key_identifier: None, /* Leaving this blank will default to the thumbprint */
        display_name: Some(desc.to_string()),
        end_date_time: None, /* Leaving this blank defaults to 1 year from now */
        key: Some(general_purpose::STANDARD.encode(cert)),
        key_id: Uuid::new_v4().to_string(),
        start_date_time: Utc::now().to_rfc3339(),
        r#type: "AsymmetricX509Cert".to_string(),
        usage: "Verify".to_string(),
    });
    let payload = json!({
        "keyCredentials": key_creds,
    });
    match to_string_pretty(&payload) {
        Ok(pretty) => {
            debug!("POST {}: {}", url, pretty);
        }
        Err(_e) => {}
    };
    let client = reqwest::Client::new();
    let resp = client
        .patch(url)
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
