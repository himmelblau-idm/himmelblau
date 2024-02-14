use anyhow::{anyhow, Result};
use reqwest::{header, Url};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct GroupObject {
    #[serde(rename = "displayName")]
    pub displayname: String,
    pub id: String,
}

pub async fn request_group(
    graph_url: &str,
    access_token: &str,
    displayname: &str,
) -> Result<GroupObject> {
    let url = Url::parse_with_params(
        &format!("{}/v1.0/groups", graph_url),
        &[("$filter", format!("displayName eq '{}'", displayname))],
    )?;
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        let json_resp: GroupObject = resp.json().await?;
        Ok(json_resp)
    } else {
        Err(anyhow!(resp.status()))
    }
}
