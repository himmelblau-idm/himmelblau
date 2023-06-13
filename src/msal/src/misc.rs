use reqwest::Url;
use serde::Deserialize;
use anyhow::{anyhow, Result};
use log::debug;

#[derive(Debug, Deserialize)]
struct FederationProvider {
    #[serde(rename = "tenantId")]
    tenant_id: String,
    authority_host: String,
}

pub async fn request_tenant_id_and_authority(odc_provider: &str, domain: &str) -> Result<(String, String)> {
    let url = Url::parse_with_params(
        &format!("https://{}/odc/v2.1/federationProvider", odc_provider),
        &[("domain", domain)],
    )?;

    let resp = reqwest::get(url).await?;
    if resp.status().is_success() {
        let json_resp: FederationProvider = resp.json().await?;
        debug!("Discovered tenant_id: {}", json_resp.tenant_id);
        debug!("Discovered authority_host: {}", json_resp.authority_host);
        Ok((json_resp.authority_host, json_resp.tenant_id))
    } else {
        Err(anyhow!(resp.status()))
    }
}
