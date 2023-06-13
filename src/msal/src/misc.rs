use reqwest::Url;
use serde::Deserialize;
use anyhow::{anyhow, Result};
use log::debug;

#[derive(Debug, Deserialize)]
struct FederationProvider {
    #[serde(rename = "tenantId")]
    tenant_id: String,
}

pub async fn request_tenant_id(domain: &str) -> Result<String> {
    let url = Url::parse_with_params(
        "https://odc.officeapps.live.com/odc/v2.1/federationProvider",
        &[("domain", domain)],
    )?;

    let resp = reqwest::get(url).await?;
    if resp.status().is_success() {
        let json_resp: FederationProvider = resp.json().await?;
        debug!("Discovered tenant_id: {}", json_resp.tenant_id);
        Ok(json_resp.tenant_id)
    } else {
        Err(anyhow!("Failed fetching the tenant id"))
    }
}
