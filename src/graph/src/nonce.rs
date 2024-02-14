use anyhow::{anyhow, Result};
use msal::discovery::{NonceService, DISCOVERY_URL};
use reqwest::{header, Url};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NonceResp {
    #[serde(rename = "Value")]
    value: String,
}

pub async fn request_nonce(
    nonce_service: Option<NonceService>,
    tenant_id: &str,
    access_token: &str,
) -> Result<String> {
    let url = match nonce_service {
        Some(nonce_service) => {
            let endpoint = match nonce_service.endpoint {
                Some(endpoint) => endpoint,
                None => format!("{}/EnrollmentServer/nonce/{}/", DISCOVERY_URL, tenant_id),
            };
            let service_version = match nonce_service.service_version {
                Some(service_version) => service_version,
                None => "1.0".to_string(),
            };
            Url::parse_with_params(&endpoint, &[("api-version", &service_version)])?
        }
        None => Url::parse_with_params(
            &format!("{}/EnrollmentServer/nonce/{}/", DISCOVERY_URL, tenant_id),
            &[("api-version", "1.0")],
        )?,
    };

    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await?;
    if resp.status().is_success() {
        let json_resp: NonceResp = resp.json().await?;
        Ok(json_resp.value)
    } else {
        Err(anyhow!(resp.status()))
    }
}
