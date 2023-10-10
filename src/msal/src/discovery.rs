use anyhow::{anyhow, Result};
use reqwest::{header, Url};
use serde::Deserialize;

pub const DRS_CLIENT_NAME_HEADER_FIELD: &str = "ocp-adrs-client-name";
pub const DRS_CLIENT_VERSION_HEADER_FIELD: &str = "ocp-adrs-client-version";
pub const DISCOVERY_URL: &str = "https://enterpriseregistration.windows.net";
const DRS_PROTOCOL_VERSION: &str = "1.9";

#[derive(Debug, Deserialize)]
pub struct DiscoveryService {
    #[serde(rename = "DiscoveryEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceRegistrationService {
    #[serde(rename = "RegistrationEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "RegistrationResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuth2 {
    #[serde(rename = "AuthCodeEndpoint")]
    pub auth_code_endpoint: Option<String>,
    #[serde(rename = "TokenEndpoint")]
    pub token_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationService {
    #[serde(rename = "OAuth2")]
    pub oauth2: Option<OAuth2>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityProviderService {
    #[serde(rename = "Federated")]
    pub federated: Option<bool>,
    #[serde(rename = "PassiveAuthEndpoint")]
    pub passive_auth_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceJoinService {
    #[serde(rename = "JoinEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "JoinResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KeyProvisioningService {
    #[serde(rename = "KeyProvisionEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "KeyProvisionResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WebAuthNService {
    #[serde(rename = "WebAuthNEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "WebAuthNResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceManagementService {
    #[serde(rename = "DeviceManagementEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "DeviceManagementResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MsaProviderData {
    #[serde(rename = "SiteId")]
    pub site_id: Option<String>,
    #[serde(rename = "SiteUrl")]
    pub site_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PrecreateService {
    #[serde(rename = "PrecreateEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "PrecreateResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TenantInfo {
    #[serde(rename = "TenantId")]
    pub tenant_id: Option<String>,
    #[serde(rename = "TenantName")]
    pub tenant_name: Option<String>,
    #[serde(rename = "DisplayName")]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AzureRbacService {
    #[serde(rename = "RbacPolicyEndpoint")]
    pub endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BPLService {
    #[serde(rename = "BPLServiceEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "BPLResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
    #[serde(rename = "BPLProxyServicePrincipalId")]
    pub service_principal_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceJoinResourceService {
    #[serde(rename = "Endpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "ResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NonceService {
    #[serde(rename = "Endpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "ResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DRSDiscoveryResp {
    #[serde(rename = "DiscoveryService")]
    pub discovery_service: Option<DiscoveryService>,
    #[serde(rename = "DeviceRegistrationService")]
    pub device_registration_service: Option<DeviceRegistrationService>,
    #[serde(rename = "AuthenticationService")]
    pub authentication_service: Option<AuthenticationService>,
    #[serde(rename = "IdentityProviderService")]
    pub identity_provider_service: Option<IdentityProviderService>,
    #[serde(rename = "DeviceJoinService")]
    pub device_join_service: Option<DeviceJoinService>,
    #[serde(rename = "KeyProvisioningService")]
    pub key_provisioning_service: Option<KeyProvisioningService>,
    #[serde(rename = "WebAuthNService")]
    pub web_auth_n_service: Option<WebAuthNService>,
    #[serde(rename = "DeviceManagementService")]
    pub device_management_service: Option<DeviceManagementService>,
    #[serde(rename = "MsaProviderData")]
    pub msa_provider_data: Option<MsaProviderData>,
    #[serde(rename = "PrecreateService")]
    pub precreate_service: Option<PrecreateService>,
    #[serde(rename = "TenantInfo")]
    pub tenant_info: Option<TenantInfo>,
    #[serde(rename = "AzureRbacService")]
    pub azure_rbac_service: Option<AzureRbacService>,
    #[serde(rename = "BPLService")]
    pub bpl_service: Option<BPLService>,
    #[serde(rename = "DeviceJoinResourceService")]
    pub device_join_resource_service: Option<DeviceJoinResourceService>,
    #[serde(rename = "NonceService")]
    pub nonce_service: Option<NonceService>,
}

pub async fn discover_enrollment_services(
    access_token: &str,
    domain_name: &str,
) -> Result<DRSDiscoveryResp> {
    let url = Url::parse_with_params(
        &format!("{}/{}/Discover", DISCOVERY_URL, domain_name),
        &[("api-version", DRS_PROTOCOL_VERSION), ("managed", "True")],
    )?;

    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .header(DRS_CLIENT_NAME_HEADER_FIELD, env!("CARGO_PKG_NAME"))
        .header(DRS_CLIENT_VERSION_HEADER_FIELD, env!("CARGO_PKG_VERSION"))
        .header(
            "User-Agent",
            format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        )
        .header(header::ACCEPT, "application/json, text/plain, */*")
        .send()
        .await?;
    if resp.status().is_success() {
        let json_resp: DRSDiscoveryResp = resp.json().await?;
        Ok(json_resp)
    } else {
        Err(anyhow!("{}", resp.text().await?))
    }
}
