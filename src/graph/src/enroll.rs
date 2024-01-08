use crate::discovery::{
    discover_enrollment_services, DISCOVERY_URL, DRS_CLIENT_NAME_HEADER_FIELD,
    DRS_CLIENT_VERSION_HEADER_FIELD,
};
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use hostname;
use kanidm_hsm_crypto::{BoxedDynTpm, LoadableIdentityKey, MachineKey, Tpm};
use openssl::rsa::Rsa;
use openssl::x509::X509;
use os_release::OsRelease;
use reqwest::{header, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_string_pretty};
use tracing::debug;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct Certificate {
    /*#[serde(rename = "Thumbprint")]
    thumbprint: String,*/
    #[serde(rename = "RawBody")]
    raw_body: String,
}

/*#[derive(Debug, Deserialize)]
struct User {
    #[serde(rename = "Upn")]
    upn: String,
}

#[derive(Debug, Deserialize)]
struct MembershipChanges {
    #[serde(rename = "LocalSID")]
    local_sid: String,
    #[serde(rename = "AddSIDs")]
    add_sids: Vec<String>,
}*/

#[derive(Debug, Deserialize)]
struct DRSResponse {
    #[serde(rename = "Certificate")]
    certificate: Certificate,
    /*#[serde(rename = "User")]
    user: User,
    #[serde(rename = "MembershipChanges")]
    membership_changes: MembershipChanges,*/
}

#[derive(Serialize, Clone, Default)]
struct JoinPayload {}

pub async fn register_device(
    machine_key: &MachineKey,
    access_token: &str,
    domain: &str,
    tpm: &mut BoxedDynTpm,
    certificate_id_key: &LoadableIdentityKey,
    transport_id_key: &LoadableIdentityKey,
) -> Result<(LoadableIdentityKey, String)> {
    let enrollment_services = discover_enrollment_services(access_token, domain).await?;
    let (join_endpoint, service_version) = match enrollment_services.device_join_service {
        Some(device_join_service) => {
            let join_endpoint = match device_join_service.endpoint {
                Some(join_endpoint) => join_endpoint,
                None => format!("{}/EnrollmentServer/device/", DISCOVERY_URL).to_string(),
            };
            let service_version = match device_join_service.service_version {
                Some(service_version) => service_version,
                None => "2.0".to_string(),
            };
            (join_endpoint, service_version)
        }
        None => (
            format!("{}/EnrollmentServer/device/", DISCOVERY_URL).to_string(),
            "2.0".to_string(),
        ),
    };

    let url = Url::parse_with_params(&join_endpoint, &[("api-version", service_version)])?;

    let host: String = match hostname::get()?.to_str() {
        Some(host) => String::from(host),
        None => return Err(anyhow!("Failed to get machine hostname for enrollment")),
    };

    let os_release = OsRelease::new()?;

    // Create the CSR
    let csr_der = match tpm.identity_key_certificate_request(
        machine_key,
        certificate_id_key,
        "7E980AD9-B86D-4306-9425-9AC066FB014A",
    ) {
        Ok(csr_der) => csr_der,
        Err(_e) => return Err(anyhow!("Failed creating CSR")),
    };

    // Load the transport key
    let id_key = match tpm.identity_key_load(machine_key, transport_id_key) {
        Ok(id_key) => id_key,
        Err(_e) => return Err(anyhow!("Failed loading id key")),
    };
    let transport_key_der = match tpm.identity_key_public_as_der(&id_key) {
        Ok(transport_key_pem) => transport_key_pem,
        Err(_e) => return Err(anyhow!("Failed getting transport key as der")),
    };
    let transport_key_rsa = Rsa::public_key_from_der(&transport_key_der)?;
    let transport_key_rsa_ref = transport_key_rsa.as_ref();
    let jwk = json!({
        "kty": "RSA",
        "kid": Uuid::new_v4(),
        "e": URL_SAFE_NO_PAD.encode(transport_key_rsa_ref.e().to_vec()),
        "n": URL_SAFE_NO_PAD.encode(transport_key_der)
    });
    let encoded_stk = URL_SAFE.encode(jwk.to_string());

    let payload = json!({
        "CertificateRequest": {
            "Type": "pkcs10",
            "Data": STANDARD.encode(csr_der)
        },
        "DeviceDisplayName": host,
        "DeviceType": "Linux",
        "JoinType": 0,
        "OSVersion": format!("{} {}", os_release.pretty_name, os_release.version_id),
        "TargetDomain": domain,
        "TransportKey": encoded_stk,
        "Attributes": {
            "ReuseDevice": "true",
            "ReturnClientSid": "true"
        }
    });
    if let Ok(pretty) = to_string_pretty(&payload) {
        debug!("POST {}: {}", url, pretty);
    }
    let client = reqwest::Client::new();
    let resp = client
        .post(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .header(header::CONTENT_TYPE, "application/json")
        .header(DRS_CLIENT_NAME_HEADER_FIELD, env!("CARGO_PKG_NAME"))
        .header(DRS_CLIENT_VERSION_HEADER_FIELD, env!("CARGO_PKG_VERSION"))
        .header(header::ACCEPT, "application/json, text/plain, */*")
        .json(&payload)
        .send()
        .await?;
    if resp.status().is_success() {
        let res: DRSResponse = resp.json().await?;
        let loadable_id_key = match tpm.identity_key_associate_certificate(
            machine_key,
            certificate_id_key,
            &STANDARD.decode(res.certificate.raw_body.clone())?,
        ) {
            Ok(loadable_id_key) => loadable_id_key,
            Err(e) => return Err(anyhow!("Failed creating loadable identity key: {:?}", e)),
        };
        let cert = X509::from_pem(
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                res.certificate.raw_body
            )
            .as_bytes(),
        )?;
        let subject_name = cert.subject_name();
        let device_id = match subject_name.entries().next() {
            Some(entry) => entry.data().as_utf8()?,
            None => {
                return Err(anyhow!(
                    "The device id was missing from the certificate response"
                ))
            }
        };
        Ok((loadable_id_key, device_id.to_string()))
    } else {
        Err(anyhow!("{}", resp.text().await?))
    }
}
