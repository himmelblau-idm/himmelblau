use crate::constants::{BROKER_APP_ID, BROKER_CLIENT_IDENT};
use anyhow::{anyhow, Result};
use compact_jwt::crypto::JwsTpmSigner;
use compact_jwt::jws::JwsBuilder;
use compact_jwt::traits::JwsMutSigner;
use kanidm_hsm_crypto::{BoxedDynTpm, IdentityKey};
use os_release::OsRelease;
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use tracing::debug;

pub enum Credentials {
    UsernamePassword(String, String),
    RefreshToken(String),
    SAMLToken(String),
}

#[derive(Serialize, Clone, Default)]
struct UsernamePasswordAuthenticationPayload {
    client_id: String,
    request_nonce: String,
    scope: String,
    win_ver: Option<String>,
    grant_type: String,
    username: String,
    password: String,
}

impl UsernamePasswordAuthenticationPayload {
    fn new(username: &str, password: &str, request_nonce: &str) -> Self {
        let os_release = match OsRelease::new() {
            Ok(os_release) => Some(format!(
                "{} {}",
                os_release.pretty_name, os_release.version_id
            )),
            Err(_) => None,
        };
        UsernamePasswordAuthenticationPayload {
            client_id: BROKER_CLIENT_IDENT.to_string(),
            request_nonce: request_nonce.to_string(),
            scope: "openid aza ugs".to_string(),
            win_ver: os_release,
            grant_type: "password".to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

#[derive(Serialize, Clone, Default)]
struct RefreshTokenAuthenticationPayload {
    client_id: String,
    request_nonce: String,
    scope: String,
    win_ver: Option<String>,
    grant_type: String,
    refresh_token: String,
}

impl RefreshTokenAuthenticationPayload {
    fn new(refresh_token: &str, request_nonce: &str) -> Self {
        let os_release = match OsRelease::new() {
            Ok(os_release) => Some(format!(
                "{} {}",
                os_release.pretty_name, os_release.version_id
            )),
            Err(_) => None,
        };
        RefreshTokenAuthenticationPayload {
            client_id: BROKER_APP_ID.to_string(),
            request_nonce: request_nonce.to_string(),
            scope: "openid aza ugs".to_string(),
            win_ver: os_release,
            grant_type: "refresh_token".to_string(),
            refresh_token: refresh_token.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Nonce {
    #[serde(rename = "Nonce")]
    nonce: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PrimaryRefreshToken {
    pub refresh_token: String,
    pub refresh_token_expires_in: u64,
    pub session_key_jwe: String,
    pub id_token: String,
}

pub struct ClientApplication {
    client: Client,
    tenant_id: String,
    authority_host: String,
}

impl ClientApplication {
    pub fn new(tenant_id: &str, authority_host: &str) -> Result<Self> {
        Ok(ClientApplication {
            client: reqwest::Client::new(),
            tenant_id: tenant_id.to_string(),
            authority_host: authority_host.to_string(),
        })
    }

    async fn request_nonce(&self) -> Result<String> {
        let resp = self
            .client
            .post(format!(
                "https://{}/common/oauth2/token",
                self.authority_host
            ))
            .body("grant_type=srv_challenge")
            .send()
            .await?;
        if resp.status().is_success() {
            let json_resp: Nonce = resp.json().await?;
            Ok(json_resp.nonce)
        } else {
            Err(anyhow!("{}", resp.text().await?))
        }
    }

    pub async fn request_user_prt(
        &self,
        credentials: Credentials,
        tpm: &mut BoxedDynTpm,
        id_key: &IdentityKey,
    ) -> Result<PrimaryRefreshToken> {
        let nonce = self.request_nonce().await?;

        // [MS-OAPXBC] 3.2.5.1.2 POST (Request for Primary Refresh Token)
        debug!("Creating the PRT request JWT");
        let jwt = JwsBuilder::from(match credentials {
            Credentials::UsernamePassword(uname, pass) => serde_json::to_vec(
                &UsernamePasswordAuthenticationPayload::new(&uname, &pass, &nonce),
            )?,
            Credentials::RefreshToken(refresh_token) => serde_json::to_vec(
                &RefreshTokenAuthenticationPayload::new(&refresh_token, &nonce),
            )?,
            _ => return Err(anyhow!("Authentication type not supported")),
        })
        .set_typ(Some("JWT"))
        .build();

        let mut jws_tpm_signer = match JwsTpmSigner::new(tpm, id_key) {
            Ok(jws_tpm_signer) => jws_tpm_signer,
            Err(_) => return Err(anyhow!("Failed loading tpm signer.")),
        };

        debug!("Signing the JWT");
        let signed_jwt = match jws_tpm_signer.sign(&jwt) {
            Ok(signed_jwt) => signed_jwt,
            Err(_) => return Err(anyhow!("Failed signing jwk.")),
        };

        let token_endpoint = format!(
            "https://{}/{}/oauth2/token",
            self.authority_host, self.tenant_id
        );
        let payload = format!(
            "windows_api_version=2.0&grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&request={}&client_info=1&tgt=true",
            signed_jwt
        );
        debug!("POST {}", token_endpoint);
        let resp = self
            .client
            .post(token_endpoint)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(payload)
            .send()
            .await?;
        if resp.status().is_success() {
            let json_resp: PrimaryRefreshToken = resp.json().await?;
            Ok(json_resp)
        } else {
            Err(anyhow!("Failed requesting a PRT: {}", resp.text().await?))
        }
    }
}
