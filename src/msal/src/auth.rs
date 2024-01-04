use crate::constants::{BROKER_APP_ID, BROKER_CLIENT_IDENT};
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use compact_jwt::crypto::JwsTpmSigner;
use compact_jwt::jws::JwsBuilder;
use compact_jwt::traits::JwsMutSigner;
use kanidm_hsm_crypto::{BoxedDynTpm, IdentityKey};
use os_release::OsRelease;
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use serde_json::{from_str as json_from_str, Value};
use std::collections::HashMap;
use tracing::debug;
use urlencoding::encode as url_encode;
use uuid::Uuid;

pub const INVALID_CRED: u32 = 0xC3CE;
pub const REQUIRES_MFA: u32 = 0xC39C;
pub const INVALID_USER: u32 = 0xC372;
pub const NO_CONSENT: u32 = 0xFDE9;
pub const NO_GROUP_CONSENT: u32 = 0xFDEA;
pub const NO_SECRET: u32 = 0x6AD09A;
pub const AUTH_PENDING: u32 = 0x11180;

/* RFC8628: 3.2. Device Authorization Response */
#[derive(Default, Clone, Deserialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    /* MS doesn't implement verification_uri_complete yet, but our
     * authentication will be simpler once they do, so assume it works and fall
     * back to verification_uri if it doesn't.
     */
    pub verification_uri_complete: Option<String>,
    pub expires_in: u32,
    pub interval: Option<u32>,
    pub message: Option<String>,
}

#[derive(Default)]
pub struct UnixUserToken {
    pub spn: String,
    pub displayname: String,
    pub uuid: Uuid,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,

    /* These are only present on failure */
    pub errors: Vec<u32>,
    pub error: String,
    pub error_description: String,
}

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
pub struct AcquireTokenResponse {
    pub token_type: String,
    pub scope: String,
    pub expires_in: u32,
    pub ext_expires_in: u32,
    access_token: String,
    refresh_token: String,
    id_token: String,
    client_info: String,
}

impl AcquireTokenResponse {
    fn unix_user_token(self) -> Result<UnixUserToken> {
        // Parse the id_token for name, spn
        let mut siter = self.id_token.splitn(3, '.');
        if siter.next().is_none() {
            return Err(anyhow!("Failed parsing id_token header"));
        }
        let payload_str = match siter.next() {
            Some(payload_str) => String::from_utf8(URL_SAFE_NO_PAD.decode(payload_str)?)?,
            None => return Err(anyhow!("Failed parsing id_token payload")),
        };
        let payload: Value = json_from_str(&payload_str)?;

        // Parse the client_info for uid
        let client_info_str = String::from_utf8(URL_SAFE_NO_PAD.decode(self.client_info)?)?;
        let client_info: Value = json_from_str(&client_info_str)?;
        let uid_str = client_info["uid"].to_string();
        let uid = Uuid::parse_str(uid_str.trim_matches('"'))?;

        Ok(UnixUserToken {
            spn: payload["preferred_username"]
                .to_string()
                .trim_matches('"')
                .to_string(),
            displayname: payload["name"].to_string().trim_matches('"').to_string(),
            uuid: uid,
            access_token: Some(self.access_token),
            refresh_token: Some(self.refresh_token),
            ..Default::default()
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ErrorResponse {
    error: String,
    error_description: String,
    error_codes: Vec<u32>,
}

impl ErrorResponse {
    fn unix_user_token_error(self) -> Result<UnixUserToken> {
        Ok(UnixUserToken {
            errors: self.error_codes,
            error: self.error,
            error_description: self.error_description,
            ..Default::default()
        })
    }
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
    refresh_cache: HashMap<String, String>,
}

impl ClientApplication {
    pub fn new(tenant_id: &str, authority_host: &str) -> Result<Self> {
        Ok(ClientApplication {
            client: reqwest::Client::new(),
            tenant_id: tenant_id.to_string(),
            authority_host: authority_host.to_string(),
            refresh_cache: HashMap::new(),
        })
    }

    pub async fn acquire_token_by_username_password(
        &mut self,
        username: &str,
        password: &str,
        scopes: Vec<&str>,
    ) -> Result<UnixUserToken> {
        let mut all_scopes = vec!["openid", "profile", "offline_access"];
        all_scopes.extend(scopes);
        let scopes_str = all_scopes.join(" ");

        let params = [
            ("client_id", BROKER_APP_ID),
            ("scope", &scopes_str),
            ("username", username),
            ("password", password),
            ("grant_type", "password"),
            ("client_info", "1"),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client
            .post(format!(
                "https://{}/{}/oauth2/v2.0/token",
                self.authority_host, self.tenant_id
            ))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await?;
        if resp.status().is_success() {
            let json_resp: AcquireTokenResponse = resp.json().await?;
            let result = json_resp.unix_user_token();

            // Cache the refresh token
            if let Ok(ref token) = result {
                if let Some(refresh_token) = &token.refresh_token {
                    if self.refresh_cache.contains_key(username) {
                        self.refresh_cache.remove(username);
                    }
                    self.refresh_cache
                        .insert(username.to_string(), refresh_token.to_string());
                }
            }

            result
        } else {
            let json_resp: ErrorResponse = resp.json().await?;
            json_resp.unix_user_token_error()
        }
    }

    pub async fn initiate_device_flow(
        &self,
        scopes: Vec<&str>,
    ) -> Result<DeviceAuthorizationResponse> {
        let mut all_scopes = vec!["openid", "profile", "offline_access"];
        all_scopes.extend(scopes);
        let scopes_str = all_scopes.join(" ");

        let params = [("client_id", BROKER_APP_ID), ("scope", &scopes_str)];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client
            .post(format!(
                "https://{}/{}/oauth2/v2.0/devicecode",
                self.authority_host, self.tenant_id
            ))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await?;
        if resp.status().is_success() {
            let json_resp: DeviceAuthorizationResponse = resp.json().await?;
            Ok(json_resp)
        } else {
            Err(anyhow!(
                "Failed initiating device flow: {}",
                resp.text().await?
            ))
        }
    }

    pub async fn acquire_token_by_device_flow(
        &mut self,
        flow: DeviceAuthorizationResponse,
    ) -> Result<UnixUserToken> {
        let params = [
            ("client_id", BROKER_APP_ID),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", &flow.device_code),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client
            .post(format!(
                "https://{}/{}/oauth2/v2.0/token",
                self.authority_host, self.tenant_id
            ))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await?;
        if resp.status().is_success() {
            let json_resp: AcquireTokenResponse = resp.json().await?;
            let result = json_resp.unix_user_token();

            // Cache the refresh token
            if let Ok(ref token) = result {
                if let Some(refresh_token) = &token.refresh_token {
                    let username = &token.spn;
                    if self.refresh_cache.contains_key(username) {
                        self.refresh_cache.remove(username);
                    }
                    self.refresh_cache
                        .insert(username.to_string(), refresh_token.to_string());
                }
            }

            result
        } else {
            let json_resp: ErrorResponse = resp.json().await?;
            json_resp.unix_user_token_error()
        }
    }

    pub async fn acquire_token_silent(
        &mut self,
        scopes: Vec<&str>,
        username: &str,
    ) -> Result<UnixUserToken> {
        let refresh_token = match self.refresh_cache.get(username) {
            Some(refresh_token) => refresh_token,
            None => return Err(anyhow!("Acquire token silent failed")),
        };
        let mut all_scopes = vec!["openid", "profile", "offline_access"];
        all_scopes.extend(scopes);
        let scopes_str = all_scopes.join(" ");

        let params = [
            ("client_id", BROKER_APP_ID),
            ("scope", &scopes_str),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_info", "1"),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client
            .post(format!(
                "https://{}/{}/oauth2/v2.0/token",
                self.authority_host, self.tenant_id
            ))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await?;
        if resp.status().is_success() {
            let json_resp: AcquireTokenResponse = resp.json().await?;
            let result = json_resp.unix_user_token();

            // Cache the refresh token
            if let Ok(ref token) = result {
                if let Some(refresh_token) = &token.refresh_token {
                    if self.refresh_cache.contains_key(username) {
                        self.refresh_cache.remove(username);
                    }
                    self.refresh_cache
                        .insert(username.to_string(), refresh_token.to_string());
                }
            }

            result
        } else {
            let json_resp: ErrorResponse = resp.json().await?;
            json_resp.unix_user_token_error()
        }
    }

    pub fn remove_account(&mut self, username: &str) -> Result<()> {
        if self.refresh_cache.contains_key(username) {
            self.refresh_cache.remove(username);
        }
        Ok(())
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
