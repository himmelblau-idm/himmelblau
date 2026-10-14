use anyhow::{anyhow, bail, Context, Result};
use axum::body::Bytes;
use broker_client::BrokerClient;
use reqwest::{header, Client, Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use uuid::Uuid;

const OFFICE_CLIENT_ID: &str = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
const NATIVE_REDIRECT: &str = "https://login.microsoftonline.com/common/oauth2/nativeclient";
const GRAPH: &str = "https://graph.microsoft.com/v1.0";
const MAX_CONTENT: usize = 250_000_000;

#[derive(Clone)]
pub struct Graph {
    http: Client,
    token_cache: Arc<Mutex<Option<CachedToken>>>,
    #[cfg(test)]
    test_endpoint: Option<Url>,
    #[cfg(test)]
    mock_broker: Arc<Mutex<MockBroker>>,
}

#[cfg(test)]
#[derive(Default)]
struct MockBroker {
    calls: usize,
    fail: bool,
}

pub struct Download {
    response: reqwest::Response,
    remaining: usize,
}

impl Download {
    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        let part = self
            .response
            .chunk()
            .await
            .map_err(reqwest::Error::without_url)
            .context("Microsoft 365 download body failed")?;
        if let Some(part) = &part {
            if part.len() > self.remaining {
                bail!("Microsoft 365 document exceeds the 250 MB bridge limit");
            }
            self.remaining -= part.len();
        }
        Ok(part)
    }
}

struct CachedToken {
    value: String,
    sites_search: bool,
    valid_until: Instant,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParentReference {
    pub drive_id: Option<String>,
    pub id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteItem {
    pub id: String,
    pub parent_reference: Option<ParentReference>,
    pub folder: Option<Value>,
    pub file: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: String,
    pub name: String,
    #[serde(rename = "eTag")]
    pub etag: Option<String>,
    pub size: Option<u64>,
    pub last_modified_date_time: Option<String>,
    pub folder: Option<Value>,
    pub file: Option<Value>,
    pub parent_reference: Option<ParentReference>,
    pub remote_item: Option<RemoteItem>,
    pub web_url: Option<String>,
}

impl Item {
    pub fn location(&self, fallback_drive: &str) -> Result<(String, String)> {
        if let Some(remote) = &self.remote_item {
            let drive = remote
                .parent_reference
                .as_ref()
                .and_then(|p| p.drive_id.as_deref())
                .ok_or_else(|| anyhow!("Shared item has no drive ID"))?;
            return Ok((drive.to_owned(), remote.id.clone()));
        }
        Ok((
            self.parent_reference
                .as_ref()
                .and_then(|p| p.drive_id.as_deref())
                .unwrap_or(fallback_drive)
                .to_owned(),
            self.id.clone(),
        ))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Site {
    pub id: String,
    pub display_name: Option<String>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Drive {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    pub id: String,
    pub last_modified_date_time: Option<String>,
    pub size: Option<u64>,
}

#[derive(Deserialize)]
struct Page<T> {
    value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    next: Option<String>,
}

impl Graph {
    pub fn new() -> Result<Self> {
        Ok(Self {
            http: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(300))
                .build()?,
            token_cache: Arc::default(),
            #[cfg(test)]
            test_endpoint: None,
            #[cfg(test)]
            mock_broker: Arc::default(),
        })
    }

    #[cfg(test)]
    pub fn mock(endpoint: Url) -> Self {
        let mut graph = Self::new().unwrap();
        graph.test_endpoint = Some(endpoint);
        graph
    }

    async fn token(&self) -> Result<String> {
        self.token_after_rejection(None).await
    }

    async fn token_after_rejection(&self, rejected: Option<&str>) -> Result<String> {
        // Serialize acquisition, and only invalidate the rejected bearer: an
        // in-flight 401 must not discard a newer token acquired by another task.
        let mut cache = self.token_cache.lock().await;
        if let Some(token) = cache.as_ref().filter(|t| {
            t.valid_until > Instant::now() && Some(t.value.as_str()) != rejected
        }) {
            return Ok(token.value.clone());
        }
        // Clear before acquisition so a broker failure cannot leave a rejected
        // token available to subsequent picker or save requests.
        *cache = None;
        let token = self.acquire_token().await?;
        let value = token.value.clone();
        *cache = Some(token);
        Ok(value)
    }

    async fn invalidate_token(&self, rejected: &str) {
        let mut cache = self.token_cache.lock().await;
        if cache.as_ref().is_some_and(|t| t.value == rejected) {
            *cache = None;
        }
    }

    async fn acquire_token(&self) -> Result<CachedToken> {
        #[cfg(test)]
        if self.test_endpoint.is_some() {
            let mut broker = self.mock_broker.lock().await;
            broker.calls += 1;
            if broker.fail {
                bail!("Mock broker unavailable");
            }
            return Ok(CachedToken {
                value: if broker.calls == 1 {
                    "mock-token".into()
                } else {
                    format!("mock-token-{}", broker.calls)
                },
                sites_search: true,
                valid_until: Instant::now() + Duration::from_secs(3600),
            });
        }
        let broker = tokio::time::timeout(Duration::from_secs(30), BrokerClient::new())
            .await
            .context("Identity broker connection timed out")?
            .context("Identity broker unavailable")?;
        let correlation = Uuid::new_v4().to_string();
        let accounts = tokio::time::timeout(
            Duration::from_secs(30),
            broker.get_accounts(
                "0.0",
                &correlation,
                &json!({"clientId": OFFICE_CLIENT_ID, "redirectUri": NATIVE_REDIRECT}),
            ),
        )
        .await
        .context("Identity broker account lookup timed out")?
        .context("Cannot read Himmelblau account")?;
        let account = accounts
            .get("accounts")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .ok_or_else(|| anyhow!("No signed-in Himmelblau account"))?;
        let response = tokio::time::timeout(
            Duration::from_secs(30),
            broker.acquire_token_silently(
                "0.0",
                &correlation,
                &json!({
                    "account": account,
                    "authParameters": {
                        "account": account,
                        "authority": "https://login.microsoftonline.com/common",
                        "authorizationType": 8,
                        "clientId": OFFICE_CLIENT_ID,
                        "redirectUri": NATIVE_REDIRECT,
                        "requestedScopes": ["https://graph.microsoft.com/.default"],
                        "additionalQueryParametersForAuthorization": {}
                    }
                }),
            ),
        )
        .await
        .context("Identity broker token acquisition timed out")?
        .context("Microsoft 365 token unavailable from Himmelblau broker")?;
        let token = response
            .pointer("/brokerTokenResponse/accessToken")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Himmelblau broker could not acquire a Microsoft 365 token; check himmelblaud for the authentication error"))?;
        let granted = response
            .pointer("/brokerTokenResponse/grantedScopes")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !has_file_write_scope(granted) {
            bail!(
                "Microsoft Office token lacks delegated file write permission (granted file scopes: {})",
                granted_file_scopes(granted)
            );
        }
        let expires_on = response
            .pointer("/brokerTokenResponse/expiresOn")
            .and_then(Value::as_u64)
            .context("Broker did not return a Graph token expiry")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System clock is before Unix epoch")?
            .as_millis() as u64;
        let remaining_ms = expires_on.saturating_sub(now);
        if remaining_ms == 0 {
            bail!("Broker returned an expired Graph token");
        }
        let safety_ms = remaining_ms.saturating_div(10).min(60_000);
        tracing::info!(
            valid_for_seconds = remaining_ms.saturating_sub(safety_ms) / 1000,
            "Microsoft 365 Graph token cached"
        );
        Ok(CachedToken {
            value: token.to_owned(),
            sites_search: has_sites_search_scope(granted),
            valid_until: Instant::now()
                + Duration::from_millis(remaining_ms.saturating_sub(safety_ms)),
        })
    }

    async fn send_authenticated(
        &self,
        request: reqwest::RequestBuilder,
        retry_safe: bool,
    ) -> Result<reqwest::Response> {
        let token = self.token().await?;
        let retry = if retry_safe {
            request.try_clone()
        } else {
            None
        };
        // Sharing-link routes can encode credentials in the path. Strip the
        // complete URL from transport errors, including errors on the retry.
        let response = request
            .bearer_auth(&token)
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("Graph request failed")?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        let refreshed = self
            .token_after_rejection(Some(&token))
            .await
            .context("Graph authentication failed and broker refresh failed")?;
        // Writes and sharing-link redemption must not be replayed. They still
        // refresh the cache so the next explicit user request can recover.
        let Some(retry) = retry else {
            return Ok(response);
        };
        let response = retry
            .bearer_auth(&refreshed)
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("Graph request failed")?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            // One retry only, and do not retain its rejected bearer either.
            self.invalidate_token(&refreshed).await;
        }
        Ok(response)
    }

    fn graph_url(&self, path: &str) -> Result<Url> {
        #[cfg(test)]
        if let Some(base) = &self.test_endpoint {
            return Ok(Url::parse(&format!(
                "{}{path}",
                base.as_str().trim_end_matches('/')
            ))?);
        }
        let url = Url::parse(&format!("{GRAPH}{path}"))?;
        if url.origin().ascii_serialization() != "https://graph.microsoft.com" {
            bail!("Graph URL escaped trusted origin");
        }
        Ok(url)
    }

    async fn request(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
        etag: Option<&str>,
    ) -> Result<reqwest::Response> {
        let trusted = url.scheme() == "https" && url.host_str() == Some("graph.microsoft.com");
        #[cfg(test)]
        let trusted = trusted
            || self
                .test_endpoint
                .as_ref()
                .is_some_and(|base| base.origin() == url.origin());
        if !trusted {
            bail!("Refusing non-Graph API URL");
        }
        let retry_safe = method == Method::GET || method == Method::HEAD;
        let mut req = self.http.request(method, url);
        if let Some(etag) = etag {
            req = req.header(header::IF_MATCH, etag);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let response = self.send_authenticated(req, retry_safe).await?;
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!(
            "Microsoft Graph returned {status}: {}",
            compact_error(&body)
        );
    }

    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request(Method::GET, self.graph_url(path)?, None, None)
            .await?
            .json()
            .await
            .context("Invalid Graph response")
    }

    async fn pages<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<Vec<T>> {
        let mut next = self.graph_url(path)?;
        let mut all = Vec::new();
        for _ in 0..100 {
            let page: Page<T> = self
                .request(Method::GET, next, None, None)
                .await?
                .json()
                .await
                .context("Invalid Graph page")?;
            all.extend(page.value);
            match page.next {
                Some(url) => {
                    next = Url::parse(&url)?;
                    if next.scheme() != "https" || next.host_str() != Some("graph.microsoft.com") {
                        bail!("Unsafe Graph nextLink");
                    }
                }
                None => return Ok(all),
            }
        }
        bail!("Graph pagination exceeded 100 pages")
    }

    pub async fn own_drive(&self) -> Result<Drive> {
        self.get_json("/me/drive").await
    }
    pub async fn root(&self, drive: &str) -> Result<Item> {
        self.get_json(&format!("/drives/{}/root", enc(drive))).await
    }
    pub async fn children(&self, drive: &str, parent: &str) -> Result<Vec<Item>> {
        let path = if parent == "root" {
            format!("/drives/{}/root/children", enc(drive))
        } else {
            format!("/drives/{}/items/{}/children", enc(drive), enc(parent))
        };
        self.pages(&path).await
    }
    pub async fn can_search_sites(&self) -> Result<bool> {
        #[cfg(test)]
        if self.test_endpoint.is_some() {
            return Ok(true);
        }
        self.token().await?;
        Ok(self
            .token_cache
            .lock()
            .await
            .as_ref()
            .is_some_and(|t| t.sites_search))
    }

    pub async fn search_drive(&self, drive: &str, search: &str) -> Result<Vec<Item>> {
        self.pages(&drive_search_path(drive, search)).await
    }
    pub async fn sites(&self, search: &str) -> Result<Vec<Site>> {
        if !self.can_search_sites().await? {
            bail!("SharePoint site search requires delegated Sites.Read.All or Sites.ReadWrite.All consent");
        }
        self.pages(&format!("/sites?search={}", enc(search))).await
    }
    pub async fn drives(&self, site: &str) -> Result<Vec<Drive>> {
        self.pages(&format!("/sites/{}/drives", enc(site))).await
    }
    pub async fn shared_search(&self, search: &str) -> Result<Vec<Item>> {
        // Drive-level search (without /root) includes items shared with the user
        // outside their own drive; remoteItem identifies those search results,
        // not just shortcuts. Keep this supported API rather than sharedWithMe,
        // which is deprecated and stops returning data after November 2026.
        // https://learn.microsoft.com/graph/api/driveitem-search#searching-for-items-a-user-can-access
        let all: Vec<Item> = self
            .pages(&format!(
                "/me/drive/search(q='{}')",
                enc(&search.replace('\'', "''"))
            ))
            .await?;
        Ok(all
            .into_iter()
            .filter(|item| item.remote_item.is_some())
            .collect())
    }
    pub async fn resolve_share(&self, link: &str) -> Result<Item> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let parsed = Url::parse(link).context("Invalid sharing URL")?;
        if parsed.scheme() != "https" {
            bail!("Sharing URL must be HTTPS");
        }
        let share = format!("u!{}", URL_SAFE_NO_PAD.encode(link.as_bytes()));
        let url = self.graph_url(&format!("/shares/{share}/driveItem"))?;
        let response = self
            .send_authenticated(
                self.http.get(url).header("Prefer", "redeemSharingLink"),
                false,
            )
            .await?;
        if !response.status().is_success() {
            bail!(
                "Microsoft Graph rejected sharing link: {}",
                response.status()
            );
        }
        Ok(response.json().await?)
    }
    pub async fn item(&self, drive: &str, item: &str) -> Result<Item> {
        self.get_json(&format!("/drives/{}/items/{}", enc(drive), enc(item)))
            .await
    }
    pub async fn versions(&self, drive: &str, item: &str) -> Result<Vec<Version>> {
        self.pages(&format!(
            "/drives/{}/items/{}/versions",
            enc(drive),
            enc(item)
        ))
        .await
    }
    pub async fn content(&self, drive: &str, item: &str) -> Result<Vec<u8>> {
        let mut download = self.download(drive, item).await?;
        let mut bytes = Vec::new();
        while let Some(part) = download.chunk().await? {
            bytes.extend_from_slice(&part);
        }
        Ok(bytes)
    }

    pub async fn download(&self, drive: &str, item: &str) -> Result<Download> {
        self.download_with_limit(drive, item, MAX_CONTENT).await
    }

    async fn download_with_limit(&self, drive: &str, item: &str, max: usize) -> Result<Download> {
        let path = format!("/drives/{}/items/{}/content", enc(drive), enc(item));
        let response = self
            .send_authenticated(self.http.get(self.graph_url(&path)?), true)
            .await?;
        let response = if response.status().is_redirection() {
            let location = response
                .headers()
                .get(header::LOCATION)
                .context("Graph download has no Location")?
                .to_str()?;
            let url = Url::parse(location)?;
            if url.scheme() != "https" {
                bail!("Graph download redirect is not HTTPS");
            }
            // The redirected URL grants access without a bearer token. Never
            // retain it in errors that callers may log or show to the user.
            self.http
                .get(url)
                .send()
                .await
                .map_err(reqwest::Error::without_url)
                .context("Microsoft 365 download request failed")?
        } else {
            response
        };
        if !response.status().is_success() {
            bail!("Microsoft 365 download failed: {}", response.status());
        }
        if response
            .content_length()
            .is_some_and(|length| length > max as u64)
        {
            bail!("Microsoft 365 document exceeds the 250 MB bridge limit");
        }
        Ok(Download {
            response,
            remaining: max,
        })
    }
    pub async fn replace(
        &self,
        drive: &str,
        item: &str,
        expected: &str,
        bytes: Bytes,
    ) -> Result<Item> {
        let current = self.item(drive, item).await?;
        if current.etag.as_deref() != Some(expected) {
            bail!("Conflict: Microsoft 365 file changed");
        }
        let path = format!(
            "/drives/{}/items/{}/createUploadSession",
            enc(drive),
            enc(item)
        );
        let response: Value = self
            .request(
                Method::POST,
                self.graph_url(&path)?,
                Some(json!({"item":{"@microsoft.graph.conflictBehavior":"replace"}})),
                Some(expected),
            )
            .await?
            .json()
            .await?;
        let upload = response
            .get("uploadUrl")
            .and_then(Value::as_str)
            .context("Graph upload session has no URL")?;
        let url = Url::parse(upload)?;
        self.validate_upload_url(&url)?;
        self.upload(url, bytes).await
    }

    fn validate_upload_url(&self, url: &Url) -> Result<()> {
        #[cfg(test)]
        if self
            .test_endpoint
            .as_ref()
            .is_some_and(|base| base.origin() == url.origin())
        {
            return Ok(());
        }
        if url.scheme() != "https" {
            bail!("Upload URL is not HTTPS");
        }
        Ok(())
    }

    async fn upload(&self, url: Url, bytes: Bytes) -> Result<Item> {
        let total = bytes.len();
        if total == 0 {
            bail!("Empty document upload needs separate Graph handling");
        }
        let chunk = 10 * 1024 * 1024;
        let mut offset = 0;
        let mut completed = None;
        while offset < total {
            let end = (offset + chunk).min(total);
            let response = self
                .http
                .put(url.clone())
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", offset, end - 1, total),
                )
                .body(bytes.slice(offset..end))
                .send()
                .await
                // Upload-session URLs are credentials, including their path
                // and query. Strip the whole URL before attaching context.
                .map_err(reqwest::Error::without_url)
                .context("Microsoft 365 upload request failed")?;
            if !response.status().is_success() {
                bail!("Microsoft 365 upload failed: {}", response.status());
            }
            if end == total {
                completed = Some(
                    response
                        .json::<Item>()
                        .await
                        .map_err(reqwest::Error::without_url)
                        .context("Invalid Microsoft 365 upload response")?,
                );
            }
            offset = end;
        }
        completed.context("Upload did not complete")
    }
    pub async fn create(
        &self,
        drive: &str,
        parent: &str,
        name: &str,
        bytes: Bytes,
    ) -> Result<Item> {
        if name.is_empty() || name.contains('/') {
            bail!("Invalid file name");
        }
        if bytes.is_empty() {
            bail!("Cannot create an empty copy with an upload session");
        }
        let path = if parent == "root" {
            format!(
                "/drives/{}/root:/{encoded}:/createUploadSession",
                enc(drive),
                encoded = enc(name)
            )
        } else {
            format!(
                "/drives/{}/items/{}:/{encoded}:/createUploadSession",
                enc(drive),
                enc(parent),
                encoded = enc(name)
            )
        };
        let response: Value = self
            .request(
                Method::POST,
                self.graph_url(&path)?,
                Some(json!({"item":{"@microsoft.graph.conflictBehavior":"fail","name":name}})),
                None,
            )
            .await?
            .json()
            .await?;
        let upload = response
            .get("uploadUrl")
            .and_then(Value::as_str)
            .context("Graph upload session has no URL")?;
        let url = Url::parse(upload)?;
        self.validate_upload_url(&url)?;
        self.upload(url, bytes).await
    }
    pub async fn update(&self, drive: &str, item: &str, etag: &str, body: Value) -> Result<Item> {
        let path = format!("/drives/{}/items/{}", enc(drive), enc(item));
        Ok(self
            .request(
                Method::PATCH,
                self.graph_url(&path)?,
                Some(body),
                Some(etag),
            )
            .await?
            .json()
            .await?)
    }
    pub async fn delete(&self, drive: &str, item: &str, etag: &str) -> Result<()> {
        let path = format!("/drives/{}/items/{}", enc(drive), enc(item));
        self.request(Method::DELETE, self.graph_url(&path)?, None, Some(etag))
            .await?;
        Ok(())
    }
    pub async fn checkout(&self, drive: &str, item: &str, checkin: bool) -> Result<()> {
        let path = format!(
            "/drives/{}/items/{}/{}",
            enc(drive),
            enc(item),
            if checkin { "checkin" } else { "checkout" }
        );
        let body = checkin
            .then(|| json!({"comment":"Saved with Himmelblau Collabora","checkInAs":"minor"}));
        self.request(Method::POST, self.graph_url(&path)?, body, None)
            .await?;
        Ok(())
    }
}

fn has_sites_search_scope(scopes: &str) -> bool {
    scopes.split_whitespace().filter_map(graph_scope).any(|s| {
        matches!(
            s.to_ascii_lowercase().as_str(),
            "sites.read.all" | "sites.readwrite.all"
        )
    })
}

fn has_file_write_scope(scopes: &str) -> bool {
    scopes
        .split_whitespace()
        .filter_map(graph_scope)
        .any(|scope| {
            matches!(
                scope.to_ascii_lowercase().as_str(),
                "files.readwrite" | "files.readwrite.all" | "sites.readwrite.all"
            )
        })
}

fn graph_scope(scope: &str) -> Option<&str> {
    if scope.contains("://") {
        scope.strip_prefix("https://graph.microsoft.com/")
    } else {
        Some(scope)
    }
}

fn granted_file_scopes(scopes: &str) -> String {
    let names: Vec<_> = scopes
        .split_whitespace()
        .filter_map(graph_scope)
        .filter(|scope| scope.starts_with("Files.") || scope.starts_with("Sites."))
        .collect();
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        drive_search_path, granted_file_scopes, has_file_write_scope, has_sites_search_scope, Graph,
    };

    type AuthRequests = std::sync::Arc<tokio::sync::Mutex<Vec<(reqwest::Method, String)>>>;

    async fn auth_mock(
        status: Option<axum::http::StatusCode>,
    ) -> (Graph, tokio::task::JoinHandle<()>, AuthRequests) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint =
            reqwest::Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let requests: AuthRequests = Default::default();
        let recorded = requests.clone();
        let router = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let recorded = recorded.clone();
            async move {
                let bearer = request.headers()[axum::http::header::AUTHORIZATION]
                    .to_str()
                    .unwrap()
                    .to_owned();
                let status = status.unwrap_or_else(|| {
                    if bearer == "Bearer mock-token" {
                        axum::http::StatusCode::UNAUTHORIZED
                    } else {
                        axum::http::StatusCode::OK
                    }
                });
                recorded
                    .lock()
                    .await
                    .push((request.method().clone(), bearer));
                (
                    status,
                    axum::Json(serde_json::json!({"id": "item", "name": "document.docx"})),
                )
            }
        });
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (Graph::mock(endpoint), task, requests)
    }

    #[tokio::test]
    async fn unauthorized_read_refreshes_unexpired_token_once() {
        let (graph, task, requests) = auth_mock(None).await;
        assert_eq!(graph.token().await.unwrap(), "mock-token");
        assert_eq!(graph.own_drive().await.unwrap().id, "item");
        assert_eq!(graph.own_drive().await.unwrap().id, "item");
        assert_eq!(graph.mock_broker.lock().await.calls, 2);
        let requests = requests.lock().await;
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].1, "Bearer mock-token");
        assert_eq!(requests[1].1, "Bearer mock-token-2");
        assert_eq!(requests[2].1, "Bearer mock-token-2");
        task.abort();
    }

    #[tokio::test]
    async fn repeated_unauthorized_read_stops_and_clears_rejected_token() {
        let (graph, task, requests) = auth_mock(Some(axum::http::StatusCode::UNAUTHORIZED)).await;
        let error = graph.own_drive().await.unwrap_err();
        assert!(error.to_string().contains("401"));
        assert_eq!(requests.lock().await.len(), 2);
        assert_eq!(graph.mock_broker.lock().await.calls, 2);
        assert!(graph.token_cache.lock().await.is_none());
        task.abort();
    }

    #[tokio::test]
    async fn failed_refresh_does_not_retain_rejected_token() {
        let (graph, task, requests) = auth_mock(None).await;
        graph.token().await.unwrap();
        graph.mock_broker.lock().await.fail = true;
        let error = graph.own_drive().await.unwrap_err();
        assert!(error.to_string().contains("broker refresh failed"));
        assert_eq!(requests.lock().await.len(), 1);
        assert_eq!(graph.mock_broker.lock().await.calls, 2);
        assert!(graph.token_cache.lock().await.is_none());
        graph.mock_broker.lock().await.fail = false;
        assert_eq!(graph.own_drive().await.unwrap().id, "item");
        assert_eq!(graph.mock_broker.lock().await.calls, 3);
        task.abort();
    }

    #[tokio::test]
    async fn forbidden_read_does_not_refresh_or_retry() {
        let (graph, task, requests) = auth_mock(Some(axum::http::StatusCode::FORBIDDEN)).await;
        assert!(graph
            .own_drive()
            .await
            .unwrap_err()
            .to_string()
            .contains("403"));
        assert_eq!(requests.lock().await.len(), 1);
        assert_eq!(graph.mock_broker.lock().await.calls, 1);
        assert_eq!(graph.token().await.unwrap(), "mock-token");
        task.abort();
    }

    #[tokio::test]
    async fn unauthorized_writes_refresh_without_automatic_replay() {
        for method in [
            reqwest::Method::POST,
            reqwest::Method::PATCH,
            reqwest::Method::DELETE,
        ] {
            let (graph, task, requests) = auth_mock(None).await;
            let url = graph.graph_url("/write").unwrap();
            let error = graph
                .request(method.clone(), url.clone(), None, Some("original-etag"))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("401"));
            assert_eq!(requests.lock().await.len(), 1);
            assert_eq!(graph.mock_broker.lock().await.calls, 2);
            // A subsequent explicit request uses the refreshed bearer.
            graph
                .request(method.clone(), url, None, Some("original-etag"))
                .await
                .unwrap();
            let requests = requests.lock().await;
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[0], (method.clone(), "Bearer mock-token".to_owned()));
            assert_eq!(requests[1], (method, "Bearer mock-token-2".to_owned()));
            task.abort();
        }
    }

    #[tokio::test]
    async fn sharing_redemption_refreshes_without_automatic_replay() {
        let (graph, task, requests) = auth_mock(None).await;
        let error = graph
            .resolve_share("https://example.com/share")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("401"));
        assert_eq!(requests.lock().await.len(), 1);
        assert_eq!(graph.mock_broker.lock().await.calls, 2);
        assert_eq!(graph.token().await.unwrap(), "mock-token-2");
        task.abort();
    }

    #[tokio::test]
    async fn download_refreshes_its_graph_bearer() {
        let (graph, task, requests) = auth_mock(None).await;
        assert!(!graph.content("drive", "item").await.unwrap().is_empty());
        assert_eq!(requests.lock().await.len(), 2);
        assert_eq!(graph.mock_broker.lock().await.calls, 2);
        task.abort();
    }

    #[tokio::test]
    async fn concurrent_rejections_preserve_the_newer_token() {
        let graph = Graph::mock(reqwest::Url::parse("http://127.0.0.1").unwrap());
        let rejected = graph.token().await.unwrap();
        let (first, second) = tokio::join!(
            graph.token_after_rejection(Some(&rejected)),
            graph.token_after_rejection(Some(&rejected)),
        );
        assert_eq!(first.unwrap(), "mock-token-2");
        assert_eq!(second.unwrap(), "mock-token-2");
        graph.invalidate_token(&rejected).await;
        assert_eq!(graph.token().await.unwrap(), "mock-token-2");
        assert_eq!(graph.mock_broker.lock().await.calls, 2);
    }

    fn assert_redacted_transfer_error(error: &anyhow::Error, context: &str) {
        assert_eq!(error.to_string(), context);
        let transport = error.downcast_ref::<reqwest::Error>().unwrap();
        assert!(transport.url().is_none());
        // Check both the user-facing display and the diagnostic source chain.
        for diagnostic in [format!("{error:#}"), format!("{error:?}")] {
            assert!(!diagnostic.contains("secret-path"));
            assert!(!diagnostic.contains("secret-query"));
            assert!(diagnostic.contains("error sending request"));
        }
    }

    #[tokio::test]
    async fn authenticated_request_and_retry_errors_hide_urls() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        for reject_first in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = reqwest::Url::parse(&format!(
                "http://{}/secret-path?sig=secret-query",
                listener.local_addr().unwrap()
            ))
            .unwrap();
            let task = tokio::spawn(async move {
                if reject_first {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut stream = BufReader::new(stream);
                    loop {
                        let mut line = String::new();
                        assert!(stream.read_line(&mut line).await.unwrap() > 0);
                        if line == "\r\n" {
                            break;
                        }
                    }
                    stream
                        .get_mut()
                        .write_all(
                            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    stream.get_mut().shutdown().await.unwrap();
                }
                // Fail the initial send, or the send after the 401 refresh.
                let (stream, _) = listener.accept().await.unwrap();
                drop(stream);
            });
            let graph = Graph::mock(url.clone());
            let error = graph
                .send_authenticated(graph.http.get(url), true)
                .await
                .unwrap_err();
            assert_redacted_transfer_error(&error, "Graph request failed");
            assert_eq!(
                graph.mock_broker.lock().await.calls,
                if reject_first { 2 } else { 1 }
            );
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn preauthenticated_upload_network_errors_do_not_expose_credentials() {
        use axum::body::Bytes;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = reqwest::Url::parse(&format!(
            "http://{}/secret-path?sig=secret-query",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let task = tokio::spawn(async move {
            // Close without a response for the baseline and the bridge request.
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                drop(stream);
            }
        });
        let graph = Graph::mock(url.clone());
        let original = graph
            .http
            .put(url.clone())
            .body("edits")
            .send()
            .await
            .unwrap_err();
        assert_eq!(original.url(), Some(&url));
        assert!(original.to_string().contains("secret-query"));

        let error = graph
            .upload(url, Bytes::from_static(b"edits"))
            .await
            .unwrap_err();
        assert_redacted_transfer_error(&error, "Microsoft 365 upload request failed");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn preauthenticated_download_network_errors_do_not_expose_credentials() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let location = format!(
            "https://{}/secret-path?sig=secret-query",
            target.local_addr().unwrap()
        );
        let target_task = tokio::spawn(async move {
            let (stream, _) = target.accept().await.unwrap();
            drop(stream);
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let router = axum::Router::new().fallback(move || {
            let location = location.clone();
            async move { axum::response::Redirect::temporary(&location) }
        });
        let graph_task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let graph = Graph::mock(reqwest::Url::parse(&origin).unwrap());
        let error = graph.download("drive", "item").await.err().unwrap();
        assert_redacted_transfer_error(&error, "Microsoft 365 download request failed");
        graph_task.abort();
        target_task.await.unwrap();
    }

    #[tokio::test]
    async fn downloads_enforce_declared_and_streamed_size_limits() {
        use axum::{body::Body, routing::get, Router};
        use std::convert::Infallible;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route(
                "/drives/drive/items/sized/content",
                get(|| async { "abcdef" }),
            )
            .route(
                "/drives/drive/items/chunked/content",
                get(|| async {
                    Body::from_stream(futures_util::stream::iter([
                        Ok::<_, Infallible>("abc"),
                        Ok("def"),
                    ]))
                }),
            );
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let graph = Graph::mock(reqwest::Url::parse(&origin).unwrap());
        assert!(graph
            .download_with_limit("drive", "sized", 5)
            .await
            .is_err());

        let mut download = graph
            .download_with_limit("drive", "chunked", 6)
            .await
            .unwrap();
        assert_eq!(download.response.content_length(), None);
        let mut bytes = Vec::new();
        while let Some(part) = download.chunk().await.unwrap() {
            bytes.extend_from_slice(&part);
        }
        assert_eq!(bytes, b"abcdef");

        let mut download = graph
            .download_with_limit("drive", "chunked", 5)
            .await
            .unwrap();
        let mut received = 0;
        loop {
            match download.chunk().await {
                Ok(Some(part)) => {
                    received += part.len();
                    assert!(received <= 5);
                }
                Ok(None) => panic!("Oversized chunked download was accepted"),
                Err(error) => {
                    assert!(error.to_string().contains("bridge limit"));
                    break;
                }
            }
        }
        task.abort();
    }

    #[tokio::test]
    async fn shared_search_uses_drive_scope_and_retains_external_items() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let router = axum::Router::new().fallback(|uri: axum::http::Uri| async move {
            assert_eq!(
                uri.path(),
                "/me/drive/search(q='Alice%27%27s%20plan%20%26%20budget')"
            );
            axum::Json(serde_json::json!({
                "value": [
                    {"id": "own-file", "name": "Own plan.docx", "file": {}},
                    {
                        "id": "search-result",
                        "name": "Shared plan.docx",
                        "file": {},
                        "remoteItem": {
                            "id": "shared-file",
                            "file": {},
                            "parentReference": {"driveId": "other-drive"}
                        }
                    }
                ]
            }))
        });
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let graph = Graph::mock(reqwest::Url::parse(&origin).unwrap());
        let items = graph.shared_search("Alice's plan & budget").await;
        task.abort();
        let items = items.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "Shared plan.docx");
        assert_eq!(
            items[0].location("own-drive").unwrap(),
            ("other-drive".to_owned(), "shared-file".to_owned())
        );
    }

    #[test]
    fn site_search_requires_sites_consent() {
        assert!(!has_sites_search_scope("Files.ReadWrite.All"));
        assert!(has_sites_search_scope(
            "Files.ReadWrite https://graph.microsoft.com/Sites.Read.All"
        ));
        assert!(has_sites_search_scope("Sites.ReadWrite.All"));
        assert!(!has_sites_search_scope(
            "https://example.com/Sites.Read.All"
        ));
    }

    #[test]
    fn drive_search_escapes_drive_and_query() {
        assert_eq!(
            drive_search_path("drive/a", "Alice's plan & budget"),
            "/drives/drive%2Fa/root/search(q='Alice%27%27s%20plan%20%26%20budget')"
        );
    }

    #[test]
    fn accepts_delegated_graph_file_write_scopes() {
        assert!(has_file_write_scope("User.Read Files.ReadWrite"));
        assert!(has_file_write_scope("Files.ReadWrite.All"));
        assert!(has_file_write_scope("Sites.ReadWrite.All"));
        assert!(has_file_write_scope("files.readwrite"));
        assert!(has_file_write_scope(
            "email openid profile https://graph.microsoft.com/Files.Read.All https://graph.microsoft.com/Files.ReadWrite.All https://graph.microsoft.com/.default"
        ));
    }

    #[test]
    fn rejects_scopes_without_file_write_access() {
        assert!(!has_file_write_scope(""));
        assert!(!has_file_write_scope("User.Read Files.Read.All"));
        assert!(!has_file_write_scope("Files.ReadWrite.AppFolder"));
        assert!(!has_file_write_scope(
            "https://example.com/Files.ReadWrite.All"
        ));
        assert!(!has_file_write_scope(
            "https://graph.microsoft.com/Files.ReadWrite.AppFolder"
        ));
    }

    #[test]
    fn error_details_show_only_relevant_scopes() {
        assert_eq!(
            granted_file_scopes("email https://graph.microsoft.com/Files.Read.All https://graph.microsoft.com/User.Read.All"),
            "Files.Read.All"
        );
    }
}

fn enc(value: &str) -> String {
    urlencoding::encode(value).into_owned()
}
fn drive_search_path(drive: &str, search: &str) -> String {
    format!(
        "/drives/{}/root/search(q='{}')",
        enc(drive),
        enc(&search.replace('\'', "''"))
    )
}
fn compact_error(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/code")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "request rejected".to_owned())
}
