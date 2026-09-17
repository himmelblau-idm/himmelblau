//! Native Okta broker compatibility, exercised through the real SDK HTTP boundary.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::db::Cache;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openidconnect::core::{CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::{JsonWebKeyId, PrivateSigningKey};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HELPER_CLIENT: &str = "d7b530a4-7680-4c23-a8bf-c52c121d2e87";
const HELPER_REDIRECT: &str = "https://login.microsoftonline.com/common/oauth2/nativeclient";
const OKTA_CLIENT: &str = "fixture-okta-client";
const OKTA_REDIRECT: &str = "http://localhost/okta-callback";
const ACCOUNT: &str = "broker-test@example.com";
const GRAPH_SCOPE: &str = "https://graph.microsoft.com/.default";

async fn provider() -> OktaProvider {
    let mut config = HimmelblauConfig::new(Some("/dev/null")).unwrap();
    config.set(
        "global",
        "oidc_issuer_url",
        "https://example.okta.com/oauth2/default",
    );
    config.set("global", "oidc_redirect_uri", OKTA_REDIRECT);
    config.set("oidc", "app_id", OKTA_CLIENT);
    let config = Arc::new(Mutex::new(config));
    let idmap = Arc::new(Mutex::new(Idmap::new().unwrap()));
    let standard = OidcProvider::new(&config, "oidc", &idmap).unwrap();
    let provider = OktaProvider::new(&config, "oidc", &idmap, &standard)
        .await
        .unwrap();
    *provider.state.lock().await = CacheState::Online;
    provider
}

async fn access(
    provider: &OktaProvider,
    client: Option<&str>,
    redirect: Option<&str>,
    req_cnf: Option<&str>,
    scopes: &[&str],
) -> Result<UnixUserToken, IdpError> {
    use tpm::{provider::SoftTpm, provider::Tpm, AuthValue};
    let db = crate::db::Db::new("").unwrap();
    let mut txn = db.write().await;
    let mut tpm = tpm::provider::BoxedDynTpm::new(SoftTpm::new());
    let auth = AuthValue::ephemeral().unwrap();
    let loadable = tpm.root_storage_key_create(&auth).unwrap();
    let key = tpm.root_storage_key_load(&auth, &loadable).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        provider.unix_user_access(
            &Id::Name(ACCOUNT.into()),
            scopes.iter().map(|s| (*s).into()).collect(),
            None,
            client.map(str::to_owned),
            redirect.map(str::to_owned),
            req_cnf.map(str::to_owned),
            &mut txn,
            &mut tpm,
            &key,
        ),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn helper_pair_is_replaced_with_configured_okta_values() {
    let provider = provider().await;
    let mut client = Some(HELPER_CLIENT.into());
    let mut redirect = Some(HELPER_REDIRECT.into());
    provider.normalize_broker_client(&mut client, &mut redirect);
    assert_eq!(client.as_deref(), Some(OKTA_CLIENT));
    assert_eq!(redirect.as_deref(), Some(OKTA_REDIRECT));
}

#[tokio::test]
async fn other_broker_pairs_are_preserved_and_strictly_validated() {
    let provider = provider().await;
    for (client, redirect, valid) in [
        (None, None, true),
        (Some(OKTA_CLIENT), None, true),
        (None, Some(OKTA_REDIRECT), true),
        (Some(OKTA_CLIENT), Some(OKTA_REDIRECT), true),
        (Some(HELPER_CLIENT), None, false),
        (None, Some(HELPER_REDIRECT), false),
        (Some(HELPER_CLIENT), Some(OKTA_REDIRECT), false),
        (Some(OKTA_CLIENT), Some(HELPER_REDIRECT), false),
        (Some("other-client"), Some(HELPER_REDIRECT), false),
        (
            Some(HELPER_CLIENT),
            Some("https://other.invalid/callback"),
            false,
        ),
        (Some("other-client"), Some(OKTA_REDIRECT), false),
        (
            Some(OKTA_CLIENT),
            Some("https://other.invalid/callback"),
            false,
        ),
    ] {
        let mut normalized_client = client.map(str::to_owned);
        let mut normalized_redirect = redirect.map(str::to_owned);
        provider.normalize_broker_client(&mut normalized_client, &mut normalized_redirect);
        assert_eq!(normalized_client.as_deref(), client);
        assert_eq!(normalized_redirect.as_deref(), redirect);
        let error = access(&provider, client, redirect, None, &[GRAPH_SCOPE])
            .await
            .err();
        if valid {
            assert!(matches!(error, Some(IdpError::NotFound { .. })),
                "valid request must reach the empty refresh cache: {client:?}, {redirect:?}: {error:?}");
        } else {
            assert!(
                matches!(error, Some(IdpError::BadRequest)),
                "mismatched request must be rejected: {client:?}, {redirect:?}: {error:?}"
            );
        }
    }
}

#[tokio::test]
async fn helper_request_reaches_the_refresh_cache() {
    let provider = provider().await;
    let result = access(
        &provider,
        Some(HELPER_CLIENT),
        Some(HELPER_REDIRECT),
        None,
        &[GRAPH_SCOPE],
    )
    .await;
    assert!(matches!(result, Err(IdpError::NotFound { what, where_ })
        if what == "account_id" && where_ == "refresh_cache"));
}

#[tokio::test]
async fn helper_normalization_does_not_allow_proof_of_possession() {
    let provider = provider().await;
    let result = access(
        &provider,
        Some(HELPER_CLIENT),
        Some(HELPER_REDIRECT),
        Some("fixture-key"),
        &[GRAPH_SCOPE],
    )
    .await;
    assert!(matches!(result, Err(IdpError::BadRequest)));
}

fn signed_id_token(issuer: &str) -> (String, Value) {
    // Public test-only key. Sign at runtime so claims do not expire in the suite.
    let key = CoreRsaPrivateSigningKey::from_pem(
        include_str!("test-signing-key.pem"),
        Some(JsonWebKeyId::new("broker-test-key".into())),
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header =
        URL_SAFE_NO_PAD.encode(json!({"alg":"RS256", "kid":"broker-test-key"}).to_string());
    let claims = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": issuer, "aud": OKTA_CLIENT, "sub": "broker-test-subject",
            "iat": now, "exp": now + 3600,
        })
        .to_string(),
    );
    let message = format!("{header}.{claims}");
    let signature = key
        .sign(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            message.as_bytes(),
        )
        .unwrap();
    let mut jwk = serde_json::to_value(key.as_verification_key()).unwrap();
    jwk["alg"] = json!("RS256");
    jwk["use"] = json!("sig");
    (
        format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)),
        jwk,
    )
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let count = stream.read(&mut buffer).await.unwrap();
        assert_ne!(count, 0, "HTTP client closed before completing its request");
        request.extend_from_slice(&buffer[..count]);
        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&request[..end]);
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if request.len() >= end + 4 + length {
                return String::from_utf8(request).unwrap();
            }
        }
    }
}

#[tokio::test]
async fn helper_requests_refresh_okta_tokens_with_filtered_scopes_and_rotation() {
    for (scopes, expected_scopes) in [
        (vec![GRAPH_SCOPE], "openid profile email offline_access"),
        (vec![GRAPH_SCOPE, "openid", "email"], "openid email"),
        (vec!["openid", "email"], "openid email"),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let issuer = format!("{origin}/oauth2/default");
        let (id_token, jwk) = signed_id_token(&issuer);
        let responses = [
            (
                "POST /oauth2/default/v1/token ",
                json!({
                    "access_token":"fixture-access", "id_token":id_token,
                    "refresh_token":"fixture-rotated", "expires_in":3600,
                    "token_type":"Bearer", "scope":"openid email",
                }),
            ),
            (
                "GET /oauth2/default/.well-known/openid-configuration ",
                json!({
                    "issuer":issuer, "jwks_uri":format!("{issuer}/v1/keys"),
                }),
            ),
            ("GET /oauth2/default/v1/keys ", json!({"keys":[jwk]})),
            (
                "GET /oauth2/default/v1/userinfo ",
                json!({
                    "sub":"broker-test-subject", "preferred_username":ACCOUNT,
                    "email":ACCOUNT, "name":"Broker Test",
                }),
            ),
        ];
        let server = tokio::spawn(async move {
            let mut token_requests = Vec::new();
            for (path, body) in responses.iter().chain(responses.iter()) {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                assert!(
                    request.starts_with(path),
                    "unexpected HTTP request: {request}"
                );
                if request.starts_with("POST ") {
                    let body = request.split_once("\r\n\r\n").unwrap().1;
                    let fields = body
                        .split('&')
                        .map(|field| {
                            let (key, value) = field.split_once('=').unwrap();
                            (
                                key.to_string(),
                                urlencoding::decode(&value.replace('+', " "))
                                    .unwrap()
                                    .into_owned(),
                            )
                        })
                        .collect::<HashMap<_, _>>();
                    token_requests.push(fields);
                }
                let body = body.to_string();
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            token_requests
        });

        let mut provider = provider().await;
        // Only the test SDK transport permits loopback HTTP. Production still
        // requires HTTPS; all token and identity validation remains enabled.
        provider
            .config
            .lock()
            .await
            .set("global", "oidc_issuer_url", &issuer);
        provider.issuer = issuer.clone();
        provider.origin = origin;
        provider.tenant_id = Uuid::new_v5(&OIDC_NAMESPACE, issuer.as_bytes());
        let mut options = ClientConfig::new(&issuer, &provider.client_id, &provider.redirect_uri);
        options.allow_loopback_http = true;
        options.scopes = vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
        ];
        provider.client = Arc::new(PublicClientApplication::new(options).unwrap());
        // This is the in-memory credential handed off by online Hello PIN login.
        provider
            .refresh_cache
            .add(
                ACCOUNT,
                &RefreshCacheEntry::RefreshToken("fixture-refresh".into()),
            )
            .await;

        for _ in 0..2 {
            let token = access(
                &provider,
                Some(HELPER_CLIENT),
                Some(HELPER_REDIRECT),
                None,
                &scopes,
            )
            .await
            .unwrap();
            assert_eq!(token.access_token.as_deref(), Some("fixture-access"));
            assert_eq!(token.id_token.raw.as_deref(), Some(id_token.as_str()));
            assert_eq!(token.id_token.preferred_username.as_deref(), Some(ACCOUNT));
            assert_eq!(token.scope.as_deref(), Some("openid email"));
            assert_eq!(token.token_type, "Bearer");
            assert!((3500..=3600).contains(&token.expires_in));
            assert!(
                matches!(provider.refresh_cache.refresh_token(ACCOUNT).await.unwrap(),
                RefreshCacheEntry::RefreshToken(secret) if secret == "fixture-rotated")
            );
        }
        let requests = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(requests.len(), 2);
        for request in &requests {
            assert_eq!(request["client_id"], OKTA_CLIENT);
            assert_eq!(request["scope"], expected_scopes);
            assert_eq!(request["grant_type"], "refresh_token");
        }
        assert_eq!(requests[0]["refresh_token"], "fixture-refresh");
        assert_eq!(requests[1]["refresh_token"], "fixture-rotated");
    }
}
