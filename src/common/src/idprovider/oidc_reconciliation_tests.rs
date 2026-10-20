//! Reconciliation through the real generic OIDC refresh and userinfo boundary.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::db::{Cache, Db};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn reconciliation_oidc_rejects_unverified_or_replacement_claims() {
    use tpm::{provider::SoftTpm, provider::Tpm, AuthValue};
    for case in [
        "replacement_missing_account",
        "matching_missing_account",
        "userinfo_failure",
        "malformed_refresh",
        "matching",
        "unrestricted",
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let account = "reconcile@example.com";
        let subject = if case == "replacement_missing_account" {
            "replacement"
        } else {
            "original"
        };
        let claims = if case.ends_with("missing_account") {
            json!({"sub":subject})
        } else {
            json!({"sub":subject,"preferred_username":account,"email":account})
        };
        let mut responses = [
            (
                "GET /.well-known/openid-configuration ",
                json!({
                "issuer":issuer,"authorization_endpoint":format!("{issuer}/authorize"),
                "token_endpoint":format!("{issuer}/token"),"userinfo_endpoint":format!("{issuer}/userinfo"),
                "jwks_uri":format!("{issuer}/keys"),"device_authorization_endpoint":format!("{issuer}/device"),
                "response_types_supported":["code"],"subject_types_supported":["public"],
                "id_token_signing_alg_values_supported":["RS256"]}),
            ),
            ("GET /keys ", json!({"keys":[]})),
            (
                "POST /token ",
                json!({"access_token":"fixture-access","refresh_token":"replacement-refresh","token_type":"Bearer","expires_in":3600}),
            ),
            ("GET /userinfo ", claims),
        ];
        if case == "malformed_refresh" {
            responses[2].1 = json!({"refresh_token":"replacement-refresh","token_type":"Bearer"});
        }
        let metadata: DeviceProviderMetadata =
            serde_json::from_value(responses[0].1.clone()).unwrap();
        let server = tokio::spawn(async move {
            for (path, body) in responses.into_iter().skip(2) {
                if case == "malformed_refresh" && path.contains("userinfo") {
                    break;
                }
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut buf = [0; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buf[..n]);
                    if bytes.windows(4).any(|v| v == b"\r\n\r\n") {
                        break;
                    }
                }
                assert!(String::from_utf8_lossy(&bytes).starts_with(path));
                let status = if case == "userinfo_failure" && path.contains("userinfo") {
                    "503 Service Unavailable"
                } else {
                    "200 OK"
                };
                let body = body.to_string();
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
        });
        let mut config = HimmelblauConfig::new(Some("/dev/null")).unwrap();
        config.set("global", "oidc_issuer_url", "https://fixture.example");
        config.set("global", "app_id", "fixture-client");
        let config = Arc::new(Mutex::new(config));
        let idmap = Arc::new(Mutex::new(Idmap::new().unwrap()));
        let provider = OidcProvider::new(&config, "oidc", &idmap).unwrap();
        let tenant = provider.tenant_id().await.unwrap();
        let range = config.lock().await.get_idmap_range("oidc");
        idmap
            .lock()
            .await
            .add_gen_domain("oidc", &tenant.to_string(), range)
            .unwrap();
        // Inject only discovery metadata; refresh and userinfo still traverse
        // the real HTTP/provider code. Production issuer validation is unchanged.
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new("fixture-client".into()),
            None,
        )
        .set_device_authorization_url(
            DeviceAuthorizationUrl::new(format!("{issuer}/device")).unwrap(),
        )
        .set_auth_type(AuthType::RequestBody);
        provider
            .client
            .client
            .lock()
            .await
            .replace(OidcDelayedInit {
                client,
                http_client: reqwest::Client::new(),
                authorization_endpoint: format!("{issuer}/authorize"),
                openid_configuration_url: format!("{issuer}/.well-known/openid-configuration"),
                password_grant_supported: false,
            });
        let old = UserToken {
            name: account.into(),
            spn: account.into(),
            uuid: Uuid::new_v5(&tenant, b"original"),
            real_gidnumber: None,
            gidnumber: 200001,
            displayname: "Original".into(),
            shell: None,
            groups: vec![],
            tenant_id: Some(tenant),
            valid: true,
        };
        provider
            .refresh_cache
            .add(
                account,
                &RefreshCacheEntry::RefreshToken("original-refresh".into()),
            )
            .await;
        let db = Db::new("").unwrap();
        let mut txn = db.write().await;
        let mut tpm = tpm::provider::BoxedDynTpm::new(SoftTpm::new());
        let auth = AuthValue::ephemeral().unwrap();
        let loadable = tpm.root_storage_key_create(&auth).unwrap();
        let key = tpm.root_storage_key_load(&auth, &loadable).unwrap();
        let expected = (case != "unrestricted").then_some((old.uuid, old.tenant_id));
        let state = tokio::time::timeout(
            Duration::from_secs(10),
            provider.unix_user_get(
                &Id::Name(account.into()),
                Some(&old),
                expected,
                &mut txn,
                &mut tpm,
                &key,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        if matches!(case, "matching" | "unrestricted") {
            assert!(matches!(state, UserTokenState::Update(_)), "{case}");
        } else {
            assert!(matches!(state, UserTokenState::Rejected), "{case}");
        }
        let secret = if matches!(case, "matching" | "unrestricted") {
            "replacement-refresh"
        } else {
            "original-refresh"
        };
        assert!(
            matches!(provider.refresh_cache.refresh_token(account).await.unwrap(),RefreshCacheEntry::RefreshToken(value) if value == secret),
            "{case}"
        );
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
    }
}
