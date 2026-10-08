//! Exercise the real provider state machine with only broker requests scripted.
#![allow(clippy::unwrap_used, clippy::needless_pass_by_value)]

use super::test_client::AuthStep;
use super::{HimmelblauProvider, EDGE_BROWSER_CLIENT_ID};
use crate::config::HimmelblauConfig;
use crate::db::{CacheError, KeyStoreTxn};
use crate::idprovider::interface::{
    AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, IdProvider, UserToken,
};
use crate::unix_proto::PamAuthRequest;
use himmelblau::auth::{BrokerClientApplication, UserToken as UnixUserToken};
use himmelblau::error::{AADSTSError, ErrorResponse, MsalError};
use himmelblau::graph::Graph;
use himmelblau::{AuthOption, MFAAuthContinue, MfaMethodInfo};
use idmap::Idmap;
use kanidm_hsm_crypto::{
    provider::{BoxedDynTpm, SoftTpm, Tpm, TpmRS256},
    structures::{LoadableMsDeviceEnrolmentKey, StorageKey},
    AuthValue,
};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{broadcast, Mutex};
use uuid::Uuid;

const ACCOUNT: &str = "testuser@example.com";
const PASSWORD: &str = "test-password";
const DOMAIN: &str = "example.com";
const TENANT: &str = "58e8a301-2502-4814-81c5-a4d17c399a45";
const OTP_PROMPT: &str = "Enter the verification code";

#[derive(Default)]
struct TestKeyStore(HashMap<String, Vec<u8>>);

impl KeyStoreTxn for TestKeyStore {
    fn get_tagged_hsm_key<K: serde::de::DeserializeOwned>(
        &mut self,
        tag: &str,
    ) -> Result<Option<K>, CacheError> {
        self.0
            .get(tag)
            .map(|bytes| serde_cbor::from_slice(bytes).map_err(|_| CacheError::SerdeJson))
            .transpose()
    }

    fn insert_tagged_hsm_key<K: serde::Serialize>(
        &mut self,
        tag: &str,
        key: &K,
    ) -> Result<(), CacheError> {
        self.0.insert(
            tag.to_string(),
            serde_cbor::to_vec(key).map_err(|_| CacheError::SerdeJson)?,
        );
        Ok(())
    }

    fn delete_tagged_hsm_key(&mut self, tag: &str) -> Result<(), CacheError> {
        self.0.remove(tag);
        Ok(())
    }
}

struct Fixture {
    provider: HimmelblauProvider,
    keystore: TestKeyStore,
    tpm: BoxedDynTpm,
    machine_key: StorageKey,
    old_token: UserToken,
    config_path: PathBuf,
}

impl Fixture {
    async fn new() -> Self {
        let config_path =
            std::env::temp_dir().join(format!("himmelblau-password-first-{}.conf", Uuid::new_v4()));
        std::fs::write(&config_path, "[global]\n").unwrap();
        let mut config = HimmelblauConfig::new(config_path.to_str()).unwrap();
        config.set("global", "allow_console_password_only", "true");
        config.set("global", "apply_policy", "true");
        config.set("offline_breakglass", "enabled", "true");
        config.set(DOMAIN, "tenant_id", TENANT);
        config.set(DOMAIN, "device_id", "test-device");
        config.set(DOMAIN, "intune_device_id", "test-intune-device");
        assert!(config.get_offline_breakglass_enabled());
        let config = Arc::new(Mutex::new(config));
        let timeout = Duration::from_secs(1);
        // Cached federation values make Graph construction entirely local.
        let graph = Graph::new(
            "127.0.0.1:9",
            DOMAIN,
            Some("127.0.0.1:9"),
            Some(TENANT),
            Some("https://127.0.0.1:9/graph"),
            timeout,
            &[],
        )
        .await
        .unwrap();
        let client = BrokerClientApplication::new(
            Some("https://127.0.0.1:9/common"),
            None,
            None,
            None,
            timeout,
            &[],
        )
        .unwrap();
        let idmap = Arc::new(Mutex::new(Idmap::new().unwrap()));
        let provider = HimmelblauProvider::new(client, &config, DOMAIN, graph, &idmap).unwrap();
        // Authentication is the subject of this test, not discovery or writes
        // to the machine-wide generated configuration.
        provider.init.set(()).unwrap();

        let mut tpm = BoxedDynTpm::new(SoftTpm::new());
        let auth = AuthValue::ephemeral().unwrap();
        let loadable_machine_key = tpm.root_storage_key_create(&auth).unwrap();
        let machine_key = tpm
            .root_storage_key_load(&auth, &loadable_machine_key)
            .unwrap();
        let transport_key = tpm.rs256_create(&machine_key).unwrap();
        // The real joined/enrolled checks deserialize key records and check
        // their presence. Broker cryptography is scripted, so no certificate
        // is loaded and its DER bytes are deliberately an empty marker.
        let cert_key = LoadableMsDeviceEnrolmentKey::Rsa2048V1 {
            loadable_rs256_key: transport_key.clone(),
            x509_der: vec![],
        };
        let mut keystore = TestKeyStore::default();
        keystore
            .insert_tagged_hsm_key(&provider.fetch_tranport_key_tag(), &transport_key)
            .unwrap();
        keystore
            .insert_tagged_hsm_key(&provider.fetch_cert_key_tag(), &cert_key)
            .unwrap();
        keystore
            .insert_tagged_hsm_key(&provider.fetch_intune_key_tag(), &cert_key)
            .unwrap();
        assert!(provider.is_domain_joined(&mut keystore).await);
        assert!(provider.is_intune_enrolled(&mut keystore).await);

        let old_token = UserToken {
            name: ACCOUNT.to_string(),
            spn: ACCOUNT.to_string(),
            uuid: Uuid::nil(),
            real_gidnumber: None,
            gidnumber: 2000,
            displayname: "Test User".to_string(),
            shell: None,
            groups: vec![],
            tenant_id: Some(Uuid::parse_str(TENANT).unwrap()),
            valid: true,
        };
        Self {
            provider,
            keystore,
            tpm,
            machine_key,
            old_token,
            config_path,
        }
    }

    async fn script(&self, steps: Vec<AuthStep>) {
        self.provider
            .client
            .lock()
            .await
            .set_steps(ACCOUNT, PASSWORD, steps);
    }

    async fn step(
        &mut self,
        handler: &mut AuthCredHandler,
        request: PamAuthRequest,
    ) -> (AuthResult, AuthCacheAction) {
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
        self.provider
            .unix_user_online_auth_step(
                ACCOUNT,
                &self.old_token,
                "login",
                false,
                handler,
                request,
                &mut self.keystore,
                &mut self.tpm,
                &self.machine_key,
                &shutdown_rx,
            )
            .await
            .unwrap()
    }

    async fn assert_finished(&self) {
        self.provider.client.lock().await.assert_finished();
        assert!(self
            .provider
            .refresh_cache
            .refresh_token(ACCOUNT)
            .await
            .is_err());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.config_path);
    }
}

fn password_first_handler() -> AuthCredHandler {
    AuthCredHandler::PasswordFirst {
        // ForceMFA must be added by the production transition, not the fixture.
        auth_options: vec![AuthOption::Fido, AuthOption::IntuneEnable],
        is_domain_joined: true,
    }
}

fn token() -> UnixUserToken {
    UnixUserToken {
        token_type: "Bearer".to_string(),
        scope: None,
        expires_in: 3600,
        ext_expires_in: 3600,
        access_token: Some("test-access-token".to_string()),
        refresh_token: "test-refresh-token".to_string(),
        id_token: Default::default(),
        client_info: Default::default(),
        prt: None,
    }
}

fn initiate() -> AuthStep {
    AuthStep::Initiate {
        options: vec![
            AuthOption::Fido,
            AuthOption::IntuneEnable,
            AuthOption::ForceMFA,
        ],
        response: Ok(MFAAuthContinue {
            msg: OTP_PROMPT.to_string(),
            mfa_methods: vec!["PhoneAppOTP".to_string()],
            mfa_method_details: vec![MfaMethodInfo {
                auth_method_id: "PhoneAppOTP".to_string(),
                display: "Verification code".to_string(),
                is_default: true,
            }],
            ..Default::default()
        }),
    }
}

fn refresh(error: MsalError) -> AuthStep {
    AuthStep::Refresh {
        client_id: Some(EDGE_BROWSER_CLIENT_ID),
        response: Err(error),
    }
}

fn token_error(codes: Vec<u32>) -> MsalError {
    MsalError::AcquireTokenFailed(ErrorResponse {
        error: "invalid_grant".to_string(),
        error_description: "test authentication requirement".to_string(),
        suberror: None,
        error_codes: codes,
    })
}

fn mfa_demands() -> Vec<MsalError> {
    let mut demands = vec![MsalError::MFARequired];
    for code in [50072, 50074, 50076] {
        demands.push(MsalError::AADSTSError(AADSTSError::new(code, None)));
        demands.push(token_error(vec![code]));
    }
    demands
}

fn assert_mfa_challenge(result: (AuthResult, AuthCacheAction), handler: &AuthCredHandler) {
    assert!(matches!(
        result,
        (
            AuthResult::Next(AuthRequest::Input { msg, echo_on: false, .. }),
            AuthCacheAction::None
        ) if msg == OTP_PROMPT
    ));
    assert!(matches!(
        handler,
        AuthCredHandler::MFA { password: Some(password), .. } if password == PASSWORD
    ));
}

fn assert_denied(result: (AuthResult, AuthCacheAction)) {
    assert!(matches!(
        result,
        (AuthResult::Denied(_), AuthCacheAction::None)
    ));
}

// The macro-expanded provider future has large debug-build construction/move
// frames. Construct and poll each test future on a dedicated stack rather than
// changing process-wide stack settings or production authentication code.
fn run_provider_test<F, Fut>(test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()>,
{
    let worker = std::thread::Builder::new()
        .name("password-first-provider-test".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(test());
        })
        .unwrap();
    if let Err(panic) = worker.join() {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn password_first_refresh_mfa_demand_enters_real_interactive_flow() {
    run_provider_test(|| async {
        let mut fixture = Fixture::new().await;
        for demand in mfa_demands() {
            fixture
                .script(vec![
                    AuthStep::Password(Ok(token())),
                    refresh(demand),
                    initiate(),
                ])
                .await;
            let mut handler = password_first_handler();
            let result = fixture
                .step(
                    &mut handler,
                    PamAuthRequest::Password {
                        cred: PASSWORD.into(),
                    },
                )
                .await;
            assert_mfa_challenge(result, &handler);
            fixture.assert_finished().await;
        }
    });
}

#[test]
fn password_first_default_client_refresh_mfa_demand_enters_interactive_flow() {
    run_provider_test(|| async {
        let mut fixture = Fixture::new().await;
        fixture
            .script(vec![
                AuthStep::Password(Ok(token())),
                refresh(MsalError::AADSTSError(AADSTSError::new(65001, None))),
                AuthStep::Refresh {
                    client_id: Some(super::DEFAULT_APP_ID),
                    response: Err(MsalError::MFARequired),
                },
                initiate(),
            ])
            .await;
        let mut handler = password_first_handler();
        let result = fixture
            .step(
                &mut handler,
                PamAuthRequest::Password {
                    cred: PASSWORD.into(),
                },
            )
            .await;
        assert_mfa_challenge(result, &handler);
        fixture.assert_finished().await;
    });
}

#[test]
fn password_first_repeated_refresh_mfa_demand_denies_without_restarting() {
    run_provider_test(|| async {
        let mut fixture = Fixture::new().await;
        for demand in mfa_demands() {
            fixture
                .script(vec![
                    AuthStep::Password(Ok(token())),
                    refresh(MsalError::MFARequired),
                    initiate(),
                    AuthStep::Complete(Ok(token())),
                    refresh(demand),
                ])
                .await;
            let mut handler = password_first_handler();
            let result = fixture
                .step(
                    &mut handler,
                    PamAuthRequest::Password {
                        cred: PASSWORD.into(),
                    },
                )
                .await;
            assert_mfa_challenge(result, &handler);
            assert_denied(
                fixture
                    .step(
                        &mut handler,
                        PamAuthRequest::Input {
                            cred: "123456".into(),
                        },
                    )
                    .await,
            );
            fixture.assert_finished().await;
        }
    });
}

#[test]
fn password_first_genuine_denials_do_not_start_mfa() {
    run_provider_test(|| async {
        let mut fixture = Fixture::new().await;
        fixture
            .script(vec![AuthStep::Password(Err(MsalError::AADSTSError(
                AADSTSError::new(50126, None),
            )))])
            .await;
        let mut handler = password_first_handler();
        assert_denied(
            fixture
                .step(
                    &mut handler,
                    PamAuthRequest::Password {
                        cred: PASSWORD.into(),
                    },
                )
                .await,
        );
        fixture.assert_finished().await;

        for codes in [vec![53003], vec![50076, 53003]] {
            fixture
                .script(vec![
                    AuthStep::Password(Ok(token())),
                    refresh(token_error(codes)),
                ])
                .await;
            let mut handler = password_first_handler();
            assert_denied(
                fixture
                    .step(
                        &mut handler,
                        PamAuthRequest::Password {
                            cred: PASSWORD.into(),
                        },
                    )
                    .await,
            );
            fixture.assert_finished().await;
        }
    });
}

#[test]
fn password_first_denied_mfa_completion_does_not_cache_password() {
    run_provider_test(|| async {
        let mut fixture = Fixture::new().await;
        fixture
            .script(vec![
                AuthStep::Password(Ok(token())),
                refresh(MsalError::MFARequired),
                initiate(),
                AuthStep::Complete(Err(MsalError::AADSTSError(AADSTSError::new(500121, None)))),
            ])
            .await;
        let mut handler = password_first_handler();
        let result = fixture
            .step(
                &mut handler,
                PamAuthRequest::Password {
                    cred: PASSWORD.into(),
                },
            )
            .await;
        assert_mfa_challenge(result, &handler);
        assert_denied(
            fixture
                .step(
                    &mut handler,
                    PamAuthRequest::Input {
                        cred: "123456".into(),
                    },
                )
                .await,
        );
        fixture.assert_finished().await;
    });
}

#[test]
fn password_first_repeated_mfa_initiation_demand_is_bounded() {
    run_provider_test(|| async {
        let mut fixture = Fixture::new().await;
        fixture
            .script(vec![
                AuthStep::Password(Ok(token())),
                refresh(MsalError::MFARequired),
                AuthStep::Initiate {
                    options: vec![
                        AuthOption::Fido,
                        AuthOption::IntuneEnable,
                        AuthOption::ForceMFA,
                    ],
                    response: Err(MsalError::MFARequired),
                },
                AuthStep::Initiate {
                    options: vec![
                        AuthOption::Fido,
                        AuthOption::IntuneEnable,
                        AuthOption::ForceMFA,
                    ],
                    response: Err(MsalError::MFARequired),
                },
            ])
            .await;
        let mut handler = password_first_handler();
        assert_denied(
            fixture
                .step(
                    &mut handler,
                    PamAuthRequest::Password {
                        cred: PASSWORD.into(),
                    },
                )
                .await,
        );
        fixture.assert_finished().await;
    });
}
