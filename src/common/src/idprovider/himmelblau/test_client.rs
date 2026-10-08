// Script only the external broker calls, keeping the provider's authentication
// state machine and cache-action selection under test. This module is compiled
// only for unit tests; unscripted clients delegate to the real broker.
#![allow(clippy::panic, clippy::too_many_arguments, clippy::unwrap_used)]

use himmelblau::auth::{AuthInit, BrokerClientApplication, UserToken};
use himmelblau::error::MsalError;
use himmelblau::{AuthOption, MFAAuthContinue};
use kanidm_hsm_crypto::{provider::BoxedDynTpm, structures::StorageKey};
use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::sync::Mutex;

#[allow(clippy::large_enum_variant)]
pub(super) enum AuthStep {
    Password(Result<UserToken, MsalError>),
    Refresh {
        client_id: Option<&'static str>,
        response: Result<UserToken, MsalError>,
    },
    Initiate {
        options: Vec<AuthOption>,
        response: Result<MFAAuthContinue, MsalError>,
    },
    Complete(Result<UserToken, MsalError>),
}

struct Script {
    account_id: &'static str,
    password: &'static str,
    steps: VecDeque<AuthStep>,
}

pub(super) struct TestBrokerClient {
    inner: BrokerClientApplication,
    script: Mutex<Option<Script>>,
}

impl From<BrokerClientApplication> for TestBrokerClient {
    fn from(inner: BrokerClientApplication) -> Self {
        Self {
            inner,
            script: Mutex::new(None),
        }
    }
}

impl Deref for TestBrokerClient {
    type Target = BrokerClientApplication;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TestBrokerClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl TestBrokerClient {
    pub(super) fn set_steps(
        &self,
        account_id: &'static str,
        password: &'static str,
        steps: Vec<AuthStep>,
    ) {
        *self.script.lock().unwrap() = Some(Script {
            account_id,
            password,
            steps: steps.into(),
        });
    }

    pub(super) fn assert_finished(&self) {
        let script = self.script.lock().unwrap();
        assert!(script.as_ref().unwrap().steps.is_empty());
    }

    fn next_step(&self, account_id: Option<&str>, password: Option<&str>) -> Option<AuthStep> {
        let mut script = self.script.lock().unwrap();
        let script = script.as_mut()?;
        if let Some(account_id) = account_id {
            assert_eq!(account_id, script.account_id);
        }
        if let Some(password) = password {
            assert_eq!(password, script.password);
        }
        Some(
            script
                .steps
                .pop_front()
                .unwrap_or_else(|| panic!("Unexpected broker call after authentication script")),
        )
    }

    pub(super) async fn acquire_token_by_username_password(
        &self,
        username: &str,
        password: &str,
        scopes: Vec<&str>,
        request_resource: Option<String>,
        client_id: Option<&str>,
        tpm: &mut BoxedDynTpm,
        storage_key: &StorageKey,
    ) -> Result<UserToken, MsalError> {
        match self.next_step(Some(username), Some(password)) {
            Some(AuthStep::Password(response)) => response,
            Some(_) => panic!("Expected a different broker call, got password authentication"),
            None => {
                self.inner
                    .acquire_token_by_username_password(
                        username,
                        password,
                        scopes,
                        request_resource,
                        client_id,
                        tpm,
                        storage_key,
                    )
                    .await
            }
        }
    }

    pub(super) async fn acquire_token_by_refresh_token(
        &self,
        refresh_token: &str,
        scopes: Vec<&str>,
        request_resource: Option<String>,
        client_id: Option<&str>,
        tpm: &mut BoxedDynTpm,
        storage_key: &StorageKey,
    ) -> Result<UserToken, MsalError> {
        match self.next_step(None, None) {
            Some(AuthStep::Refresh {
                client_id: expected_client,
                response,
            }) => {
                assert_eq!(client_id, expected_client);
                response
            }
            Some(_) => panic!("Expected a different broker call, got token refresh"),
            None => {
                self.inner
                    .acquire_token_by_refresh_token(
                        refresh_token,
                        scopes,
                        request_resource,
                        client_id,
                        tpm,
                        storage_key,
                    )
                    .await
            }
        }
    }

    pub(super) async fn initiate_acquire_token_by_mfa_flow_for_device_enrollment(
        &self,
        username: &str,
        password: Option<&str>,
        options: &[AuthOption],
        auth_init: Option<AuthInit>,
        selected_method: Option<&str>,
    ) -> Result<MFAAuthContinue, MsalError> {
        match self.next_step(Some(username), password) {
            Some(AuthStep::Initiate {
                options: expected_options,
                response,
            }) => {
                assert!(password.is_some());
                assert!(options == expected_options);
                assert!(auth_init.is_none(), "MFA must use a fresh auth configuration");
                response
            }
            Some(_) => panic!("Expected a different broker call, got MFA initiation"),
            None => {
                self.inner
                    .initiate_acquire_token_by_mfa_flow_for_device_enrollment(
                        username,
                        password,
                        options,
                        auth_init,
                        selected_method,
                    )
                    .await
            }
        }
    }

    pub(super) async fn acquire_token_by_mfa_flow(
        &self,
        username: &str,
        auth_data: Option<&str>,
        poll_attempt: Option<u32>,
        flow: &mut MFAAuthContinue,
    ) -> Result<UserToken, MsalError> {
        match self.next_step(Some(username), None) {
            Some(AuthStep::Complete(response)) => response,
            Some(_) => panic!("Expected a different broker call, got MFA completion"),
            None => {
                self.inner
                    .acquire_token_by_mfa_flow(username, auth_data, poll_attempt, flow)
                    .await
            }
        }
    }
}
