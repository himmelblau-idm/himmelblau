extern crate himmelblau_unix_common as real_common;

use kanidm_hsm_crypto::AuthValue;
use real_common::constants::{DEFAULT_HSM_PIN_PATH, DEFAULT_HSM_PIN_PATH_ENC};
use real_common::unix_config::HsmType;
use std::process::Command;
use std::sync::Mutex;
use tracing::{error, info, trace};

const CREDENTIALS_DIRECTORY: &str = "/run/credentials/himmelblaud.service";
const CREDENTIAL_PIN: &str = "/run/credentials/himmelblaud.service/hsm-pin";
const READ_PIN: &[u8] = b"0123456789abcdef0123456789abcdef";
const DECRYPTED_PIN: &[u8] = b"abcdef0123456789abcdef0123456789";

struct MockState {
    calls: Vec<(&'static str, String)>,
    decrypt_fails: bool,
    read_fails: bool,
}

static MOCK: Mutex<MockState> = Mutex::new(MockState {
    calls: Vec::new(),
    decrypt_fails: false,
    read_fails: false,
});

// The macro imports this module's PIN I/O mocks, like module mocks in a TS test.
mod himmelblau_unix_common {
    pub use real_common::{constants, unix_config};

    pub mod tpm {
        pub use real_common::tpm::{is_systemd_credential, open_tpm, open_tpm_if_possible};
        use std::error::Error;
        use zeroize::Zeroizing;

        pub fn decrypt_hsm_pin(path: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
            let mut mock = crate::MOCK.lock().unwrap();
            mock.calls.push(("decrypt", path.to_string()));
            if mock.decrypt_fails {
                return Err(std::io::Error::other("mock decrypt failure").into());
            }
            Ok(crate::DECRYPTED_PIN.to_vec().into())
        }

        pub async fn read_hsm_pin(path: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
            let mut mock = crate::MOCK.lock().unwrap();
            mock.calls.push(("read", path.to_string()));
            if mock.read_fails {
                return Err(std::io::Error::other("mock read failure").into());
            }
            Ok(crate::READ_PIN.to_vec().into())
        }

        pub async fn write_hsm_pin(path: &str) -> Result<(), Box<dyn Error>> {
            crate::MOCK
                .lock()
                .unwrap()
                .calls
                .push(("create", path.to_string()));
            Ok(())
        }
    }
}

struct TestConfig {
    path: &'static str,
}

impl TestConfig {
    fn get_hsm_pin_path(&self) -> String {
        self.path.to_string()
    }

    fn get_hsm_type(&self) -> HsmType {
        HsmType::Soft
    }

    fn get_tpm_tcti_name(&self) -> String {
        String::new()
    }
}

#[allow(unused_mut)]
async fn initialize(path: &'static str) -> Option<AuthValue> {
    let cfg = TestConfig { path };
    let no_machine_key = async {
        Ok::<_, std::convert::Infallible>(None::<kanidm_hsm_crypto::structures::LoadableStorageKey>)
    };
    let (auth_value, _hsm) = real_common::tpm_init!(cfg, no_machine_key, return None);
    Some(auth_value)
}

// Each child runs only its named test, isolating both environment and mock state.
fn run_in_child(test_name: &str, credentials_directory: Option<&str>) -> bool {
    const CHILD_TEST: &str = "HIMMELBLAU_PIN_TEST_CHILD";
    if std::env::var(CHILD_TEST).as_deref() == Ok(test_name) {
        return false;
    }

    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_TEST, test_name);
    if let Some(directory) = credentials_directory {
        command.env("CREDENTIALS_DIRECTORY", directory);
    } else {
        command.env_remove("CREDENTIALS_DIRECTORY");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{test_name} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    true
}

fn assert_calls(expected: &[(&str, &str)]) {
    let mock = MOCK.lock().unwrap();
    let calls: Vec<_> = mock
        .calls
        .iter()
        .map(|(operation, path)| (*operation, path.as_str()))
        .collect();
    assert_eq!(calls, expected);
}

fn assert_pin(result: Option<AuthValue>, expected_pin: &[u8]) {
    let AuthValue::Key256Bit { auth_key: actual } = result.expect("PIN initialization failed");
    let AuthValue::Key256Bit { auth_key: expected } = AuthValue::try_from(expected_pin).unwrap();
    let actual_bytes: &[u8] = actual.as_ref();
    let expected_bytes: &[u8] = expected.as_ref();
    assert_eq!(actual_bytes, expected_bytes);
}

#[tokio::test]
async fn systemd_credential_is_read_without_decrypting_or_creating() {
    if run_in_child(
        "systemd_credential_is_read_without_decrypting_or_creating",
        Some(CREDENTIALS_DIRECTORY),
    ) {
        return;
    }

    let result = initialize(CREDENTIAL_PIN).await;
    assert_pin(result, READ_PIN);
    assert_calls(&[("read", CREDENTIAL_PIN)]);
}

#[tokio::test]
async fn systemd_read_failure_does_not_fall_back() {
    if run_in_child(
        "systemd_read_failure_does_not_fall_back",
        Some(CREDENTIALS_DIRECTORY),
    ) {
        return;
    }

    MOCK.lock().unwrap().read_fails = true;
    assert!(initialize(CREDENTIAL_PIN).await.is_none());
    assert_calls(&[("read", CREDENTIAL_PIN)]);
}

#[tokio::test]
async fn non_systemd_caller_decrypts_existing_pin() {
    if run_in_child("non_systemd_caller_decrypts_existing_pin", None) {
        return;
    }

    let result = initialize(DEFAULT_HSM_PIN_PATH).await;
    assert_pin(result, DECRYPTED_PIN);
    assert_calls(&[("decrypt", DEFAULT_HSM_PIN_PATH_ENC)]);
}

#[tokio::test]
async fn non_systemd_decrypt_failure_creates_then_reads_pin() {
    if run_in_child("non_systemd_decrypt_failure_creates_then_reads_pin", None) {
        return;
    }

    MOCK.lock().unwrap().decrypt_fails = true;
    let result = initialize(DEFAULT_HSM_PIN_PATH).await;
    assert_pin(result, READ_PIN);
    assert_calls(&[
        ("decrypt", DEFAULT_HSM_PIN_PATH_ENC),
        ("create", DEFAULT_HSM_PIN_PATH),
        ("read", DEFAULT_HSM_PIN_PATH),
    ]);
}

#[tokio::test]
async fn sibling_directory_is_not_a_systemd_credential() {
    if run_in_child(
        "sibling_directory_is_not_a_systemd_credential",
        Some(CREDENTIALS_DIRECTORY),
    ) {
        return;
    }

    let result = initialize("/run/credentials/himmelblaud.service-other/hsm-pin").await;
    assert_pin(result, DECRYPTED_PIN);
    assert_calls(&[("decrypt", DEFAULT_HSM_PIN_PATH_ENC)]);
}
