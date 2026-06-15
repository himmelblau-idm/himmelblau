use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::time::{sleep, timeout, Duration};
use zeroize::{Zeroize, Zeroizing};

const BRIDGE_SOCKET_FILE_NAME: &str = "bridge.sock";
const CONTAINER_SESSION_RUNTIME_DIR: &str = "/run/himmelblau-orchestrator-session";
const CONTAINER_BRIDGE_SOCKET_PATH: &str = "/run/himmelblau-orchestrator-session/bridge.sock";
const CONTAINER_STOP_TIMEOUT_SECS: &str = "0";

#[derive(Debug, Clone)]
pub struct ContainerInstance {
    pub id: String,
    pub name: String,
    pub session_dir: PathBuf,
    pub bridge_socket_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PodmanClient {
    binary: String,
    image: String,
    network: Option<String>,
    runtime_dir: PathBuf,
    action_timeout_secs: u64,
    session_idle_timeout_secs: u64,
    no_new_privileges: bool,
    apparmor_profile: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum BridgeAction<'a> {
    Fill { selector: &'a str, value: &'a str },
    Click { selector: &'a str },
    SubmitForm { selector: &'a str },
    Navigate { url: &'a str },
}

#[derive(Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum BridgeRequest<'a> {
    Action { payload: BridgeAction<'a> },
    InspectPage,
    WaitForSettle,
    Ping,
}

#[derive(Debug, Deserialize)]
struct BridgeResponse {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    pong: Option<bool>,
    #[serde(default)]
    value: Option<Value>,
}

impl Drop for BridgeResponse {
    fn drop(&mut self) {
        if let Some(error) = &mut self.error {
            error.zeroize();
        }
        if let Some(value) = &mut self.value {
            zeroize_json_value(value);
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PageInspection {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub browser_error: Option<String>,
    #[serde(default)]
    pub forms: Vec<InspectedForm>,
    #[serde(default)]
    pub actions: Vec<InspectedAction>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct InspectedForm {
    #[serde(default)]
    pub fields: Vec<InspectedField>,
    #[serde(default)]
    pub actions: Vec<InspectedAction>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct InspectedField {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub selector: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub input_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub autocomplete: String,
    #[serde(default)]
    pub id_attr: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub placeholder: String,
    #[serde(default)]
    pub aria_label: String,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct InspectedAction {
    #[serde(default)]
    pub selector: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub kind: String,
}

fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(inner) => inner.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_json_value(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[derive(Debug)]
struct SessionRuntimePaths {
    session_dir: PathBuf,
    bridge_socket_path: PathBuf,
}

impl PodmanClient {
    pub fn new(
        binary: impl Into<String>,
        image: impl Into<String>,
        network: Option<String>,
        runtime_dir: impl Into<PathBuf>,
        action_timeout_secs: u64,
        session_idle_timeout_secs: u64,
        no_new_privileges: bool,
        apparmor_profile: Option<String>,
    ) -> Self {
        Self {
            binary: binary.into(),
            image: image.into(),
            network,
            runtime_dir: runtime_dir.into(),
            action_timeout_secs,
            session_idle_timeout_secs,
            no_new_privileges,
            apparmor_profile,
        }
    }

    pub async fn image_exists(&self) -> Result<bool> {
        let output = Command::new(&self.binary)
            .arg("image")
            .arg("exists")
            .arg(&self.image)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("failed to execute podman image exists")?;

        if output.status.success() {
            return Ok(true);
        }

        if output.status.code() == Some(1) {
            return Ok(false);
        }

        Err(anyhow!(
            "podman image exists failed for '{}': status={}; stdout={}; stderr={}",
            self.image,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }

    pub async fn image_label_matches(&self, label: &str, expected: &str) -> Result<bool> {
        let output = Command::new(&self.binary)
            .arg("image")
            .arg("inspect")
            .arg("--format")
            .arg(format!("{{{{ index .Config.Labels \"{label}\" }}}}"))
            .arg(&self.image)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("failed to execute podman image inspect")?;

        if !output.status.success() {
            return Err(anyhow!(
                "podman image inspect failed for '{}': status={}; stdout={}; stderr={}",
                self.image,
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim() == expected)
    }

    pub async fn build_image_from_dir(&self, build_dir: &Path) -> Result<()> {
        if !build_dir.is_dir() {
            return Err(anyhow!(
                "orchestrator container build directory does not exist: {}",
                build_dir.display()
            ));
        }

        let dockerfile = build_dir.join("Dockerfile");
        if !dockerfile.is_file() {
            return Err(anyhow!(
                "orchestrator container Dockerfile does not exist: {}",
                dockerfile.display()
            ));
        }

        let output = Command::new(&self.binary)
            .arg("build")
            .arg("--layers")
            .arg("-t")
            .arg(&self.image)
            .arg(build_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("failed to execute podman build")?;

        if output.status.success() {
            return Ok(());
        }

        Err(anyhow!(
            "podman build failed for image '{}' from '{}': status={}\nstdout:\n{}\nstderr:\n{}",
            self.image,
            build_dir.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }

    pub async fn create_session_container(&self, session_id: &str) -> Result<ContainerInstance> {
        let runtime_paths = self
            .prepare_session_runtime(session_id)
            .await
            .with_context(|| format!("failed preparing runtime for session '{}'", session_id))?;
        let name = sanitize_container_name(session_id);
        let mut command = Command::new(&self.binary);
        command
            .arg("run")
            .arg("--detach")
            .arg("--rm")
            .arg("--replace")
            .arg("--stop-timeout")
            .arg(CONTAINER_STOP_TIMEOUT_SECS)
            .arg("--cap-drop")
            .arg("ALL")
            .arg("--read-only")
            .arg("--tmpfs")
            .arg("/tmp:size=64m,mode=1777")
            .arg("--tmpfs")
            .arg("/run:size=32m,mode=755")
            .arg("--name")
            .arg(&name)
            .arg("--volume")
            .arg(format!(
                "{}:{}:rw,z",
                runtime_paths.session_dir.display(),
                CONTAINER_SESSION_RUNTIME_DIR
            ))
            .arg("--env")
            .arg(format!(
                "ORCHESTRATOR_BRIDGE_SOCKET={}",
                CONTAINER_BRIDGE_SOCKET_PATH
            ));

        if self.no_new_privileges {
            command.arg("--security-opt").arg("no-new-privileges");
        }

        if let Some(profile) = &self.apparmor_profile {
            command
                .arg("--security-opt")
                .arg(format!("apparmor={profile}"));
        }

        for mount in host_certificate_mounts() {
            if Path::new(mount.host_path).exists() {
                command
                    .arg("--volume")
                    .arg(format!("{}:{}:ro", mount.host_path, mount.container_path));
            }
        }

        if let Some(network) = &self.network {
            command.arg("--network").arg(network);
        }

        command
            .arg(&self.image)
            .arg("orchestrator-playwright-bridge")
            .arg("--session-id")
            .arg(session_id)
            .arg("--idle-seconds")
            .arg(self.session_idle_timeout_secs.max(1).to_string());

        let output = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("failed to execute podman run")?;

        if !output.status.success() {
            let _ = self.cleanup_session_runtime_paths(&runtime_paths).await;
            return Err(anyhow!(
                "podman run failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if id.is_empty() {
            let _ = self.cleanup_session_runtime_paths(&runtime_paths).await;
            return Err(anyhow!("podman run returned empty container id"));
        }

        let container = ContainerInstance {
            id,
            name,
            session_dir: runtime_paths.session_dir,
            bridge_socket_path: runtime_paths.bridge_socket_path,
        };

        if let Err(error) = self.wait_for_bridge_socket(&container).await {
            let _ = self.destroy_session_container(&container).await;
            return Err(error).with_context(|| {
                format!(
                    "container '{}' started but bridge socket never became ready",
                    container.name
                )
            });
        }

        Ok(container)
    }

    async fn wait_for_bridge_socket(&self, container: &ContainerInstance) -> Result<()> {
        let attempts = (self.action_timeout_secs.max(1) * 5).min(300);
        for _ in 0..attempts {
            if self.ping_container(container).await.is_ok() {
                return Ok(());
            }

            sleep(Duration::from_millis(200)).await;
        }

        Err(anyhow!(
            "timed out waiting for orchestrator-playwright-bridge readiness on {}",
            container.bridge_socket_path.display()
        ))
    }

    pub async fn ping_container(&self, container: &ContainerInstance) -> Result<()> {
        let response = self
            .send_bridge_request(
                container,
                BridgeRequest::Ping,
                Duration::from_secs(1),
                "bridge ping failed",
            )
            .await?;

        if response.pong.unwrap_or(false) {
            return Ok(());
        }

        Err(anyhow!("bridge ping response missing pong=true"))
    }

    pub async fn fill(
        &self,
        container: &ContainerInstance,
        selector: &str,
        value: &str,
    ) -> Result<()> {
        let _ = self
            .send_bridge_request(
                container,
                BridgeRequest::Action {
                    payload: BridgeAction::Fill { selector, value },
                },
                self.action_timeout(),
                "bridge fill action failed",
            )
            .await?;
        Ok(())
    }

    pub async fn click(&self, container: &ContainerInstance, selector: &str) -> Result<()> {
        let _ = self
            .send_bridge_request(
                container,
                BridgeRequest::Action {
                    payload: BridgeAction::Click { selector },
                },
                self.action_timeout(),
                "bridge click action failed",
            )
            .await?;
        Ok(())
    }

    pub async fn submit_form(&self, container: &ContainerInstance, selector: &str) -> Result<()> {
        let _ = self
            .send_bridge_request(
                container,
                BridgeRequest::Action {
                    payload: BridgeAction::SubmitForm { selector },
                },
                self.action_timeout(),
                "bridge submit form action failed",
            )
            .await?;
        Ok(())
    }

    pub async fn navigate(&self, container: &ContainerInstance, url: &str) -> Result<()> {
        let _ = self
            .send_bridge_request(
                container,
                BridgeRequest::Action {
                    payload: BridgeAction::Navigate { url },
                },
                self.action_timeout(),
                "bridge navigate action failed",
            )
            .await?;
        Ok(())
    }

    pub async fn inspect_page(&self, container: &ContainerInstance) -> Result<PageInspection> {
        let response = self
            .send_bridge_request(
                container,
                BridgeRequest::InspectPage,
                self.action_timeout(),
                "bridge page inspection failed",
            )
            .await?;

        let mut response = response;
        let value = std::mem::take(&mut response.value)
            .ok_or_else(|| anyhow!("bridge inspection response missing value"))?;
        serde_json::from_value(value).context("failed decoding bridge page inspection")
    }

    pub async fn wait_for_settle(&self, container: &ContainerInstance) -> Result<()> {
        let _ = self
            .send_bridge_request(
                container,
                BridgeRequest::WaitForSettle,
                self.action_timeout(),
                "bridge wait for settle failed",
            )
            .await?;
        Ok(())
    }

    pub async fn destroy_session_container(&self, container: &ContainerInstance) -> Result<()> {
        let mut container_error = None;
        let output_result = Command::new(&self.binary)
            .arg("rm")
            .arg("-f")
            .arg("--time")
            .arg(CONTAINER_STOP_TIMEOUT_SECS)
            .arg(&container.id)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await;

        match output_result {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if !stderr.contains("no such container")
                        && !stderr.contains("no container with name")
                    {
                        container_error = Some(anyhow!("podman rm failed: {}", stderr));
                    }
                }
            }
            Err(error) => {
                container_error = Some(anyhow!("failed to execute podman rm: {}", error));
            }
        }

        let runtime_paths = SessionRuntimePaths {
            session_dir: container.session_dir.clone(),
            bridge_socket_path: container.bridge_socket_path.clone(),
        };
        let runtime_cleanup = self.cleanup_session_runtime_paths(&runtime_paths);

        if let Err(error) = runtime_cleanup.await {
            if container_error.is_none() {
                container_error = Some(error);
            }
        }

        if let Some(error) = container_error {
            return Err(error);
        }

        Ok(())
    }

    fn action_timeout(&self) -> Duration {
        Duration::from_secs(self.action_timeout_secs.max(1))
    }

    async fn prepare_session_runtime(&self, session_id: &str) -> Result<SessionRuntimePaths> {
        let sessions_root = self.runtime_dir.join("sessions");
        ensure_dir_with_mode(&self.runtime_dir, 0o700).await?;
        ensure_dir_with_mode(&sessions_root, 0o700).await?;

        let session_dir = sessions_root.join(sanitize_session_dir_name(session_id));
        match fs::metadata(&session_dir).await {
            Ok(_) => {
                fs::remove_dir_all(&session_dir).await.with_context(|| {
                    format!(
                        "failed removing stale session runtime directory {}",
                        session_dir.display()
                    )
                })?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed reading session runtime directory {}",
                        session_dir.display()
                    )
                });
            }
        }

        ensure_dir_with_mode(&session_dir, 0o700).await?;

        let bridge_socket_path = session_dir.join(BRIDGE_SOCKET_FILE_NAME);
        match fs::remove_file(&bridge_socket_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed removing stale bridge socket {}",
                        bridge_socket_path.display()
                    )
                });
            }
        }

        Ok(SessionRuntimePaths {
            session_dir,
            bridge_socket_path,
        })
    }

    async fn cleanup_session_runtime_paths(&self, runtime: &SessionRuntimePaths) -> Result<()> {
        match fs::remove_file(&runtime.bridge_socket_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed removing bridge socket {}",
                        runtime.bridge_socket_path.display()
                    )
                });
            }
        }

        match fs::remove_dir_all(&runtime.session_dir).await {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed removing session runtime directory {}",
                        runtime.session_dir.display()
                    )
                });
            }
        }

        Ok(())
    }

    async fn send_bridge_request(
        &self,
        container: &ContainerInstance,
        request: BridgeRequest<'_>,
        request_timeout: Duration,
        operation: &str,
    ) -> Result<BridgeResponse> {
        let payload = Zeroizing::new(
            serde_json::to_vec(&request)
                .with_context(|| format!("failed serializing {} request", operation))?,
        );

        let socket_path = container.bridge_socket_path.clone();

        timeout(request_timeout, async move {
            let mut stream = UnixStream::connect(&socket_path).await.with_context(|| {
                format!(
                    "failed connecting to bridge socket {}",
                    socket_path.display()
                )
            })?;

            stream
                .write_all(&payload)
                .await
                .with_context(|| format!("failed writing {} request", operation))?;
            stream
                .shutdown()
                .await
                .with_context(|| format!("failed closing write side for {} request", operation))?;

            let mut response_bytes = Zeroizing::new(Vec::new());
            stream
                .read_to_end(&mut response_bytes)
                .await
                .with_context(|| format!("failed reading {} response", operation))?;

            if response_bytes.is_empty() {
                return Err(anyhow!("bridge returned empty response for {}", operation));
            }

            let response: BridgeResponse = serde_json::from_slice(&response_bytes)
                .with_context(|| format!("failed parsing bridge response for {}", operation))?;

            if !response.ok {
                return Err(anyhow!(
                    "{}: {}",
                    operation,
                    response
                        .error
                        .as_deref()
                        .unwrap_or("unknown bridge failure")
                ));
            }

            Ok(response)
        })
        .await
        .with_context(|| format!("timed out waiting for {}", operation))?
    }
}

struct HostCertificateMount {
    host_path: &'static str,
    container_path: &'static str,
}

fn host_certificate_mounts() -> &'static [HostCertificateMount] {
    &[
        HostCertificateMount {
            host_path: "/etc/ssl/certs",
            container_path: "/host-trust/etc-ssl-certs",
        },
        HostCertificateMount {
            host_path: "/etc/pki/trust",
            container_path: "/host-trust/etc-pki-trust",
        },
        HostCertificateMount {
            host_path: "/etc/pki/ca-trust",
            container_path: "/host-trust/etc-pki-ca-trust",
        },
        HostCertificateMount {
            host_path: "/etc/pki/tls/certs",
            container_path: "/host-trust/etc-pki-tls-certs",
        },
        HostCertificateMount {
            host_path: "/etc/ca-certificates",
            container_path: "/host-trust/etc-ca-certificates",
        },
        HostCertificateMount {
            host_path: "/usr/local/share/ca-certificates",
            container_path: "/host-trust/usr-local-share-ca-certificates",
        },
    ]
}

fn sanitize_container_name(session_id: &str) -> String {
    let mut name = String::from("himmelblau-orch-");
    for ch in session_id.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            name.push(ch);
        } else {
            name.push('_');
        }
    }
    name
}

fn sanitize_session_dir_name(session_id: &str) -> String {
    let mut name = String::new();
    for ch in session_id.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            name.push(ch);
        } else {
            name.push('_');
        }
    }

    if name.is_empty() {
        "session".to_string()
    } else {
        name
    }
}

async fn ensure_dir_with_mode(path: &Path, mode: u32) -> Result<()> {
    fs::create_dir_all(path)
        .await
        .with_context(|| format!("failed creating directory {}", path.display()))?;
    fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .await
        .with_context(|| format!("failed setting permissions on {}", path.display()))?;
    Ok(())
}
