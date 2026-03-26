use crate::provider_definitions::SuccessCondition;
use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{sleep, timeout, Duration};

#[derive(Debug, Clone)]
pub struct ContainerInstance {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct PodmanClient {
    binary: String,
    image: String,
    network: Option<String>,
    action_timeout_secs: u64,
    no_new_privileges: bool,
}

impl PodmanClient {
    pub fn new(
        binary: impl Into<String>,
        image: impl Into<String>,
        network: Option<String>,
        action_timeout_secs: u64,
        no_new_privileges: bool,
    ) -> Self {
        Self {
            binary: binary.into(),
            image: image.into(),
            network,
            action_timeout_secs,
            no_new_privileges,
        }
    }

    pub async fn create_session_container(&self, session_id: &str) -> Result<ContainerInstance> {
        let name = sanitize_container_name(session_id);
        let mut command = Command::new(&self.binary);
        command
            .arg("run")
            .arg("--detach")
            .arg("--rm")
            .arg("--replace")
            .arg("--cap-drop")
            .arg("ALL")
            .arg("--read-only")
            .arg("--tmpfs")
            .arg("/tmp:size=64m,mode=1777")
            .arg("--tmpfs")
            .arg("/run:size=32m,mode=755")
            .arg("--name")
            .arg(&name);

        if self.no_new_privileges {
            command.arg("--security-opt").arg("no-new-privileges");
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
            .arg(self.action_timeout_secs.to_string());

        let output = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("failed to execute podman run")?;

        if !output.status.success() {
            return Err(anyhow!(
                "podman run failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if id.is_empty() {
            return Err(anyhow!("podman run returned empty container id"));
        }

        self.wait_for_bridge_socket(&id).await.with_context(|| {
            format!(
                "container '{}' started but bridge socket never became ready",
                name
            )
        })?;

        Ok(ContainerInstance { id, name })
    }

    async fn wait_for_bridge_socket(&self, container_id: &str) -> Result<()> {
        let attempts = (self.action_timeout_secs.max(1) * 5).min(300);
        for _ in 0..attempts {
            let output = Command::new(&self.binary)
                .arg("exec")
                .arg(container_id)
                .arg("orchestrator-playwright-bridge")
                .arg("--ping")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .await;

            if let Ok(output) = output {
                if output.status.success() {
                    return Ok(());
                }
            }

            sleep(Duration::from_millis(200)).await;
        }

        Err(anyhow!(
            "timed out waiting for orchestrator-playwright-bridge readiness"
        ))
    }

    pub async fn execute_flow_action(&self, container_id: &str, payload: &str) -> Result<()> {
        let output = timeout(
            Duration::from_secs(self.action_timeout_secs.max(1)),
            Command::new(&self.binary)
                .arg("exec")
                .arg(container_id)
                .arg("orchestrator-playwright-bridge")
                .arg("--action")
                .arg(payload)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        )
        .await
        .context("timed out waiting for podman exec action")?
        .context("failed to execute podman exec action")?;

        if !output.status.success() {
            return Err(anyhow!(
                "podman exec action failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    pub async fn capture_artifact(
        &self,
        container_id: &str,
        source: &str,
    ) -> Result<Option<String>> {
        let output = timeout(
            Duration::from_secs(self.action_timeout_secs.max(1)),
            Command::new(&self.binary)
                .arg("exec")
                .arg(container_id)
                .arg("orchestrator-playwright-bridge")
                .arg("--extract")
                .arg(source)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        )
        .await
        .context("timed out waiting for podman artifact extraction")?
        .context("failed to execute podman artifact extraction")?;

        if !output.status.success() {
            return Err(anyhow!(
                "podman extract failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if raw.is_empty() || raw == "null" {
            return Ok(None);
        }

        Ok(Some(raw))
    }

    pub async fn check_success_condition(
        &self,
        container_id: &str,
        success: &SuccessCondition,
    ) -> Result<bool> {
        let payload =
            serde_json::to_string(success).context("failed to serialize success condition")?;
        let output = timeout(
            Duration::from_secs(self.action_timeout_secs.max(1)),
            Command::new(&self.binary)
                .arg("exec")
                .arg(container_id)
                .arg("orchestrator-playwright-bridge")
                .arg("--success")
                .arg(payload)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        )
        .await
        .context("timed out waiting for podman success probe")?
        .context("failed to execute podman success probe")?;

        if !output.status.success() {
            return Err(anyhow!(
                "podman success probe failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim() == "true")
    }

    pub async fn destroy_session_container(&self, container_id: &str) -> Result<()> {
        let output = Command::new(&self.binary)
            .arg("rm")
            .arg("-f")
            .arg(container_id)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("failed to execute podman rm")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("no such container") || stderr.contains("no container with name") {
                return Ok(());
            }

            return Err(anyhow!("podman rm failed: {}", stderr));
        }

        Ok(())
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
