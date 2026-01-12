/*
 * Himmelblau Embedded Browser Service - Container Management
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Default path where container build files are installed
const CONTAINER_FILES_PATH: &str = "/usr/share/himmelblau/embedded-browser/container";

/// Check if podman is available on the system
pub async fn podman_available() -> bool {
    match Command::new("podman")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
    {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

/// Check if the container image exists
pub async fn container_image_exists(image_name: &str) -> bool {
    match Command::new("podman")
        .args(["image", "exists", image_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
    {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

/// Build the container image from the installed container files
/// Returns Ok(()) if the image was built successfully, Err with message otherwise
pub async fn build_container_image(image_name: &str) -> Result<(), String> {
    let container_dir = Path::new(CONTAINER_FILES_PATH);

    // Check if container files exist
    if !container_dir.exists() {
        return Err(format!(
            "Container build files not found at {}. Is himmelblau-embedded-browser installed correctly?",
            CONTAINER_FILES_PATH
        ));
    }

    let containerfile_path = container_dir.join("Containerfile");
    if !containerfile_path.exists() {
        return Err(format!(
            "Containerfile not found at {:?}",
            containerfile_path
        ));
    }

    info!("Building container image {}...", image_name);
    info!("This may take a few minutes on first run.");

    let output = Command::new("podman")
        .args([
            "build",
            "-t",
            image_name,
            "-f",
            containerfile_path.to_str().unwrap_or("Containerfile"),
            CONTAINER_FILES_PATH,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Failed to execute podman build: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Failed to build container image: {}", stderr);
        return Err(format!("Failed to build container image: {}", stderr));
    }

    info!("Container image {} built successfully", image_name);
    Ok(())
}

/// Ensure the container image is available, building it if necessary
/// Returns Ok(true) if the image was already present, Ok(false) if it was just built
pub async fn ensure_container_image(image_name: &str) -> Result<bool, String> {
    if container_image_exists(image_name).await {
        debug!("Container image {} already exists", image_name);
        return Ok(true);
    }

    info!(
        "Container image {} not found, building...",
        image_name
    );
    build_container_image(image_name).await?;
    Ok(false)
}

/// Manages Podman container lifecycle for browser sessions
pub struct ContainerManager {
    /// Maps session_id to container_id
    containers: RwLock<HashMap<String, String>>,
    /// Maps session_id to VNC port
    ports: RwLock<HashMap<String, u16>>,
    /// Next available port for VNC
    next_port: RwLock<u16>,
}

impl ContainerManager {
    pub fn new() -> Self {
        Self {
            containers: RwLock::new(HashMap::new()),
            ports: RwLock::new(HashMap::new()),
            next_port: RwLock::new(15900), // Start from port 15900
        }
    }

    /// Allocate a port for VNC
    async fn allocate_port(&self) -> u16 {
        let mut next = self.next_port.write().await;
        let port = *next;
        *next += 1;
        if *next > 16900 {
            *next = 15900; // Wrap around
        }
        port
    }

    /// Start a browser container for the given session
    pub async fn start_browser(
        &self,
        session_id: &str,
        url: &str,
        width: u32,
        height: u32,
        container_image: &str,
    ) -> Result<u16, String> {
        // Check if session already exists
        {
            let containers = self.containers.read().await;
            if containers.contains_key(session_id) {
                return Err(format!("Session {} already exists", session_id));
            }
        }

        let vnc_port = self.allocate_port().await;
        let resolution = format!("{}x{}x24", width, height);
        let container_name = format!("himmelblau-browser-{}", session_id);

        info!(
            "Starting browser container {} for session {} with URL: {}",
            container_name, session_id, url
        );

        // Run the container
        let output = Command::new("podman")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &container_name,
                "-p",
                &format!("{}:5900", vnc_port),
                "-e",
                &format!("VNC_RESOLUTION={}", resolution),
                "-e",
                &format!("TARGET_URL={}", url),
                container_image,
                url,
            ])
            .output()
            .await
            .map_err(|e| format!("Failed to execute podman: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Failed to start container: {}", stderr);
            return Err(format!("Failed to start container: {}", stderr));
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        debug!("Started container {} with ID: {}", container_name, container_id);

        // Store the mapping
        {
            let mut containers = self.containers.write().await;
            containers.insert(session_id.to_string(), container_id);
        }
        {
            let mut ports = self.ports.write().await;
            ports.insert(session_id.to_string(), vnc_port);
        }

        // Wait a moment for VNC to start
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        Ok(vnc_port)
    }

    /// Stop a browser container for the given session
    pub async fn stop_browser(&self, session_id: &str) -> Result<(), String> {
        let container_id = {
            let mut containers = self.containers.write().await;
            containers.remove(session_id)
        };

        {
            let mut ports = self.ports.write().await;
            ports.remove(session_id);
        }

        if let Some(container_id) = container_id {
            info!("Stopping container {} for session {}", container_id, session_id);

            let output = Command::new("podman")
                .args(["stop", "-t", "5", &container_id])
                .output()
                .await
                .map_err(|e| format!("Failed to execute podman stop: {}", e))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to stop container gracefully: {}", stderr);

                // Try to force kill
                let _ = Command::new("podman")
                    .args(["kill", &container_id])
                    .output()
                    .await;
            }

            debug!("Container {} stopped", container_id);
        }

        Ok(())
    }

    /// Get the VNC port for a session
    #[allow(dead_code)]
    pub async fn get_vnc_port(&self, session_id: &str) -> Option<u16> {
        let ports = self.ports.read().await;
        ports.get(session_id).copied()
    }

    /// Check if a container is still running
    #[allow(dead_code)]
    pub async fn is_container_running(&self, session_id: &str) -> bool {
        let container_id = {
            let containers = self.containers.read().await;
            match containers.get(session_id) {
                Some(id) => id.clone(),
                None => return false,
            }
        };

        let output = Command::new("podman")
            .args(["inspect", "--format", "{{.State.Running}}", &container_id])
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.trim() == "true"
            }
            _ => false,
        }
    }

    /// Check container logs for completion patterns
    #[allow(dead_code)]
    pub async fn check_completion(&self, session_id: &str) -> Option<bool> {
        let container_id = {
            let containers = self.containers.read().await;
            containers.get(session_id)?.clone()
        };

        let output = Command::new("podman")
            .args(["logs", "--tail", "50", &container_id])
            .output()
            .await
            .ok()?;

        let logs = String::from_utf8_lossy(&output.stdout);
        let logs_lower = logs.to_lowercase();

        // Check for success patterns
        let success_patterns = [
            "you have signed in",
            "you're signed in",
            "close this window",
            "authentication successful",
            "status: success",
        ];

        for pattern in success_patterns {
            if logs_lower.contains(pattern) {
                return Some(true);
            }
        }

        // Check for failure patterns
        let failure_patterns = [
            "authentication failed",
            "error:",
            "access denied",
            "status: failed",
        ];

        for pattern in failure_patterns {
            if logs_lower.contains(pattern) {
                return Some(false);
            }
        }

        None // Still in progress
    }

    /// Stop all running containers
    #[allow(dead_code)]
    pub async fn stop_all(&self) {
        let session_ids: Vec<String> = {
            let containers = self.containers.read().await;
            containers.keys().cloned().collect()
        };

        for session_id in session_ids {
            let _ = self.stop_browser(&session_id).await;
        }
    }
}

impl Default for ContainerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ContainerManager {
    fn drop(&mut self) {
        // Note: async cleanup in Drop is tricky
        // The actual cleanup should be done before dropping
        // This is just a safety measure
    }
}
