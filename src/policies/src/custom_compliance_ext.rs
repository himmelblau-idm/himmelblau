/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
use crate::cse::CSE;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use himmelblau::intune::{ComplianceState, IntuneStatus, PolicyStatus};
use himmelblau_unix_common::config::HimmelblauConfig;
use std::fs::Permissions;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{ChildStderr, ChildStdout, Command, Output, Stdio};
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempPath};
use tracing::{debug, error};

/// Maximum wall-clock time a tenant-supplied discovery script may run for.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Minimum extra time allowed for the pipes to drain after the script has
/// exited. Only whatever is still sitting in the pipe buffers remains at that
/// point, so this is generous; it exists so that a script finishing right on
/// the deadline does not lose its output.
const READER_GRACE: Duration = Duration::from_secs(5);

/// How long a single `poll()` waits before the loop re-checks the child and the
/// deadline. Bounds how late a timeout can fire, nothing else.
const POLL_INTERVAL_MS: libc::c_int = 50;

/// Upper bound on how much a script may write to each stream. A discovery
/// script is expected to emit a small JSON object; anything beyond this is
/// runaway output and must not be allowed to grow the daemon's heap without
/// limit for the whole timeout budget.
const MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;

/// A child pipe read without blocking.
///
/// Reader *threads* are deliberately avoided. A thread parked in `read_to_end()`
/// cannot be cancelled and only returns once every writer has closed the pipe -
/// which a process that escaped the child's process group (e.g. via `setsid()`)
/// can prevent for as long as it chooses to live. Abandoning such threads leaks
/// a thread, its stack and an unbounded buffer per invocation, so instead the
/// descriptors are drained non-blockingly from the one loop that owns them and
/// closed when the budget expires.
struct Pipe {
    /// `None` once EOF (or an error) has been seen, or once it is dropped.
    src: Option<ChildStream>,
    buf: Vec<u8>,
    truncated: bool,
}

/// The two child streams are distinct types but are only ever used as raw fds.
enum ChildStream {
    Out(ChildStdout),
    Err(ChildStderr),
}

impl AsRawFd for ChildStream {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            ChildStream::Out(s) => s.as_raw_fd(),
            ChildStream::Err(s) => s.as_raw_fd(),
        }
    }
}

impl Pipe {
    fn new(src: ChildStream) -> Result<Self> {
        // SAFETY: `src` owns the descriptor for the lifetime of this struct.
        let fd = src.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(anyhow!(
                "Failed to make script pipe non-blocking: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(Pipe {
            src: Some(src),
            buf: Vec::new(),
            truncated: false,
        })
    }

    fn open(&self) -> bool {
        self.src.is_some()
    }

    /// Close the read end. Any process still holding the write end - including
    /// one that escaped the process group - gets `EPIPE`/`SIGPIPE` on its next
    /// write rather than an audience for the rest of its life.
    fn close(&mut self) {
        self.src = None;
    }

    /// Read everything currently buffered. Returns without blocking.
    fn drain(&mut self) {
        let Some(src) = self.src.as_ref() else {
            return;
        };
        let fd = src.as_raw_fd();
        let mut chunk = [0u8; 8192];
        loop {
            // SAFETY: `fd` is owned by `self.src` and `chunk` is valid for
            // `chunk.len()` bytes.
            let n = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
            if n > 0 {
                let n = n as usize;
                let room = MAX_STREAM_BYTES.saturating_sub(self.buf.len());
                if room == 0 {
                    // Keep draining so the writer never blocks (which would
                    // stall a script that is merely verbose), but stop growing.
                    self.truncated = true;
                    continue;
                }
                self.buf.extend_from_slice(&chunk[..n.min(room)]);
                self.truncated |= n > room;
                continue;
            }
            if n == 0 {
                // EOF: every writer closed.
                self.close();
                return;
            }
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return,
                _ => {
                    self.close();
                    return;
                }
            }
        }
    }
}

/// Run `cmd` to completion, killing its entire process group if it exceeds
/// `timeout`.
///
/// `Command::output()` waits forever. Because `execute_script()` is called from
/// the async `apply_compliance()`, a script that hangs parks a Tokio worker,
/// which stops `himmelblaud_tasks` from pinging its systemd watchdog, and
/// `WatchdogSec` then SIGABRTs the whole service - taking down Kerberos, policy
/// application and compliance reporting along with it.
///
/// The process *group* is signalled rather than just the direct child: discovery
/// scripts are shells, and the process that actually hangs is typically a
/// grandchild. Killing only the child would leave that grandchild orphaned and
/// still running (in the case that motivated this, spinning at 100% CPU).
fn output_with_timeout(mut cmd: Command, timeout: Duration) -> Result<Output> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Give the child its own process group so the whole tree can be signalled.
        .process_group(0);

    let mut child = cmd.spawn().context("Failed to spawn script")?;
    let pgid = child.id() as libc::pid_t;

    // Both pipes are drained non-blockingly below. A script writing more than
    // one pipe buffer would otherwise block in write() while we block in
    // try_wait().
    let mut out = Pipe::new(ChildStream::Out(
        child.stdout.take().context("Missing stdout pipe")?,
    ))?;
    let mut err = Pipe::new(ChildStream::Err(
        child.stderr.take().context("Missing stderr pipe")?,
    ))?;

    let deadline = Instant::now() + timeout;
    let mut status = None;
    // Set once the child has exited; bounds how long we keep reading pipes that
    // some process it left behind is still holding open.
    let mut drain_deadline = None;

    loop {
        poll_readable(&[&out, &err], POLL_INTERVAL_MS);
        out.drain();
        err.drain();

        if status.is_none() {
            status = child.try_wait().context("Failed to wait on script")?;
            if status.is_some() {
                drain_deadline = Some(deadline.max(Instant::now() + READER_GRACE));
            }
        }

        if status.is_some() && !out.open() && !err.open() {
            // Clean finish: child reaped, both pipes at EOF.
            break;
        }

        let now = Instant::now();
        match drain_deadline {
            // Still running. Out of budget: kill the whole group and give up.
            None if now >= deadline => {
                // SAFETY: `pgid` is the group created for this child by
                // `process_group(0)` above, so this cannot signal anything
                // outside the script's own process tree.
                unsafe {
                    libc::killpg(pgid, libc::SIGKILL);
                }
                let _ = child.wait();
                // Dropping the pipes closes the read ends, so any process that
                // escaped the group via setsid() cannot hold us here.
                return Err(anyhow!(
                    "Script exceeded {}s timeout and was killed",
                    timeout.as_secs()
                ));
            }
            // Exited, but something it left behind still holds a pipe open.
            // Take what was read rather than discarding a possibly complete
            // result; truncated output fails JSON validation downstream anyway.
            Some(drain_deadline) if now >= drain_deadline => {
                debug!(
                    stdout_open = out.open(),
                    stderr_open = err.open(),
                    "Script exited but left a process holding its pipes open; using partial output"
                );
                // Best effort: anything still in the group gets cleaned up. A
                // process that called setsid() is out of reach, but closing our
                // read ends means we never block on it either way.
                unsafe {
                    libc::killpg(pgid, libc::SIGKILL);
                }
                break;
            }
            _ => {}
        }
    }

    if out.truncated || err.truncated {
        debug!(
            max_bytes = MAX_STREAM_BYTES,
            "Script output exceeded the per-stream limit and was truncated"
        );
    }

    Ok(Output {
        // Set in the loop before any path that reaches here.
        status: status.context("Script did not report an exit status")?,
        stdout: out.buf,
        stderr: err.buf,
    })
}

/// Wait up to `timeout_ms` for any still-open pipe to become readable.
///
/// Purely a throttle for the drain loop: errors are not actionable, since the
/// subsequent `read()` reports anything that matters.
fn poll_readable(pipes: &[&Pipe], timeout_ms: libc::c_int) {
    let mut fds: Vec<libc::pollfd> = pipes
        .iter()
        .filter_map(|p| p.src.as_ref())
        .map(|s| libc::pollfd {
            fd: s.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();

    // SAFETY: `fds` is valid for `fds.len()` entries. With no open pipes left
    // this degenerates to a plain sleep, which is what we want while waiting
    // for a child that has closed its output to exit.
    unsafe {
        libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms);
    }
}

fn execute_script(script: &[u8]) -> Result<String> {
    // Check if the content is valid UTF-8 text and, if so, whether it
    // starts with a shebang.  When a shebang is present the file is
    // executed directly (the kernel honours the interpreter line);
    // otherwise it is run via /bin/sh.
    let (contents, has_shebang) = match std::str::from_utf8(script) {
        Ok(text) => {
            // Normalize Windows line endings for text content
            let normalized = text.replace("\r\n", "\n");
            let shebang = normalized.starts_with("#!");
            (normalized.into_bytes(), shebang)
        }
        Err(_) => (script.to_vec(), false),
    };

    // Create a temporary file
    let mut file = NamedTempFile::new().context("Failed to create temp file")?;

    // Write the script contents
    file.write_all(&contents)
        .context("Failed to write script to temp file")?;
    file.flush().context("Failed to flush script to disk")?;

    // Make it executable
    let mut perms: Permissions = file.as_file().metadata()?.permissions();
    perms.set_mode(0o500);
    file.as_file().set_permissions(perms)?;

    // Close the file handle but keep the path so it can be executed.
    // Executing a file that is still open for writing can return ETXTBSY.
    let temp_path: TempPath = file.into_temp_path();

    // Execute: directly if it has a shebang, via /bin/sh otherwise
    let started = Instant::now();
    let output = if has_shebang {
        output_with_timeout(Command::new(&temp_path), SCRIPT_TIMEOUT)
            .context("Failed to execute script directly")?
    } else {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg(&temp_path);
        output_with_timeout(cmd, SCRIPT_TIMEOUT).context("Failed to execute script via /bin/sh")?
    };
    let elapsed = started.elapsed();

    // Remove the temp file (best-effort)
    let _ = temp_path.close();

    // Ignores exit codes as the scripts might be of dubious quality, only check stdout
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    debug!(
        exit_code = ?output.status.code(),
        elapsed_ms = elapsed.as_millis(),
        stdout_len = stdout.len(),
        stderr_len = stderr.len(),
        "Custom compliance script execution finished"
    );
    if !stderr.is_empty() {
        debug!(stderr = %stderr, "Custom compliance script stderr");
    }
    if stdout.is_empty() {
        if stderr.is_empty() {
            anyhow::bail!("No output returned from script");
        } else {
            anyhow::bail!("Script returned no stdout: {}", stderr);
        }
    }

    // Validate that the output is well-formed JSON
    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&stdout)
        .context("Output is not well-formed json")?;

    Ok(stdout)
}

pub struct CustomComplianceCSE {}

#[async_trait]
impl CSE for CustomComplianceCSE {
    fn new(_config: &HimmelblauConfig, _username: &str) -> Self {
        Self {}
    }

    /// Process a group of policies. For deleted policies, no action is taken.
    /// For changed policies, run compliance checks and return an error if any check fails.
    async fn process_group_policy(&self, policies: &mut IntuneStatus) -> Result<bool> {
        debug!(
            num_policies = policies.policy_statuses.len(),
            "CustomComplianceCSE: checking policies for custom compliance"
        );
        for policy in policies.policy_statuses.iter_mut() {
            let detail_ids: Vec<&str> = policy
                .details
                .iter()
                .map(|d| d.setting_definition_item_id.as_str())
                .collect();
            debug!(
                policy_id = %policy.policy_id,
                ?detail_ids,
                "CustomComplianceCSE: inspecting policy details"
            );
            // Validate this is a compliance policy
            if policy.details.iter().any(|detail| {
                let id = &detail.setting_definition_item_id;
                id == "linux_customcompliance_discoveryscript"
            }) {
                debug!(
                    policy_id = %policy.policy_id,
                    "CustomComplianceCSE: matched custom compliance policy, applying"
                );
                self.apply_compliance(policy).await;
            } else {
                debug!(
                    policy_id = %policy.policy_id,
                    "CustomComplianceCSE: not a custom compliance policy, skipping"
                );
            }
        }
        Ok(true)
    }
}

impl CustomComplianceCSE {
    /// Applies the compliance checks for a given policy.
    ///
    /// Finds the discovery script detail, decodes and executes it, then
    /// sets the status on that detail. On error, sets an error status
    /// instead of aborting the entire policy evaluation.
    async fn apply_compliance(&self, policy: &mut PolicyStatus) {
        // Find the discovery script detail
        let script_detail = policy
            .details
            .iter_mut()
            .find(|d| d.setting_definition_item_id == "linux_customcompliance_discoveryscript");

        let Some(detail) = script_detail else {
            debug!(
                policy_id = %policy.policy_id,
                "CustomComplianceCSE: no discovery script detail found in policy"
            );
            return;
        };

        debug!(
            policy_id = %policy.policy_id,
            expected_value_len = detail.expected_value.len(),
            "CustomComplianceCSE: found discovery script, decoding and executing"
        );

        // Decode and execute the script
        let decoded = (|| -> Result<Vec<u8>> {
            let decoded = STANDARD
                .decode(detail.expected_value.clone())
                .map_err(|e| anyhow!("Failed to decode CSE: {}", e))?;
            if let Ok(script) = std::str::from_utf8(&decoded) {
                debug!(
                    policy_id = %policy.policy_id,
                    script = %script,
                    "CustomComplianceCSE: decoded discovery CSE content"
                );
            } else {
                debug!(
                    policy_id = %policy.policy_id,
                    len = decoded.len(),
                    "CustomComplianceCSE: decoded binary discovery CSE content"
                );
            }
            Ok(decoded)
        })();

        // The script runs on a blocking thread. It is bounded by
        // SCRIPT_TIMEOUT, but even a bounded minute parked on a Tokio worker
        // would keep himmelblaud_tasks from pinging its systemd watchdog.
        let result = match decoded {
            Ok(decoded) => tokio::task::spawn_blocking(move || execute_script(&decoded))
                .await
                .unwrap_or_else(|e| Err(anyhow!("Compliance script task failed: {}", e))),
            Err(e) => Err(e),
        };

        match result {
            Ok(output) => {
                debug!(
                    policy_id = %policy.policy_id,
                    output = %output,
                    "CustomComplianceCSE: script executed successfully"
                );
                detail.set_status(
                    Some("Unknown".to_string()),
                    Some(output),
                    &ComplianceState::Unknown,
                );
            }
            Err(e) => {
                error!(
                    policy_id = %policy.policy_id,
                    error = %format!("{e:#}"),
                    "CustomComplianceCSE: script execution failed"
                );
                detail.set_status(
                    Some("Error".to_string()),
                    Some(format!("{e:#}")),
                    &ComplianceState::Error,
                );
            }
        }
    }
}
