// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use futures::StreamExt;
use std::os::fd::OwnedFd;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::unix::pipe;
use tokio::sync::OnceCell;
use zbus::{proxy, Connection, Fd, OwnedObjectPath};

pub use zbus::Variant;

pub type UnitProperties = Vec<(&'static str, Variant<'static>)>;
type AuxiliaryUnits = Vec<(String, UnitProperties)>;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait Manager {
    #[zbus(property(emits_changed_signal = "false"))]
    fn version(&self) -> zbus::Result<String>;
    fn subscribe(&self) -> zbus::Result<()>;
    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn unref_unit(&self, name: &str) -> zbus::Result<()>;
    fn start_transient_unit(
        &self,
        name: &str,
        mode: &str,
        properties: &UnitProperties,
        auxiliary: &AuxiliaryUnits,
    ) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1"
)]
trait Unit {
    #[zbus(property(emits_changed_signal = "false"))]
    fn load_state(&self) -> zbus::Result<String>;
    #[zbus(property(emits_changed_signal = "false"))]
    fn active_state(&self) -> zbus::Result<String>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Service",
    default_service = "org.freedesktop.systemd1"
)]
trait Service {
    #[zbus(property(emits_changed_signal = "false"))]
    fn result(&self) -> zbus::Result<String>;
}

#[derive(Debug)]
pub struct TransientUnit {
    pub name: String,
    pub properties: UnitProperties,
}

#[async_trait]
pub trait UnitManager: Send + Sync {
    async fn unit_exists(&self, name: &str) -> Result<bool>;
    async fn stop_unit(&self, name: &str) -> Result<()>;
    async fn start_transient(
        &self,
        unit: TransientUnit,
        auxiliary: Vec<TransientUnit>,
    ) -> Result<()>;
}

#[derive(Debug)]
pub struct UnitOutput {
    pub job_result: String,
    pub service_result: String,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl UnitOutput {
    pub fn success(&self) -> bool {
        self.job_result == "done" && self.service_result == "success"
    }
}

#[derive(Default)]
pub struct Systemd {
    connection: OnceCell<Connection>,
}

fn missing_unit(error: &zbus::Error) -> bool {
    match error {
        zbus::Error::MethodError(name, _, _) => {
            name.as_str() == "org.freedesktop.systemd1.NoSuchUnit"
        }
        zbus::Error::FDO(error) => matches!(error.as_ref(), zbus::fdo::Error::UnknownObject(_)),
        _ => false,
    }
}

async fn wait_for_job(
    jobs: &mut zbus::proxy::SignalStream<'_>,
    expected: &OwnedObjectPath,
) -> Result<String> {
    while let Some(message) = jobs.next().await {
        let (_, path, _, result): (u32, OwnedObjectPath, String, String) =
            message.body().deserialize()?;
        if &path == expected {
            return Ok(result);
        }
    }
    bail!("Systemd job notification stream closed");
}

fn require_done(name: &str, result: &str) -> Result<()> {
    if result != "done" {
        bail!("Systemd job for {} failed: {}", name, result);
    }
    Ok(())
}

fn parse_systemd_version(raw: &str) -> Result<u32> {
    let version = raw.strip_prefix('v').unwrap_or(raw);
    let end = version
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(version.len());
    version[..end]
        .parse()
        .with_context(|| format!("Invalid systemd version: {:?}", raw))
}

impl Systemd {
    async fn connection(&self) -> Result<&Connection> {
        self.connection
            .get_or_try_init(|| async {
                let connection = Connection::system()
                    .await
                    .context("Failed to connect to the system bus")?;
                {
                    let manager = ManagerProxy::new(&connection).await?;
                    manager.subscribe().await?;
                }
                Ok(connection)
            })
            .await
    }

    pub async fn version(&self) -> Result<u32> {
        tokio::time::timeout(CONTROL_TIMEOUT, async {
            let manager = ManagerProxy::new(self.connection().await?).await?;
            let version = manager.version().await?;
            parse_systemd_version(&version)
        })
        .await
        .context("Timed out querying systemd version")?
    }

    async fn unit_exists_inner(&self, name: &str) -> Result<bool> {
        let connection = self.connection().await?;
        let manager = ManagerProxy::new(connection).await?;
        let path = match manager.get_unit(name).await {
            Ok(path) => path,
            Err(e) if missing_unit(&e) => return Ok(false),
            Err(e) => return Err(e).with_context(|| format!("Failed to find unit {}", name)),
        };
        let unit = UnitProxy::builder(connection).path(path).build().await?;
        match tokio::try_join!(unit.load_state(), unit.active_state()) {
            Ok((load, active)) => match load.as_str() {
                "loaded" | "masked" => Ok(true),
                "not-found" => Ok(active != "inactive"),
                state => bail!("Unexpected load state for {}: {}", name, state),
            },
            Err(e) if missing_unit(&e) => Ok(false),
            Err(e) => Err(e).with_context(|| format!("Failed to query unit {}", name)),
        }
    }

    async fn start_job(
        &self,
        unit: TransientUnit,
        auxiliary: Vec<TransientUnit>,
        started: &mut bool,
    ) -> Result<String> {
        let connection = self.connection().await?;
        let manager = ManagerProxy::new(connection).await?;
        let TransientUnit { name, properties } = unit;
        let auxiliary: AuxiliaryUnits = auxiliary
            .into_iter()
            .map(|unit| (unit.name, unit.properties))
            .collect();
        let filter = [(2, name.as_str())];
        // Subscribe before queuing the job: a short-lived unit can finish before the reply.
        let mut jobs = manager
            .inner()
            .receive_signal_with_args("JobRemoved", &filter)
            .await?;
        let job = manager
            .start_transient_unit(&name, "fail", &properties, &auxiliary)
            .await;
        // In particular, do not retain local copies of output FDs while waiting for EOF.
        drop(properties);
        drop(auxiliary);
        let job = job.with_context(|| format!("Failed to create transient unit {}", name))?;
        *started = true;
        wait_for_job(&mut jobs, &job).await
    }

    async fn stop_unit_inner(&self, name: &str) -> Result<()> {
        if !self.unit_exists_inner(name).await? {
            return Ok(());
        }
        let manager = ManagerProxy::new(self.connection().await?).await?;
        let filter = [(2, name)];
        let mut jobs = manager
            .inner()
            .receive_signal_with_args("JobRemoved", &filter)
            .await?;
        let job = match manager.stop_unit(name, "replace").await {
            Ok(job) => job,
            Err(e) if missing_unit(&e) => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("Failed to stop {}", name)),
        };
        require_done(name, &wait_for_job(&mut jobs, &job).await?)
    }

    async fn service_result(&self, name: &str) -> Result<String> {
        let connection = self.connection().await?;
        let manager = ManagerProxy::new(connection).await?;
        let service = ServiceProxy::builder(connection)
            .path(manager.get_unit(name).await?)
            .build()
            .await?;
        service
            .result()
            .await
            .context("Failed to read service result")
    }

    async fn release_unit(&self, name: &str) -> Result<()> {
        let manager = ManagerProxy::new(self.connection().await?).await?;
        match manager.unref_unit(name).await {
            Ok(()) => Ok(()),
            Err(e) if missing_unit(&e) => Ok(()),
            Err(e) => Err(e).with_context(|| format!("Failed to release unit {}", name)),
        }
    }

    pub async fn run_with_output(
        &self,
        mut unit: TransientUnit,
        timeout: Duration,
    ) -> Result<UnitOutput> {
        let name = unit.name.clone();
        let (mut stdout, stdout_fd) = CapturedStream::pair()?;
        let (mut stderr, stderr_fd) = CapturedStream::pair()?;
        unit.properties.extend([
            ("AddRef", true.into()),
            ("StandardInput", "null".into()),
            (
                "StandardOutputFileDescriptor",
                Variant::Fd(Fd::Owned(stdout_fd)),
            ),
            (
                "StandardErrorFileDescriptor",
                Variant::Fd(Fd::Owned(stderr_fd)),
            ),
        ]);
        let mut started = false;
        let mut released = false;
        let outcome = tokio::time::timeout(timeout, async {
            let completion = async {
                let job_result = self.start_job(unit, Vec::new(), &mut started).await?;
                let service_result = self.service_result(&name).await?;
                // PID 1 holds the output FDs until the unit is collected.
                self.release_unit(&name).await?;
                released = true;
                Ok::<_, anyhow::Error>((job_result, service_result))
            };
            let (outcome, (), ()) =
                tokio::try_join!(completion, stdout.read_all(), stderr.read_all())?;
            Ok(outcome)
        })
        .await;
        let mut outcome = match outcome {
            Ok(result) => result,
            Err(e) => Err(anyhow!("Timed out waiting for {}: {}", name, e)),
        };
        if outcome.is_err() && started {
            let cleanup = tokio::time::timeout(CLEANUP_TIMEOUT, self.stop_unit(&name))
                .await
                .context("Timed out stopping script unit")
                .and_then(|result| result);
            outcome = merge_cleanup(outcome, cleanup, "Failed to stop script unit");
        }
        if started && !released {
            let cleanup = tokio::time::timeout(CLEANUP_TIMEOUT, self.release_unit(&name))
                .await
                .context("Timed out releasing script unit")
                .and_then(|result| result);
            outcome = merge_cleanup(outcome, cleanup, "Failed to release script unit");
        }
        let (job_result, service_result) = outcome?;
        Ok(UnitOutput {
            job_result,
            service_result,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        })
    }
}

#[async_trait]
impl UnitManager for Systemd {
    async fn unit_exists(&self, name: &str) -> Result<bool> {
        tokio::time::timeout(CONTROL_TIMEOUT, self.unit_exists_inner(name))
            .await
            .with_context(|| format!("Timed out querying {}", name))?
    }

    async fn stop_unit(&self, name: &str) -> Result<()> {
        tokio::time::timeout(CONTROL_TIMEOUT, self.stop_unit_inner(name))
            .await
            .with_context(|| format!("Timed out stopping {}", name))?
    }

    async fn start_transient(
        &self,
        unit: TransientUnit,
        auxiliary: Vec<TransientUnit>,
    ) -> Result<()> {
        let name = unit.name.clone();
        let mut started = false;
        let result = tokio::time::timeout(
            CONTROL_TIMEOUT,
            self.start_job(unit, auxiliary, &mut started),
        )
        .await
        .with_context(|| format!("Timed out creating {}", name))??;
        require_done(&name, &result)
    }
}

fn merge_cleanup<T>(result: Result<T>, cleanup: Result<()>, context: &str) -> Result<T> {
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error.context(context.to_string())),
        (Err(error), Err(cleanup)) => Err(error.context(format!("{}: {:#}", context, cleanup))),
    }
}

struct CapturedStream {
    stream: pipe::Receiver,
    bytes: Vec<u8>,
}

impl CapturedStream {
    fn pair() -> Result<(Self, OwnedFd)> {
        let (writer, reader) = pipe::pipe().context("Failed to create output pipe")?;
        Ok((
            Self {
                stream: reader,
                bytes: Vec::new(),
            },
            writer.into_blocking_fd()?,
        ))
    }

    async fn read_all(&mut self) -> Result<()> {
        let mut chunk = [0; 8192];
        let mut truncated = false;
        loop {
            let count = self.stream.read(&mut chunk).await?;
            if count == 0 {
                break;
            }
            let room = MAX_STREAM_BYTES.saturating_sub(self.bytes.len());
            self.bytes.extend_from_slice(&chunk[..count.min(room)]);
            truncated |= count > room;
        }
        if truncated {
            debug!(
                limit = MAX_STREAM_BYTES,
                "Script output stream was truncated"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use zbus::Type;

    #[test]
    fn manager_versions_accept_release_and_git_versions() {
        for (version, expected) in [
            ("239", 239),
            ("252.6-1~deb12u1", 252),
            ("v259~rc1-42-gabcdef", 259),
            ("245 (245.4-1)", 245),
        ] {
            assert_eq!(parse_systemd_version(version).expect("version"), expected);
        }
        for version in ["", "v", "unknown", "systemd 239"] {
            assert!(parse_systemd_version(version).is_err());
        }
    }

    #[test]
    fn transient_arguments_have_the_systemd_wire_signatures() {
        assert_eq!(UnitProperties::SIGNATURE.to_string(), "a(sv)");
        assert_eq!(AuxiliaryUnits::SIGNATURE.to_string(), "a(sa(sv))");
        assert_eq!(
            <(u32, OwnedObjectPath, String, String)>::SIGNATURE.to_string(),
            "(uoss)"
        );
    }

    #[test]
    fn unit_success_requires_both_job_and_service_success() {
        let mut output = UnitOutput {
            job_result: "done".to_string(),
            service_result: "success".to_string(),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        assert!(output.success());
        output.service_result = "timeout".to_string();
        assert!(!output.success());
        output.service_result = "success".to_string();
        output.job_result = "dependency".to_string();
        assert!(!output.success());
    }

    #[tokio::test]
    async fn output_capture_is_bounded_and_drains_beyond_the_limit() {
        let (mut capture, writer) = CapturedStream::pair().expect("pipe");
        let mut writer = pipe::Sender::from_owned_fd(writer).expect("writer");
        let write = async {
            let chunk = [b'x'; 8192];
            for _ in 0..(MAX_STREAM_BYTES / chunk.len() + 2) {
                writer.write_all(&chunk).await.expect("write");
            }
            drop(writer);
        };
        let (result, ()) = tokio::join!(capture.read_all(), write);
        result.expect("read");
        assert_eq!(capture.bytes.len(), MAX_STREAM_BYTES);
    }

    #[tokio::test]
    async fn cancelling_a_reader_does_not_leave_a_background_task() {
        let (mut capture, writer) = CapturedStream::pair().expect("pipe");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), capture.read_all())
                .await
                .is_err()
        );
        drop(capture);
        let mut writer = pipe::Sender::from_owned_fd(writer).expect("writer");
        assert!(writer.write_all(b"closed").await.is_err());
    }
}
