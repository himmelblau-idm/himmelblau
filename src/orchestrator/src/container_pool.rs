use crate::podman::{ContainerInstance, PodmanClient};
use anyhow::{anyhow, Result};
use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex, Notify};
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, info, warn};

pub struct ContainerPool {
    podman: Arc<PodmanClient>,
    state: Mutex<ContainerPoolState>,
    replenish_notify: Notify,
}

struct ContainerPoolState {
    spare: Option<ContainerInstance>,
    replenish_in_progress: bool,
    next_warm_id: u64,
    shutting_down: bool,
}

impl ContainerPool {
    pub fn new(podman: Arc<PodmanClient>) -> Self {
        Self {
            podman,
            state: Mutex::new(ContainerPoolState {
                spare: None,
                replenish_in_progress: false,
                next_warm_id: 0,
                shutting_down: false,
            }),
            replenish_notify: Notify::new(),
        }
    }

    pub async fn acquire_container(
        self: &Arc<Self>,
        session_id: &str,
    ) -> Result<ContainerInstance> {
        let spare = {
            let mut state = self.state.lock().await;
            state.spare.take()
        };

        if let Some(container) = spare {
            match self.podman.ping_container(&container).await {
                Ok(()) => {
                    info!(
                        container = %container.name,
                        session_id,
                        "using warm orchestrator container for session"
                    );
                    self.ensure_spare().await;
                    return Ok(container);
                }
                Err(error) => {
                    warn!(
                        container = %container.name,
                        ?error,
                        "discarding unresponsive warm orchestrator container"
                    );
                    if let Err(destroy_error) =
                        self.podman.destroy_session_container(&container).await
                    {
                        warn!(
                            container = %container.name,
                            ?destroy_error,
                            "failed to destroy unresponsive warm orchestrator container"
                        );
                    }
                }
            }
        }

        self.ensure_spare().await;
        info!(
            session_id,
            "no warm orchestrator container available; creating session container synchronously"
        );
        self.podman
            .create_session_container(session_id)
            .await
            .map_err(|error| {
                anyhow!(
                    "failed to create session container for '{}': {error}",
                    session_id
                )
            })
    }

    pub async fn run_maintenance(
        self: Arc<Self>,
        mut shutdown_rx: broadcast::Receiver<()>,
        keepalive_every: Duration,
    ) {
        self.ensure_spare().await;

        let mut ticker = interval(keepalive_every.max(Duration::from_secs(1)));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("container pool received shutdown signal");
                    break;
                }
                _ = ticker.tick() => {
                    self.check_or_replenish_spare().await;
                }
            }
        }

        self.shutdown().await;
    }

    async fn check_or_replenish_spare(self: &Arc<Self>) {
        let spare = {
            let state = self.state.lock().await;
            state.spare.clone()
        };

        let Some(container) = spare else {
            self.ensure_spare().await;
            return;
        };

        if self.podman.ping_container(&container).await.is_ok() {
            debug!(
                container = %container.name,
                "warm orchestrator container is ready"
            );
            return;
        }

        let stale = {
            let mut state = self.state.lock().await;
            if state
                .spare
                .as_ref()
                .is_some_and(|spare| spare.id == container.id)
            {
                state.spare.take()
            } else {
                None
            }
        };

        if let Some(stale) = stale {
            warn!(
                container = %stale.name,
                "warm orchestrator container failed readiness check; replacing it"
            );
            if let Err(error) = self.podman.destroy_session_container(&stale).await {
                warn!(
                    container = %stale.name,
                    ?error,
                    "failed to destroy stale warm orchestrator container"
                );
            }
        }

        self.ensure_spare().await;
    }

    async fn ensure_spare(self: &Arc<Self>) {
        let warm_session_id = {
            let mut state = self.state.lock().await;
            if state.shutting_down || state.spare.is_some() || state.replenish_in_progress {
                return;
            }

            state.replenish_in_progress = true;
            state.next_warm_id = state.next_warm_id.saturating_add(1);
            format!("warm-{}-{}", process::id(), state.next_warm_id)
        };

        let pool = Arc::clone(self);
        tokio::spawn(async move {
            pool.replenish_spare(warm_session_id).await;
        });
    }

    async fn replenish_spare(self: Arc<Self>, warm_session_id: String) {
        debug!(
            warm_session_id,
            "starting warm orchestrator container replenishment"
        );

        let result = self.podman.create_session_container(&warm_session_id).await;
        let mut destroy_container = None;

        {
            let mut state = self.state.lock().await;
            state.replenish_in_progress = false;

            match result {
                Ok(container) if state.shutting_down || state.spare.is_some() => {
                    destroy_container = Some(container);
                }
                Ok(container) => {
                    info!(
                        container = %container.name,
                        "warm orchestrator container is ready"
                    );
                    state.spare = Some(container);
                }
                Err(error) => {
                    warn!(?error, "failed to create warm orchestrator container");
                }
            }
        }

        self.replenish_notify.notify_one();

        if let Some(container) = destroy_container {
            if let Err(error) = self.podman.destroy_session_container(&container).await {
                warn!(
                    container = %container.name,
                    ?error,
                    "failed to destroy unused warm orchestrator container"
                );
            }
        }
    }

    async fn shutdown(&self) {
        let spare = {
            let mut state = self.state.lock().await;
            state.shutting_down = true;
            state.spare.take()
        };

        if let Some(container) = spare {
            if let Err(error) = self.podman.destroy_session_container(&container).await {
                warn!(
                    container = %container.name,
                    ?error,
                    "failed to destroy warm orchestrator container during shutdown"
                );
            }
        }

        loop {
            let notified = self.replenish_notify.notified();
            let replenish_in_progress = {
                let state = self.state.lock().await;
                state.replenish_in_progress
            };

            if !replenish_in_progress {
                break;
            }

            notified.await;
        }

        let spare = {
            let mut state = self.state.lock().await;
            state.spare.take()
        };

        if let Some(container) = spare {
            if let Err(error) = self.podman.destroy_session_container(&container).await {
                warn!(
                    container = %container.name,
                    ?error,
                    "failed to destroy late warm orchestrator container during shutdown"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_pool() -> ContainerPool {
        ContainerPool::new(Arc::new(PodmanClient::new(
            "podman",
            "localhost/test:latest",
            None,
            PathBuf::from("/tmp/himmelblau-orchestrator-test"),
            1,
            1,
            true,
            None,
        )))
    }

    #[tokio::test]
    async fn shutdown_waits_for_replenish_completion() {
        let pool = Arc::new(test_pool());
        {
            let mut state = pool.state.lock().await;
            state.replenish_in_progress = true;
        }

        let shutdown_pool = Arc::clone(&pool);
        let shutdown = tokio::spawn(async move {
            shutdown_pool.shutdown().await;
        });

        tokio::task::yield_now().await;
        {
            let mut state = pool.state.lock().await;
            state.replenish_in_progress = false;
        }
        pool.replenish_notify.notify_one();

        let result = tokio::time::timeout(Duration::from_secs(1), shutdown).await;
        assert!(result.is_ok(), "shutdown should not hang");
        if let Ok(join_result) = result {
            assert!(join_result.is_ok(), "shutdown task should not panic");
        }
    }
}
