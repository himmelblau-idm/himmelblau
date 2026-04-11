/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::error::Error;
use std::io::{Error as IoError, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime};

use crate::unix_proto::{ClientRequest, ClientResponse};

/// Check if the current process is being started by systemd as the
/// himmelblaud daemon or its tasks helper.  During service startup
/// sd-executor resolves DynamicUser= and SupplementaryGroups= via NSS
/// and may also call into PAM.  If himmelblau is listed in nsswitch.conf
/// or the PAM stack, contacting the himmelblaud socket at that point
/// would deadlock: the socket-activated socket is listening but the
/// daemon (this very process) hasn't exec'd yet.
///
/// Both the NSS and PAM modules should call this before attempting to
/// connect to the daemon and bail out immediately when it returns true.
pub fn should_skip_daemon_call() -> bool {
    use std::sync::OnceLock;

    static SKIP: OnceLock<bool> = OnceLock::new();
    *SKIP.get_or_init(|| {
        matches!(
            std::env::var_os("SYSTEMD_ACTIVATION_UNIT").as_deref(),
            Some(v) if v == "himmelblaud.service" || v == "himmelblaud-tasks.service"
        )
    })
}

pub struct DaemonClientBlocking {
    stream: UnixStream,
}

impl DaemonClientBlocking {
    pub fn new(path: &str) -> Result<DaemonClientBlocking, Box<dyn Error>> {
        debug!(%path);

        let stream = UnixStream::connect(path)
            .map_err(|e| {
                // ENOENT means the daemon isn't running — expected during boot,
                // daemon-reload, or when himmelblau is not configured. Log at
                // debug to avoid distracting users with spurious error output.
                if e.kind() == ErrorKind::NotFound {
                    debug!(
                        "himmelblaud socket not found at {} (daemon not running?)",
                        path
                    );
                } else {
                    error!(
                        "Unix socket stream setup error while connecting to {} -> {:?}",
                        path, e
                    );
                }
                e
            })
            .map_err(Box::new)?;

        Ok(DaemonClientBlocking { stream })
    }

    pub fn call_and_wait(
        &mut self,
        req: &ClientRequest,
        timeout: u64,
    ) -> Result<ClientResponse, Box<dyn Error>> {
        let timeout = Duration::from_secs(timeout);
        // Use a short per-read timeout so we can poll without blocking the
        // entire wall-clock budget in a single read() call. This is critical
        // for long-running daemon operations like MFA device flow polling
        // which can take well over 60 seconds.
        let read_poll = Duration::from_secs(1);

        let data = serde_json::to_vec(&req).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            Box::new(IoError::new(ErrorKind::Other, "JSON encode error"))
        })?;

        match self.stream.set_read_timeout(Some(read_poll)) {
            Ok(()) => {}
            Err(e) => {
                error!(
                    "Unix socket stream setup error while setting read timeout -> {:?}",
                    e
                );
                return Err(Box::new(e));
            }
        };
        match self.stream.set_write_timeout(Some(timeout)) {
            Ok(()) => {}
            Err(e) => {
                error!(
                    "Unix socket stream setup error while setting write timeout -> {:?}",
                    e
                );
                return Err(Box::new(e));
            }
        };

        self.stream
            .write_all(data.as_slice())
            .and_then(|_| self.stream.flush())
            .map_err(|e| {
                error!("stream write error -> {:?}", e);
                e
            })
            .map_err(Box::new)?;

        // Now wait on the response.
        let start = SystemTime::now();
        let mut read_started = false;
        let mut data = Vec::with_capacity(1024);
        let mut counter = 0;

        loop {
            let mut buffer = [0; 1024];
            let durr = SystemTime::now().duration_since(start).map_err(Box::new)?;
            if durr > timeout {
                error!("Socket timeout");
                // timed out, not enough activity.
                break;
            }
            // Would be a lot easier if we had peek ...
            // https://github.com/rust-lang/rust/issues/76923
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    if read_started {
                        debug!("read_started true, we have completed");
                        // We're done, no more bytes.
                        break;
                    } else {
                        debug!("Waiting ...");
                        // Still can wait ...
                        continue;
                    }
                }
                Ok(count) => {
                    data.extend_from_slice(&buffer);
                    counter += count;
                    if count == 1024 {
                        debug!("Filled 1024 bytes, looping ...");
                        // We have filled the buffer, we need to copy and loop again.
                        read_started = true;
                        continue;
                    } else {
                        debug!("Filled {} bytes, complete", count);
                        // We have a partial read, so we are complete.
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    // set_read_timeout() causes blocking reads to return
                    // WouldBlock/TimedOut when no data arrives within the
                    // timeout window. Check the wall-clock timeout and retry.
                    let durr = SystemTime::now().duration_since(start).map_err(Box::new)?;
                    if durr > timeout {
                        error!("Socket timeout waiting for daemon response");
                        return Err(Box::new(IoError::new(
                            ErrorKind::TimedOut,
                            "socket timeout",
                        )));
                    }
                    continue;
                }
                Err(e) => {
                    error!("Stream read failure from {:?} -> {:?}", &self.stream, e);
                    // Failure!
                    return Err(Box::new(e));
                }
            }
        }

        // Extend from slice fills with 0's, so we need to truncate now.
        data.truncate(counter);

        // Now attempt to decode.
        let cr = serde_json::from_slice::<ClientResponse>(data.as_slice()).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            Box::new(IoError::new(ErrorKind::Other, "JSON decode error"))
        })?;

        Ok(cr)
    }

    /// This writes the request to the existing socket and returns immediately,
    /// without waiting for a response.
    pub fn call_and_forget(&mut self, req: &ClientRequest) -> Result<(), Box<dyn Error>> {
        let data = serde_json::to_vec(req).map_err(|e| {
            warn!("socket encoding error -> {:?}", e);
            Box::new(IoError::new(ErrorKind::Other, "JSON encode error"))
        })?;

        let timeout = Duration::from_secs(2);
        self.stream.set_write_timeout(Some(timeout)).map_err(|e| {
            warn!("set_write_timeout error -> {:?}", e);
            Box::new(e)
        })?;

        self.stream
            .write_all(data.as_slice())
            .and_then(|_| self.stream.flush())
            .map_err(|e| {
                warn!("stream write error -> {:?}", e);
                Box::new(e)
            })?;

        Ok(())
    }
}
