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
use std::ffi::OsStr;
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
        // SYSTEMD_ACTIVATION_UNIT may be inherited from an untrusted caller.
        // Only a root process running directly under the system manager may
        // use it to suppress daemon calls during credential resolution.
        let activation_unit = std::env::var_os("SYSTEMD_ACTIVATION_UNIT");
        should_skip_daemon_call_for(
            unsafe { libc::geteuid() },
            unsafe { libc::getppid() },
            activation_unit.as_deref(),
        )
    })
}

fn should_skip_daemon_call_for(
    effective_uid: libc::uid_t,
    parent_pid: libc::pid_t,
    activation_unit: Option<&OsStr>,
) -> bool {
    effective_uid == 0
        && parent_pid == 1
        && matches!(
            activation_unit,
            Some(v) if v == "himmelblaud.service" || v == "himmelblaud-tasks.service"
        )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::{should_skip_daemon_call_for, DaemonClientBlocking};
    use crate::unix_proto::{ClientRequest, ClientResponse, PamAuthResponse};
    use std::ffi::OsStr;
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn daemon_call_is_skipped_for_himmelblau_units_started_by_system_manager() {
        for unit in ["himmelblaud.service", "himmelblaud-tasks.service"] {
            assert!(should_skip_daemon_call_for(0, 1, Some(OsStr::new(unit))));
        }
    }

    #[test]
    fn daemon_call_is_not_skipped_for_untrusted_process_contexts() {
        let unit = Some(OsStr::new("himmelblaud.service"));

        assert!(!should_skip_daemon_call_for(1000, 1, unit));
        assert!(!should_skip_daemon_call_for(0, 2, unit));
    }

    #[test]
    fn daemon_call_is_not_skipped_for_missing_or_unknown_units() {
        assert!(!should_skip_daemon_call_for(0, 1, None));
        assert!(!should_skip_daemon_call_for(
            0,
            1,
            Some(OsStr::new("unrelated.service")),
        ));
    }

    fn padded_response(target_len: usize) -> (Vec<u8>, String) {
        let empty = serde_json::to_vec(&ClientResponse::PamAuthenticateStepResponse(
            PamAuthResponse::Denied(String::new()),
        ))
        .unwrap();
        let message = "x".repeat(target_len.checked_sub(empty.len()).unwrap());
        let response = serde_json::to_vec(&ClientResponse::PamAuthenticateStepResponse(
            PamAuthResponse::Denied(message.clone()),
        ))
        .unwrap();
        assert_eq!(response.len(), target_len);
        (response, message)
    }

    fn read_request(stream: &mut UnixStream) {
        let mut request = [0; 1024];
        assert!(stream.read(&mut request).unwrap() > 0);
    }

    fn assert_denied(response: ClientResponse, expected: &str) {
        match response {
            ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Denied(message)) => {
                assert_eq!(message, expected);
            }
            other => panic!("expected denied response, got {:?}", other),
        }
    }

    #[test]
    fn response_is_decoded_at_exact_buffer_multiples() {
        for target_len in [1024, 2048] {
            let (response, expected) = padded_response(target_len);
            let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
            let (release_tx, release_rx) = mpsc::channel();

            let server = thread::spawn(move || {
                read_request(&mut server_stream);
                server_stream.write_all(&response).unwrap();
                server_stream.flush().unwrap();
                release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            });

            let mut client = DaemonClientBlocking {
                stream: client_stream,
            };
            let result = client.call_and_wait(&ClientRequest::Status, 1);
            release_tx.send(()).unwrap();
            server.join().unwrap();

            assert_denied(result.unwrap(), &expected);
        }
    }

    #[test]
    fn fragmented_response_is_read_until_json_is_complete() {
        let response = serde_json::to_vec(&ClientResponse::PamAuthenticateStepResponse(
            PamAuthResponse::Denied("fragmented".to_string()),
        ))
        .unwrap();
        let split = response.len() / 2;
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let (release_tx, release_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            read_request(&mut server_stream);
            server_stream.write_all(&response[..split]).unwrap();
            server_stream.flush().unwrap();
            thread::sleep(Duration::from_millis(20));
            server_stream.write_all(&response[split..]).unwrap();
            server_stream.flush().unwrap();
            release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        });

        let mut client = DaemonClientBlocking {
            stream: client_stream,
        };
        let result = client.call_and_wait(&ClientRequest::Status, 1);
        release_tx.send(()).unwrap();
        server.join().unwrap();

        assert_denied(result.unwrap(), "fragmented");
    }

    #[test]
    fn truncated_response_fails_when_peer_closes() {
        let response = serde_json::to_vec(&ClientResponse::PamAuthenticateStepResponse(
            PamAuthResponse::Denied("truncated".to_string()),
        ))
        .unwrap();
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();

        let server = thread::spawn(move || {
            read_request(&mut server_stream);
            server_stream.write_all(&response[..response.len() - 1]).unwrap();
        });

        let mut client = DaemonClientBlocking {
            stream: client_stream,
        };
        let error = client
            .call_and_wait(&ClientRequest::Status, 1)
            .unwrap_err();
        server.join().unwrap();

        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn incomplete_response_honors_wall_clock_timeout() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let (release_tx, release_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            read_request(&mut server_stream);
            release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        });

        let mut client = DaemonClientBlocking {
            stream: client_stream,
        };
        let error = client
            .call_and_wait(&ClientRequest::Status, 1)
            .unwrap_err();
        release_tx.send(()).unwrap();
        server.join().unwrap();

        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            ErrorKind::TimedOut
        );
    }

    #[test]
    fn connection_can_be_reused_for_successive_responses() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();

        let server = thread::spawn(move || {
            for response in [ClientResponse::Ok, ClientResponse::Error] {
                read_request(&mut server_stream);
                server_stream
                    .write_all(&serde_json::to_vec(&response).unwrap())
                    .unwrap();
                server_stream.flush().unwrap();
            }
        });

        let mut client = DaemonClientBlocking {
            stream: client_stream,
        };
        assert!(matches!(
            client.call_and_wait(&ClientRequest::Status, 1).unwrap(),
            ClientResponse::Ok
        ));
        assert!(matches!(
            client.call_and_wait(&ClientRequest::Status, 1).unwrap(),
            ClientResponse::Error
        ));
        server.join().unwrap();
    }
}

pub struct DaemonClientBlocking {
    stream: UnixStream,
}

impl DaemonClientBlocking {
    pub fn new(path: &str) -> std::io::Result<DaemonClientBlocking> {
        debug!(%path);

        let stream = UnixStream::connect(path).map_err(|e| {
            // ENOENT means the daemon isn't running - expected during boot,
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
        })?;

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
            Box::new(IoError::other("JSON encode error"))
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
        let mut data = Vec::with_capacity(1024);

        loop {
            let mut buffer = [0; 1024];
            let durr = SystemTime::now().duration_since(start).map_err(Box::new)?;
            if durr > timeout {
                error!("Socket timeout waiting for daemon response");
                return Err(Box::new(IoError::new(
                    ErrorKind::TimedOut,
                    "socket timeout",
                )));
            }
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    error!("Socket closed before a complete response was received");
                    return Err(Box::new(IoError::new(
                        ErrorKind::UnexpectedEof,
                        "socket closed before a complete response was received",
                    )));
                }
                Ok(count) => {
                    data.extend_from_slice(&buffer[..count]);
                    match serde_json::from_slice::<ClientResponse>(&data) {
                        Ok(response) => return Ok(response),
                        Err(e) if e.is_eof() => {
                            debug!(
                                "Read {} bytes; waiting for the rest of the JSON response",
                                count
                            );
                        }
                        Err(e) => {
                            error!("socket encoding error -> {:?}", e);
                            return Err(Box::new(IoError::other("JSON decode error")));
                        }
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
                }
                Err(e) => {
                    error!("Stream read failure from {:?} -> {:?}", &self.stream, e);
                    return Err(Box::new(e));
                }
            }
        }
    }

    /// This writes the request to the existing socket and returns immediately,
    /// without waiting for a response.
    pub fn call_and_forget(&mut self, req: &ClientRequest) -> Result<(), Box<dyn Error>> {
        let data = serde_json::to_vec(req).map_err(|e| {
            warn!("socket encoding error -> {:?}", e);
            Box::new(IoError::other("JSON encode error"))
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
