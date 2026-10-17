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
use std::io::Error as IoError;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{self, Duration};
use zeroize::Zeroizing;

use crate::secret_memory::{encode_json, extend_secret};
use crate::unix_proto::{ClientRequest, ClientResponse};

async fn call_daemon_inner(
    path: &str,
    req: ClientRequest,
) -> Result<ClientResponse, Box<dyn Error>> {
    trace!(?path, "calling daemon");
    let mut stream = UnixStream::connect(path).await?;
    let data = encode_json(&req).map_err(|_| IoError::other("JSON encode error"))?;
    stream.write_all(&data).await?;
    stream.flush().await?;
    drop(data);

    // Direct I/O avoids Framed retaining sent or consumed secret-bearing bytes
    // in BytesMut spare capacity. Both buffers wipe on cancellation and error.
    let mut data = Zeroizing::new(Vec::with_capacity(1024));
    let mut buffer = Zeroizing::new([0_u8; 1024]);
    loop {
        let count = stream.read(buffer.as_mut()).await?;
        if count == 0 {
            return Err(Box::new(IoError::new(
                std::io::ErrorKind::UnexpectedEof,
                "socket closed before a complete response was received",
            )));
        }
        extend_secret(&mut data, &buffer[..count]);
        match serde_json::from_slice::<ClientResponse>(&data) {
            Ok(response) => return Ok(response),
            Err(error) if error.is_eof() => {}
            Err(_) => return Err(Box::new(IoError::other("JSON decode error"))),
        }
    }
}

/// Makes a call to kanidm_unixd via a unix socket at `path`
pub async fn call_daemon(
    path: &str,
    req: ClientRequest,
    timeout: u64,
) -> Result<ClientResponse, Box<dyn Error>> {
    let sleep = time::sleep(Duration::from_secs(timeout));
    tokio::pin!(sleep);

    tokio::select! {
        _ = &mut sleep => {
            error!(?timeout, "Timed out making request to kanidm_unixd");
            Err(Box::new(IoError::other("timeout")))
        }
        res = call_daemon_inner(path, req) => {
            res
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn direct_client_reads_fragmented_response() -> Result<(), Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!("himmelblau-client-{}", uuid::Uuid::new_v4()));
        let listener = UnixListener::bind(&path)?;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut pending = Vec::new();
            loop {
                let mut buffer = [0; 128];
                let count = socket.read(&mut buffer).await?;
                if count == 0 {
                    return Err(IoError::other("truncated request"));
                }
                pending.extend_from_slice(&buffer[..count]);
                if let Ok(request) = serde_json::from_slice::<ClientRequest>(&pending) {
                    assert!(matches!(request, ClientRequest::Status));
                    break;
                }
            }
            socket.write_all(b"\"O").await?;
            tokio::task::yield_now().await;
            socket.write_all(b"k\"").await?;
            Ok::<(), IoError>(())
        });
        let response = call_daemon(&path.to_string_lossy(), ClientRequest::Status, 2).await;
        server.await??;
        std::fs::remove_file(path)?;
        assert!(matches!(response?, ClientResponse::Ok));
        Ok(())
    }
}
