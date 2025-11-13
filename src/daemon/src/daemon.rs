/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use std::error::Error;
use std::fs::metadata;
use std::io;
use std::io::{Error as IoError, ErrorKind};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use clap::{Arg, ArgAction, Command};
use futures::{SinkExt, StreamExt};
use himmelblau::{ClientInfo, IdToken, UserToken as UnixUserToken};
use himmelblau_unix_common::config::{split_username, HimmelblauConfig};
use himmelblau_unix_common::constants::{DEFAULT_APP_ID, DEFAULT_CONFIG_PATH};
use himmelblau_unix_common::db::{Cache, CacheTxn, Db};
use himmelblau_unix_common::idprovider::himmelblau::HimmelblauMultiProvider;
use himmelblau_unix_common::idprovider::interface::Id;
use himmelblau_unix_common::resolver::{AuthSession, Resolver};
use himmelblau_unix_common::unix_config::UidAttr;
use himmelblau_unix_common::unix_passwd::{parse_etc_group, parse_etc_passwd};
use himmelblau_unix_common::unix_proto::{
    ClientRequest, ClientResponse, PamAuthResponse, TaskRequest, TaskResponse,
};
use himmelblau_unix_common::user_map::UserMap;
use himmelblau_unix_common::{tpm_init, tpm_loadable_machine_key, tpm_machine_key};
use uuid::Uuid;

use kanidm_utils_users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};
use libc::umask;
use sd_notify::NotifyState;
use sketching::tracing_forest::traits::*;
use sketching::tracing_forest::util::*;
use sketching::tracing_forest::{self};
use tokio::fs::File;
use tokio::io::AsyncReadExt; // for read_to_end()
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::time;
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::span;

use kanidm_hsm_crypto::{provider::BoxedDynTpm, provider::SoftTpm, provider::Tpm};

use notify_debouncer_full::{new_debouncer, notify::RecursiveMode};

mod broker;
use broker::Broker;
use identity_dbus_broker::himmelblau_broker_serve;

//=== the codec

type AsyncTaskRequest = (TaskRequest, oneshot::Sender<i32>);

#[derive(Default)]
struct ClientCodec;

impl Decoder for ClientCodec {
    type Error = io::Error;
    type Item = ClientRequest;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("Attempting to decode request ...");
        match serde_json::from_slice::<ClientRequest>(src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<ClientResponse> for ClientCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: ClientResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        trace!("Attempting to send response -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

#[derive(Default)]
struct TaskCodec;

impl Decoder for TaskCodec {
    type Error = io::Error;
    type Item = TaskResponse;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match serde_json::from_slice::<TaskResponse>(src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<TaskRequest> for TaskCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: TaskRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!(
            "Attempting to send request -> {:?} ...",
            msg.as_safe_string()
        );
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

/// Pass this a file path and it'll look for the file and remove it if it's there.
fn rm_if_exist(p: &str) {
    if Path::new(p).exists() {
        debug!("Removing requested file {:?}", p);
        let _ = std::fs::remove_file(p).map_err(|e| {
            error!(
                "Failure while attempting to attempting to remove {:?} -> {:?}",
                p, e
            );
        });
    } else {
        debug!("Path {:?} doesn't exist, not attempting to remove.", p);
    }
}

async fn handle_task_client(
    stream: UnixStream,
    task_channel_tx: &Sender<AsyncTaskRequest>,
    task_channel_rx: &mut Receiver<AsyncTaskRequest>,
) -> Result<(), Box<dyn Error>> {
    // setup the codec
    let mut reqs = Framed::new(stream, TaskCodec);

    loop {
        // TODO wait on the channel OR the task handler, so we know
        // when it closes.
        let v = match task_channel_rx.recv().await {
            Some(v) => v,
            None => return Ok(()),
        };

        debug!("Sending Task -> {:?}", v.0.as_safe_string());

        // Write the req to the socket.
        if let Err(_e) = reqs.send(v.0.clone()).await {
            // re-queue the event if not timed out.
            // This is indicated by the one shot being dropped.
            if !v.1.is_closed() {
                let _ = task_channel_tx
                    .send_timeout(v, Duration::from_millis(100))
                    .await;
            }
            // now return the error.
            return Err(Box::new(IoError::new(ErrorKind::Other, "oh no!")));
        }

        match reqs.next().await {
            Some(Ok(TaskResponse::Success(status))) => {
                debug!("Task was acknowledged and completed.");
                // Send a result back via the one-shot
                // Ignore if it fails.
                let _ = v.1.send(status);
            }
            other => {
                error!("Error -> {:?}", other);
                return Err(Box::new(IoError::new(ErrorKind::Other, "oh no!")));
            }
        }
    }
}

async fn handle_client(
    sock: UnixStream,
    cachelayer: Arc<Resolver<HimmelblauMultiProvider>>,
    task_channel_tx: &Sender<AsyncTaskRequest>,
    cfg: HimmelblauConfig,
) -> Result<(), Box<dyn Error>> {
    trace!("Accepted connection");

    let Ok(ucred) = sock.peer_cred() else {
        return Err(Box::new(IoError::new(
            ErrorKind::Other,
            "Unable to verify peer credentials.",
        )));
    };

    let mut reqs = Framed::new(sock, ClientCodec);
    let mut pam_auth_session_state = None;

    // Setup a broadcast channel so that if we have an unexpected disconnection, we can
    // tell consumers to stop work.
    let (shutdown_tx, _shutdown_rx) = broadcast::channel(1);

    trace!("Waiting for requests ...");
    while let Some(Ok(req)) = reqs.next().await {
        let resp = match req {
            ClientRequest::NssAccounts => {
                trace!("nssaccounts req");
                cachelayer
                    .get_nssaccounts()
                    .await
                    .map(ClientResponse::NssAccounts)
                    .unwrap_or_else(|_| {
                        error!("unable to enum accounts");
                        ClientResponse::NssAccounts(Vec::new())
                    })
            }
            ClientRequest::NssAccountByUid(gid) => {
                trace!("nssaccountbyuid req");
                cachelayer
                    .get_nssaccount_gid(gid)
                    .await
                    .map(ClientResponse::NssAccount)
                    .unwrap_or_else(|_| {
                        error!("unable to load account, returning empty.");
                        ClientResponse::NssAccount(None)
                    })
            }
            ClientRequest::NssAccountByName(account_id) => {
                let account_id = account_id.to_lowercase();
                trace!("nssaccountbyname req");
                cachelayer
                    .get_nssaccount_name(account_id.as_str())
                    .await
                    .map(ClientResponse::NssAccount)
                    .unwrap_or_else(|_| {
                        error!("unable to load account, returning empty.");
                        ClientResponse::NssAccount(None)
                    })
            }
            ClientRequest::NssGroups => {
                trace!("nssgroups req");
                cachelayer
                    .get_nssgroups()
                    .await
                    .map(ClientResponse::NssGroups)
                    .unwrap_or_else(|_| {
                        error!("unable to enum groups");
                        ClientResponse::NssGroups(Vec::new())
                    })
            }
            ClientRequest::NssGroupByGid(gid) => {
                trace!("nssgroupbygid req");
                cachelayer
                    .get_nssgroup_gid(gid)
                    .await
                    .map(ClientResponse::NssGroup)
                    .unwrap_or_else(|_| {
                        error!("unable to load group, returning empty.");
                        ClientResponse::NssGroup(None)
                    })
            }
            ClientRequest::NssGroupByName(grp_id) => {
                trace!("nssgroupbyname req");
                cachelayer
                    .get_nssgroup_name(grp_id.as_str())
                    .await
                    .map(ClientResponse::NssGroup)
                    .unwrap_or_else(|_| {
                        error!("unable to load group, returning empty.");
                        ClientResponse::NssGroup(None)
                    })
            }
            ClientRequest::PamAuthenticateInit(account_id, service, no_hello_pin) => {
                let account_id = account_id.to_lowercase();
                let span = span!(Level::INFO, "pam authenticate init");
                trace!("pam authenticate init");

                async {
                    // We may re-init upon auth failure, at which point we will
                    // disregard the previous state and start over.
                    match cachelayer
                        .pam_account_authenticate_init(
                            account_id.as_str(),
                            service.as_str(),
                            no_hello_pin,
                            shutdown_tx.subscribe(),
                        )
                        .await
                    {
                        Ok((auth_session, pam_auth_response)) => {
                            pam_auth_session_state = Some(auth_session);
                            pam_auth_response.into()
                        }
                        Err(_) => ClientResponse::Error,
                    }
                }
                .instrument(span)
                .await
            }
            ClientRequest::PamAuthenticateStep(pam_next_req) => {
                let span = span!(Level::INFO, "pam authenticate step");
                async {
                    trace!("pam authenticate step");
                    match &mut pam_auth_session_state {
                        Some(auth_session) => {
                            match cachelayer
                                .pam_account_authenticate_step(auth_session, pam_next_req)
                                .await
                                .map(|pam_auth_response| pam_auth_response.into())
                                .unwrap_or(ClientResponse::Error)
                            {
                                ClientResponse::PamAuthenticateStepResponse(mut resp) => {
                                    match auth_session {
                                        AuthSession::Success(account_id) => {
                                            let account_id = account_id.to_lowercase();
                                            match resp {
                                                PamAuthResponse::Success => {
                                                    if cfg.get_logon_script().is_some() {
                                                        let scopes = cfg.get_logon_token_scopes();
                                                        let domain = split_username(&account_id)
                                                            .map(|(_, domain)| domain);
                                                        let client_id = domain.and_then(|d| {
                                                            cfg.get_logon_token_app_id(d)
                                                        });
                                                        let access_token = match cachelayer
                                                            .get_user_accesstoken(
                                                                Id::Name(account_id.to_string()),
                                                                scopes,
                                                                client_id,
                                                            )
                                                            .await
                                                        {
                                                            Some(token) => token
                                                                .access_token
                                                                .clone()
                                                                .unwrap_or("".to_string()),
                                                            None => "".to_string(),
                                                        };

                                                        let (tx, rx) = oneshot::channel();

                                                        match task_channel_tx
                                                            .send_timeout(
                                                                (
                                                                    TaskRequest::LogonScript(
                                                                        account_id.to_string(),
                                                                        access_token.to_string(),
                                                                    ),
                                                                    tx,
                                                                ),
                                                                Duration::from_millis(100),
                                                            )
                                                            .await
                                                        {
                                                            Ok(()) => {
                                                                // Now wait for the other end OR timeout.
                                                                match time::timeout_at(
                                                                    time::Instant::now()
                                                                        + Duration::from_secs(60),
                                                                    rx,
                                                                )
                                                                .await
                                                                {
                                                                    Ok(Ok(status)) => {
                                                                        if status == 2 {
                                                                            let msg = "Authentication was explicitly denied by the logon script";
                                                                            debug!(msg);
                                                                            resp =
                                                                                PamAuthResponse::Denied(msg.to_string());
                                                                        }
                                                                    }
                                                                    _ => {
                                                                        error!("Execution of logon script failed");
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                error!("Execution of logon script failed: {:?}", e);
                                                            }
                                                        }
                                                    }

                                                    // Initialize the user Kerberos ccache
                                                    if let Some((uid, gid, cloud_ccache, ad_ccache)) =
                                                        cachelayer
                                                            .get_user_ccaches(Id::Name(
                                                                account_id.to_string(),
                                                            ))
                                                            .await
                                                    {
                                                        let (tx, rx) = oneshot::channel();

                                                        match task_channel_tx
                                                            .send_timeout(
                                                                (
                                                                    TaskRequest::KerberosCCache(
                                                                        uid,
                                                                        gid,
                                                                        cloud_ccache,
                                                                        ad_ccache,
                                                                    ),
                                                                    tx,
                                                                ),
                                                                Duration::from_millis(100),
                                                            )
                                                            .await
                                                        {
                                                            Ok(()) => {
                                                                // Now wait for the other end OR timeout.
                                                                match time::timeout_at(
                                                                    time::Instant::now()
                                                                        + Duration::from_secs(60),
                                                                    rx,
                                                                )
                                                                .await
                                                                {
                                                                    Ok(Ok(status)) => {
                                                                        if status != 0 {
                                                                            error!("Kerberos credential cache load failed for {}: Status code: {}", account_id, status);
                                                                        }
                                                                    }
                                                                    Ok(Err(e)) => {
                                                                        error!("Kerberos credential cache load failed for {}: {:?}", account_id, e);
                                                                    }
                                                                    Err(e) => {
                                                                        error!("Kerberos credential cache load failed for {}: {:?}", account_id, e);
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                error!("Kerberos credential cache load failed for {}: {:?}", account_id, e);
                                                            }
                                                        }
                                                    }

                                                    // Fetch the user Profile picture
                                                    if let Some(token) = cachelayer
                                                        .get_user_accesstoken(
                                                            Id::Name(account_id.to_string()),
                                                            vec![],
                                                            None,
                                                        )
                                                        .await
                                                    {
                                                        if let Some(access_token) = &token.access_token {
                                                            let (tx, rx) = oneshot::channel();

                                                            match task_channel_tx
                                                                .send_timeout(
                                                                    (
                                                                        TaskRequest::LoadProfilePhoto(
                                                                            account_id.to_string(),
                                                                            access_token.to_string(),
                                                                        ),
                                                                        tx,
                                                                    ),
                                                                    Duration::from_millis(100),
                                                                )
                                                                .await
                                                            {
                                                                Ok(()) => {
                                                                    // Now wait for the other end OR timeout.
                                                                    match time::timeout_at(
                                                                        time::Instant::now()
                                                                            + Duration::from_secs(60),
                                                                        rx,
                                                                    )
                                                                    .await
                                                                    {
                                                                        Ok(_) => {
                                                                            info!("Fetching user profile picture succeeded");
                                                                        }
                                                                        _ => {
                                                                            error!("Fetching user profile picture failed");
                                                                        }
                                                                    }
                                                                }
                                                                Err(_) => {
                                                                    error!("Fetching user profile picture failed");
                                                                }
                                                            }
                                                        }
                                                    }

                                                    // Apply Intune policies
                                                    if cfg.get_apply_policy()
                                                    {
                                                        let intune_device_id = split_username(&account_id)
                                                            .map(|(_, domain)| domain)
                                                            .and_then(|domain| {
                                                                // The intune_device_id may have been written after startup,
                                                                // so we re-read the config here.
                                                                HimmelblauConfig::new(Some(&cfg.get_config_file())).ok()
                                                                .map(|cfg| {
                                                                    cfg.get_intune_device_id(domain)
                                                                })
                                                            }).flatten();
                                                        let graph_token = cachelayer
                                                            .get_user_accesstoken(
                                                                Id::Name(account_id.clone()),
                                                                vec!["00000003-0000-0000-c000-000000000000/.default".to_string()],
                                                                Some(DEFAULT_APP_ID.to_string())
                                                            ).await;
                                                        let intune_token = cachelayer
                                                            .get_user_accesstoken(
                                                                Id::Name(account_id.clone()),
                                                                vec!["0000000a-0000-0000-c000-000000000000/.default".to_string()],
                                                                Some(DEFAULT_APP_ID.to_string())
                                                            ).await;
                                                        let iwservice_token = cachelayer
                                                            .get_user_accesstoken(
                                                                Id::Name(account_id.clone()),
                                                                vec!["b8066b99-6e67-41be-abfa-75db1a2c8809/.default".to_string()],
                                                                Some(DEFAULT_APP_ID.to_string())
                                                            ).await;

                                                        if let Some(graph_token) = graph_token {
                                                            if let Some(intune_token) = intune_token {
                                                                if let Some(iwservice_token) = iwservice_token {
                                                                    let (tx, rx) = oneshot::channel();

                                                                    match task_channel_tx
                                                                        .send_timeout(
                                                                            (
                                                                                TaskRequest::ApplyPolicy(
                                                                                    intune_device_id,
                                                                                    account_id.clone(),
                                                                                    graph_token
                                                                                        .access_token
                                                                                        .clone()
                                                                                        .unwrap_or("".to_string()),
                                                                                    intune_token
                                                                                        .access_token
                                                                                        .clone()
                                                                                        .unwrap_or("".to_string()),
                                                                                    iwservice_token
                                                                                        .access_token
                                                                                        .clone()
                                                                                        .unwrap_or("".to_string()),
                                                                                ),
                                                                                tx,
                                                                            ),
                                                                            Duration::from_millis(500),
                                                                        )
                                                                        .await
                                                                    {
                                                                        Ok(()) => {
                                                                            // Now wait for the other end OR timeout.
                                                                            match time::timeout_at(
                                                                                /* From the MS specs:
                                                                                 * Custom compliance discovery scripts for Microsoft Intune
                                                                                 * Limits:
                                                                                 * Scripts must have a limited run time:
                                                                                 *   On Linux, scripts must take five minutes or less to run.
                                                                                 */
                                                                                time::Instant::now()
                                                                                    + Duration::from_secs(
                                                                                        300,
                                                                                    ),
                                                                                rx,
                                                                            )
                                                                            .await
                                                                            {
                                                                                Ok(Ok(status)) => {
                                                                                    if status == 0 {
                                                                                        debug!("Successfully applied Intune policies");
                                                                                    } else {
                                                                                        warn!("Intune failure");
                                                                                    }
                                                                                }
                                                                                Ok(Err(e)) => {
                                                                                    warn!("Intune failure: {}", e);
                                                                                }
                                                                                Err(e) => {
                                                                                    warn!("Intune failure: {}", e);
                                                                                }
                                                                            }
                                                                        }
                                                                        Err(e) => {
                                                                            warn!("Intune failure: {}", e);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }

                                                    ClientResponse::PamAuthenticateStepResponse(resp)
                                                }
                                                _ => ClientResponse::PamAuthenticateStepResponse(resp),
                                            }
                                        }
                                        _ => ClientResponse::PamAuthenticateStepResponse(resp),
                                    }
                                }
                                other => other,
                            }
                        }
                        None => {
                            warn!("Attempt to continue auth session while current session is inactive");
                            ClientResponse::Error
                        }
                    }
                }
                .instrument(span)
                .await
            }
            ClientRequest::PamAccountAllowed(account_id) => {
                let account_id = account_id.to_lowercase();
                trace!("pam account allowed");
                cachelayer
                    .pam_account_allowed(account_id.as_str())
                    .await
                    .map(ClientResponse::PamStatus)
                    .unwrap_or(ClientResponse::Error)
            }
            ClientRequest::PamAccountBeginSession(account_id) => {
                let account_id = account_id.to_lowercase();
                let span = span!(Level::INFO, "pam account begin session");
                async {
                    trace!("pam account begin session");
                    match cachelayer
                        .pam_account_beginsession(account_id.as_str())
                        .await
                    {
                        Ok(Some(info)) => {
                            let (tx, rx) = oneshot::channel();

                            let resp1 = match task_channel_tx
                                .send_timeout(
                                    (TaskRequest::HomeDirectory(info), tx),
                                    Duration::from_millis(100),
                                )
                                .await
                            {
                                Ok(()) => {
                                    // Now wait for the other end OR timeout.
                                    match time::timeout_at(
                                        time::Instant::now() + Duration::from_millis(1000),
                                        rx,
                                    )
                                    .await
                                    {
                                        Ok(Ok(_)) => {
                                            trace!("Task completed, returning to pam ...");
                                            ClientResponse::Ok
                                        }
                                        _ => {
                                            // Timeout or other error.
                                            ClientResponse::Error
                                        }
                                    }
                                }
                                Err(_) => {
                                    // We could not submit the req. Move on!
                                    ClientResponse::Error
                                }
                            };

                            let (tx, rx) = oneshot::channel();

                            let sudo_groups = cfg.get_sudo_groups();
                            let mut is_sudoer: bool = false;

                            for sudo_group in sudo_groups {
                                let sudo_group_uuid = match Uuid::parse_str(&sudo_group) {
                                    Ok(uuid) => uuid,
                                    Err(e) => {
                                        debug!("Failed to parse a sudo group: {}", e);
                                        continue;
                                    }
                                };

                                let members = cachelayer.get_groupmembers(sudo_group_uuid).await;
                                if members.contains(&account_id) {
                                    is_sudoer = true;
                                }
                            }

                            let resp2 = match task_channel_tx
                                .send_timeout(
                                    (
                                        TaskRequest::LocalGroups(account_id.to_string(), is_sudoer),
                                        tx,
                                    ),
                                    Duration::from_millis(100),
                                )
                                .await
                            {
                                Ok(()) => {
                                    // Now wait for the other end OR timeout.
                                    match time::timeout_at(
                                        time::Instant::now() + Duration::from_millis(1000),
                                        rx,
                                    )
                                    .await
                                    {
                                        Ok(Ok(_)) => {
                                            trace!("Task completed, returning to pam ...");
                                            ClientResponse::Ok
                                        }
                                        _ => {
                                            // Timeout or other error.
                                            ClientResponse::Error
                                        }
                                    }
                                }
                                Err(_) => {
                                    // We could not submit the req. Move on!
                                    ClientResponse::Error
                                }
                            };

                            match resp1 {
                                ClientResponse::Error => ClientResponse::Error,
                                _ => resp2,
                            }
                        }
                        _ => ClientResponse::Error,
                    }
                }
                .instrument(span)
                .await
            }
            ClientRequest::PamChangeAuthToken(account_id, access_token, refresh_token, new_pin) => {
                let account_id = account_id.to_lowercase();
                let span = span!(Level::INFO, "sm_chauthtok req");
                async {
                    trace!("sm_chauthtok req");
                    let token = UnixUserToken {
                        token_type: "Bearer".to_string(),
                        scope: None,
                        expires_in: 0,
                        ext_expires_in: 0,
                        access_token: Some(access_token),
                        refresh_token,
                        id_token: IdToken::default(),
                        client_info: ClientInfo::default(),
                        prt: None,
                    };
                    cachelayer
                        .change_auth_token(&account_id, &token, &new_pin)
                        .await
                        .map(|_| ClientResponse::Ok)
                        .unwrap_or(ClientResponse::Error)
                }
                .instrument(span)
                .await
            }
            ClientRequest::InvalidateCache => {
                trace!("invalidate cache");
                cachelayer
                    .invalidate()
                    .await
                    .map(|_| ClientResponse::Ok)
                    .unwrap_or(ClientResponse::Error)
            }
            ClientRequest::ClearCache => {
                trace!("clear cache");
                if ucred.uid() == 0 {
                    cachelayer
                        .clear_cache()
                        .await
                        .map(|_| ClientResponse::Ok)
                        .unwrap_or(ClientResponse::Error)
                } else {
                    error!("Only root may clear the cache");
                    ClientResponse::Error
                }
            }
            ClientRequest::OfflineBreakGlass(ttl) => {
                trace!("offline break glass");
                if ucred.uid() == 0 {
                    cachelayer
                        .offline_break_glass(ttl)
                        .await
                        .map(|_| ClientResponse::Ok)
                        .unwrap_or(ClientResponse::Error)
                } else {
                    error!("Only root may set the offline break glass time to live");
                    ClientResponse::Error
                }
            }
            ClientRequest::Status => {
                trace!("status check");
                if cachelayer.test_connection().await {
                    ClientResponse::Ok
                } else {
                    ClientResponse::Error
                }
            }
        };
        reqs.send(resp).await?;
        reqs.flush().await?;
        trace!("flushed response!");
    }

    // Signal any tasks that they need to stop.
    if let Err(shutdown_err) = shutdown_tx.send(()) {
        warn!(
            ?shutdown_err,
            "Unable to signal tasks to stop, they will naturally timeout instead."
        )
    }

    // Disconnect them
    trace!("Disconnecting client ...");
    Ok(())
}

async fn process_etc_passwd_group(
    cachelayer: &Resolver<HimmelblauMultiProvider>,
) -> Result<(), Box<dyn Error>> {
    let mut file = File::open("/etc/passwd").await?;
    let mut contents = vec![];
    file.read_to_end(&mut contents).await?;

    let users = parse_etc_passwd(contents.as_slice()).map_err(|_| "Invalid passwd content")?;

    let mut file = File::open("/etc/group").await?;
    let mut contents = vec![];
    file.read_to_end(&mut contents).await?;

    let groups = parse_etc_group(contents.as_slice()).map_err(|_| "Invalid group content")?;

    let id_iter = users
        .iter()
        .map(|user| (user.name.clone(), user.uid))
        .chain(groups.iter().map(|group| (group.name.clone(), group.gid)));

    cachelayer.reload_nxset(id_iter).await;

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cuid = get_current_uid();
    let ceuid = get_effective_uid();
    let cgid = get_current_gid();
    let cegid = get_effective_gid();
    let systemd_booted = sd_notify::booted().unwrap_or(false);

    let clap_args = Command::new("himmelblaud")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Himmelblau Authentication Daemon")
        .arg(
            Arg::new("skip-root-check")
                .help("Allow running as root. Don't use this in production as it is risky!")
                .short('r')
                .long("skip-root-check")
                .env("HIMMELBLAU_SKIP_ROOT_CHECK")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("debug")
                .help("Show extra debug information")
                .short('d')
                .long("debug")
                .env("HIMMELBLAU_DEBUG")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("configtest")
                .help("Display the configuration and exit")
                .short('t')
                .long("configtest")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("config")
                .help("Set the config file path")
                .short('c')
                .long("config")
                .default_value(DEFAULT_CONFIG_PATH)
                .env("HIMMELBLAU_CONFIG")
                .action(ArgAction::Set),
        )
        .get_matches();

    if clap_args.get_flag("debug") {
        std::env::set_var("RUST_LOG", "debug");
    }
    let Some(cfg_path_str) = clap_args.get_one::<String>("config") else {
        error!("Failed to pull the config path");
        return ExitCode::FAILURE;
    };
    // Read the configuration
    let cfg = match HimmelblauConfig::new(Some(cfg_path_str)) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse {}: {}", cfg_path_str, e);
            return ExitCode::FAILURE;
        }
    };
    if cfg.get_debug() {
        std::env::set_var("RUST_LOG", "debug");
    }

    // https://docs.rs/console-subscriber/latest/console_subscriber/struct.Builder.html#method.with_default_env
    #[cfg(feature = "console")]
    let console_layer = console_subscriber::ConsoleLayer::builder()
        .with_default_env()
        .spawn();

    #[allow(clippy::expect_used)]
    tracing_forest::worker_task()
        .set_global(true)
        // Fall back to stderr
        .map_sender(|sender| sender.or_stderr())
        .build_on(|subscriber| {
           #[cfg(feature = "console")]
           let subscriber = subscriber
               .with(console_layer);

            subscriber
            .with(EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("info"))
                .expect("Failed to init envfilter")
            )
        })
        .on(async {
            let span = span!(Level::INFO, "initialisation");
            let _enter = span.enter();

            if clap_args.get_flag("skip-root-check") {
                warn!("Skipping root user check, if you're running this for testing, ensure you clean up temporary files.")
                // TODO: this wording is not great m'kay.
            } else if cuid == 0 || ceuid == 0 || cgid == 0 || cegid == 0 {
                error!("Refusing to run - this process must not operate as root.");
                return ExitCode::FAILURE
            };

            let cfg_path: PathBuf = PathBuf::from(cfg_path_str);

            if !cfg_path.exists() {
                // there's no point trying to start up if we can't read a usable config!
                error!(
                    "Client config missing from {} - cannot start up. Quitting.",
                    cfg_path_str
                );
                let diag = kanidm_lib_file_permissions::diagnose_path(cfg_path.as_ref());
                info!(%diag);
                return ExitCode::FAILURE
            } else {
                let cfg_meta = match metadata(&cfg_path) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Unable to read metadata for {} - {:?}", cfg_path_str, e);
                        let diag = kanidm_lib_file_permissions::diagnose_path(cfg_path.as_ref());
                        info!(%diag);
                        return ExitCode::FAILURE
                    }
                };
                if !kanidm_lib_file_permissions::readonly(&cfg_meta) {
                    warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                        cfg_path_str
                        );
                }

                if cfg_meta.uid() == cuid || cfg_meta.uid() == ceuid {
                    warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                        cfg_path_str
                    );
                }
            }

            if clap_args.get_flag("configtest") {
                eprintln!("###################################");
                eprintln!("Dumping configs:\n###################################");
                eprintln!("###################################");
                eprintln!("Config (from {:#?})", &cfg_path);
                eprintln!("{:?}", cfg);
                return ExitCode::SUCCESS;
            }

            let socket_path = cfg.get_socket_path();
            let task_socket_path = cfg.get_task_socket_path();
            let broker_socket_path = cfg.get_broker_socket_path();

            debug!("🧹 Cleaning up sockets from previous invocations");
            rm_if_exist(&socket_path);
            rm_if_exist(&task_socket_path);
            rm_if_exist(&broker_socket_path);


            // Check the db path will be okay.
            {
                let db_path = PathBuf::from(cfg.get_db_path());
                // We only need to check the parent folder path permissions as the db itself may not exist yet.
                if let Some(db_parent_path) = db_path.parent() {
                    if !db_parent_path.exists() {
                        error!(
                            "Refusing to run, DB folder {} does not exist",
                            db_parent_path
                                .to_str()
                                .unwrap_or("<db_parent_path invalid>")
                        );
                        let diag = kanidm_lib_file_permissions::diagnose_path(db_path.as_ref());
                        info!(%diag);
                        return ExitCode::FAILURE
                    }

                    let db_par_path_buf = db_parent_path.to_path_buf();

                    let i_meta = match metadata(&db_par_path_buf) {
                        Ok(v) => v,
                        Err(e) => {
                            error!(
                                "Unable to read metadata for {} - {:?}",
                                db_par_path_buf
                                    .to_str()
                                    .unwrap_or("<db_par_path_buf invalid>"),
                                e
                            );
                            return ExitCode::FAILURE
                        }
                    };

                    if !i_meta.is_dir() {
                        error!(
                            "Refusing to run - DB folder {} may not be a directory",
                            db_par_path_buf
                                .to_str()
                                .unwrap_or("<db_par_path_buf invalid>")
                        );
                        return ExitCode::FAILURE
                    }
                    if kanidm_lib_file_permissions::readonly(&i_meta) {
                        warn!("WARNING: DB folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!", db_par_path_buf.to_str()
                        .unwrap_or("<db_par_path_buf invalid>")
                        );
                    }

                    if i_meta.mode() & 0o007 != 0 {
                        warn!("WARNING: DB folder {} has 'everyone' permission bits in the mode. This could be a security risk ...", db_par_path_buf.to_str()
                        .unwrap_or("<db_par_path_buf invalid>")
                        );
                    }
                }

                // check to see if the db's already there
                if db_path.exists() {
                    if !db_path.is_file() {
                        error!(
                            "Refusing to run - DB path {} already exists and is not a file.",
                            db_path.to_str().unwrap_or("<db_path invalid>")
                        );
                        let diag = kanidm_lib_file_permissions::diagnose_path(db_path.as_ref());
                        info!(%diag);
                        return ExitCode::FAILURE
                    };

                    match metadata(&db_path) {
                        Ok(v) => v,
                        Err(e) => {
                            error!(
                                "Unable to read metadata for {} - {:?}",
                                db_path.to_str().unwrap_or("<db_path invalid>"),
                                e
                            );
                            let diag = kanidm_lib_file_permissions::diagnose_path(db_path.as_ref());
                            info!(%diag);
                            return ExitCode::FAILURE
                        }
                    };
                    // TODO: permissions dance to enumerate the user's ability to write to the file? ref #456 - r2d2 will happily keep trying to do things without bailing.
                };
            }

            // Create the database
            let db = match Db::new(&cfg.get_db_path()) {
                Ok(db) => db,
                Err(_e) => {
                    error!("Failed to create database");
                    return ExitCode::FAILURE
                }
            };

            // perform any db migrations.
            let mut dbtxn = db.write().await;
            if dbtxn.migrate()
                .and_then(|_| {
                    dbtxn.commit()
                }).is_err() {
                    error!("Failed to migrate database");
                    return ExitCode::FAILURE
                }

            let (auth_value, mut hsm) = tpm_init!(cfg, return ExitCode::FAILURE);

            // With the assistance of the DB, setup the HSM and its machine key.

            let loadable_machine_key = tpm_loadable_machine_key!(
                db,
                hsm,
                auth_value,
                true,
                // on_error
                return ExitCode::FAILURE
            );

            let machine_key = tpm_machine_key!(
                hsm,
                auth_value,
                loadable_machine_key,
                cfg,
                // on_error
                return ExitCode::FAILURE
            );

            // Okay, the hsm is now loaded and ready to go.

            // Create the identify provider connection
            let mut keystore = db.write().await;
            let idprovider = match HimmelblauMultiProvider::new(cfg.get_config_file().as_str(), &mut keystore).await {
                Ok(idprovider) => idprovider,
                Err(e) => {
                    error!("{}", e);
                    return ExitCode::FAILURE;
                }
            };
            if let Err(err) = keystore.commit() {
                error!(?err, "Failed to commit database transaction, unable to proceed");
                return ExitCode::FAILURE
            }

            // Setup the tasks socket first.
            let (task_channel_tx, mut task_channel_rx) = channel(16);
            let task_channel_tx = Arc::new(task_channel_tx);

            let task_channel_tx_cln = task_channel_tx.clone();

            let user_map = UserMap::new(&cfg.get_user_map_file());
            let cl_inner = match Resolver::new(
                db,
                idprovider,
                hsm,
                machine_key,
                cfg.get_cache_timeout(),
                cfg.get_pam_allow_groups(),
                cfg.get_shell(None),
                cfg.get_home_prefix(None),
                cfg.get_home_attr(None),
                cfg.get_home_alias(None),
                UidAttr::Name,
                UidAttr::Name,
                user_map.get_id_overrides(),
            )
            .await
            {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to build cache layer.");
                    return ExitCode::FAILURE
                }
            };

            let cachelayer = Arc::new(cl_inner);

            // Setup the root-only socket. Take away all other access bits.
            let before = unsafe { umask(0o0077) };
            let task_listener = match UnixListener::bind(task_socket_path.clone()) {
                Ok(l) => l,
                Err(_e) => {
                    error!("Failed to bind UNIX socket {}", task_socket_path);
                    return ExitCode::FAILURE
                }
            };
            // Undo umask changes.
            let _ = unsafe { umask(before) };

            // Pre-process /etc/passwd and /etc/group for nxset
            if process_etc_passwd_group(&cachelayer).await.is_err() {
                error!("Failed to process system id providers");
                return ExitCode::FAILURE
            }

            // Start to build the worker tasks
            let (broadcast_tx, mut broadcast_rx) = broadcast::channel(4);
            let mut c_broadcast_rx = broadcast_tx.subscribe();
            let mut d_broadcast_rx = broadcast_tx.subscribe();

            let task_b = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = c_broadcast_rx.recv() => {
                            break;
                        }
                        accept_res = task_listener.accept() => {
                            match accept_res {
                                Ok((socket, _addr)) => {
                                    // Did it come from root?
                                    if let Ok(ucred) = socket.peer_cred() {
                                        if ucred.uid() != 0 {
                                            // move along.
                                            warn!("Task handler not running as root, ignoring ...");
                                            continue;
                                        }
                                    } else {
                                        // move along.
                                        warn!("Unable to determine socked peer cred, ignoring ...");
                                        continue;
                                    };
                                    debug!("A task handler has connected.");
                                    // It did? Great, now we can wait and spin on that one
                                    // client.

                                    tokio::select! {
                                        _ = d_broadcast_rx.recv() => {
                                            break;
                                        }
                                        // We have to check for signals here else this tasks waits forever.
                                        Err(e) = handle_task_client(socket, &task_channel_tx, &mut task_channel_rx) => {
                                            error!("Task client error occurred; error = {:?}", e);
                                        }
                                    }
                                    // If they DC we go back to accept.
                                }
                                Err(err) => {
                                    error!("Task Accept error -> {:?}", err);
                                }
                            }
                        }
                    }
                    // done
                }
                info!("Stopped task connector");
            });

            // TODO: Setup a task that handles pre-fetching here.

            let (inotify_tx, mut inotify_rx) = channel(4);

            #[allow(clippy::blocks_in_conditions)]
            let watcher =
            match new_debouncer(Duration::from_secs(5), None, move |_event| {
                let _ = inotify_tx.try_send(true);
            })
                .and_then(|mut debouncer| {
                    debouncer.watch(Path::new("/etc/passwd"), RecursiveMode::NonRecursive)
                        .map(|()| debouncer)
                })
                .and_then(|mut debouncer| debouncer.watch(Path::new("/etc/group"), RecursiveMode::NonRecursive)
                        .map(|()| debouncer)
                )

            {
                Ok(watcher) => {
                    watcher
                }
                Err(e) => {
                    error!("Failed to setup inotify {:?}",  e);
                    return ExitCode::FAILURE
                }
            };

            let mut c_broadcast_rx = broadcast_tx.subscribe();

            let inotify_cachelayer = cachelayer.clone();
            let task_c = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = c_broadcast_rx.recv() => {
                            break;
                        }
                        _ = inotify_rx.recv() => {
                            if process_etc_passwd_group(&inotify_cachelayer).await.is_err() {
                                error!("Failed to process system id providers");
                            }
                        }
                    }
                }
                info!("Stopped inotify watcher");
            });

            // Spawn the himmelblau dbus broker
            let dbus_cachelayer = cachelayer.clone();
            let e_broadcast_rx = broadcast_tx.subscribe();
            let task_d = match himmelblau_broker_serve::<Broker>(
                Broker { cachelayer: dbus_cachelayer },
                &broker_socket_path,
                e_broadcast_rx
            ).await {
                Ok(task_d) => task_d,
                Err(e) => {
                    error!("D-Bus error occurred; error = {:?}", e);
                    return ExitCode::FAILURE
                },
            };

            // Set the umask while we open the path for most clients.
            let before = unsafe { umask(0) };
            let listener = match UnixListener::bind(socket_path.clone()) {
                Ok(l) => l,
                Err(_e) => {
                    error!("Failed to bind UNIX socket at {}", socket_path);
                    return ExitCode::FAILURE
                }
            };
            // Undo umask changes.
            let _ = unsafe { umask(before) };

            let task_a = tokio::spawn(async move {
                loop {
                    let tc_tx = task_channel_tx_cln.clone();
                    let cfg_h = cfg.clone();

                    tokio::select! {
                        _ = broadcast_rx.recv() => {
                            break;
                        }
                        accept_res = listener.accept() => {
                            match accept_res {
                                Ok((socket, _addr)) => {
                                    let cachelayer_ref = cachelayer.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_client(socket, cachelayer_ref.clone(), &tc_tx, cfg_h).await
                                        {
                                            error!("handle_client error occurred; error = {:?}", e);
                                        }
                                    });
                                }
                                Err(err) => {
                                    error!("Error while handling connection -> {:?}", err);
                                }
                            }
                        }
                    }

                }
                info!("Stopped resolver");
            });

            info!("Server started ...");

            if systemd_booted {
                if let Ok(monotonic_usec) = sd_notify::NotifyState::monotonic_usec_now() {
                    let _ = sd_notify::notify(true, &[NotifyState::Ready, monotonic_usec]);
                }
            }

            drop(_enter);

            loop {
                tokio::select! {
                    Ok(()) = tokio::signal::ctrl_c() => {
                        break
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::terminate();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        break
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::alarm();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::hangup();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::user_defined1();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::user_defined2();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                }
            }

            info!("Signal received, sending down signal to tasks");
            if systemd_booted {
                if let Ok(monotonic_usec) = sd_notify::NotifyState::monotonic_usec_now() {
                    let _ = sd_notify::notify(true, &[NotifyState::Stopping, monotonic_usec]);
                }
            }

            // Send a broadcast that we are done.
            if let Err(e) = broadcast_tx.send(true) {
                error!("Unable to shutdown workers {:?}", e);
            }

            drop(watcher);

            let _ = task_a.await;
            let _ = task_b.await;
            let _ = task_c.await;
            let _ = task_d.await;

            ExitCode::SUCCESS
    })
    .await
    // TODO: can we catch signals to clean up sockets etc, especially handy when running as root
}
