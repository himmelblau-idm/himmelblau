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
use std::io;
use std::process::ExitCode;
use std::sync::Arc;
use std::fs::{set_permissions, Permissions};
use std::os::unix::fs::PermissionsExt;

use bytes::{BufMut, BytesMut};
use clap::{Arg, ArgAction, Command};

use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use himmelblau_unix_common::constants::DEFAULT_SOCK_PATH;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse, NssUser, NssGroup};
use himmelblau_unix_common::config::{HimmelblauConfig, split_username};
use himmelblau_unix_common::memcache::{HimmelblauMemcache, UserCacheEntry};
use msal::authentication::{PublicClientApplication, REQUIRES_MFA, NO_CONSENT, NO_SECRET};
use msal::misc::{request_user_groups, DirectoryObject};
use futures::{SinkExt, StreamExt};

use std::path::{Path};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio_util::codec::{Decoder, Encoder, Framed};

use log::{warn, error, debug, info, LevelFilter};
use systemd_journal_logger::JournalLog;

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

struct ClientCodec;

impl Decoder for ClientCodec {
    type Error = io::Error;
    type Item = ClientRequest;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
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
        debug!("Attempting to send response -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

impl ClientCodec {
    fn new() -> Self {
        ClientCodec
    }
}

fn nss_account_from_cache(config: Arc<HimmelblauConfig>, user_entry: &UserCacheEntry) -> NssUser {
    let account_id: &str = user_entry.get("user_principal_name")
        .expect("Failed fetching user_principal_name");
    let (sam, domain) = split_username(account_id)
        .expect("Failed splitting the username");
    let uid: u32 = user_entry.get_uid();
    let name: String = user_entry.get("display_name")
        .expect("Failed fetching gecos").to_string();
    NssUser {
        homedir: config.get_homedir(account_id, uid, sam, domain),
        name: account_id.to_string(),
        uid: uid,
        gid: uid,
        gecos: name.to_string(),
        shell: config.get_shell(domain),
    }
}

fn nss_group_from_cache(account_id: &str, gid: u32, members: Vec<String>) -> NssGroup {
    NssGroup {
        name: account_id.to_string(),
        gid,
        members: members,
    }
}

async fn handle_client(
    sock: UnixStream,
    cmem_cache: Arc<Mutex<HimmelblauMemcache>>,
) -> Result<(), Box<dyn Error>> {
    debug!("Accepted connection");

    let mut reqs = Framed::new(sock, ClientCodec::new());

    // Read the configuration
    let cconfig = Arc::new(HimmelblauConfig::new(DEFAULT_CONFIG_PATH)
        .expect("Failed loading configuration"));

    while let Some(Ok(req)) = reqs.next().await {
        let resp = match req {
            ClientRequest::PamAuthenticate(account_id, cred) => {
                debug!("pam authenticate");
                let (_sam, domain) = split_username(&account_id)
                    .expect("Failed splitting the username");
                let config = Arc::clone(&cconfig);
                let (_tenant_id, authority_url, graph) = config.get_authority_url(domain).await;
                let app_id = config.get_app_id(domain);
                let app = PublicClientApplication::new(&app_id, authority_url.as_str());
                let (mut token, mut err) = app.acquire_token_by_username_password(account_id.as_str(), cred.as_str(), vec!["GroupMember.Read.All"]);
                // We may have been denied GroupMember.Read.All, try again without it
                if err.contains(&NO_CONSENT) {
                    (token, err) = app.acquire_token_by_username_password(account_id.as_str(), cred.as_str(), vec![]);
                }
                ClientResponse::PamStatus(
                    if token.contains_key("access_token") {
                        info!("Authentication successful for user '{}'", account_id);
                        let mut mem_cache = cmem_cache.lock().await;
                        let name_def = "".to_string();
                        let name = match token.get("name") {
                            Some(name) => name,
                            None => &name_def,
                        };
                        match token.get("local_account_id") {
                            Some(oid) => {
                                let access_token = token.get("access_token")
                                    .expect("Failed addressing access_token after confirmed presence");
                                mem_cache.insert_user(&config, &account_id, access_token, oid, name);
                                let groups: Vec<DirectoryObject> = match request_user_groups(&graph, access_token).await
                                {
                                    Ok(groups) => groups,
                                    Err(_e) => {
                                        debug!("Failed fetching user groups for {}", account_id);
                                        vec![]
                                    },
                                };
                                mem_cache.insert_user_groups(&config, domain, groups, &account_id);
                            },
                            None => {
                                warn!("Failed caching user {}", account_id);
                            },
                        };
                        Some(true)
                    } else {
                        if err.contains(&REQUIRES_MFA) {
                            info!("Azure AD application requires MFA");
                            //TODO: Attempt an interactive auth via the browser
                        }
                        if err.contains(&NO_CONSENT) {
                            let url = format!("{}/adminconsent?client_id={}", authority_url, app_id);
                            error!("Azure AD application requires consent, either from tenant, or from user, go to: {}", url);
                        }
                        if err.contains(&NO_SECRET) {
                            let url = "https://learn.microsoft.com/en-us/azure/active-directory/develop/scenario-desktop-app-registration#redirect-uris";
                            error!("Azure AD application requires enabling 'Allow public client flows'. {}",
                                   url);
                        }
                        error!("{}: {}",
                               token.get("error")
                               .expect("Failed fetching error code"),
                               token.get("error_description")
                               .expect("Failed fetching error description"));
                        Some(false)
                    }
                )
            }
            ClientRequest::PamAccountAllowed(_account_id) => {
                debug!("pam account allowed");
                // TODO: How to determine if user is allowed logon?
                ClientResponse::PamStatus(Some(true))
            }
            ClientRequest::PamAccountBeginSession(_account_id) => {
                debug!("pam account begin session");
                ClientResponse::PamStatus(Some(true))
            }
            ClientRequest::NssAccounts => {
                debug!("nssaccounts req");
                let mem_cache = cmem_cache.lock().await;
                let resp = ClientResponse::NssAccounts(mem_cache.user_iter()
                    .map(|(_, user_entry)| {
                        let config = Arc::clone(&cconfig);
                        nss_account_from_cache(config, user_entry)
                    }).collect()
                );
                resp
            }
            ClientRequest::NssAccountByName(account_id) => {
                debug!("nssaccountbyname req");
                let mem_cache = cmem_cache.lock().await;
                match mem_cache.get_user(&account_id) {
                    Some(user_entry) => {
                        let config = Arc::clone(&cconfig);
                        ClientResponse::NssAccount(Some(nss_account_from_cache(config, user_entry)))
                    },
                    None => {
                        debug!("Failed to find account '{}'", account_id);
                        ClientResponse::NssAccount(None)
                    }
                }
            }
            ClientRequest::NssAccountByUid(uid) => {
                let mem_cache = cmem_cache.lock().await;
                let resp = match mem_cache.user_iter().find(|(_, user_entry)| user_entry.get_uid() == uid) {
                    Some((_, user_entry)) => {
                        let config = Arc::clone(&cconfig);
                        ClientResponse::NssAccount(Some(nss_account_from_cache(config, user_entry)))
                    },
                    None => {
                        debug!("Failed to find account '{}'", uid);
                        ClientResponse::NssAccount(None)
                    }
                }; resp
            }
            ClientRequest::NssGroups => {
                debug!("nssgroups req");
                // Generate a group for each user (with matching gid)
                let mem_cache = cmem_cache.lock().await;
                let mut resp: Vec<NssGroup> = mem_cache.user_iter()
                    .map(|(account_id, user_entry)| {
                        nss_group_from_cache(account_id, user_entry.get_uid(), vec![account_id.to_string()])
                    }).collect();
                resp.extend(
                    // Extend the list from the cache of group memberships
                    mem_cache.group_iter()
                        .map(|(_, group_entry)| {
                            let members: Vec<String> = group_entry.iter_members()
                                .map(|member| member.to_owned()).collect();
                            let display_name = group_entry.get("display_name")
                                    .expect("Failed fetching display_name");
                            nss_group_from_cache(display_name, group_entry.get_gid(), members)
                        }).collect::<Vec<NssGroup>>()
                );
                ClientResponse::NssGroups(resp)
            }
            ClientRequest::NssGroupByName(grp_id) => {
                debug!("nssgroupbyname req");
                // Generate a group that maches the user
                let mem_cache = cmem_cache.lock().await;
                match mem_cache.get_user(&grp_id) {
                    Some(user_entry) => {
                        ClientResponse::NssGroup(Some(nss_group_from_cache(&grp_id, user_entry.get_uid(), vec![grp_id.to_string()])))
                    },
                    None => {
                        // Also check the cache of group memberships
                        match mem_cache.group_iter().find(|(_, group_entry)| *group_entry.get("display_name").unwrap() == grp_id) {
                            Some((_, group_entry)) => {
                                let members: Vec<String> = group_entry.iter_members()
                                    .map(|member| member.to_owned()).collect();
                                let gid: u32 = group_entry.get_gid();
                                let display_name = group_entry.get("display_name")
                                    .expect("Failed fetching display_name");
                                ClientResponse::NssGroup(Some(nss_group_from_cache(display_name, gid, members)))
                            },
                            None => {
                                debug!("Failed to find group '{}'", grp_id);
                                ClientResponse::NssGroup(None)
                            }
                        }
                    }
                }
            }
            ClientRequest::NssGroupByGid(gid) => {
                // Generate a group that maches the user
                let mem_cache = cmem_cache.lock().await;
                let resp = match mem_cache.user_iter().find(|(_, user_entry)| user_entry.get_uid() == gid) {
                    Some((grp_id, _user_entry)) => {
                        ClientResponse::NssGroup(Some(nss_group_from_cache(&grp_id, gid, vec![grp_id.to_string()])))
                    },
                    None => {
                        // Also check the cache of group memberships
                        match mem_cache.group_iter().find(|(_, group_entry)| group_entry.get_gid() == gid) {
                            Some((_, group_entry)) => {
                                let members: Vec<String> = group_entry.iter_members()
                                    .map(|member| member.to_owned()).collect();
                                let display_name = group_entry.get("display_name")
                                    .expect("Failed fetching display_name");
                                ClientResponse::NssGroup(Some(nss_group_from_cache(display_name, gid, members)))
                            },
                            None => {
                                debug!("Failed to find group '{}'", gid);
                                ClientResponse::NssGroup(None)
                            }
                        }
                    }
                }; resp
            }
        };
        reqs.send(resp).await?;
        reqs.flush().await?;
        debug!("flushed response!");
    }

    // Disconnect them
    debug!("Disconnecting client ...");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let clap_args = Command::new("himmelblaud")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Himmelblau Authentication Daemon")
        .arg(
            Arg::new("debug")
                .help("Show extra debug information")
                .short('d')
                .long("debug")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    JournalLog::default().install().unwrap();
    if clap_args.get_flag("debug") {
        log::set_max_level(LevelFilter::Debug);
    }

    async {
        // Read the configuration
        let config = match HimmelblauConfig::new(DEFAULT_CONFIG_PATH) {
            Ok(c) => c,
            Err(e) => {
                error!("{}", e);
                return ExitCode::FAILURE
            }
        };

        let socket_path = match config.get("global", "socket_path") {
            Some(val) => String::from(val),
            None => {
                debug!("Using default socket path {}", DEFAULT_SOCK_PATH);
                String::from(DEFAULT_SOCK_PATH)
            }
        };
        debug!("🧹 Cleaning up socket from previous invocations");
        rm_if_exist(&socket_path);

        let mem_cache = Arc::new(Mutex::new(HimmelblauMemcache::new()));

        // Open the socket for all to read and write
        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(_e) => {
                error!("Failed to bind UNIX socket at {}", &socket_path);
                return ExitCode::FAILURE
            }
        };
        set_permissions(&socket_path, Permissions::from_mode(0o777))
            .expect(format!("Failed to set permissions for {}", &socket_path).as_str());

        let server = async move {
            loop {
                let cmem_cache = mem_cache.clone();
                match listener.accept().await {
                    Ok((socket, _addr)) => {
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(socket, cmem_cache).await
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
        };

        info!("Server started ...");

        server.await;
        ExitCode::SUCCESS
    }
    .await
}
