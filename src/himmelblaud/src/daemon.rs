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
use std::collections::HashMap;

use bytes::{BufMut, BytesMut};
use clap::{Arg, ArgAction, Command};

use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use himmelblau_unix_common::constants::DEFAULT_SOCK_PATH;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse, NssUser, NssGroup};
use himmelblau_unix_common::config::{HimmelblauConfig, split_username};
use msal::authentication::{PublicClientApplication, REQUIRES_MFA, NO_CONSENT, NO_SECRET};
use futures::{SinkExt, StreamExt};

use std::path::{Path};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio_util::codec::{Decoder, Encoder, Framed};

use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand::SeedableRng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

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

fn gen_unique_account_uid(config: &Arc<HimmelblauConfig>, domain: &str, oid: &str) -> u32 {
    let mut hash = DefaultHasher::new();
    oid.hash(&mut hash);
    let seed = hash.finish();
    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    let (min, max): (u32, u32) = config.get_idmap_range(domain);
    rng.gen_range(min..=max)
}

fn nss_account_from_cache(config: Arc<HimmelblauConfig>, account_id: &str, oid: &str, name: &str) -> NssUser {
    let (sam, domain) = split_username(account_id)
        .expect("Failed splitting the username");
    let uid: u32 = gen_unique_account_uid(&config, domain, oid);
    NssUser {
        homedir: config.get_homedir(account_id, uid, sam, domain),
        name: account_id.to_string(),
        uid: uid,
        gid: uid,
        gecos: name.to_string(),
        shell: config.get_shell(domain),
    }
}

fn nss_group_from_cache(config: Arc<HimmelblauConfig>, account_id: &str, oid: &str) -> NssGroup {
    let (_sam, domain) = split_username(account_id)
        .expect("Failed splitting the username");
    let gid: u32 = gen_unique_account_uid(&config, domain, oid);
    NssGroup {
        name: account_id.to_string(),
        gid,
        members: vec![account_id.to_string()],
    }
}

async fn handle_client(
    sock: UnixStream,
    cmem_cache: Arc<Mutex<HashMap<String, (String, String)>>>,
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
                let (_tenant_id, authority_url) = config.get_authority_url(domain, None)
                    .expect("The tenant id was not set in the configuration");
                let app_id = config.get_app_id(domain);
                let app = PublicClientApplication::new(&app_id, authority_url.as_str());
                let (token, err) = app.acquire_token_by_username_password(account_id.as_str(), cred.as_str(), vec![]);
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
                            Some(oid) => mem_cache.insert(account_id, (oid.to_string(), name.to_string())),
                            None => {
                                warn!("Failed caching user {}", account_id);
                                None
                            }
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
            ClientRequest::NssAccounts => {
                debug!("nssaccounts req");
                let mem_cache = cmem_cache.lock().await;
                let resp = ClientResponse::NssAccounts(mem_cache.iter()
                    .map(|(account_id, (oid, name))| {
                        let config = Arc::clone(&cconfig);
                        nss_account_from_cache(config, account_id, oid, name)
                    }).collect()
                );
                resp
            }
            ClientRequest::NssAccountByName(account_id) => {
                debug!("nssaccountbyname req");
                let mem_cache = cmem_cache.lock().await;
                match mem_cache.get(account_id.to_string().as_str()) {
                    Some((oid, name)) => {
                        let config = Arc::clone(&cconfig);
                        ClientResponse::NssAccount(Some(nss_account_from_cache(config, &account_id, &oid, &name)))
                    },
                    None => ClientResponse::NssAccount(None),
                }
            }
            ClientRequest::NssGroups => {
                debug!("nssgroups req");
                // Generate a group for each user (with matching gid)
                let mem_cache = cmem_cache.lock().await;
                let resp = ClientResponse::NssGroups(mem_cache.iter()
                    .map(|(account_id, (oid, _name))| {
                        let config = Arc::clone(&cconfig);
                        nss_group_from_cache(config, account_id, oid)
                    }).collect()
                );
                resp
            }
            ClientRequest::NssGroupByName(grp_id) => {
                debug!("nssgroupbyname req");
                // Generate a group that maches the user
                let mem_cache = cmem_cache.lock().await;
                match mem_cache.get(grp_id.to_string().as_str()) {
                    Some((oid, _name)) => {
                        let config = Arc::clone(&cconfig);
                        ClientResponse::NssGroup(Some(nss_group_from_cache(config, &grp_id, &oid)))
                    },
                    None => ClientResponse::NssGroup(None),
                }
            }
            _ => todo!()
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

        let mem_cache = Arc::new(Mutex::new(HashMap::new()));

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
