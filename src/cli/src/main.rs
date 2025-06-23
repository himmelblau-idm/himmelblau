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

#[macro_use]
extern crate tracing;

use std::process::ExitCode;

use broker_client::BrokerClient;
use clap::Parser;
use himmelblau::{error::MsalError, graph::Graph, AuthOption, BrokerClientApplication};
use himmelblau_unix_common::auth_handle_mfa_resp;
use himmelblau_unix_common::client::call_daemon;
use himmelblau_unix_common::client_sync::DaemonClientBlocking;
use himmelblau_unix_common::config::{split_username, HimmelblauConfig};
use himmelblau_unix_common::constants::{DEFAULT_CONFIG_PATH, DEFAULT_ODC_PROVIDER, ID_MAP_CACHE};
use himmelblau_unix_common::db::{Cache, CacheTxn, Db, KeyStoreTxn};
use himmelblau_unix_common::idmap_cache::{StaticGroup, StaticIdCache, StaticUser};
use himmelblau_unix_common::tpm_init;
use himmelblau_unix_common::unix_proto::{
    ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse,
};
use himmelblau_unix_common::{tpm_loadable_machine_key, tpm_machine_key};
use kanidm_hsm_crypto::{
    soft::SoftTpm, BoxedDynTpm, LoadableIdentityKey, LoadableMsOapxbcRsaKey, Tpm,
};
use rpassword::{prompt_password, read_password};
use serde::Deserialize;
use serde_json::{json, to_string_pretty, Value};
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use uuid::Uuid;

include!("./opt/tool.rs");

mod graph;
use crate::graph::CliGraph;

#[derive(Debug, Deserialize)]
struct Accounts {
    accounts: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct Account {
    username: String,
}

#[derive(Debug, Deserialize)]
struct BrokerTokenResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct Token {
    #[serde(rename = "brokerTokenResponse")]
    response: BrokerTokenResponse,
}

fn insert_module_line(
    pam_file: &str,
    module_line: &str,
    after_pred: Option<&dyn Fn(&str) -> bool>,
    before_pred: Option<&dyn Fn(&str) -> bool>,
    dry_run: bool,
) -> anyhow::Result<()> {
    let original = std::fs::read_to_string(pam_file)?;
    let mut lines: Vec<String> = original.lines().map(|l| l.to_string()).collect();

    if lines.iter().any(|l| l.contains("pam_himmelblau.so")) {
        debug!("{} already contains pam_himmelblau; skipping", pam_file);
        return Ok(());
    }

    let mut insert_index = None;

    if let Some(before) = before_pred {
        for (i, line) in lines.iter().enumerate() {
            if before(line) {
                insert_index = Some(i);
                break;
            }
        }
    }

    // Only search for after if we didn't find a before
    if insert_index.is_none() {
        if let Some(after) = after_pred {
            for (i, line) in lines.iter().enumerate().rev() {
                if after(line) {
                    insert_index = Some(i + 1);
                    break;
                }
            }
        }
    }

    // Default to end
    let insert_index = insert_index.unwrap_or(lines.len());
    lines.insert(insert_index, module_line.to_string());

    if dry_run {
        println!("[{}] (dry run):", pam_file);
        for line in &lines {
            println!("{}", line);
        }
    } else {
        std::fs::write(pam_file, lines.join("\n") + "\n")?;
        info!("Modified {}", pam_file);
    }

    Ok(())
}

fn configure_pam(
    dry_run: bool,
    auth_file: Option<&str>,
    account_file: Option<&str>,
    session_file: Option<&str>,
    password_file: Option<&str>,
) -> anyhow::Result<()> {
    let auth_file = auth_file.unwrap_or("/etc/pam.d/common-auth");
    let account_file = account_file.unwrap_or("/etc/pam.d/common-account");
    let session_file = session_file.unwrap_or("/etc/pam.d/common-session");
    let password_file = password_file.unwrap_or("/etc/pam.d/common-password");

    insert_module_line(
        auth_file,
        "auth\tsufficient\tpam_himmelblau.so ignore_unknown_user",
        Some(&|l: &str| l.contains("pam_localuser.so")),
        Some(&|l: &str| l.contains("pam_unix.so") && l.contains("auth")),
        dry_run,
    )?;

    insert_module_line(
        account_file,
        "account\tsufficient\tpam_himmelblau.so ignore_unknown_user",
        None,
        Some(&|l: &str| l.contains("pam_unix.so") && l.contains("account")),
        dry_run,
    )?;

    insert_module_line(
        session_file,
        "session\toptional\tpam_himmelblau.so",
        None,
        None,
        dry_run,
    )?;

    insert_module_line(
        password_file,
        "password\tsufficient\tpam_himmelblau.so ignore_unknown_user",
        None,
        Some(&|l: &str| {
            l.contains("pam_unix.so") && l.contains("password")
                || l.contains("pam_cracklib.so") && l.contains("password")
                || l.contains("pam_pwquality.so") && l.contains("password")
        }),
        dry_run,
    )?;

    Ok(())
}

macro_rules! match_sm_auth_client_response {
    ($expr:expr, $req:ident, $hello_pin_min_length:ident, $($pat:pat => $result:expr),*) => {
        match $expr {
            Ok(r) => match r {
                $($pat => $result),*
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Success) => {
                    println!("auth success!");
                    break;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Denied(msg)) => {
                    println!("auth failed: {}", msg);
                    break;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Unknown) => {
                    println!("auth user unknown");
                    break;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::SetupPin {
                    msg,
                }) => {
                    println!("{}", msg);

                    let mut pin;
                    let mut confirm;
                    loop {
                        pin = match prompt_password("New PIN: ") {
                            Ok(password) => {
                                if password.len() < $hello_pin_min_length {
                                    println!("Chosen pin is too short! {} chars required.", $hello_pin_min_length);
                                    continue;
                                }
                                password
                            },
                            Err(err) => {
                                println!("unable to get pin: {:?}", err);
                                return ExitCode::FAILURE;
                            }
                        };

                        confirm = match prompt_password("Confirm PIN: ") {
                            Ok(password) => password,
                            Err(err) => {
                                println!("unable to get confirmation pin: {:?}", err);
                                return ExitCode::FAILURE;
                            }
                        };

                        if pin == confirm {
                            break;
                        } else {
                            println!("Inputs did not match. Try again.");
                        }
                    }

                    // Now setup the request for the next loop.
                    $req = ClientRequest::PamAuthenticateStep(PamAuthRequest::SetupPin {
                        pin,
                    });
                    continue;
                },
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Pin) => {
                    let cred = match prompt_password("PIN: ") {
                        Ok(password) => password,
                        Err(err) => {
                            debug!("unable to get pin: {:?}", err);
                            return ExitCode::FAILURE;
                        }
                    };

                    // Now setup the request for the next loop.
                    $req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Pin { cred });
                    continue;
                }
                _ => {
                    // unexpected response.
                    error!("Error: unexpected response -> {:?}", r);
                    break;
                }
            },
            Err(e) => {
                error!("Error -> {:?}", e);
                break;
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let opt = HimmelblauUnixParser::parse();

    let debug = match opt.commands {
        HimmelblauUnixOpt::Application(ApplicationOpt::List {
            debug,
            account_id: _,
            client_id: _,
        }) => debug,
        HimmelblauUnixOpt::Application(ApplicationOpt::Create {
            debug,
            account_id: _,
            client_id: _,
            display_name: _,
        }) => debug,
        HimmelblauUnixOpt::AuthTest {
            debug,
            account_id: _,
        } => debug,
        HimmelblauUnixOpt::CacheClear { debug, really: _ } => debug,
        HimmelblauUnixOpt::CacheInvalidate { debug } => debug,
        HimmelblauUnixOpt::ConfigurePam {
            debug,
            really: _,
            auth_file: _,
            account_file: _,
            session_file: _,
            password_file: _,
        } => debug,
        HimmelblauUnixOpt::Enumerate {
            debug,
            account_id: _,
            client_id: _,
        } => debug,
        HimmelblauUnixOpt::Idmap(IdmapOpt::UserAdd {
            debug,
            account_id: _,
            uid: _,
            gid: _,
        }) => debug,
        HimmelblauUnixOpt::Idmap(IdmapOpt::GroupAdd {
            debug,
            account_id: _,
            gid: _,
        }) => debug,
        HimmelblauUnixOpt::Status { debug } => debug,
        HimmelblauUnixOpt::Version { debug } => debug,
    };

    if debug {
        std::env::set_var("RUST_LOG", "debug");
    }
    sketching::tracing_subscriber::fmt::init();

    macro_rules! init {
        ($cfg:expr, $account_id:expr) => {{
            let (_, domain) = match split_username(&$account_id) {
                Some(out) => out,
                None => {
                    error!("Could not split domain from input username");
                    return ExitCode::FAILURE;
                }
            };

            let graph = match Graph::new(DEFAULT_ODC_PROVIDER, &domain, None, None, None).await {
                Ok(graph) => graph,
                Err(e) => {
                    error!("Failed discovering tenant: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            let tenant_id = match $cfg.get_tenant_id(domain) {
                Some(tenant_id) => tenant_id,
                None => "common".to_string(),
            };
            let authority = format!("https://{}/{}", $cfg.get_authority_host(domain), tenant_id);

            (graph, domain, authority)
        }};
    }

    macro_rules! obtain_host_data {
        ($domain:expr, $cfg:ident) => {{
            let (auth_value, mut tpm) = tpm_init!($cfg);

            let db = match Db::new(&$cfg.get_db_path()) {
                Ok(db) => db,
                Err(e) => {
                    error!("Failed loading Himmelblau cache: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            // Fetch the machine key
            let loadable_machine_key = tpm_loadable_machine_key!(
                db,
                tpm,
                auth_value,
                false,
                // on_error
                return ExitCode::FAILURE
            );
            let machine_key = tpm_machine_key!(
                tpm,
                auth_value,
                loadable_machine_key,
                $cfg,
                // on_error
                return ExitCode::FAILURE
            );

            let mut db_txn = db.write().await;

            // Fetch the transport key
            let tranport_key_tag = format!("{}/transport", $domain);
            let loadable_transport_key: LoadableMsOapxbcRsaKey =
                match db_txn.get_tagged_hsm_key(&tranport_key_tag) {
                    Ok(Some(ltk)) => ltk,
                    Err(e) => {
                        error!("Unable to access hsm loadable transport key: {:?}", e);
                        return ExitCode::FAILURE;
                    }
                    _ => {
                        error!("Unable to access hsm loadable transport key.");
                        return ExitCode::FAILURE;
                    }
                };

            // Fetch the certificate key
            let cert_key_tag = format!("{}/certificate", $domain);
            let loadable_cert_key: LoadableIdentityKey =
                match db_txn.get_tagged_hsm_key(&cert_key_tag) {
                    Ok(Some(ltk)) => ltk,
                    Err(e) => {
                        error!("Unable to access hsm certificate key: {:?}", e);
                        return ExitCode::FAILURE;
                    }
                    _ => {
                        error!("Unable to access hsm certificate key.");
                        return ExitCode::FAILURE;
                    }
                };

            (tpm, loadable_transport_key, loadable_cert_key, machine_key)
        }};
    }

    macro_rules! client {
        ($authority:expr, $transport_key:expr, $cert_key:expr) => {{
            match BrokerClientApplication::new(Some(&$authority), None, $transport_key, $cert_key) {
                Ok(app) => app,
                Err(e) => {
                    error!("Failed creating app: {:?}", e);
                    return ExitCode::FAILURE;
                }
            }
        }};
    }

    macro_rules! auth {
        ($app:expr, $account_id:expr) => {{
            let auth_options = vec![AuthOption::Passwordless];
            let auth_init = match $app.check_user_exists(&$account_id, &auth_options).await {
                Ok(auth_init) => auth_init,
                Err(e) => {
                    error!("Failed checking if user exists: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };
            debug!("User {} exists? {}", &$account_id, auth_init.exists());

            let password = if !auth_init.passwordless() {
                print!("{} password: ", &$account_id);
                io::stdout().flush().unwrap();
                match read_password() {
                    Ok(password) => Some(password),
                    Err(e) => {
                        error!("{:?}", e);
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                None
            };

            let mut mfa_req = match $app
                .initiate_acquire_token_by_mfa_flow_for_device_enrollment(
                    &$account_id,
                    password.as_deref(),
                    &auth_options,
                    Some(auth_init),
                )
                .await
            {
                Ok(mfa) => mfa,
                Err(e) => match e {
                    MsalError::PasswordRequired => {
                        print!("{} password: ", &$account_id);
                        io::stdout().flush().unwrap();
                        let password = match read_password() {
                            Ok(password) => Some(password),
                            Err(e) => {
                                error!("{:?}", e);
                                return ExitCode::FAILURE;
                            }
                        };
                        let auth_init =
                            match $app.check_user_exists(&$account_id, &auth_options).await {
                                Ok(auth_init) => auth_init,
                                Err(e) => {
                                    error!("Failed checking if user exists: {:?}", e);
                                    return ExitCode::FAILURE;
                                }
                            };
                        match $app
                            .initiate_acquire_token_by_mfa_flow_for_device_enrollment(
                                &$account_id,
                                password.as_deref(),
                                &auth_options,
                                Some(auth_init),
                            )
                            .await
                        {
                            Ok(mfa) => mfa,
                            Err(e) => {
                                error!("{:?}", e);
                                return ExitCode::FAILURE;
                            }
                        }
                    }
                    _ => {
                        error!("{:?}", e);
                        return ExitCode::FAILURE;
                    }
                },
            };
            print!("{}", mfa_req.msg);
            io::stdout().flush().unwrap();

            let token = auth_handle_mfa_resp!(
                mfa_req,
                // FIDO
                {
                    error!("Fido not enabled");
                    return ExitCode::FAILURE;
                },
                // PROMPT
                {
                    let input = match read_password() {
                        Ok(password) => password,
                        Err(e) => {
                            error!("{:?} ", e);
                            return ExitCode::FAILURE;
                        }
                    };
                    match $app
                        .acquire_token_by_mfa_flow(&$account_id, Some(&input), None, &mut mfa_req)
                        .await
                    {
                        Ok(token) => token,
                        Err(e) => {
                            error!("MFA FAIL: {:?}", e);
                            return ExitCode::FAILURE;
                        }
                    }
                },
                // POLL
                {
                    let mut poll_attempt = 1;
                    let polling_interval = mfa_req.polling_interval.unwrap_or(5000);
                    loop {
                        match $app
                            .acquire_token_by_mfa_flow(
                                &$account_id,
                                None,
                                Some(poll_attempt),
                                &mut mfa_req,
                            )
                            .await
                        {
                            Ok(token) => break token,
                            Err(e) => match e {
                                MsalError::MFAPollContinue => {
                                    poll_attempt += 1;
                                    sleep(Duration::from_millis(polling_interval.into()));
                                    continue;
                                }
                                e => {
                                    error!("MFA FAIL: {:?}", e);
                                    return ExitCode::FAILURE;
                                }
                            },
                        }
                    }
                }
            );
            println!();
            token
        }};
    }

    macro_rules! on_behalf_of_token {
        ($app:expr, $token:expr, $tpm:expr, $machine_key:expr, $scope:expr, $resource:expr, $client_id:expr) => {{
            match $app
                .acquire_token_by_refresh_token(
                    &$token.refresh_token,
                    $scope,
                    $resource,
                    $client_id,
                    &mut $tpm,
                    &$machine_key,
                )
                .await
            {
                Ok(token) => token,
                Err(e) => {
                    error!("{:?}", e);
                    return ExitCode::FAILURE;
                }
            }
        }};
    }

    macro_rules! obtain_access_token {
        ($account_id:ident, $scopes:expr, $resource:expr, $client_id:ident) => {{
            match $account_id {
                Some(account_id) => {
                    if unsafe { libc::geteuid() } != 0 {
                        error!("Authenticating as another user can only be performed by root.");
                        return ExitCode::FAILURE;
                    }

                    let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
                        Ok(c) => c,
                        Err(_e) => {
                            error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                            return ExitCode::FAILURE;
                        }
                    };

                    let (graph, domain, authority) = init!(cfg, account_id);
                    let (mut tpm, loadable_transport_key, loadable_cert_key, machine_key) =
                        obtain_host_data!(domain, cfg);
                    let app = client!(
                        authority,
                        Some(loadable_transport_key),
                        Some(loadable_cert_key)
                    );
                    let token = auth!(app, account_id);

                    match on_behalf_of_token!(
                        app,
                        token,
                        tpm,
                        machine_key,
                        $scopes,
                        $resource,
                        Some(&$client_id)
                    ).access_token.clone() {
                        Some(access_token) => (graph, access_token),
                        None => {
                            error!("Failed obtaining access token!");
                            return ExitCode::FAILURE;
                        }
                    }
                },
                None => {
                    let broker = match BrokerClient::new().await {
                        Ok(broker) => broker,
                        Err(e) => {
                            error!("Failed initiating broker: {:?}", e);
                            return ExitCode::FAILURE;
                        }
                    };
                    let session_id = Uuid::new_v4().to_string();

                    let account = match broker.get_accounts(
                        "0.0",
                        &session_id,
                        &json!({
                            "clientId": $client_id.clone(),
                            "redirectUri": session_id.clone(),
                        }),
                    )
                    .await {
                        Ok(accounts) => match serde_json::from_value::<Accounts>(accounts) {
                            Ok(accounts) => accounts.accounts[0].clone(),
                            Err(e) => {
                                error!("Failed deserializing authenticated account: {:?}", e);
                                return ExitCode::FAILURE;
                            }
                        }
                        Err(e) => {
                            error!("Failed discovering authenticated account: {:?}", e);
                            return ExitCode::FAILURE;
                        }
                    };
                    let account_id = match serde_json::from_value::<Account>(account.clone()) {
                        Ok(account) => account.username,
                        Err(e) => {
                            error!("Failed deserializing authenticated account: {:?}", e);
                            return ExitCode::FAILURE;
                        }
                    };

                    let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
                        Ok(c) => c,
                        Err(_e) => {
                            error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                            return ExitCode::FAILURE;
                        }
                    };

                    let (graph, _, authority) = init!(cfg, account_id);

                    match broker.acquire_token_silently(
                        "0.0",
                        &session_id,
                        &json!({
                            "account": account,
                            "authParameters": {
                                "account": account,
                                "additionalQueryParametersForAuthorization": {},
                                "authority": authority,
                                "authorizationType": 8,
                                "clientId": $client_id,
                                "redirectUri": "https://login.microsoftonline.com/common/oauth2/nativeclient",
                                "requestedScopes": $scopes,
                                "ssoUrl": "https://login.microsoftonline.com/",
                            }
                        }),
                    )
                    .await {
                        Ok(token) => match serde_json::from_value::<Token>(token) {
                            Ok(token) => (graph, token.response.access_token),
                            Err(_) => {
                                error!("Failed to parse token response!");
                                return ExitCode::FAILURE;
                            }
                        }
                        Err(e) => {
                            error!("Failed requesting authenticated account token: {:?}", e);
                            return ExitCode::FAILURE;
                        }
                    }
                }
            }
        }};
    }

    match opt.commands {
        HimmelblauUnixOpt::Application(ApplicationOpt::List {
            debug: _,
            account_id,
            client_id,
        }) => {
            debug!("Starting application list tool ...");

            let (graph, access_token) = obtain_access_token!(
                account_id,
                vec!["https://graph.microsoft.com/Application.Read.All"],
                None,
                client_id
            );

            let cli_graph = match CliGraph::new(&graph).await {
                Ok(cli_graph) => cli_graph,
                Err(e) => {
                    error!("Failed to create cli graph: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            let apps = match cli_graph.list_applications(&access_token).await {
                Ok(apps) => apps,
                Err(e) => {
                    error!("Failed to get apps: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            let apps_str = match to_string_pretty(&apps) {
                Ok(apps_str) => apps_str,
                Err(e) => {
                    error!("Failed to serialize apps: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };
            println!("{}", apps_str);

            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::Application(ApplicationOpt::Create {
            debug: _,
            account_id,
            client_id,
            display_name,
        }) => {
            debug!("Starting application list tool ...");

            let (graph, access_token) = obtain_access_token!(
                account_id,
                vec!["https://graph.microsoft.com/Application.ReadWrite.All"],
                None,
                client_id
            );

            let cli_graph = match CliGraph::new(&graph).await {
                Ok(cli_graph) => cli_graph,
                Err(e) => {
                    error!("Failed to create cli graph: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            match cli_graph
                .create_application(&access_token, &display_name, None)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to create app: {:?}", e);
                    return ExitCode::FAILURE;
                }
            }

            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::AuthTest {
            debug: _,
            account_id,
        } => {
            debug!("Starting PAM auth tester tool ...");

            let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
                }
            };

            // Map the name
            let account_id = cfg.map_name_to_upn(&account_id);

            let mut timeout = cfg.get_unix_sock_timeout();
            let mut daemon_client = match DaemonClientBlocking::new(&cfg.get_socket_path()) {
                Ok(dc) => dc,
                Err(e) => {
                    error!(err = ?e, "Error DaemonClientBlocking::new()");
                    return ExitCode::FAILURE;
                }
            };
            let pin_min_len = cfg.get_hello_pin_min_length();

            let mut req =
                ClientRequest::PamAuthenticateInit(account_id.clone(), "aad-tool".to_string());
            loop {
                match_sm_auth_client_response!(daemon_client.call_and_wait(&req, timeout), req, pin_min_len,
                    ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Password) => {
                        // Prompt for and get the password
                        let cred = match prompt_password("Password: ") {
                            Ok(p) => p,
                            Err(e) => {
                                error!("Problem getting input: {}", e);
                                return ExitCode::FAILURE;
                            }
                        };

                        // Now setup the request for the next loop.
                        timeout = cfg.get_unix_sock_timeout();
                        req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password { cred });
                        continue;
                    },
                    ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFACode {
                        msg,
                    }) => {
                        // Prompt for and get the MFA code
                        println!("{}", msg);
                        let cred = match prompt_password("Code: ") {
                            Ok(p) => p,
                            Err(e) => {
                                error!("Problem getting input: {}", e);
                                return ExitCode::FAILURE;
                            }
                        };

                        // Now setup the request for the next loop.
                        timeout = cfg.get_unix_sock_timeout();
                        req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFACode {
                            cred,
                        });
                        continue;
                    },
                    ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFAPoll {
                        msg,
                        polling_interval,
                    }) => {
                        // Prompt the MFA message
                        println!("{}", msg);

                        let mut poll_attempt = 0;
                        req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFAPoll { poll_attempt });
                        loop {
                            thread::sleep(Duration::from_secs(polling_interval.into()));

                            // Counter intuitive, but we don't need a max poll attempts here because
                            // if the resolver goes away, then this will error on the sock and
                            // will shutdown. This allows the resolver to dynamically extend the
                            // timeout if needed, and removes logic from the front end.
                            match_sm_auth_client_response!(
                                daemon_client.call_and_wait(&req, timeout), req, pin_min_len,
                                ClientResponse::PamAuthenticateStepResponse(
                                        PamAuthResponse::MFAPollWait,
                                ) => {
                                    // Continue polling if the daemon says to wait
                                    poll_attempt += 1;
                                    req = ClientRequest::PamAuthenticateStep(
                                        PamAuthRequest::MFAPoll { poll_attempt }
                                    );
                                    continue;
                                }
                            );
                        }
                    }
                );
            }
            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::CacheClear { debug: _, really } => {
            debug!("Starting cache clear tool ...");

            let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
                }
            };

            if !really {
                error!("Are you sure you want to proceed? This will revert the host to an unjoined state while NOT removing the host object from Entra Id. If so use --really");
                return ExitCode::SUCCESS;
            }

            let req = ClientRequest::ClearCache;

            match call_daemon(&cfg.get_socket_path(), req, cfg.get_unix_sock_timeout()).await {
                Ok(r) => match r {
                    ClientResponse::Ok => info!("success"),
                    _ => {
                        error!("Error: unexpected response -> {:?}", r);
                    }
                },
                Err(e) => {
                    error!("Error -> {:?}", e);
                }
            };
            println!("success");
            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::CacheInvalidate { debug: _ } => {
            debug!("Starting cache invalidate tool ...");

            let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
                }
            };

            let req = ClientRequest::InvalidateCache;

            match call_daemon(&cfg.get_socket_path(), req, cfg.get_unix_sock_timeout()).await {
                Ok(r) => match r {
                    ClientResponse::Ok => info!("success"),
                    _ => {
                        error!("Error: unexpected response -> {:?}", r);
                    }
                },
                Err(e) => {
                    error!("Error -> {:?}", e);
                }
            };
            println!("success");
            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::ConfigurePam {
            debug: _,
            really,
            auth_file,
            account_file,
            session_file,
            password_file,
        } => {
            trace!("Configuring pam_himmelblau ...");
            if really && unsafe { libc::geteuid() } != 0 {
                error!("This command must be run as root.");
                return ExitCode::FAILURE;
            }

            if !really {
                info!("Performing a dry run. If you want to enforce this change, use --really");
            }

            match configure_pam(
                !really,
                auth_file.as_deref(),
                account_file.as_deref(),
                session_file.as_deref(),
                password_file.as_deref(),
            ) {
                Ok(_) => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            }
        }
        HimmelblauUnixOpt::Enumerate {
            debug: _,
            account_id,
            client_id,
        } => {
            debug!("Starting enumerate tool ...");

            if unsafe { libc::geteuid() } != 0 {
                error!("This command must be run as root.");
                return ExitCode::FAILURE;
            }

            let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
                }
            };

            let (graph, domain, authority) = init!(cfg, account_id);
            let (mut tpm, loadable_transport_key, loadable_cert_key, machine_key) =
                obtain_host_data!(domain, cfg);
            let app = client!(
                authority,
                Some(loadable_transport_key),
                Some(loadable_cert_key)
            );
            let token = auth!(app, account_id);

            let token = on_behalf_of_token!(
                app,
                token,
                tpm,
                machine_key,
                vec!["https://graph.microsoft.com/User.Read.All"],
                None,
                Some(&client_id)
            );

            let access_token = match &token.access_token {
                Some(access_token) => access_token.clone(),
                None => {
                    error!("Failed to get access token");
                    return ExitCode::FAILURE;
                }
            };

            let users = match graph
                .request_all_users_with_extension_attributes(&access_token)
                .await
            {
                Ok(users) => users,
                Err(e) => {
                    error!("Failed to enumerate users: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            let groups = match graph
                .request_all_groups_with_extension_attributes(&access_token)
                .await
            {
                Ok(groups) => groups,
                Err(e) => {
                    error!("Failed to enumerate groups: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            let cache = match StaticIdCache::new(ID_MAP_CACHE, true) {
                Ok(cache) => cache,
                Err(e) => {
                    error!("Failed to open idmap cache: {}", e);
                    return ExitCode::FAILURE;
                }
            };

            for user in users {
                if let Some(uid) = user.uid {
                    let gid = user.gid.unwrap_or(uid);
                    let cache_user = StaticUser {
                        name: user.upn.clone(),
                        uid,
                        gid,
                    };

                    if let Err(e) = cache.insert_user(&cache_user) {
                        error!(
                            "Failed to inserting enumerated user {} in cache: {}",
                            user.upn, e
                        );
                        return ExitCode::FAILURE;
                    }
                }
            }

            for group in groups {
                if let Some(gid) = group.gid {
                    let cache_group = StaticGroup {
                        name: group.displayname.clone(),
                        gid,
                    };

                    if let Err(e) = cache.insert_group(&cache_group) {
                        error!(
                            "Failed to inserting enumerated group {} in cache: {}",
                            group.displayname, e
                        );
                        return ExitCode::FAILURE;
                    }
                }
            }

            info!("Users and groups enumerated successfully.");

            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::Idmap(subcommand) => {
            if unsafe { libc::geteuid() } != 0 {
                error!("This command must be run as root.");
                return ExitCode::FAILURE;
            }

            match subcommand {
                IdmapOpt::UserAdd {
                    debug: _,
                    account_id,
                    uid,
                    gid,
                } => {
                    trace!("Configuring id user mapping ...");

                    let cache = match StaticIdCache::new(ID_MAP_CACHE, true) {
                        Ok(cache) => cache,
                        Err(e) => {
                            error!("Failed to open idmap cache: {}", e);
                            return ExitCode::FAILURE;
                        }
                    };

                    let user = StaticUser {
                        name: account_id,
                        uid,
                        gid,
                    };

                    if let Err(e) = cache.insert_user(&user) {
                        error!("Failed to insert user mapping: {}", e);
                        return ExitCode::FAILURE;
                    }

                    info!("User mapping inserted successfully.");
                }

                IdmapOpt::GroupAdd {
                    debug: _,
                    account_id,
                    gid,
                } => {
                    trace!("Configuring id group mapping ...");

                    let cache = match StaticIdCache::new(ID_MAP_CACHE, true) {
                        Ok(cache) => cache,
                        Err(e) => {
                            error!("Failed to open idmap cache: {}", e);
                            return ExitCode::FAILURE;
                        }
                    };

                    let group = StaticGroup {
                        name: account_id,
                        gid,
                    };

                    if let Err(e) = cache.insert_group(&group) {
                        error!("Failed to insert group mapping: {}", e);
                        return ExitCode::FAILURE;
                    }

                    info!("Group mapping inserted successfully.");
                }
            }

            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::Status { debug: _ } => {
            trace!("Starting cache status tool ...");

            let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
                }
            };

            let req = ClientRequest::Status;

            let spath = PathBuf::from(cfg.get_socket_path());
            if !spath.exists() {
                error!(
                    "himmelblaud socket {} does not exist - is the service running?",
                    cfg.get_socket_path()
                )
            } else {
                match call_daemon(&cfg.get_socket_path(), req, cfg.get_unix_sock_timeout()).await {
                    Ok(r) => match r {
                        ClientResponse::Ok => println!("working!"),
                        _ => {
                            error!("Error: unexpected response -> {:?}", r);
                        }
                    },
                    Err(e) => {
                        error!("Error -> {:?}", e);
                    }
                }
            }
            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::Version { debug: _ } => {
            println!("himmelblau {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
    }
}
