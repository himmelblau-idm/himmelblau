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
use std::str::FromStr;
use std::sync::Arc;

use broker_client::BrokerClient;
use clap::Parser;
use himmelblau::ConfidentialClientApplication;
use himmelblau::{error::MsalError, graph::Graph, AuthOption, BrokerClientApplication};
use himmelblau_unix_common::auth::{authenticate_async, SimpleMessagePrinter};
use himmelblau_unix_common::auth_handle_mfa_resp;
use himmelblau_unix_common::client::call_daemon;
use himmelblau_unix_common::config::{split_username, HimmelblauConfig};
use himmelblau_unix_common::constants::{
    CONFIDENTIAL_CLIENT_CERT_KEY_TAG, CONFIDENTIAL_CLIENT_CERT_TAG, CONFIDENTIAL_CLIENT_SECRET_TAG,
    DEFAULT_CONFIG_PATH, DEFAULT_ODC_PROVIDER, ID_MAP_CACHE,
};
use himmelblau_unix_common::db::{Cache, CacheTxn, Db, KeyStoreTxn};
use himmelblau_unix_common::idmap_cache::{StaticGroup, StaticIdCache, StaticUser};
use himmelblau_unix_common::pam::{Options, PamResultCode};
use himmelblau_unix_common::tpm::confidential_client_creds;
use himmelblau_unix_common::tpm_init;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse};
use himmelblau_unix_common::{tpm_loadable_machine_key, tpm_machine_key};
use kanidm_hsm_crypto::glue::traits::EncodeDer;
use kanidm_hsm_crypto::glue::{
    spki::der::pem::LineEnding,
    traits::{EncodePem, Keypair},
    x509,
    x509::Builder,
};
use kanidm_hsm_crypto::{
    provider::BoxedDynTpm, provider::SoftTpm, provider::Tpm,
    structures::LoadableMsDeviceEnrolmentKey, structures::LoadableMsOapxbcRsaKey,
};
use rpassword::read_password;
use serde::Deserialize;
use serde_json::{json, to_string_pretty, Value};
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

include!("./opt/tool.rs");

mod graph;
use crate::graph::{CliGraph, GraphResources};

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

async fn confidential_client_access_token(
    client_id: Option<String>,
    account_id: Option<String>,
    domain: Option<String>,
) -> Option<(String, String)> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }

    let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
        Ok(c) => c,
        Err(_) => {
            error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
            return None;
        }
    };

    let domain = if let Some(account_id) = &account_id {
        match split_username(&account_id) {
            Some((_, domain)) => domain.to_string(),
            None => {
                error!("Could not split domain from input username");
                return None;
            }
        }
    } else if let Some(domain) = domain {
        domain
    } else {
        // Attempt using the default domain
        cfg.get_configured_domains()[0].clone()
    };

    let (auth_value, mut tpm) = tpm_init!(cfg, return None);

    let db = match Db::new(&cfg.get_db_path()) {
        Ok(db) => db,
        Err(e) => {
            error!("Failed loading Himmelblau cache: {:?}", e);
            return None;
        }
    };

    // Fetch the machine key
    let loadable_machine_key = tpm_loadable_machine_key!(db, tpm, auth_value, false, return None);
    let machine_key = tpm_machine_key!(tpm, auth_value, loadable_machine_key, cfg, return None);

    let mut keystore = db.write().await;
    if let Ok(Some((cred_client_id, client_creds))) =
        confidential_client_creds(&mut tpm, &mut keystore, &machine_key, &domain)
    {
        if let Some(client_id) = client_id {
            if client_id.to_lowercase() != cred_client_id.to_lowercase() {
                return None;
            }
        }
        let authority_host = cfg.get_authority_host(&domain);
        let tenant_id = match cfg.get_tenant_id(&domain) {
            Some(tenant_id) => tenant_id,
            None => "common".to_string(),
        };
        let authority = format!("https://{}/{}", authority_host, tenant_id);

        let app = match ConfidentialClientApplication::new(
            &cred_client_id,
            Some(&authority),
            client_creds,
        ) {
            Ok(app) => app,
            Err(e) => {
                error!(?e, "Failed initializing confidential client");
                return None;
            }
        };
        if let Ok(token) = app
            .acquire_token_silent(
                vec!["00000003-0000-0000-c000-000000000000/.default"],
                Some(&mut tpm),
            )
            .await
        {
            debug!("Proceeding with confidential client credentials...");
            return Some((domain, token.access_token.clone()));
        }
    }
    None
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let opt = HimmelblauUnixParser::parse();

    let debug = match opt.commands {
        HimmelblauUnixOpt::AddCred(AddCredOpt::Cert {
            debug,
            client_id: _,
            domain: _,
            valid_days: _,
            cert_out: _,
        }) => debug,
        HimmelblauUnixOpt::AddCred(AddCredOpt::Secret {
            debug,
            client_id: _,
            domain: _,
            secret: _,
        }) => debug,
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
            redirect_uris: _,
            user_read_write: _,
            group_read_write: _,
        }) => debug,
        HimmelblauUnixOpt::Application(ApplicationOpt::ListSchemaExtensions {
            debug,
            account_id: _,
            client_id: _,
            schema_app_object_id: _,
        }) => debug,
        HimmelblauUnixOpt::Application(ApplicationOpt::AddSchemaExtensions {
            debug,
            account_id: _,
            client_id: _,
            schema_app_object_id: _,
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
        HimmelblauUnixOpt::User(UserOpt::SetPosixAttrs {
            debug,
            account_id: _,
            schema_client_id: _,
            user_id: _,
            uid: _,
            gid: _,
            home: _,
            shell: _,
            gecos: _,
        }) => debug,
        HimmelblauUnixOpt::Group(GroupOpt::SetPosixAttrs {
            debug,
            account_id: _,
            schema_client_id: _,
            group_id: _,
            gid: _,
        }) => debug,
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
        ($cfg:expr, $account_id:expr, $domain:expr) => {{
            let domain = if let Some(account_id) = $account_id {
                match split_username(&account_id) {
                    Some((_, domain)) => domain.to_string(),
                    None => {
                        error!("Could not split domain from input username");
                        return ExitCode::FAILURE;
                    }
                }
            } else if let Some(domain) = $domain {
                domain
            } else {
                error!("No domain input provided.");
                return ExitCode::FAILURE;
            };

            let graph = match Graph::new(DEFAULT_ODC_PROVIDER, &domain, None, None, None).await {
                Ok(graph) => graph,
                Err(e) => {
                    error!("Failed discovering tenant: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            let tenant_id = match $cfg.get_tenant_id(&domain) {
                Some(tenant_id) => tenant_id,
                None => "common".to_string(),
            };
            let authority = format!("https://{}/{}", $cfg.get_authority_host(&domain), tenant_id);

            (graph, domain, authority)
        }};
    }

    macro_rules! obtain_host_data {
        ($domain:expr, $cfg:ident) => {{
            let (auth_value, mut tpm) = tpm_init!($cfg, return ExitCode::FAILURE);

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
            let loadable_cert_key: LoadableMsDeviceEnrolmentKey =
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

                    let (graph, domain, authority) = init!(cfg, Some(account_id.to_string()), None);
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

                    let (graph, _, authority) = init!(cfg, Some(account_id.to_string()), None);

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
        HimmelblauUnixOpt::AddCred(AddCredOpt::Cert {
            debug: _,
            client_id,
            domain,
            valid_days,
            cert_out,
        }) => {
            debug!("Starting add-cred cert tool ...");

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

            let (auth_value, mut tpm) = tpm_init!(cfg, return ExitCode::FAILURE);

            let db = match Db::new(&cfg.get_db_path()) {
                Ok(db) => db,
                Err(e) => {
                    error!("Failed loading Himmelblau cache: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            // Fetch the machine key
            let loadable_machine_key =
                tpm_loadable_machine_key!(db, tpm, auth_value, false, return ExitCode::FAILURE);
            let machine_key = tpm_machine_key!(
                tpm,
                auth_value,
                loadable_machine_key,
                cfg,
                return ExitCode::FAILURE
            );

            let loadable_cert_key = match tpm.msoapxbc_rsa_key_create(&machine_key) {
                Ok(loadable_cert_key) => loadable_cert_key,
                Err(e) => {
                    error!(?e, "Unable to create new cert key");
                    return ExitCode::FAILURE;
                }
            };
            let cert_key = match tpm.msoapxbc_rsa_key_load(&machine_key, &loadable_cert_key) {
                Ok(cert_key) => cert_key,
                Err(e) => {
                    error!(?e, "Unable to load cert key");
                    return ExitCode::FAILURE;
                }
            };
            let signing_key = match tpm.rs256_keypair(&cert_key) {
                Ok(signing_key) => signing_key,
                Err(e) => {
                    error!(?e, "Failed getting keypair");
                    return ExitCode::FAILURE;
                }
            };

            // Prepare X.509 fields
            let serial_number = x509::SerialNumber::from(1u32);

            let now = SystemTime::now();
            let validity = x509::Validity {
                not_before: match x509::Time::try_from(now) {
                    Ok(not_before) => not_before,
                    Err(e) => {
                        error!(?e, ?now, "Failed parsing timestamp");
                        return ExitCode::FAILURE;
                    }
                },
                not_after: match x509::Time::try_from(now + Duration::from_secs(valid_days * 86400))
                {
                    Ok(not_after) => not_after,
                    Err(e) => {
                        error!(?e, ?now, "Failed parsing timestamp");
                        return ExitCode::FAILURE;
                    }
                },
            };

            let subject = match x509::Name::from_str(&format!("CN={}", client_id)) {
                Ok(subject) => subject,
                Err(e) => {
                    error!(?e, "Failed setting subject");
                    return ExitCode::FAILURE;
                }
            };

            // Get the SubjectPublicKeyInfo from the TPM key
            let subject_public_key_info =
                match x509::SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key()) {
                    Ok(subject_public_key_info) => subject_public_key_info,
                    Err(e) => {
                        error!(?e, "Failed setting subject key info");
                        return ExitCode::FAILURE;
                    }
                };

            // Build the certificate (self-signed, so issuer = None)
            let mut cert_builder = match x509::CertificateBuilder::new(
                x509::Profile::Manual { issuer: None },
                serial_number,
                validity,
                subject,
                subject_public_key_info,
                &signing_key,
            ) {
                Ok(cert_builder) => cert_builder,
                Err(e) => {
                    error!(?e, "Failed building certificate");
                    return ExitCode::FAILURE;
                }
            };

            // Encode the TBS certificate
            let tbs = match cert_builder.finalize() {
                Ok(tbs) => tbs,
                Err(e) => {
                    error!(?e, "Failed encoding the TBS certificate");
                    return ExitCode::FAILURE;
                }
            };

            // Sign it using the TPM RSA key
            let signature = match tpm.rs256_sign_to_bitstring(&cert_key, &tbs) {
                Ok(signature) => signature,
                Err(e) => {
                    error!(?e, "Failed signing the certificate");
                    return ExitCode::FAILURE;
                }
            };

            // Complete the certificate assembly
            let cert = match cert_builder.assemble(signature) {
                Ok(cert) => cert,
                Err(e) => {
                    error!(?e, "Failed assembling the certificate");
                    return ExitCode::FAILURE;
                }
            };

            let mut db_txn = db.write().await;

            // Write the key to the cache
            let key_tag = format!("{}/{}", domain, CONFIDENTIAL_CLIENT_CERT_KEY_TAG);
            if let Err(e) = db_txn.insert_tagged_hsm_key(&key_tag, &loadable_cert_key) {
                error!(?e, "Failed inserting certificate key into cache");
                return ExitCode::FAILURE;
            }

            // Seal the certificate, and store that also
            let cert_tag = format!("{}/{}", domain, CONFIDENTIAL_CLIENT_CERT_TAG);
            let sealed_cert = match tpm.seal_data(
                &machine_key,
                match cert.to_der() {
                    Ok(der) => der,
                    Err(e) => {
                        error!(?e, "Failed fetching certificate der");
                        return ExitCode::FAILURE;
                    }
                }
                .into(),
            ) {
                Ok(sealed_cert) => sealed_cert,
                Err(e) => {
                    error!(?e, "Failed sealing certificate");
                    return ExitCode::FAILURE;
                }
            };
            if let Err(e) = db_txn.insert_tagged_hsm_key(&cert_tag, &sealed_cert) {
                error!(?e, "Failed inserting certificate key into cache");
                return ExitCode::FAILURE;
            }

            if let Err(e) = db_txn.commit() {
                error!(?e, "Failed inserting certificate key into cache");
                return ExitCode::FAILURE;
            }

            // Write to PEM
            if let Err(e) = std::fs::write(
                cert_out.clone(),
                match cert.to_pem(LineEnding::LF) {
                    Ok(pem) => pem,
                    Err(e) => {
                        error!(?e, "Failed fetching certificate pem");
                        return ExitCode::FAILURE;
                    }
                },
            ) {
                error!(?e, "Failed writing certificate to {}", cert_out);
                return ExitCode::FAILURE;
            }

            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::AddCred(AddCredOpt::Secret {
            debug: _,
            client_id,
            domain,
            secret,
        }) => {
            debug!("Starting add-cred secret tool ...");

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

            let (auth_value, mut tpm) = tpm_init!(cfg, return ExitCode::FAILURE);

            let db = match Db::new(&cfg.get_db_path()) {
                Ok(db) => db,
                Err(e) => {
                    error!("Failed loading Himmelblau cache: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            // Fetch the machine key
            let loadable_machine_key =
                tpm_loadable_machine_key!(db, tpm, auth_value, false, return ExitCode::FAILURE);
            let machine_key = tpm_machine_key!(
                tpm,
                auth_value,
                loadable_machine_key,
                cfg,
                return ExitCode::FAILURE
            );

            let secret_info = json!({
                "secret": secret,
                "client_id": client_id,
            });

            let sealed_secret =
                match tpm.seal_data(&machine_key, secret_info.to_string().into_bytes().into()) {
                    Ok(sealed_secret) => sealed_secret,
                    Err(e) => {
                        error!(?e, "Failed sealing secret");
                        return ExitCode::FAILURE;
                    }
                };

            let mut db_txn = db.write().await;

            // Write the secret to the cache
            let secret_tag = format!("{}/{}", domain, CONFIDENTIAL_CLIENT_SECRET_TAG);
            if let Err(e) = db_txn.insert_tagged_hsm_key(&secret_tag, &sealed_secret) {
                error!(?e, "Failed inserting sealed secret into cache");
                return ExitCode::FAILURE;
            }

            if let Err(e) = db_txn.commit() {
                error!(?e, "Failed inserting certificate key into cache");
                return ExitCode::FAILURE;
            }

            ExitCode::SUCCESS
        }
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
            redirect_uris,
            user_read_write,
            group_read_write,
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

            let mut graph_resources = vec![];
            if user_read_write {
                graph_resources.push(GraphResources::UserReadWriteAll);
            }
            if group_read_write {
                graph_resources.push(GraphResources::GroupReadWriteAll);
            }

            match cli_graph
                .create_application(
                    &access_token,
                    &display_name,
                    None,
                    redirect_uris.iter().map(|s| s.as_str()).collect(),
                    &graph_resources,
                )
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
        HimmelblauUnixOpt::Application(ApplicationOpt::ListSchemaExtensions {
            debug: _,
            account_id,
            client_id,
            schema_app_object_id,
        }) => {
            debug!("Starting list schema extensions tool ...");

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

            let schema_extensions = match cli_graph
                .list_schema_extensions(&access_token, &schema_app_object_id)
                .await
            {
                Ok(schema_extensions) => schema_extensions,
                Err(e) => {
                    error!("Failed listing schema extensions: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };
            let json = match serde_json::to_string_pretty(&schema_extensions) {
                Ok(json) => json,
                Err(e) => {
                    error!("Failed parsing schema extensions response: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };
            println!("{}", json);

            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::Application(ApplicationOpt::AddSchemaExtensions {
            debug: _,
            account_id,
            client_id,
            schema_app_object_id,
        }) => {
            debug!("Starting add schema extensions tool ...");

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
                .add_schema_extensions(&access_token, &schema_app_object_id)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    error!("Failed adding schema extensions: {:?}", e);
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

            let opts = Options::default();
            let msg_printer = Arc::new(SimpleMessagePrinter::default());
            match authenticate_async(
                None,
                cfg,
                account_id,
                "aad-tool".to_string(),
                opts,
                msg_printer,
            )
            .await
            {
                PamResultCode::PAM_SUCCESS => return ExitCode::SUCCESS,
                e => {
                    error!("Authentication failed: {:?}", e);
                    return ExitCode::FAILURE;
                }
            }
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

            let (graph, access_token) = match confidential_client_access_token(
                Some(client_id.clone()),
                Some(account_id.clone()),
                None,
            )
            .await
            {
                Some((domain, access_token)) => {
                    let graph =
                        match Graph::new(DEFAULT_ODC_PROVIDER, &domain, None, None, None).await {
                            Ok(graph) => graph,
                            Err(e) => {
                                error!("Failed discovering tenant: {:?}", e);
                                return ExitCode::FAILURE;
                            }
                        };
                    (graph, access_token)
                }
                None => {
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

                    let (graph, domain, authority) = init!(cfg, Some(account_id.clone()), None);
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

                    match &token.access_token {
                        Some(access_token) => (graph, access_token.clone()),
                        None => {
                            error!("Failed to get access token");
                            return ExitCode::FAILURE;
                        }
                    }
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
        HimmelblauUnixOpt::User(UserOpt::SetPosixAttrs {
            debug: _,
            account_id,
            schema_client_id,
            user_id,
            uid,
            gid,
            home,
            shell,
            gecos,
        }) => {
            debug!("Starting user set posix attrs tool ...");

            let (graph, access_token) = obtain_access_token!(
                account_id,
                vec!["https://graph.microsoft.com/User.ReadWrite.All"],
                None,
                schema_client_id
            );

            let cli_graph = match CliGraph::new(&graph).await {
                Ok(cli_graph) => cli_graph,
                Err(e) => {
                    error!("Failed to create cli graph: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            match cli_graph
                .set_user_posix_attrs(
                    &access_token,
                    &user_id,
                    &schema_client_id,
                    uid,
                    gid,
                    home,
                    shell,
                    gecos,
                )
                .await
            {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to set user posix attrs: {:?}", e);
                    return ExitCode::FAILURE;
                }
            }

            ExitCode::SUCCESS
        }
        HimmelblauUnixOpt::Group(GroupOpt::SetPosixAttrs {
            debug: _,
            account_id,
            schema_client_id,
            group_id,
            gid,
        }) => {
            debug!("Starting group set posix attrs tool ...");

            let (graph, access_token) = obtain_access_token!(
                account_id,
                vec!["https://graph.microsoft.com/Group.ReadWrite.All"],
                None,
                schema_client_id
            );

            let cli_graph = match CliGraph::new(&graph).await {
                Ok(cli_graph) => cli_graph,
                Err(e) => {
                    error!("Failed to create cli graph: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            match cli_graph
                .set_group_posix_attrs(&access_token, &group_id, &schema_client_id, gid)
                .await
            {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to set group posix attrs: {:?}", e);
                    return ExitCode::FAILURE;
                }
            }

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
