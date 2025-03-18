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
use serde_json::json;
mod broker;
use broker::BrokerClient;
use clap::{CommandFactory, Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use std::env;
use std::error::Error;
use std::io::{self, Read, Write};
use uuid::Uuid;

const SSO_URL_DEFAULT: &str = "https://login.microsoftonline.com/";
const EDGE_BROWSER_CLIENT_ID: &str = "d7b530a4-7680-4c23-a8bf-c52c121d2e87";
const GRAPH_SCOPES: [&str; 1] = ["https://graph.microsoft.com/.default"];

struct NativeMessaging;

impl NativeMessaging {
    fn get_message() -> Result<serde_json::Value, Box<dyn Error>> {
        let mut raw_length = [0u8; 4];
        io::stdin().read_exact(&mut raw_length)?;
        let message_length = u32::from_le_bytes(raw_length) as usize;

        let mut buffer = vec![0u8; message_length];
        io::stdin().read_exact(&mut buffer)?;

        let message_str = String::from_utf8(buffer)?;
        Ok(serde_json::from_str(&message_str)?)
    }

    fn encode_message<T: Serialize>(message_content: &T) -> Result<Vec<u8>, Box<dyn Error>> {
        let encoded_content = serde_json::to_vec(message_content)?;
        let mut result = Vec::new();
        result.extend(&(encoded_content.len() as u32).to_ne_bytes());
        result.extend(encoded_content);
        Ok(result)
    }

    fn send_message(encoded_message: &[u8]) -> Result<(), Box<dyn Error>> {
        io::stdout().write_all(encoded_message)?;
        io::stdout().flush()?;
        Ok(())
    }
}

struct SsoMib {
    broker: BrokerClient,
    session_id: String,
}

impl SsoMib {
    async fn new() -> Result<Self, Box<dyn Error>> {
        let broker = BrokerClient::new().await?;
        Ok(SsoMib {
            broker,
            session_id: Uuid::new_v4().to_string(),
        })
    }

    fn _get_auth_parameters(&self, account: &Value, scopes: Vec<&str>) -> Value {
        json!({
            "account": account.clone(),
            "additionalQueryParametersForAuthorization": {},
            "authority": "https://login.microsoftonline.com/common",
            "authorizationType": 8,
            "clientId": EDGE_BROWSER_CLIENT_ID,
            "redirectUri": "https://login.microsoftonline.com/common/oauth2/nativeclient",
            "requestedScopes": scopes,
            "ssoUrl": SSO_URL_DEFAULT,
        })
    }

    async fn get_accounts(&self) -> Result<Value, Box<dyn Error>> {
        self.broker
            .get_accounts(
                "0.0",
                &self.session_id,
                &json!({
                    "clientId": EDGE_BROWSER_CLIENT_ID,
                    "redirectUri": self.session_id.clone(),
                }),
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    async fn acquire_prt_sso_cookie(
        &self,
        account: &Value,
        sso_url: &str,
        scopes: Option<Vec<&str>>,
    ) -> Result<Value, Box<dyn Error>> {
        let scopes = scopes.unwrap_or(GRAPH_SCOPES.to_vec());
        self.broker
            .acquire_prt_sso_cookie(
                "0.0",
                &self.session_id,
                &json!({
                    "account": account,
                    "authParameters": self._get_auth_parameters(account, scopes),
                    "ssoUrl": sso_url,
                }),
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    async fn acquire_token_silently(
        &self,
        account: &Value,
        scopes: Option<Vec<&str>>,
    ) -> Result<Value, Box<dyn Error>> {
        let scopes = scopes.unwrap_or(GRAPH_SCOPES.to_vec());
        self.broker
            .acquire_token_silently(
                "0.0",
                &self.session_id,
                &json!({
                    "account": account,
                    "authParameters": self._get_auth_parameters(account, scopes),
                }),
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    async fn get_broker_version(&self) -> Result<Value, Box<dyn Error>> {
        self.broker
            .get_linux_broker_version(
                "0.0",
                &self.session_id,
                &json!({
                    "msalCppVersion": env!("CARGO_PKG_VERSION"),
                }),
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Run in interactive mode
    #[arg(short, long)]
    interactive: bool,

    /// Account index to use for operations
    #[arg(short, long, default_value_t = 0)]
    account: usize,

    /// ssoUrl part of SSO PRT cookie request
    #[arg(name = "ssoUrl", short, long, default_value_t = SSO_URL_DEFAULT.to_string())]
    sso_url: String,

    #[command(subcommand)]
    command: Option<SubCommands>,
}

#[derive(Subcommand, Debug)]
enum SubCommands {
    #[command(name = "getAccounts")]
    GetAccounts,
    #[command(name = "getVersion")]
    GetVersion,
    #[command(name = "acquirePrtSsoCookie")]
    AcquirePrtSsoCookie,
    #[command(name = "acquireTokenSilently")]
    AcquireTokenSilently,
}

async fn run_interactive() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let ssomib = SsoMib::new().await?;
    let accounts = ssomib.get_accounts().await?;

    match args.command {
        Some(SubCommands::GetAccounts) => {
            println!("{}", serde_json::to_string_pretty(&accounts)?);
        }
        Some(SubCommands::GetVersion) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&ssomib.get_broker_version().await?)?
            );
        }
        Some(SubCommands::AcquirePrtSsoCookie) => {
            let account = &accounts["accounts"][args.account];
            let cookie = ssomib
                .acquire_prt_sso_cookie(account, &args.sso_url, None)
                .await?;
            println!("{}", serde_json::to_string_pretty(&cookie)?);
        }
        Some(SubCommands::AcquireTokenSilently) => {
            let account = &accounts["accounts"][args.account];
            let token = ssomib.acquire_token_silently(account, None).await?;
            println!("{}", serde_json::to_string_pretty(&token)?);
        }
        _ => Args::command().print_help()?,
    }
    Ok(())
}

async fn run_as_native_messaging() -> Result<(), Box<dyn Error>> {
    eprintln!("Running as native messaging instance.");
    eprintln!("For interactive mode, start with --interactive");

    let ssomib = SsoMib::new().await?;
    NativeMessaging::send_message(&NativeMessaging::encode_message(&json!({
        "command": "brokerStateChanged",
        "message": "online",
    }))?)?;

    loop {
        let received_message = NativeMessaging::get_message()?;
        match received_message["command"].as_str() {
            Some("acquirePrtSsoCookie") => {
                let account = &received_message["account"];
                let sso_url = received_message
                    .get("ssoUrl")
                    .and_then(|v| v.as_str())
                    .unwrap_or(SSO_URL_DEFAULT);
                let cookie = ssomib
                    .acquire_prt_sso_cookie(account, sso_url, None)
                    .await?;
                NativeMessaging::send_message(&NativeMessaging::encode_message(&json!({
                    "command": received_message["command"],
                    "message": cookie,
                }))?)?;
            }
            Some("acquireTokenSilently") => {
                let account = &received_message["account"];
                let scopes = received_message
                    .get("scopes")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                    .unwrap_or(GRAPH_SCOPES.to_vec());
                let token = ssomib.acquire_token_silently(account, Some(scopes)).await?;
                NativeMessaging::send_message(&NativeMessaging::encode_message(&json!({
                    "command": received_message["command"],
                    "message": token,
                }))?)?;
            }
            Some("getAccounts") => {
                NativeMessaging::send_message(&NativeMessaging::encode_message(&json!({
                    "command": received_message["command"],
                    "message": ssomib.get_accounts().await?,
                }))?)?;
            }
            Some("getVersion") => {
                NativeMessaging::send_message(&NativeMessaging::encode_message(&json!({
                    "command": received_message["command"],
                    "message": ssomib.get_broker_version().await?,
                }))?)?;
            }
            _ => {
                eprintln!("Invalid request '{:?}'", received_message["command"]);
                NativeMessaging::send_message(&NativeMessaging::encode_message(&json!({
                    "command": received_message["command"],
                    "message": { "error": "Invalid request" },
                }))?)?;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let interactive = env::args().any(|arg| arg == "--interactive")
        || env::args().any(|arg| arg == "-i")
        || env::args().any(|arg| arg == "--help")
        || env::args().any(|arg| arg == "-h")
        || env::args().any(|arg| arg == "--version")
        || env::args().any(|arg| arg == "-V");

    if interactive {
        if let Err(e) = run_interactive().await {
            eprintln!("run_interactive failed: {:?}", e);
        }
    } else if let Err(e) = run_as_native_messaging().await {
        eprintln!("run_as_native_messaging failed: {:?}", e);
    }
}
