use clap::{App, Arg, SubCommand, ArgAction};
use tracing::{debug, error, info};
use anyhow::{anyhow, Result};
use std::process::ExitCode;
use msal::authentication::PublicClientApplication;
use himmelblau_unix_common::constants::{DEFAULT_CONFIG_PATH, DEFAULT_APP_ID};
use himmelblau_unix_common::config::HimmelblauConfig;
use hostname;
use os_release::OsRelease;
use uuid::Uuid;
use std::io;
use std::io::Write;

use tokio;
use serde_json::{json, to_string_pretty};
use reqwest::header;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Device {
    id: String,
    #[serde(rename = "deviceId")]
    device_id: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

async fn enroll(mut config: HimmelblauConfig, domain: &str, admin: &str) -> Result<()> {
    let (_tenant_id, authority_url, graph) = config.get_authority_url(domain).await;
    let app_id = config.get_app_id(domain);
    if app_id == DEFAULT_APP_ID {
        error!("Please specify an app_id in himmelblau.conf.");
        /* TODO: Figure out how to join via Intune Portal for Linux. Currently
         * it throws Access Denied errors. */
        return Err(anyhow!("Enrollment directly in the Intune Portal for Linux is not possible."));
    }
    let app = PublicClientApplication::new(&app_id, authority_url.as_str());
    let scopes = vec!["Directory.AccessAsUser.All"];
    info!("If you get error AADSTS500113 during authentication, you need to configure the Redirect URI of your \"Mobile and Desktop application\" as ``http://localhost`` for your Application in Azure.");
    let (token, _err) = app.acquire_token_interactive(scopes, "login", admin, domain);
    if token.contains_key("access_token") {
        debug!("Authentication successful");
        let access_token: &str = match token.get("access_token") {
            Some(val) => val,
            None => {
                return Err(anyhow!("Failed fetching access_token"));
            }
        };
        let url = &format!("{}/v1.0/devices", graph);
        let host: String = String::from(hostname::get()?.to_str().unwrap());
        let os_release = OsRelease::new()?;
        let payload = json!({
            "accountEnabled": true,
            "alternativeSecurityIds":
            [
                {
                    "type": 2,
                    /* TODO: This needs to be a real Alt-Security-Identity
                     * associated with an X.509 cert which will allow us to
                     * authenticate later. Otherwise this machine account is
                     * useless. */
                    "key": "Y3YxN2E1MWFlYw=="
                }
            ],
            "deviceId": Uuid::new_v4(),
            "displayName": host,
            "operatingSystem": "Linux",
            "operatingSystemVersion": format!("{} {}", os_release.pretty_name, os_release.version_id),
            /* TODO: Figure out how to set the trustType (probably to
             * "AzureAd"). This appears to be necessary for fetching policy
             * later, but Access Denied errors are being thrown when this is
             * set. */
        });
        debug!("POST {}: {}", url, to_string_pretty(&payload).unwrap());
        let client = reqwest::Client::new();
        let resp = client
            .post(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(header::CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await?;
        if resp.status().is_success() {
            let res: Device = resp.json().await?;
            info!("Device enrolled with object id {}", res.id);
            config.set("global", "device_id", &res.id);
            /* FIXME: We need to write the config as root, but the
             * authentication can only happen with a graphical login (so no
             * sudo). */
            match config.write(DEFAULT_CONFIG_PATH) {
                Ok(()) => debug!("Successfully wrote configuration."),
                Err(e) => error!("Failed writing configuration: {}", e),
            };
            Ok(())
        } else {
            Err(anyhow!(resp.status()))
        }
    } else {
        Err(anyhow!("{}: {}",
            token.get("error").unwrap(),
            token.get("error_description").unwrap()))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = App::new("aad-tool")
        .arg(
            Arg::new("debug")
                .help("Show extra debug information")
                .short('d')
                .long("debug")
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            SubCommand::with_name("enroll")
                .about("Enroll this device in Azure Active Directory")
                .arg(
                    Arg::with_name("domain")
                        .value_name("DOMAIN")
                        .help("Sets the Azure AD domain to enroll in")
                        .required(true)
                )
                .arg(
                    Arg::with_name("username")
                        .help("The calling user must be in one of the following Azure AD roles: Global Administrator, Intune Administrator, or Windows 365 Administrator.")
                        .short('U')
                        .long("username")
                        .takes_value(true)
                )
                .arg(
                    Arg::new("app-id")
                        .help("Sets the Application (client) ID")
                        .short('a')
                        .long("app-id")
                        .multiple_values(false)
                        .takes_value(true)
                )
        ).get_matches();

    if args.get_flag("debug") {
        std::env::set_var("RUST_LOG", "debug");
    }
    tracing_subscriber::fmt::init();

    // Read the configuration
    let mut config = match HimmelblauConfig::new(DEFAULT_CONFIG_PATH) {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            return ExitCode::FAILURE
        }
    };

    match args.subcommand() {
        Some(("enroll", enroll_args)) => {
            let domain: &str = enroll_args.value_of("domain")
                .expect("Failed unwrapping the domain name");
            let admin: String = match enroll_args.value_of("username") {
                Some(username) => username.to_owned(),
                None => {
                    print!("Username: ");
                    io::stdout().flush()
                        .expect("Failed flushing prompt");
                    let mut buf = String::new();
                    io::stdin().read_line(&mut buf)
                        .expect("Failed reading username");
                    buf.to_owned()
                },
            };
            match enroll_args.value_of("app-id") {
                Some(app_id) => {
                    config.set("global", "app_id", app_id);
                },
                None => {},
            }
            match enroll(config, domain, &admin).await {
                Ok(()) => debug!("Success"),
                Err(e) => {
                    error!("{}", e);
                    return ExitCode::FAILURE;
                }
            };
        },
        _ => {
            error!("Invalid command. Use 'aad-tool --help' for more information");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
