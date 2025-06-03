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

use clap::Parser;
use himmelblau_unix_common::client::call_daemon;
use himmelblau_unix_common::client_sync::DaemonClientBlocking;
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::{DEFAULT_CONFIG_PATH, ID_MAP_CACHE};
use himmelblau_unix_common::idmap_cache::{StaticGroup, StaticIdCache, StaticUser};
use himmelblau_unix_common::unix_proto::{
    ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse,
};
use rpassword::prompt_password;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

include!("./opt/tool.rs");

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
    let insert_index = insert_index.unwrap_or_else(|| lines.len());
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

    match opt.commands {
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
