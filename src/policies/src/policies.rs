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
use crate::compliance_ext::ComplianceCSE;
use crate::cse::CSE;
use crate::scripts_ext::ScriptsCSE;
use anyhow::{anyhow, Result};
use broker_client::{user_token_from_broker_token_resp, BrokerClient};
use himmelblau::graph::Graph;
use himmelblau::intune::{IntuneForLinux, IntuneStatus};
use himmelblau::{ClientInfo, EnrollAttrs, IdToken, UserToken};
use himmelblau_unix_common::config::{split_username, HimmelblauConfig};
use himmelblau_unix_common::constants::DEFAULT_APP_ID;
use libc::{geteuid, uid_t};
use serde::Deserialize;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, instrument};

#[derive(Deserialize)]
struct BrokerAccounts {
    accounts: Vec<Value>,
}

macro_rules! seteuid_result {
    ($uid:ident) => {{
        (unsafe { libc::seteuid($uid) } != 0)
            .then(|| Err(anyhow!(std::io::Error::last_os_error())))
            .unwrap_or(Ok(()))
    }};
}

#[instrument(skip(config))]
pub async fn apply_intune_policy(config: &HimmelblauConfig, uid: uid_t) -> Result<bool> {
    let correlation_id = uuid::Uuid::new_v4().to_string();
    debug!(?uid, "Attempting to enforce policies");

    let original_uid = unsafe { geteuid() };
    seteuid_result!(uid)?;
    let broker = BrokerClient::new().await.map_err(|e| {
        let _ = seteuid_result!(original_uid);
        anyhow!("Failed to initialize BrokerClient: {:?}", e)
    })?;
    let accounts: BrokerAccounts = serde_json::from_value(
        broker
            .get_accounts(
                "0.0",
                &correlation_id,
                &json!({
                    "clientId": DEFAULT_APP_ID,
                    "redirectUri": correlation_id.clone(),
                }),
            )
            .await
            .map_err(|e| {
                let _ = seteuid_result!(original_uid);
                anyhow!(e)
            })?,
    )
    .map_err(|e| anyhow!(e))?;
    seteuid_result!(original_uid)?;
    debug!(
        "Discovered {} accounts for policy application",
        accounts.accounts.len()
    );

    if let Some(account) = accounts.accounts.get(0) {
        let account_id = account
            .get("username")
            .and_then(|v| v.as_str())
            .ok_or(anyhow!("Missing username in account"))?;

        let domain = split_username(account_id)
            .map(|(_, domain)| domain)
            .ok_or(anyhow!(
                "Failed to parse domain name from account id '{}'",
                account_id
            ))?;

        let intune_device_id = match config.get_intune_device_id(&domain) {
            Some(id) => id,
            // This device isn't enrolled in Intune, there is nothing to enforce
            None => return Ok(true),
        };
        debug!(
            ?uid,
            ?intune_device_id,
            "Applying policies for user and device"
        );

        let graph = Graph::new(&config.get_odc_provider(domain), domain, None, None, None)
            .await
            .map_err(|e| anyhow!(e))?;

        macro_rules! acquire_token {
            ($scope:expr) => {{
                let original_uid = unsafe { geteuid() };
                seteuid_result!(uid)?;
                let broker_token = broker
                    .acquire_token_silently(
                        "0.0",
                        &correlation_id,
                        &json!({
                            "account": account,
                            "authParameters": {
                                "account": account.clone(),
                                "additionalQueryParametersForAuthorization": {},
                                "authority": "https://login.microsoftonline.com/common",
                                "authorizationType": 8,
                                "clientId": DEFAULT_APP_ID,
                                "redirectUri": "https://login.microsoftonline.com/common/oauth2/nativeclient",
                                "requestedScopes": vec![$scope],
                                "ssoUrl": "https://login.microsoftonline.com/",
                            }
                        }),
                    )
                    .await
                    .map_err(|e| {
                        let _ = seteuid_result!(original_uid);
                        anyhow!(e)
                })?;
                let token = user_token_from_broker_token_resp!(broker_token);
                seteuid_result!(original_uid)?;
                token
            }};
        }

        let access_token = acquire_token!("00000003-0000-0000-c000-000000000000/.default")
            .access_token
            .clone()
            .ok_or(anyhow!("Missing accessToken in response"))?;
        let endpoints = graph
            .intune_service_endpoints(&access_token)
            .await
            .map_err(|e| anyhow!(e))?;
        debug!("Discovered Intune service endpoints");

        let intune = IntuneForLinux::new(endpoints).map_err(|e| anyhow!(e))?;

        let token = acquire_token!("0000000a-0000-0000-c000-000000000000/.default");

        // Update device details
        let attrs =
            EnrollAttrs::new(domain.to_string(), None, None, None, None).map_err(|e| anyhow!(e))?;
        intune
            .details(&token, &attrs, &intune_device_id)
            .await
            .map_err(|e| anyhow!(e))?;
        debug!("Updated Intune device details");

        // Get the list of policies to apply
        let policies = intune
            .policies(&token, &intune_device_id)
            .await
            .map_err(|e| anyhow!(e))?;
        debug!(?policies, "Received policy enforcement actions");
        let mut statuses: IntuneStatus = policies.into();

        let gp_extensions: Vec<Arc<dyn CSE>> = vec![
            Arc::new(ScriptsCSE::new(config, account_id)),
            Arc::new(ComplianceCSE::new(config, account_id)),
        ];

        for ext in gp_extensions {
            ext.process_group_policy(&mut statuses).await?;
        }
        debug!("Enforced Intune policy");

        // Report policy status
        debug!(?statuses, "Reporting Intune policy status");
        intune
            .status(&token, statuses)
            .await
            .map_err(|e| anyhow!(e))?;
    }

    Ok(true)
}
