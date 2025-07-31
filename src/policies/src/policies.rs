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
use crate::custom_compliance_ext::CustomComplianceCSE;
use crate::scripts_ext::ScriptsCSE;
use anyhow::{anyhow, Result};
use himmelblau::graph::Graph;
use himmelblau::intune::{IntuneForLinux, IntuneStatus};
use himmelblau::{ClientInfo, EnrollAttrs, IdToken, UserToken};
use himmelblau_unix_common::config::{split_username, HimmelblauConfig};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use tracing::{debug, error, instrument};

#[instrument(skip(config, graph_token, intune_token, iwservice_token))]
pub async fn apply_intune_policy(
    config: &HimmelblauConfig,
    account_id: &str,
    graph_token: &str,
    intune_token: &str,
    iwservice_token: &str,
) -> Result<bool> {
    debug!(?account_id, "Attempting to enforce policies");

    let domain = split_username(account_id)
        .map(|(_, domain)| domain)
        .ok_or(anyhow!(
            "Failed to parse domain name from account id '{}'",
            account_id
        ))?;

    let intune_device_id = match config.get_intune_device_id(domain) {
        Some(id) => id,
        // This device isn't enrolled in Intune, there is nothing to enforce
        None => {
            debug!("Device not enrolled in Intune, skipping");
            return Ok(true);
        }
    };
    debug!(
        ?account_id,
        ?intune_device_id,
        "Applying policies for user and device"
    );

    let graph = Graph::new(&config.get_odc_provider(domain), domain, None, None, None)
        .await
        .map_err(|e| anyhow!(e))?;

    let endpoints = graph
        .intune_service_endpoints(graph_token)
        .await
        .map_err(|e| anyhow!(e))?;
    debug!("Discovered Intune service endpoints");

    let intune = IntuneForLinux::new(endpoints).map_err(|e| anyhow!(e))?;

    let token = UserToken {
        token_type: String::new(),
        scope: None,
        expires_in: 0,
        ext_expires_in: 0,
        refresh_token: String::new(),
        access_token: Some(intune_token.to_string()),
        client_info: ClientInfo::default(),
        id_token: IdToken::default(),
        prt: None,
    };

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
    debug!("Received policy enforcement actions:\n{:#?}", policies);
    let mut statuses: IntuneStatus = policies.into();
    statuses.set_device_id(intune_device_id.clone());

    let mut gp_extensions: Vec<Arc<dyn CSE>> = vec![
        Arc::new(ScriptsCSE::new(config, account_id)),
        Arc::new(ComplianceCSE::new(config, account_id)),
    ];

    if config.get_enable_experimental_intune_custom_compliance() {
        gp_extensions.push(Arc::new(CustomComplianceCSE::new(config, account_id)));
    }

    let mut errors = vec![];
    for ext in gp_extensions {
        match ext.process_group_policy(&mut statuses).await {
            Ok(_) => {}
            Err(e) => {
                errors.push(e);
            }
        }
    }
    debug!("Enforced Intune policy");

    // Report policy status
    debug!("Reporting Intune policy status:\n{:#?}", statuses);
    intune
        .status(&token, statuses)
        .await
        .map_err(|e| anyhow!(e))?;

    let iwservice_token = UserToken {
        token_type: String::new(),
        scope: None,
        expires_in: 0,
        ext_expires_in: 0,
        refresh_token: String::new(),
        access_token: Some(iwservice_token.to_string()),
        client_info: ClientInfo::default(),
        id_token: IdToken::default(),
        prt: None,
    };

    // Check compliance status
    sleep(Duration::from_secs(3));
    let device_info = intune
        .get_compliance_info(&iwservice_token, &intune_device_id)
        .await
        .map_err(|e| anyhow!(e))?;
    debug!(?device_info.compliance_state, "Intune compliance status");
    if !device_info.noncompliant_rules.is_empty() {
        error!(?device_info.noncompliant_rules, "Intune NonCompliant rules report");
    }

    /* TODO: Right now we ignore the NonCompliant Rules report because Custom
     * Compliance policy responses are not parsing correctly in Intune. Once
     * this issue is resolved, we can enforce NonCompliance.
     */

    if !errors.is_empty() {
        Err(anyhow!("Policy enforcement failed: {:?}", errors))
    } else {
        Ok(true)
    }
}
