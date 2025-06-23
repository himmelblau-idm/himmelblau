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
use anyhow::{anyhow, Result};
use himmelblau::graph::Graph;
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Applications {
    pub(crate) value: Vec<Application>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Application {
    #[serde(rename = "appId")]
    pub(crate) app_id: String,
    #[serde(rename = "displayName")]
    pub(crate) display_name: String,
}

pub(crate) struct CliGraph {
    client: Client,
    graph_url: String,
}

impl CliGraph {
    pub(crate) async fn new(graph: &Graph) -> Result<CliGraph> {
        Ok(CliGraph {
            client: Client::new(),
            graph_url: graph.graph_url().await.map_err(|e| anyhow!(e))?,
        })
    }

    pub(crate) async fn list_applications(&self, access_token: &str) -> Result<Applications> {
        let url = format!("{}/v1.0/applications", self.graph_url,);
        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| anyhow!(e))?;
        if resp.status().is_success() {
            let json_resp: Applications = resp.json().await.map_err(|e| anyhow!(e))?;
            Ok(json_resp)
        } else {
            Err(anyhow!(resp.status()))
        }
    }

    pub(crate) async fn create_application(
        &self,
        access_token: &str,
        display_name: &str,
        sign_in_audience: Option<&str>,
    ) -> Result<()> {
        let url = format!("{}/v1.0/applications", self.graph_url,);
        let body = json!({
            "displayName": display_name,
            "signInAudience": sign_in_audience.unwrap_or("AzureADMyOrg"),
        });
        let resp = self
            .client
            .post(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!(e))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!(resp.status()))
        }
    }
}
