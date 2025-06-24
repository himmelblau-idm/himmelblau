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
use serde_json::{json, Map, Value};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphResources {
    GroupReadWriteAll,
    UserReadWriteAll,
}

impl fmt::Display for GraphResources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id = match self {
            GraphResources::GroupReadWriteAll => "4e46008b-f24c-477d-8fff-7bb4ec7aafe0",
            GraphResources::UserReadWriteAll => "204e0828-b5ca-4ad8-b9f3-f32a958e7cc4",
        };
        write!(f, "{}", id)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtensionProperty {
    pub name: String,
    #[serde(rename = "dataType")]
    pub data_type: String,
    #[serde(rename = "targetObjects")]
    pub target_objects: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Applications {
    pub(crate) value: Vec<Application>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Application {
    #[serde(rename = "id")]
    pub(crate) object_id: String,
    #[serde(rename = "appId")]
    pub(crate) app_id: String,
    #[serde(rename = "displayName")]
    pub(crate) display_name: String,
}

macro_rules! extension_property {
    ($schema_client_id:ident, $property:expr) => {
        format!(
            "extension_{}_{}",
            $schema_client_id.replace('-', ""),
            $property
        )
    };
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
        redirect_uris: Vec<&str>,
        graph_resources: &[GraphResources],
    ) -> Result<()> {
        let url = format!("{}/v1.0/applications", self.graph_url);
        let mut body = json!({
            "displayName": display_name,
            "signInAudience": sign_in_audience.unwrap_or("AzureADMyOrg"),
        });
        if !graph_resources.is_empty() {
            body["requiredResourceAccess"] = json!([
                {
                    "resourceAppId": "00000003-0000-0000-c000-000000000000",
                    "resourceAccess": graph_resources.iter()
                        .map(|r| {
                            json!({
                                "id": r.to_string(),
                                "type": "Scope"
                            })
                        })
                        .collect::<Vec<_>>()
                }
            ]);
        }
        let mut redirects = vec![];
        for redirect_uri in redirect_uris {
            redirects.push(redirect_uri);
        }
        body["publicClient"] = json!({
            "redirectUris": redirects,
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

    pub(crate) async fn add_schema_extensions(
        &self,
        access_token: &str,
        object_id: &str,
    ) -> Result<(), anyhow::Error> {
        let url = format!(
            "{}/v1.0/applications/{}/extensionProperties",
            self.graph_url, object_id
        );

        let attrs = vec![
            ExtensionProperty {
                name: "uidNumber".into(),
                data_type: "Integer".into(),
                target_objects: vec!["User".into()],
            },
            ExtensionProperty {
                name: "gidNumber".into(),
                data_type: "Integer".into(),
                target_objects: vec!["User".into(), "Group".into()],
            },
            ExtensionProperty {
                name: "unixHomeDirectory".into(),
                data_type: "String".into(),
                target_objects: vec!["User".into()],
            },
            ExtensionProperty {
                name: "loginShell".into(),
                data_type: "String".into(),
                target_objects: vec!["User".into()],
            },
            ExtensionProperty {
                name: "gecos".into(),
                data_type: "String".into(),
                target_objects: vec!["User".into()],
            },
        ];

        for prop in attrs {
            let resp = self
                .client
                .post(&url)
                .bearer_auth(access_token)
                .json(&prop)
                .send()
                .await?;

            if !resp.status().is_success() {
                let text = resp.text().await?;
                error!("Failed to add extension property '{}': {}", prop.name, text);
            }
        }

        Ok(())
    }

    pub(crate) async fn list_schema_extensions(
        &self,
        access_token: &str,
        schema_app_object_id: &str,
    ) -> Result<Vec<ExtensionProperty>, anyhow::Error> {
        let url = format!(
            "https://graph.microsoft.com/v1.0/applications/{}/extensionProperties",
            schema_app_object_id
        );

        let resp = self
            .client
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Graph API error {}: {}", status, body));
        }

        let json: serde_json::Value = resp.json().await?;
        let props: Vec<ExtensionProperty> = serde_json::from_value(
            json.get("value")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Missing 'value' field in response"))?,
        )?;

        Ok(props)
    }

    pub(crate) async fn set_user_posix_attrs(
        &self,
        token: &str,
        user_id: &str,
        schema_client_id: &str,
        uid: Option<u32>,
        gid: Option<u32>,
        home: Option<String>,
        shell: Option<String>,
        gecos: Option<String>,
    ) -> Result<(), anyhow::Error> {
        let mut map = Map::new();

        if let Some(uid) = uid {
            map.insert(
                extension_property!(schema_client_id, "uidNumber"),
                json!(uid),
            );
        }
        if let Some(gid) = gid {
            map.insert(
                extension_property!(schema_client_id, "gidNumber"),
                json!(gid),
            );
        }
        if let Some(home) = home {
            map.insert(
                extension_property!(schema_client_id, "unixHomeDirectory"),
                json!(home),
            );
        }
        if let Some(shell) = shell {
            map.insert(
                extension_property!(schema_client_id, "loginShell"),
                json!(shell),
            );
        }
        if let Some(gecos) = gecos {
            map.insert(extension_property!(schema_client_id, "gecos"), json!(gecos));
        }

        if map.is_empty() {
            return Err(anyhow::anyhow!("No attributes specified"));
        }

        let url = format!("{}/v1.0/users/{}", self.graph_url, user_id);
        let resp = self
            .client
            .patch(&url)
            .bearer_auth(token)
            .json(&Value::Object(map))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Failed to update user {}: {}: {}",
                user_id,
                status,
                body
            ));
        }

        Ok(())
    }

    pub(crate) async fn set_group_posix_attrs(
        &self,
        token: &str,
        group_id: &str,
        schema_client_id: &str,
        gid: u32,
    ) -> Result<(), anyhow::Error> {
        let body = json!({
            extension_property!(schema_client_id, "gidNumber"): gid
        });

        let url = format!("{}/v1.0/groups/{}", self.graph_url, group_id);
        let resp = self
            .client
            .patch(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Failed to update group {}: {}: {}",
                group_id,
                status,
                body
            ));
        }

        Ok(())
    }
}
