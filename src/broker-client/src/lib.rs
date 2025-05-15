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
use serde_json::Value;
use zbus::{proxy, Connection};

#[macro_export]
macro_rules! user_token_from_broker_token_resp {
    ($token:expr) => {{
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!(e))?;
        UserToken {
            token_type: $token
                .get("accessTokenType")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing accessTokenType"))?
                .to_string(),
            scope: $token
                .get("grantedScopes")
                .and_then(|v| v.as_str())
                .map(String::from),
            expires_in: ($token
                .get("expiresOn")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                - now.as_secs()) as u32,
            ext_expires_in: ($token
                .get("extendedExpiresOn")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                - now.as_secs()) as u32,
            access_token: $token
                .get("accessToken")
                .and_then(|v| v.as_str())
                .map(String::from),
            refresh_token: String::new(),
            id_token: $token
                .get("idToken")
                .and_then(|v| v.as_str())
                .map(|s| IdToken::from_str(s))
                .transpose()
                .map_err(|e| anyhow!(e))?
                .ok_or_else(|| anyhow!("Missing or invalid idToken"))?,
            client_info: $token
                .get("clientInfo")
                .and_then(|v| v.as_str())
                .map(|s| ClientInfo::from_str(s))
                .transpose()
                .map_err(|e| anyhow!(e))?
                .ok_or_else(|| anyhow!("Missing or invalid clientInfo"))?,
            prt: None,
        }
    }};
}

#[proxy(
    interface = "com.microsoft.identity.Broker1",
    default_service = "com.microsoft.identity.broker1",
    default_path = "/com/microsoft/identity/broker1"
)]
trait IdentityBroker {
    #[zbus(name = "acquirePrtSsoCookie")]
    fn acquire_prt_sso_cookie(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &str,
    ) -> zbus::Result<String>;

    #[zbus(name = "acquireTokenInteractively")]
    fn acquire_token_interactively(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &str,
    ) -> zbus::Result<String>;

    #[zbus(name = "acquireTokenSilently")]
    fn acquire_token_silently(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &str,
    ) -> zbus::Result<String>;

    #[zbus(name = "cancelInteractiveFlow")]
    fn cancel_interactive_flow(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &str,
    ) -> zbus::Result<String>;

    #[zbus(name = "generateSignedHttpRequest")]
    fn generate_signed_http_request(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &str,
    ) -> zbus::Result<String>;

    #[zbus(name = "getAccounts")]
    fn get_accounts(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &str,
    ) -> zbus::Result<String>;

    #[zbus(name = "getLinuxBrokerVersion")]
    fn get_linux_broker_version(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &str,
    ) -> zbus::Result<String>;

    #[zbus(name = "removeAccount")]
    fn remove_account(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &str,
    ) -> zbus::Result<String>;
}

pub struct BrokerClient {
    connection: Connection,
}

#[allow(dead_code)]
impl BrokerClient {
    pub async fn new() -> zbus::Result<Self> {
        Ok(Self {
            connection: Connection::session().await?,
        })
    }

    async fn proxy(&self) -> zbus::Result<IdentityBrokerProxy<'_>> {
        IdentityBrokerProxy::new(&self.connection).await
    }

    pub async fn acquire_prt_sso_cookie(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &Value,
    ) -> zbus::Result<Value> {
        let proxy = self.proxy().await?;
        let response_str = proxy
            .acquire_prt_sso_cookie(
                protocol_version,
                correlation_id,
                &serde_json::to_string(request_json)
                    .map_err(|e| zbus::Error::Failure(e.to_string()))?,
            )
            .await?;
        serde_json::from_str(&response_str).map_err(|e| zbus::Error::Failure(e.to_string()))
    }

    pub async fn acquire_token_interactively(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &Value,
    ) -> zbus::Result<Value> {
        let proxy = self.proxy().await?;
        let response_str = proxy
            .acquire_token_interactively(
                protocol_version,
                correlation_id,
                &serde_json::to_string(request_json)
                    .map_err(|e| zbus::Error::Failure(e.to_string()))?,
            )
            .await?;
        serde_json::from_str(&response_str).map_err(|e| zbus::Error::Failure(e.to_string()))
    }

    pub async fn acquire_token_silently(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &Value,
    ) -> zbus::Result<Value> {
        let proxy = self.proxy().await?;
        let response_str = proxy
            .acquire_token_silently(
                protocol_version,
                correlation_id,
                &serde_json::to_string(request_json)
                    .map_err(|e| zbus::Error::Failure(e.to_string()))?,
            )
            .await?;
        serde_json::from_str(&response_str).map_err(|e| zbus::Error::Failure(e.to_string()))
    }

    pub async fn cancel_interactive_flow(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &Value,
    ) -> zbus::Result<Value> {
        let proxy = self.proxy().await?;
        let response_str = proxy
            .cancel_interactive_flow(
                protocol_version,
                correlation_id,
                &serde_json::to_string(request_json)
                    .map_err(|e| zbus::Error::Failure(e.to_string()))?,
            )
            .await?;
        serde_json::from_str(&response_str).map_err(|e| zbus::Error::Failure(e.to_string()))
    }

    pub async fn generate_signed_http_request(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &Value,
    ) -> zbus::Result<Value> {
        let proxy = self.proxy().await?;
        let response_str = proxy
            .generate_signed_http_request(
                protocol_version,
                correlation_id,
                &serde_json::to_string(request_json)
                    .map_err(|e| zbus::Error::Failure(e.to_string()))?,
            )
            .await?;
        serde_json::from_str(&response_str).map_err(|e| zbus::Error::Failure(e.to_string()))
    }

    pub async fn get_accounts(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &Value,
    ) -> zbus::Result<Value> {
        let proxy = self.proxy().await?;
        let response_str = proxy
            .get_accounts(
                protocol_version,
                correlation_id,
                &serde_json::to_string(request_json)
                    .map_err(|e| zbus::Error::Failure(e.to_string()))?,
            )
            .await?;
        serde_json::from_str(&response_str).map_err(|e| zbus::Error::Failure(e.to_string()))
    }

    pub async fn get_linux_broker_version(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &Value,
    ) -> zbus::Result<Value> {
        let proxy = self.proxy().await?;
        let response_str = proxy
            .get_linux_broker_version(
                protocol_version,
                correlation_id,
                &serde_json::to_string(request_json)
                    .map_err(|e| zbus::Error::Failure(e.to_string()))?,
            )
            .await?;
        serde_json::from_str(&response_str).map_err(|e| zbus::Error::Failure(e.to_string()))
    }

    pub async fn remove_account(
        &self,
        protocol_version: &str,
        correlation_id: &str,
        request_json: &Value,
    ) -> zbus::Result<Value> {
        let proxy = self.proxy().await?;
        let response_str = proxy
            .remove_account(
                protocol_version,
                correlation_id,
                &serde_json::to_string(request_json)
                    .map_err(|e| zbus::Error::Failure(e.to_string()))?,
            )
            .await?;
        serde_json::from_str(&response_str).map_err(|e| zbus::Error::Failure(e.to_string()))
    }
}
