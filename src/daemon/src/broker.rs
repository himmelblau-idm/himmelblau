use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use himmelblau_unix_common::idprovider::himmelblau::HimmelblauMultiProvider;
use himmelblau_unix_common::idprovider::interface::Id;
use himmelblau_unix_common::resolver::Resolver;
use identity_dbus_broker::HimmelblauBroker;
use libc::uid_t;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug)]
struct AccountReq {
    username: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthParametersReq {
    #[serde(rename = "requestedScopes")]
    requested_scopes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenReq {
    account: AccountReq,
    #[serde(rename = "authParameters")]
    auth_parameters: AuthParametersReq,
}

#[derive(Serialize, Deserialize, Debug)]
struct SsoCookieReq {
    username: String,
}

#[derive(Clone)]
pub(crate) struct Broker {
    pub(crate) cachelayer: Arc<Resolver<HimmelblauMultiProvider>>,
}

#[async_trait]
impl HimmelblauBroker for Broker {
    async fn acquire_token_interactively(
        &mut self,
        protocol_version: String,
        correlation_id: String,
        request_json: String,
        uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        self.acquire_token_silently(protocol_version, correlation_id, request_json, uid)
            .await
    }

    async fn acquire_token_silently(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        request_json: String,
        uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        // Double check the user is making a request for their own account
        let user = self
            .cachelayer
            .get_usertoken(Id::Gid(uid))
            .await
            .map_err(|_| "Unable to load account")?
            .ok_or("Unable to find account")?;
        let request: TokenReq =
            serde_json::from_str(&request_json).map_err(|e| format!("{:?}", e))?;
        if request.account.username.to_lowercase() != user.spn.to_lowercase() {
            return Err("Invalid request for user!".into());
        }
        let scopes = request.auth_parameters.requested_scopes;
        let token = self
            .cachelayer
            .get_user_accesstoken(Id::Name(user.spn), scopes)
            .await
            .ok_or("Failed to authenticate user")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("{:?}", e))?;
        let res = json!({
            "brokerTokenResponse": {
                "accessToken": token.access_token.clone()
                    .ok_or(Box::new(io::Error::new(io::ErrorKind::Other, "Failed to fetch access token")))?,
                "accessTokenType": token.token_type,
                "clientInfo": URL_SAFE_NO_PAD.encode(json!(&token.client_info).to_string()),
                "expiresOn": (token.expires_in as u128) + now.as_millis(),
                "extendedExpiresOn": (token.ext_expires_in as u64) + now.as_secs(),
                "grantedScopes": token.scope.clone()
                    .ok_or(Box::new(io::Error::new(io::ErrorKind::Other, "Failed to fetch scopes")))?,
                "idToken": URL_SAFE_NO_PAD.encode(json!(&token.id_token).to_string()),
            }
        });
        Ok(res.to_string())
    }

    async fn get_accounts(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        // Only return the account for the requesting user
        let user = self
            .cachelayer
            .get_usertoken(Id::Gid(uid))
            .await
            .map_err(|_| "Unable to load account")?
            .ok_or("Unable to find account")?;
        let res = json!({
            "accounts": [
                {
                    "givenName": user.displayname,
                    "homeAccountId": format!("{}.{}", user.uuid.to_string(), user.tenant_id.to_string()),
                    "localAccountId": user.uuid.to_string(),
                    "name": user.displayname,
                    "realm": user.tenant_id.to_string(),
                    "username": user.spn
                }
            ]
        });
        Ok(res.to_string())
    }

    async fn remove_account(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        _uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        Err("Not implemented".into())
    }

    async fn acquire_prt_sso_cookie(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        request_json: String,
        uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        // Double check the user is making a request for their own account
        let user = self
            .cachelayer
            .get_usertoken(Id::Gid(uid))
            .await
            .map_err(|_| "Unable to load account")?
            .ok_or("Unable to find account")?;
        let request: SsoCookieReq =
            serde_json::from_str(&request_json).map_err(|e| format!("{:?}", e))?;
        if request.username.to_lowercase() != user.spn.to_lowercase() {
            return Err("Invalid request for user!".into());
        }
        self.cachelayer
            .get_user_prt_cookie(Id::Name(user.spn))
            .await
            .ok_or("Failed to fetch prt sso cookie".into())
    }

    async fn generate_signed_http_request(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        _uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        Err("Not implemented".into())
    }

    async fn cancel_interactive_flow(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        _uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        Err("Not implemented".into())
    }

    async fn get_linux_broker_version(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        _uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        let res = json!({
            "linuxBrokerVersion": env!("CARGO_PKG_VERSION"),
        });
        Ok(res.to_string())
    }
}
