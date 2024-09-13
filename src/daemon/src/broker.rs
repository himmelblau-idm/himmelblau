use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use himmelblau_unix_common::idprovider::himmelblau::HimmelblauMultiProvider;
use himmelblau_unix_common::idprovider::interface::Id;
use himmelblau_unix_common::resolver::Resolver;
use identity_dbus_broker::HimmelblauBroker;
use libc::uid_t;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;

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

pub(crate) struct Broker {
    pub(crate) cachelayer: Arc<Resolver<HimmelblauMultiProvider>>,
}

impl HimmelblauBroker for Broker {
    fn acquire_token_interactively(
        &mut self,
        protocol_version: String,
        correlation_id: String,
        request_json: String,
        uid: uid_t,
    ) -> Result<String, dbus::MethodErr> {
        self.acquire_token_silently(protocol_version, correlation_id, request_json, uid)
    }

    fn acquire_token_silently(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        request_json: String,
        uid: uid_t,
    ) -> Result<String, dbus::MethodErr> {
        let rt = Runtime::new().map_err(|e| dbus::MethodErr::failed(&format!("{:?}", e)))?;
        // Double check the user is making a request for their own account
        let user = rt
            .block_on(self.cachelayer.get_usertoken(Id::Gid(uid)))
            .map_err(|e| dbus::MethodErr::failed(&format!("Unable to load account: {:?}", e)))?
            .ok_or(dbus::MethodErr::failed("Unable to find account"))?;
        let request: TokenReq = serde_json::from_str(&request_json)
            .map_err(|e| dbus::MethodErr::failed(&format!("{:?}", e)))?;
        if request.account.username.to_lowercase() != user.spn.to_lowercase() {
            return Err(dbus::MethodErr::failed("Invalid request for user!"));
        }
        let scopes = request.auth_parameters.requested_scopes;
        let token = rt
            .block_on(
                self.cachelayer
                    .get_user_accesstoken(Id::Name(user.spn), scopes),
            )
            .ok_or(dbus::MethodErr::failed("Failed to authenticate user"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| dbus::MethodErr::failed(&format!("{:?}", e)))?;
        let res = json!({
            "brokerTokenResponse": {
                "accessToken": token.access_token.clone()
                    .ok_or(dbus::MethodErr::failed("Failed to fetch access token"))?,
                "accessTokenType": token.token_type,
                "clientInfo": URL_SAFE_NO_PAD.encode(json!(&token.client_info).to_string()),
                "expiresOn": (token.expires_in as u128) + now.as_millis(),
                "extendedExpiresOn": (token.ext_expires_in as u64) + now.as_secs(),
                "grantedScopes": token.scope.clone()
                    .ok_or(dbus::MethodErr::failed("Failed to fetch scopes"))?,
                "idToken": URL_SAFE_NO_PAD.encode(json!(&token.id_token).to_string()),
            }
        });
        Ok(res.to_string())
    }

    fn get_accounts(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        uid: uid_t,
    ) -> Result<String, dbus::MethodErr> {
        let rt = Runtime::new().map_err(|e| dbus::MethodErr::failed(&format!("{:?}", e)))?;
        // Only return the account for the requesting user
        let user = rt
            .block_on(self.cachelayer.get_usertoken(Id::Gid(uid)))
            .map_err(|e| dbus::MethodErr::failed(&format!("Unable to load account: {:?}", e)))?
            .ok_or(dbus::MethodErr::failed("Unable to find account"))?;
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

    fn remove_account(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        _uid: uid_t,
    ) -> Result<String, dbus::MethodErr> {
        Err(dbus::MethodErr::failed("Not implemented"))
    }

    fn acquire_prt_sso_cookie(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        request_json: String,
        uid: uid_t,
    ) -> Result<String, dbus::MethodErr> {
        let rt = Runtime::new().map_err(|e| dbus::MethodErr::failed(&format!("{:?}", e)))?;
        // Double check the user is making a request for their own account
        let user = rt
            .block_on(self.cachelayer.get_usertoken(Id::Gid(uid)))
            .map_err(|e| dbus::MethodErr::failed(&format!("Unable to load account: {:?}", e)))?
            .ok_or(dbus::MethodErr::failed("Unable to find account"))?;
        let request: SsoCookieReq = serde_json::from_str(&request_json)
            .map_err(|e| dbus::MethodErr::failed(&format!("{:?}", e)))?;
        if request.username.to_lowercase() != user.spn.to_lowercase() {
            return Err(dbus::MethodErr::failed("Invalid request for user!"));
        }
        rt.block_on(self.cachelayer.get_user_prt_cookie(Id::Name(user.spn)))
            .ok_or(dbus::MethodErr::failed("Failed to fetch prt sso cookie"))
    }

    fn generate_signed_http_request(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        _uid: uid_t,
    ) -> Result<String, dbus::MethodErr> {
        Err(dbus::MethodErr::failed("Not implemented"))
    }

    fn cancel_interactive_flow(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        _uid: uid_t,
    ) -> Result<String, dbus::MethodErr> {
        Err(dbus::MethodErr::failed("Not implemented"))
    }

    fn get_linux_broker_version(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        _uid: uid_t,
    ) -> Result<String, dbus::MethodErr> {
        let res = json!({
            "linuxBrokerVersion": env!("CARGO_PKG_VERSION"),
        });
        Ok(res.to_string())
    }
}
