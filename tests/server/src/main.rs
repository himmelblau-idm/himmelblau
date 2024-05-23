#[macro_use]
extern crate rocket;
use rocket::response::content;
use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::form_urlencoded;

static DOMAIN: &str = "contoso.samba.org";
static TENANT_ID: &str = "b4cfc615-064b-46c9-a06e-398a7c7b599f";

#[get("/?<domain>")]
fn federation_provider(domain: Option<&str>) -> Option<Value> {
    if let Some(domain) = domain {
        if domain == DOMAIN {
            return Some(json!({
                "tenantId": TENANT_ID,
                "authority_host": "127.0.0.1:8443",
                "graph": "https://127.0.0.1:8443",
            }));
        }
    }
    None
}

#[get("/")]
fn base() -> String {
    // This is how Himmelblau detects if the server is online
    "success".to_string()
}

#[get("/?<client_id>&<response_type>&<redirect_uri>&<prompt>&<scope>&<response_mode>&<sso_reload>&<amr_values>&<resource>")]
fn authorize(
    client_id: Option<&str>,
    response_type: Option<&str>,
    redirect_uri: Option<&str>,
    prompt: Option<&str>,
    scope: Option<&str>,
    response_mode: Option<&str>,
    sso_reload: bool,
    amr_values: Option<&str>,
    resource: Option<&str>,
) -> content::RawHtml<String> {
    let auth_config = json!({
        "sessionId": "12345",
        "sFT": "12345",
        "sCtx": "12345",
        "canary": "12345",
        "urlPost": "/common/login",
    });
    content::RawHtml(format!(
        r#"<body><script>$Config={}  //]]></script></body>"#,
        auth_config.to_string()
    ))
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct GetCredentialType {
    username: String,
    #[serde(rename = "isOtherIdpSupported")]
    is_other_idp_supported: bool,
    #[serde(rename = "checkPhones")]
    check_phones: bool,
    #[serde(rename = "isRemoteNGCSupported")]
    is_remote_ngc_supported: bool,
    #[serde(rename = "isCookieBannerShown")]
    is_cookie_banner_shown: bool,
    #[serde(rename = "isFidoSupported")]
    is_fido_supported: bool,
    #[serde(rename = "originalRequest")]
    original_request: String,
    #[serde(rename = "flowToken")]
    flow_token: String,
}

#[post("/", format = "json", data = "<payload>")]
fn get_cred_type(payload: Json<GetCredentialType>) -> Value {
    assert_eq!(payload.username.to_lowercase(), format!("tux@{}", DOMAIN));
    return json!({
        "Credentials": {
            "FederationRedirectUrl": None::<String>,
            "HasPassword": true,
        },
        "ThrottleStatus": 0,
        "IfExistsResult": 0,
    });
}

#[post("/", data = "<payload>")]
fn login(payload: String) -> Option<content::RawHtml<String>> {
    let params: HashMap<String, String> = form_urlencoded::parse(&payload.into_bytes())
        .into_owned()
        .collect();
    match params.get("passwd") {
        Some(passwd) => assert_eq!(passwd, "password"),
        None => return None,
    }
    match params.get("login") {
        Some(login) => assert_eq!(&format!("tux@{}", DOMAIN), login),
        None => return None,
    }
    let auth_config = json!({
        "sessionId": "12345",
        "sFT": "12345",
        "sCtx": "12345",
        "canary": "12345",
        "arrUserProofs": [
            {
                "authMethodId": "PhoneAppOTP",
                "isDefault": true,
                "display": "",
            }
        ],
        "urlEndAuth": "/common/SAS/EndAuth",
        "urlBeginAuth": "/common/SAS/BeginAuth",
        "urlPost": "/common/SAS/ProcessAuth",
    });
    Some(content::RawHtml(format!(
        r#"<body><script>$Config={}  //]]></script></body>"#,
        auth_config.to_string()
    )))
}

#[post("/")]
fn token() {
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/odc/v2.1/federationProvider", routes![federation_provider])
        .mount(
            format!("/{}/oauth2/authorize", TENANT_ID),
            routes![authorize],
        )
        .mount(
            format!("/{}/GetCredentialType", TENANT_ID),
            routes![get_cred_type],
        )
        .mount("/common/login", routes![login])
        .mount(
            format!("/{}/oauth2/v2.0/token", TENANT_ID),
            routes![token],
        )
        .mount("/", routes![base])
}
