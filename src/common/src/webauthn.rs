//! PAM security-key ceremonies for the configured native OIDC origin.
//! Entra's separate FIDO and hybrid transport implementation stays in auth.rs.
use crate::auth::{fido_status_check, MessagePrinter};
use crate::i18n::tr;
use crate::unix_proto::WebAuthnOperation;
use authenticator::{
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
    ctap2::server::{
        AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
        ResidentKeyRequirement, UserVerificationRequirement,
    },
    statecallback::StateCallback,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use okta::webauthn::{AssertionCredential, AttestationCredential, WebAuthnAdapter};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    sync::{mpsc::channel, Arc},
    time::Duration,
};

fn bytes(value: &Value) -> Result<Vec<u8>, ()> {
    let values = value.as_array().ok_or(())?;
    if values.len() > 65536 {
        return Err(());
    }
    values
        .iter()
        .map(|v| {
            v.as_f64()
                .filter(|n| n.is_finite() && n.fract() == 0.0 && *n >= 0.0 && *n <= 255.0)
                .map(|n| n as u8)
                .ok_or(())
        })
        .collect()
}

fn descriptors(value: &Value) -> Result<Vec<PublicKeyCredentialDescriptor>, ()> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    let values = value.as_array().ok_or(())?;
    if values.len() > 128 {
        return Err(());
    }
    values
        .iter()
        .map(|v| {
            if v["type"] != "public-key" {
                return Err(());
            }
            Ok(PublicKeyCredentialDescriptor {
                id: bytes(&v["id"])?,
                transports: vec![],
            })
        })
        .collect()
}

fn verification(value: &Value) -> Result<UserVerificationRequirement, ()> {
    match value.as_str() {
        Some("required") => Ok(UserVerificationRequirement::Required),
        Some("discouraged") => Ok(UserVerificationRequirement::Discouraged),
        Some("preferred") | None => Ok(UserVerificationRequirement::Preferred),
        _ => Err(()),
    }
}

fn relying_party(origin: &str, supplied: Option<&str>) -> Result<String, ()> {
    let url = reqwest::Url::parse(origin).map_err(|_| ())?;
    if url.scheme() != "https" || url.origin().ascii_serialization() != origin {
        return Err(());
    }
    let host = url.domain().ok_or(())?;
    let rp = supplied.unwrap_or(host);
    // Keep credentials scoped to the configured origin. Parent-domain RP IDs
    // require an explicit trusted-origin policy before they can be supported.
    if rp != host {
        return Err(());
    }
    Ok(rp.into())
}

pub(crate) fn perform(
    printer: Arc<dyn MessagePrinter>,
    operation: WebAuthnOperation,
    origin: &str,
    options: &Value,
    configured_timeout_ms: u64,
) -> Result<Value, ()> {
    let public = &options["publicKey"];
    let supplied_rp = match operation {
        WebAuthnOperation::Get => public["rpId"].as_str(),
        WebAuthnOperation::Create => public["rp"]["id"].as_str(),
    };
    let rp = relying_party(origin, supplied_rp)?;
    let timeout_ms = configured_timeout_ms.clamp(1000, 300_000).min(
        public["timeout"]
            .as_u64()
            .unwrap_or(300_000)
            .clamp(1000, 300_000),
    );
    let timeout = Duration::from_millis(timeout_ms) + Duration::from_secs(1);
    let client_data_json = serde_json::to_vec(&json!({
        "type": match operation { WebAuthnOperation::Get => "webauthn.get", WebAuthnOperation::Create => "webauthn.create" },
        "challenge": URL_SAFE_NO_PAD.encode(bytes(&public["challenge"])?),
        "origin": origin, "crossOrigin": false,
    })).map_err(|_| ())?;
    let client_data_hash = Sha256::digest(&client_data_json).into();
    let mut service = AuthenticatorService::new().map_err(|_| ())?;
    service.add_u2f_usb_hid_platform_transports();
    printer.print_text(&format!(
        "[FIDO_INSERT] {}",
        tr("Insert your security key.")
    ));
    let status = fido_status_check(printer, tr("Touch your security key."));
    let adapter = WebAuthnAdapter::new().map_err(|_| ())?;
    let result = match operation {
        WebAuthnOperation::Get => {
            let allow_list = descriptors(&public["allowCredentials"])?;
            let args = SignArgs {
                client_data_hash,
                origin: origin.into(),
                relying_party_id: rp,
                allow_list: allow_list.clone(),
                user_verification_req: verification(&public["userVerification"])?,
                user_presence_req: true,
                extensions: AuthenticationExtensionsClientInputs::default(),
                pin: None,
                use_ctap1_fallback: false,
            };
            let (tx, rx) = channel();
            service
                .sign(
                    timeout_ms,
                    args,
                    status,
                    StateCallback::new(Box::new(move |result| {
                        let _ = tx.send(result);
                    })),
                )
                .map_err(|_| ())?;
            let result = rx
                .recv_timeout(timeout)
                .map_err(|_| ())
                .and_then(|r| r.map_err(|_| ()));
            let _ = service.cancel();
            let assertion = result?.assertion;
            let id = assertion
                .credentials
                .as_ref()
                .map(|c| c.id.as_slice())
                .or_else(|| {
                    if allow_list.len() == 1 {
                        Some(allow_list[0].id.as_slice())
                    } else {
                        None
                    }
                })
                .ok_or(())?;
            adapter.assertion(&AssertionCredential {
                id: URL_SAFE_NO_PAD.encode(id),
                client_data_json,
                authenticator_data: assertion.auth_data.to_vec(),
                signature: assertion.signature,
            })
        }
        WebAuthnOperation::Create => {
            let selection = &public["authenticatorSelection"];
            if selection["authenticatorAttachment"] == "platform" {
                return Err(());
            }
            let resident_key_req = if selection["requireResidentKey"] == true {
                ResidentKeyRequirement::Required
            } else {
                match selection["residentKey"].as_str() {
                    Some("required") => ResidentKeyRequirement::Required,
                    Some("preferred") => ResidentKeyRequirement::Preferred,
                    Some("discouraged") | None => ResidentKeyRequirement::Discouraged,
                    _ => return Err(()),
                }
            };
            let params = public["pubKeyCredParams"].as_array().ok_or(())?;
            let mut pub_cred_params = Vec::new();
            for param in params {
                if param["type"] != "public-key" {
                    continue;
                }
                let algorithm = param["alg"]
                    .as_i64()
                    .and_then(|n| i32::try_from(n).ok())
                    .ok_or(())?;
                if let Ok(param) = PublicKeyCredentialParameters::try_from(algorithm) {
                    pub_cred_params.push(param);
                }
            }
            if pub_cred_params.is_empty() {
                return Err(());
            }
            let args = RegisterArgs {
                client_data_hash,
                origin: origin.into(),
                relying_party: RelyingParty {
                    id: rp,
                    name: public["rp"]["name"].as_str().map(str::to_owned),
                },
                user: PublicKeyCredentialUserEntity {
                    id: bytes(&public["user"]["id"])?,
                    name: public["user"]["name"].as_str().map(str::to_owned),
                    display_name: public["user"]["displayName"].as_str().map(str::to_owned),
                },
                pub_cred_params,
                exclude_list: descriptors(&public["excludeCredentials"])?,
                user_verification_req: verification(&selection["userVerification"])?,
                resident_key_req,
                extensions: AuthenticationExtensionsClientInputs::default(),
                pin: None,
                use_ctap1_fallback: false,
            };
            let (tx, rx) = channel();
            service
                .register(
                    timeout_ms,
                    args,
                    status,
                    StateCallback::new(Box::new(move |result| {
                        let _ = tx.send(result);
                    })),
                )
                .map_err(|_| ())?;
            let result = rx
                .recv_timeout(timeout)
                .map_err(|_| ())
                .and_then(|r| r.map_err(|_| ()));
            let _ = service.cancel();
            let result = result?;
            let data = result
                .att_obj
                .auth_data
                .credential_data
                .as_ref()
                .ok_or(())?;
            adapter.attestation(&AttestationCredential {
                id: URL_SAFE_NO_PAD.encode(&data.credential_id),
                client_data_json,
                attestation_object: serde_cbor::to_vec(&result.att_obj).map_err(|_| ())?,
                transports: vec!["usb".into()],
            })
        }
    };
    result.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rp_is_bound_to_the_configured_https_origin() {
        assert_eq!(
            relying_party("https://tenant.okta.com", None).unwrap(),
            "tenant.okta.com"
        );
        assert!(relying_party("https://tenant.okta.com", Some("attacker.example")).is_err());
        assert!(relying_party("https://tenant.okta.com", Some("com")).is_err());
        assert!(relying_party("http://tenant.okta.com", None).is_err());
    }
    #[test]
    fn binary_options_reject_out_of_range_and_fractional_bytes() {
        assert_eq!(bytes(&json!([0, 255])).unwrap(), [0, 255]);
        assert!(bytes(&json!([256])).is_err());
        assert!(bytes(&json!([1.5])).is_err());
    }
}
