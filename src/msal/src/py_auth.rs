use anyhow::{anyhow, Result};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::IntoPyDict;
use pyo3::types::PyDict;
use pyo3::types::PyList;
use pyo3::types::PyString;
use pyo3::types::PyTuple;
use std::collections::HashMap;
use tracing::error;
use uuid::Uuid;

pub const INVALID_CRED: u32 = 0xC3CE;
pub const REQUIRES_MFA: u32 = 0xC39C;
pub const INVALID_USER: u32 = 0xC372;
pub const NO_CONSENT: u32 = 0xFDE9;
pub const NO_GROUP_CONSENT: u32 = 0xFDEA;
pub const NO_SECRET: u32 = 0x6AD09A;
pub const AUTH_PENDING: u32 = 0x11180;

pub struct PublicClientApplication {
    app: Py<PyAny>,
}

pub struct ConfidentialClientApplication {
    app: Py<PyAny>,
}

#[derive(Default)]
pub struct UnixUserToken {
    pub spn: String,
    pub displayname: String,
    pub uuid: Uuid,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,

    /* These are only present on failure */
    pub errors: Vec<u32>,
    pub error: String,
    pub error_description: String,
}

impl<'a> FromPyObject<'a> for UnixUserToken {
    fn extract(obj: &'a PyAny) -> PyResult<Self> {
        let dict_obj: &PyDict = obj.extract()?;
        let mut res: UnixUserToken = Default::default();
        for (key, val) in dict_obj.iter() {
            let py_key: &PyString = key.extract()?;
            let k: String = py_key.to_string_lossy().into_owned();
            if k == "error_codes" {
                let error_codes: &PyList = val.extract()?;
                res.errors = error_codes.extract()?;
            } else if k == "id_token_claims" {
                let py_val: &PyDict = val.extract()?;
                for (skey, sval) in py_val.iter() {
                    let py_skey: &PyString = skey.extract()?;
                    let sk: String = py_skey.to_string_lossy().into_owned();
                    match sk.as_str() {
                        "name" => res.displayname = sval.extract()?,
                        "preferred_username" => res.spn = sval.extract()?,
                        "oid" => {
                            res.uuid = match Uuid::parse_str(sval.extract()?) {
                                Ok(uuid) => uuid,
                                Err(e) => {
                                    error!("Failed parsing user uuid: {}", e);
                                    return Err(PyValueError::new_err(format!(
                                        "Failed parsing user uuid: {}",
                                        e
                                    )));
                                }
                            };
                        }
                        &_ => {} // Ignore the others
                    }
                }
            } else if k == "access_token" {
                let py_val: &PyString = match val.extract() {
                    Ok(val) => val,
                    Err(_e) => {
                        return Err(PyValueError::new_err(
                            "Failed extracting access_token from auth response",
                        ));
                    }
                };
                let access_token: String = py_val.to_string_lossy().into_owned();
                res.access_token = Some(access_token);
            } else if k == "refresh_token" {
                let py_val: &PyString = match val.extract() {
                    Ok(val) => val,
                    Err(_e) => {
                        return Err(PyValueError::new_err(
                            "Failed extracting refresh_token from auth response",
                        ));
                    }
                };
                let refresh_token: String = py_val.to_string_lossy().into_owned();
                res.refresh_token = Some(refresh_token);
            } else if k == "error" {
                let msg: &PyString = val.extract()?;
                res.error = msg.extract()?;
            } else if k == "error_description" {
                let msg: &PyString = val.extract()?;
                res.error_description = msg.extract()?;
            }
        }
        Ok(res)
    }
}

#[derive(Default)]
pub struct DeviceToken {
    pub access_token: Option<String>,

    /* These are only present on failure */
    pub errors: Vec<u32>,
    pub error: String,
    pub error_description: String,
}

impl<'a> FromPyObject<'a> for DeviceToken {
    fn extract(obj: &'a PyAny) -> PyResult<Self> {
        let dict_obj: &PyDict = obj.extract()?;
        let mut res: DeviceToken = Default::default();
        for (key, val) in dict_obj.iter() {
            let py_key: &PyString = key.extract()?;
            let k: String = py_key.to_string_lossy().into_owned();
            if k == "access_token" {
                let py_val: &PyString = match val.extract() {
                    Ok(val) => val,
                    Err(_e) => {
                        return Err(PyValueError::new_err(
                            "Failed extracting access_token from auth response",
                        ));
                    }
                };
                let access_token: String = py_val.to_string_lossy().into_owned();
                res.access_token = Some(access_token);
            } else if k == "error" {
                let msg: &PyString = val.extract()?;
                res.error = msg.extract()?;
            } else if k == "error_description" {
                let msg: &PyString = val.extract()?;
                res.error_description = msg.extract()?;
            }
        }
        Ok(res)
    }
}

/* RFC8628: 3.2. Device Authorization Response */
#[derive(Default, Clone)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    /* MS doesn't implement verification_uri_complete yet, but our
     * authentication will be simpler once they do, so assume it works and fall
     * back to verification_uri if it doesn't.
     */
    pub verification_uri_complete: Option<String>,
    pub expires_in: u32,
    pub interval: Option<u32>,
    pub message: Option<String>,
}

impl<'a> FromPyObject<'a> for DeviceAuthorizationResponse {
    fn extract(obj: &'a PyAny) -> PyResult<Self> {
        let dict_obj: &PyDict = obj.extract()?;
        let mut res: DeviceAuthorizationResponse = Default::default();
        for (key, val) in dict_obj.iter() {
            let py_key: &PyString = key.extract()?;
            let k: String = py_key.to_string_lossy().into_owned();
            match k.as_str() {
                "device_code" => res.device_code = val.extract()?,
                "user_code" => res.user_code = val.extract()?,
                "verification_uri" => res.verification_uri = val.extract()?,
                "verification_uri_complete" => res.verification_uri_complete = Some(val.extract()?),
                "expires_in" => res.expires_in = val.extract()?,
                "interval" => res.interval = Some(val.extract()?),
                "message" => res.message = Some(val.extract()?),
                &_ => {}
            }
        }
        Ok(res)
    }
}

pub struct ClientCredential {
    pub client_assertion: String,
}

pub trait ClientApplication {
    fn app(&self) -> &Py<PyAny>;
    fn new(
        app_id: &str,
        authority_url: &str,
        client_credential: Option<ClientCredential>,
    ) -> Result<Self>
    where
        Self: Sized;

    fn acquire_token_by_username_password(
        &self,
        username: &str,
        password: &str,
        scopes: Vec<&str>,
    ) -> Result<UnixUserToken> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self
                .app()
                .getattr(py, "acquire_token_by_username_password")?;
            let py_username: &PyString = PyString::new(py, username);
            let py_password: &PyString = PyString::new(py, password);
            let py_scopes: &PyList = PyList::new(py, scopes);
            let largs: &PyList = PyList::new(py, vec![py_username, py_password]);
            largs.append(py_scopes)?;
            let args: &PyTuple = PyTuple::new(py, largs);
            let resp: Py<PyAny> = func.call1(py, args)?;
            let token: UnixUserToken = resp.extract(py)?;
            Ok(token)
        })
    }

    fn acquire_token_silent(&self, scopes: Vec<&str>, username: &str) -> Result<UnixUserToken> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app().getattr(py, "acquire_token_silent")?;
            let py_scopes: &PyList = PyList::new(py, scopes);
            let account = match self.get_accounts() {
                Ok(accounts) => {
                    match accounts
                        .iter()
                        .find(|tok| match tok.get("username") {
                            Some(val) => val == username,
                            None => false,
                        })
                        .cloned()
                    {
                        Some(account) => account,
                        None => {
                            return Err(anyhow!(
                                "Failed to locate user '{}' in auth cache",
                                username
                            ))
                        }
                    }
                }
                Err(e) => return Err(anyhow!("{}", e)),
            };
            let largs: &PyList = PyList::new(py, vec![py_scopes]);
            largs.append(account.clone())?;
            let args: &PyTuple = PyTuple::new(py, largs);
            let resp: Py<PyAny> = func.call1(py, args)?;
            let mut token: UnixUserToken = resp.extract(py)?;
            token.spn = match account.get("username") {
                Some(spn) => spn.to_string(),
                None => return Err(anyhow!("Failed getting account username")),
            };
            token.uuid = match account.get("local_account_id") {
                Some(oid) => match Uuid::parse_str(oid) {
                    Ok(uuid) => uuid,
                    Err(_e) => return Err(anyhow!("Failed getting account uuid")),
                },
                None => return Err(anyhow!("Failed getting account uuid")),
            };
            Ok(token)
        })
    }

    fn get_authorization_request_url(
        &self,
        scopes: Vec<&str>,
        login_hint: &str,
        prompt: &str,
        domain_hint: &str,
    ) -> Result<String> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = match self.app().getattr(py, "get_authorization_request_url") {
                Ok(func) => func,
                Err(_e) => {
                    return Err(anyhow!(
                        "Failed loading function get_authorization_request_url"
                    ))
                }
            };
            let py_scopes: &PyList = PyList::new(py, scopes);
            let py_login_hint: &PyString = PyString::new(py, login_hint);
            let py_redirect_uri: &PyString = PyString::new(py, "http://localhost");
            let py_prompt: &PyString = PyString::new(py, prompt);
            let py_domain_hint: &PyString = PyString::new(py, domain_hint);
            let args = (py_scopes,);
            let kwargs = PyDict::new(py);
            match kwargs.set_item("login_hint", py_login_hint) {
                Ok(()) => (),
                Err(_e) => return Err(anyhow!("Failed setting login_hint")),
            };
            match kwargs.set_item("redirect_uri", py_redirect_uri) {
                Ok(()) => (),
                Err(_e) => return Err(anyhow!("Failed setting redirect_uri")),
            };
            match kwargs.set_item("prompt", py_prompt) {
                Ok(()) => (),
                Err(_e) => return Err(anyhow!("Failed setting prompt")),
            };
            match kwargs.set_item("domain_hint", py_domain_hint) {
                Ok(()) => (),
                Err(_e) => return Err(anyhow!("Failed setting domain_hint")),
            };
            match func.call(py, args, Some(kwargs)) {
                Ok(any) => match any.downcast::<PyString>(py) {
                    Ok(ret) => Ok(ret.to_string()),
                    Err(_e) => Err(anyhow!("Failed downcasting the PyAny to a PyString")),
                },
                Err(_e) => Err(anyhow!("Failed calling acquire_token_interactive")),
            }
        })
    }

    fn get_accounts(&self) -> Result<Vec<HashMap<String, String>>> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = match self.app().getattr(py, "get_accounts") {
                Ok(func) => func,
                Err(_e) => return Err(anyhow!("Failed loading function get_accounts")),
            };
            match func.call0(py) {
                Ok(accounts) => match accounts.extract(py) {
                    Ok(extracted) => Ok(extracted),
                    Err(_e) => Err(anyhow!("Extraction to a list of hashmaps failed")),
                },
                Err(_e) => Err(anyhow!("Failed calling get_accounts")),
            }
        })
    }

    fn get_account(&self, account_id: &str) -> Option<HashMap<String, String>> {
        match self.get_accounts() {
            Ok(accounts) => accounts
                .iter()
                .find(|tok| match tok.get("username") {
                    Some(username) => username == account_id,
                    None => false,
                })
                .cloned(),
            Err(_e) => None,
        }
    }

    fn remove_account(&self, username: &str) -> Result<()> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app().getattr(py, "remove_account")?;
            if let Some(py_account) = self.get_account(username) {
                let args: &PyTuple = PyTuple::new(py, vec![py_account]);
                func.call1(py, args)?;
            }
            Ok(())
        })
    }

    fn acquire_token_by_refresh_token(
        &self,
        refresh_token: &str,
        scopes: Vec<&str>,
    ) -> Result<UnixUserToken> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app().getattr(py, "acquire_token_by_refresh_token")?;
            let py_refresh_token: &PyString = PyString::new(py, refresh_token);
            let py_scopes: &PyList = PyList::new(py, scopes);
            let largs: &PyList = PyList::new(py, vec![py_refresh_token]);
            largs.append(py_scopes)?;
            let args: &PyTuple = PyTuple::new(py, largs);
            let resp: Py<PyAny> = func.call1(py, args)?;
            let token: UnixUserToken = resp.extract(py)?;
            Ok(token)
        })
    }
}

impl ClientApplication for PublicClientApplication {
    fn app(&self) -> &Py<PyAny> {
        &self.app
    }

    fn new(
        app_id: &str,
        authority_url: &str,
        _client_credential: Option<ClientCredential>,
    ) -> Result<Self> {
        Python::with_gil(|py| {
            let msal = match PyModule::import(py, "msal") {
                Ok(msal) => msal,
                Err(_e) => return Err(anyhow!("Failed importing msal")),
            };
            let kwargs = [("authority", authority_url)].into_py_dict(py);
            let func: Py<PyAny> = match msal.getattr("PublicClientApplication") {
                Ok(func) => func,
                Err(_e) => return Err(anyhow!("Failed loading PublicClientApplication")),
            }
            .into();
            let py_app_id: &PyString = PyString::new(py, app_id);
            let args: &PyTuple = PyTuple::new(py, vec![py_app_id]);
            let py_app = match func.call(py, args, Some(kwargs)) {
                Ok(py_app) => py_app,
                Err(_e) => return Err(anyhow!("Initialization of PublicClientApplication failed")),
            };
            Ok(PublicClientApplication { app: py_app })
        })
    }
}

impl PublicClientApplication {
    pub fn acquire_token_interactive(
        &self,
        scopes: Vec<&str>,
        prompt: &str,
        login_hint: &str,
        domain_hint: &str,
    ) -> Result<UnixUserToken> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app.getattr(py, "acquire_token_interactive")?;
            let py_scopes: &PyList = PyList::new(py, scopes);
            let py_prompt: &PyString = PyString::new(py, prompt);
            let py_login_hint: &PyString = PyString::new(py, login_hint);
            let py_domain_hint: &PyString = PyString::new(py, domain_hint);
            let largs: &PyList = PyList::new(py, vec![py_scopes]);
            largs.append(py_prompt)?;
            largs.append(py_login_hint)?;
            largs.append(py_domain_hint)?;
            let args: &PyTuple = PyTuple::new(py, largs);
            let resp: Py<PyAny> = func.call1(py, args)?;
            let token: UnixUserToken = resp.extract(py)?;
            Ok(token)
        })
    }

    pub fn initiate_device_flow(&self, scopes: Vec<&str>) -> Result<DeviceAuthorizationResponse> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app.getattr(py, "initiate_device_flow")?;
            let py_scopes: &PyList = PyList::new(py, scopes);
            let largs: &PyList = PyList::new(py, vec![py_scopes]);
            let args: &PyTuple = PyTuple::new(py, largs);
            let resp: Py<PyAny> = func.call1(py, args)?;
            let flow: DeviceAuthorizationResponse = resp.extract(py)?;
            Ok(flow)
        })
    }

    pub fn acquire_token_by_device_flow(
        &self,
        flow: DeviceAuthorizationResponse,
    ) -> Result<UnixUserToken> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app.getattr(py, "acquire_token_by_device_flow")?;
            let py_flow: &PyDict = PyDict::new(py);
            py_flow.set_item("device_code", flow.device_code)?;
            py_flow.set_item("user_code", flow.user_code)?;
            py_flow.set_item("verification_uri", flow.verification_uri)?;
            if let Some(verification_uri_complete) = flow.verification_uri_complete {
                py_flow.set_item("verification_uri_complete", verification_uri_complete)?;
            };
            py_flow.set_item("expires_in", flow.expires_in)?;
            if let Some(interval) = flow.interval {
                py_flow.set_item("interval", interval)?
            }
            if let Some(message) = flow.message {
                py_flow.set_item("message", message)?
            }
            let largs: &PyList = PyList::new(py, vec![py_flow]);
            let args: &PyTuple = PyTuple::new(py, largs);
            let resp: Py<PyAny> = func.call1(py, args)?;
            let token: UnixUserToken = resp.extract(py)?;
            Ok(token)
        })
    }
}

impl ClientApplication for ConfidentialClientApplication {
    fn app(&self) -> &Py<PyAny> {
        &self.app
    }

    fn new(
        app_id: &str,
        authority_url: &str,
        client_credential: Option<ClientCredential>,
    ) -> Result<Self> {
        Python::with_gil(|py| {
            let msal = match PyModule::import(py, "msal") {
                Ok(msal) => msal,
                Err(_e) => return Err(anyhow!("Failed importing msal")),
            };
            let kwargs = vec![("authority", authority_url)];
            let py_kwargs = kwargs.into_py_dict(py);
            match client_credential {
                Some(client_credential) => {
                    let py_client_credential: &PyDict = PyDict::new(py);
                    py_client_credential
                        .set_item("client_assertion", client_credential.client_assertion)?;
                    py_kwargs.set_item("client_credential", py_client_credential)?;
                }
                None => return Err(anyhow!("Failed loading ConfidentialClientApplication")),
            }
            let func: Py<PyAny> = match msal.getattr("ConfidentialClientApplication") {
                Ok(func) => func,
                Err(_e) => return Err(anyhow!("Failed loading ConfidentialClientApplication")),
            }
            .into();
            let py_app_id: &PyString = PyString::new(py, app_id);
            let args: &PyTuple = PyTuple::new(py, vec![py_app_id]);
            let py_app = match func.call(py, args, Some(py_kwargs)) {
                Ok(py_app) => py_app,
                Err(_e) => {
                    return Err(anyhow!(
                        "Initialization of ConfidentialClientApplication failed"
                    ))
                }
            };
            Ok(ConfidentialClientApplication { app: py_app })
        })
    }
}

impl ConfidentialClientApplication {
    pub fn acquire_token_for_client(&self, scopes: Vec<&str>) -> Result<DeviceToken> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app().getattr(py, "acquire_token_for_client")?;
            let py_scopes: &PyList = PyList::new(py, scopes);
            let largs: &PyList = PyList::new(py, vec![py_scopes]);
            let args: &PyTuple = PyTuple::new(py, largs);
            let resp: Py<PyAny> = func.call1(py, args)?;
            let token: DeviceToken = resp.extract(py)?;
            Ok(token)
        })
    }
}
