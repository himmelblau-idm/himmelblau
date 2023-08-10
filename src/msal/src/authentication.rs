use pyo3::prelude::*;
use pyo3::types::IntoPyDict;
use pyo3::types::PyString;
use pyo3::types::PyTuple;
use pyo3::types::PyList;
use pyo3::types::PyDict;
use std::collections::HashMap;
use anyhow::{Result, anyhow};
use uuid::Uuid;

pub const INVALID_CRED: u32 = 0xC3CE;
pub const REQUIRES_MFA: u32 = 0xC39C;
pub const INVALID_USER: u32 = 0xC372;
pub const NO_CONSENT:   u32 = 0xFDE9;
pub const NO_GROUP_CONSENT: u32 = 0xFDEA;
pub const NO_SECRET:    u32 = 0x6AD09A;

pub struct PublicClientApplication {
    app: Py<PyAny>
}

#[derive(Default)]
pub struct UnixUserToken {
    pub spn: String,
    pub displayname: String,
    pub uuid: Uuid,
    pub access_token: Option<String>,

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
                        "oid" => res.uuid = Uuid::parse_str(sval.extract()?)
                            .expect("Failed parsing user uuid"),
                        &_ => {}, // Ignore the others
                    }
                }
            } else if k == "access_token" {
                let py_val: &PyString = match val.extract() {
                    Ok(val) => val,
                    Err(_e) => panic!("Failed extracting access_token from auth response"),
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

#[derive(Default)]
pub struct DeviceAuthorizationFlow {
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

impl<'a> FromPyObject<'a> for DeviceAuthorizationFlow {
    fn extract(obj: &'a PyAny) -> PyResult<Self> {
        let dict_obj: &PyDict = obj.extract()?;
        let mut res: DeviceAuthorizationFlow = Default::default();
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
                &_ => {},
            }
        }
        Ok(res)
    }
}

impl PublicClientApplication {
    pub fn new(app_id: &str, authority_url: &str) -> PublicClientApplication {
        Python::with_gil(|py| {
            let msal = PyModule::import(py, "msal")
                .expect("Failed importing msal");
            let kwargs = [("authority", authority_url)].into_py_dict(py);
            let func: Py<PyAny> = msal.getattr("PublicClientApplication")
                .expect("Failed loading the PublicClientApplication")
                .into();
            let py_app_id: &PyString = PyString::new(py, app_id);
            let args: &PyTuple = PyTuple::new(py, vec![py_app_id]);
            let py_app = func.call(py, args, Some(kwargs))
                .expect("Initialization of PublicClientApplication failed");
            PublicClientApplication {
                app: py_app
            }
        })
    }

    pub fn acquire_token_by_username_password(&self, username: &str, password: &str, scopes: Vec<&str>) -> Result<UnixUserToken> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app.getattr(py, "acquire_token_by_username_password")?
                .into();
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

    pub fn acquire_token_interactive(&self, scopes: Vec<&str>, prompt: &str, login_hint: &str, domain_hint: &str) -> Result<UnixUserToken> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app.getattr(py, "acquire_token_interactive")?
                .into();
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

    pub fn acquire_token_silent(&self, scopes: Vec<&str>, username: &str) -> Result<UnixUserToken> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app.getattr(py, "acquire_token_silent")?
                .into();
            let py_scopes: &PyList = PyList::new(py, scopes);
            let account = match self.get_accounts()
                .iter()
                .find(|tok| tok.get("username").expect("Failed to find username in account") == username)
                .cloned() {
                Some(account) => account,
                None => return Err(anyhow!("Failed to locate user '{}' in auth cache", username)),
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

    pub fn initiate_device_flow(&self, scopes: Vec<&str>) -> Result<DeviceAuthorizationFlow> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app.getattr(py, "initiate_device_flow")?
                .into();
            let py_scopes: &PyList = PyList::new(py, scopes);
            let largs: &PyList = PyList::new(py, vec![py_scopes]);
            let args: &PyTuple = PyTuple::new(py, largs);
            let resp: Py<PyAny> = func.call1(py, args)?;
            let flow: DeviceAuthorizationFlow = resp.extract(py)?;
            Ok(flow)
        })
    }

    pub fn acquire_token_by_device_flow(&self, flow: DeviceAuthorizationFlow) -> Result<UnixUserToken> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app.getattr(py, "acquire_token_by_device_flow")?
                .into();
            let py_flow: &PyDict = PyDict::new(py);
            py_flow.set_item("device_code", flow.device_code)?;
            py_flow.set_item("user_code", flow.user_code)?;
            py_flow.set_item("verification_uri", flow.verification_uri)?;
            match flow.verification_uri_complete {
                Some(verification_uri_complete) => {
                    py_flow.set_item("verification_uri_complete", verification_uri_complete)?;
                },
                None => {}
            };
            py_flow.set_item("expires_in", flow.expires_in)?;
            match flow.interval {
                Some(interval) => py_flow.set_item("interval", interval)?,
                None => {}
            };
            match flow.message {
                Some(message) => py_flow.set_item("message", message)?,
                None => {}
            };
            let largs: &PyList = PyList::new(py, vec![py_flow]);
            let args: &PyTuple = PyTuple::new(py, largs);
            let resp: Py<PyAny> = func.call1(py, args)?;
            let token: UnixUserToken = resp.extract(py)?;
            Ok(token)
        })
    }

    pub fn get_authorization_request_url(&self, scopes: Vec<&str>, login_hint: &str, prompt: &str, domain_hint: &str) -> String {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app.getattr(py, "get_authorization_request_url")
                .expect("Failed loading function get_authorization_request_url")
                .into();
            let py_scopes: &PyList = PyList::new(py, scopes);
            let py_login_hint: &PyString = PyString::new(py, login_hint);
            let py_redirect_uri: &PyString = PyString::new(py, "http://localhost");
            let py_prompt: &PyString = PyString::new(py, prompt);
            let py_domain_hint: &PyString = PyString::new(py, domain_hint);
            let args = (py_scopes,);
            let kwargs = PyDict::new(py);
            kwargs.set_item("login_hint", py_login_hint)
                .expect("Failed setting login_hint");
            kwargs.set_item("redirect_uri", py_redirect_uri)
                .expect("Failed setting redirect_uri");
            kwargs.set_item("prompt", py_prompt)
                .expect("Failed setting prompt");
            kwargs.set_item("domain_hint", py_domain_hint)
                .expect("Failed setting domain_hint");
            func.call(py, args, Some(kwargs))
                .expect("Failed calling acquire_token_interactive")
                .downcast::<PyString>(py)
                .expect("Failed downcasting the PyAny to a PyString")
                .to_string()
        })
    }

    pub fn get_accounts(&self) -> Vec<HashMap<String, String>> {
        Python::with_gil(|py| {
            let func: Py<PyAny> = self.app.getattr(py, "get_accounts")
                .expect("Failed loading function get_accounts")
                .into();
            func.call0(py)
                .expect("Failed calling get_accounts")
                .extract(py)
                .expect("Extraction to a list of hashmaps failed")
        })
    }

    pub fn get_account(&self, account_id: &String) -> Option<HashMap<String, String>> {
        self.get_accounts()
            .iter()
            .find(|tok| tok.get("username").expect("Failed to find username in account") == account_id)
            .cloned()
    }
}
