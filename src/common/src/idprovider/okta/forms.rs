//! Convert IDX schemas to ordinary PAM conversations. Protocol fields never
//! come from the user; the SDK retains the selected action and its stateHandle.
use super::diagnostics;
use crate::i18n::tr;
use crate::idprovider::interface::{AuthRequest, IdpError};
use crate::unix_proto::{PamAuthRequest, WebAuthnOperation};
use okta::{AuthFlow, AuthInput, FormInput, StepId, StepKind};
use serde_json::{json, Map, Value};
use std::collections::VecDeque;
use zeroize::Zeroize;

const MAX_FIELDS: usize = 128;
const MAX_DEPTH: usize = 16;

fn erase(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(erase),
        Value::Object(values) => values.values_mut().for_each(erase),
        _ => (),
    }
}

/// A partially completed form must not leak via Debug or linger after cancel.
#[derive(Default)]
pub(super) struct Form {
    selected: Option<StepId>,
    step_name: String,
    fields: VecDeque<Field>,
    values: Value,
    prompt: Option<Prompt>,
    choices: Vec<usize>,
    poll: bool,
    webauthn_path: Option<Vec<String>>,
    factor: Option<FactorKind>,
    verified_input: bool,
    pub password: Option<zeroize::Zeroizing<String>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FactorKind {
    Password,
    Authenticator,
}

/// Policy and assurance state for one native authentication transaction.
pub(super) struct FlowPolicy {
    remote: bool,
    enable_passwordless: bool,
    allow_console_password_only: bool,
    preferred_method: Option<String>,
    preference_matched: bool,
    preference_warning_emitted: bool,
    pub password_complete: bool,
    pub authenticator_complete: bool,
}

impl FlowPolicy {
    pub fn new(
        remote: bool,
        enable_passwordless: bool,
        allow_console_password_only: bool,
        preferred_method: Option<String>,
    ) -> Self {
        Self {
            remote,
            enable_passwordless,
            allow_console_password_only,
            preferred_method,
            preference_matched: false,
            preference_warning_emitted: false,
            password_complete: false,
            authenticator_complete: false,
        }
    }

    pub fn requires_authenticator(&self) -> bool {
        self.remote || !self.allow_console_password_only
    }

    fn prefer_authenticator(&self) -> bool {
        self.enable_passwordless || (self.requires_authenticator() && self.password_complete)
    }

    pub fn record(&mut self, factor: Option<FactorKind>, accepted: bool) {
        if !accepted {
            return;
        }
        match factor {
            Some(FactorKind::Password) => self.password_complete = true,
            Some(FactorKind::Authenticator) => self.authenticator_complete = true,
            None => (),
        }
    }

    pub fn warn_unmatched_preference(&mut self) {
        if self.preference_matched || self.preference_warning_emitted {
            return;
        }
        if self.preferred_method.is_some() {
            warn!(
                "Configured mfa_method could not be matched to an available Okta remediation or method; using the provider fallback"
            );
            self.preference_warning_emitted = true;
        }
    }
}

impl Drop for Form {
    fn drop(&mut self) {
        erase(&mut self.values);
    }
}

struct Field {
    path: Vec<String>,
    schema: Value,
}

impl Drop for Field {
    fn drop(&mut self) {
        erase(&mut self.schema);
    }
}

enum Prompt {
    Step,
    Field(Field),
    Password(Field),
    Confirm {
        field: Field,
        value: zeroize::Zeroizing<String>,
    },
    Submit,
    WebAuthn,
    ArrayCount(Field),
}

pub(super) enum Next {
    Prompt(AuthRequest),
    Submit(StepId, AuthInput, Option<FactorKind>),
    Unsupported,
}

fn text(value: &str) -> String {
    // Server labels are data, not terminal escape sequences.
    value
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(2048)
        .collect()
}

fn label(schema: &Value) -> String {
    text(
        schema["label"]
            .as_str()
            .or_else(|| schema["name"].as_str())
            .unwrap_or("Value"),
    )
}

fn step_label(name: &str) -> String {
    match name {
        "identify" => tr("Sign in"),
        "challenge-authenticator" => tr("Verify authenticator"),
        "select-authenticator-authenticate" => tr("Choose an authenticator"),
        "select-authenticator-enroll" => tr("Set up an authenticator"),
        "enroll-authenticator" => tr("Enroll authenticator"),
        "currentAuthenticator-send" => tr("Send another verification request"),
        "currentAuthenticatorEnrollment-recover" => tr("Recover authenticator"),
        "cancel" => tr("Cancel"),
        "skip" => tr("Skip"),
        _ => text(&name.replace('-', " ")),
    }
}

fn schema_text(value: &Value) -> String {
    serde_json::to_string(value)
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn is_password_schema(value: &Value) -> bool {
    let value = schema_text(value);
    value.contains("password") || value.contains("okta_password")
}

fn is_push_schema(value: &Value) -> bool {
    let value = schema_text(value);
    value.contains("push") || value.contains("notification")
}

fn is_otp_schema(value: &Value) -> bool {
    let value = schema_text(value);
    value.contains("otp")
        || value.contains("passcode")
        || value.contains("enter a code")
        || value.contains("enter code")
        || value.contains("verification code")
}

fn exact_schema_match(value: &Value, preferred: &str) -> bool {
    fn matches(value: &Value, preferred: &str) -> bool {
        match value {
            Value::String(value) => value.eq_ignore_ascii_case(preferred),
            Value::Array(values) => values.iter().any(|value| matches(value, preferred)),
            Value::Object(values) => values.values().any(|value| matches(value, preferred)),
            _ => false,
        }
    }
    matches(value, preferred)
}

fn mapped_preference_matches(value: &Value, preferred: &str) -> Option<bool> {
    match preferred.to_ascii_lowercase().as_str() {
        "phoneappnotification" | "companionappsnotification" => Some(is_push_schema(value)),
        "phoneappotp" => Some(is_otp_schema(value)),
        _ => None,
    }
}

fn is_known_step_preference(preferred: &str) -> bool {
    matches!(
        preferred.to_ascii_lowercase().as_str(),
        "identify"
            | "challenge-authenticator"
            | "select-authenticator-authenticate"
            | "select-authenticator-enroll"
            | "enroll-authenticator"
    )
}

fn is_remember_device_field(name: &str, schema: &Value) -> bool {
    let name = name.to_ascii_lowercase();
    schema["type"] == "boolean"
        && (matches!(name.as_str(), "rememberdevice" | "rememberme" | "remember")
            || label(schema).eq_ignore_ascii_case("Remember this device"))
}

pub(super) fn messages(flow: &AuthFlow) -> String {
    let mut output = Vec::new();
    fn collect(value: &Value, output: &mut Vec<String>, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        match value {
            Value::Array(items) => items.iter().for_each(|v| collect(v, output, depth + 1)),
            Value::Object(fields) => {
                if let Some(message) = fields.get("message").and_then(Value::as_str) {
                    output.push(text(message));
                }
                if let Some(value) = fields.get("value") {
                    collect(value, output, depth + 1);
                }
            }
            _ => (),
        }
    }
    if let Some(value) = flow.messages() {
        collect(value, &mut output, 0);
    }
    output.dedup();
    output.join("\n")
}

fn authenticator(flow: &AuthFlow) -> &Value {
    let Some(context) = flow.context() else {
        return &Value::Null;
    };
    // IDX can refer to either an authenticator or an existing enrollment.
    let referenced = flow
        .steps()
        .iter()
        .filter(|step| is_verification_step(step.name()) || step.kind == StepKind::Poll)
        .find_map(|step| {
            let relates = &step.schema()["relatesTo"];
            relates
                .as_str()
                .or_else(|| relates.as_array()?.first()?.as_str())
                .and_then(|reference| match reference {
                    "$.currentAuthenticator" => context.get("currentAuthenticator"),
                    "$.currentAuthenticatorEnrollment" => {
                        context.get("currentAuthenticatorEnrollment")
                    }
                    _ => None,
                })
        });
    referenced
        .or_else(|| context.get("currentAuthenticator"))
        .or_else(|| context.get("currentAuthenticatorEnrollment"))
        .or_else(|| context.get("authenticator"))
        .map(|value| value.get("value").unwrap_or(value))
        .unwrap_or(&Value::Null)
}

pub(super) fn current_authenticator(flow: &AuthFlow) -> String {
    let current = authenticator(flow);
    ["id", "key", "type"]
        .iter()
        .filter_map(|name| current[*name].as_str())
        .collect::<Vec<_>>()
        .join(":")
}

// Map provider values to fixed diagnostic labels; never log authenticator IDs.
fn authenticator_category(flow: &AuthFlow) -> &'static str {
    match authenticator(flow)["key"].as_str() {
        Some("okta_password" | "password") => "password",
        Some("okta_verify") => "okta_verify",
        Some("google_otp") => "totp",
        Some("webauthn") => "webauthn",
        Some("phone_number") => "phone",
        Some("okta_email") => "email",
        _ => "unknown",
    }
}

fn factor_kind(flow: &AuthFlow) -> Option<FactorKind> {
    let current = authenticator(flow);
    let key = current["key"].as_str().unwrap_or("");
    let kind = current["type"].as_str().unwrap_or("");
    if matches!(key, "okta_password" | "password") || kind == "password" {
        Some(FactorKind::Password)
    } else if matches!(kind, "app" | "phone" | "email" | "security_key")
        || matches!(
            key,
            "okta_verify" | "google_otp" | "webauthn" | "phone_number" | "okta_email"
        )
    {
        Some(FactorKind::Authenticator)
    } else {
        None
    }
}

fn is_verification_step(name: &str) -> bool {
    matches!(
        name,
        "challenge-authenticator" | "enroll-authenticator" | "reenroll-authenticator"
    )
}

fn is_credential_field(field: &Field) -> bool {
    field.path.last().is_some_and(|name| {
        matches!(
            name.as_str(),
            "passcode" | "password" | "totp" | "verificationCode" | "verification_code"
        )
    })
}

fn message_errors(value: &Value, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return true;
    }
    match value {
        Value::Null => false,
        Value::Array(items) => items.iter().any(|item| message_errors(item, depth + 1)),
        Value::Object(object) => {
            if let Some(items) = object.get("value") {
                return message_errors(items, depth + 1);
            }
            // Only explicitly informational notices are safe to ignore for acceptance.
            !object
                .get("class")
                .and_then(Value::as_str)
                .is_some_and(|class| class.eq_ignore_ascii_case("INFO"))
        }
        _ => true,
    }
}

pub(super) fn has_validation_errors(flow: &AuthFlow) -> bool {
    fn contains_errors(value: &Value, depth: usize) -> bool {
        if depth > MAX_DEPTH {
            return true;
        }
        match value {
            Value::Object(object) => object.iter().any(|(key, value)| {
                if key == "messages" {
                    message_errors(value, depth + 1)
                } else {
                    contains_errors(value, depth + 1)
                }
            }),
            Value::Array(items) => items.iter().any(|item| contains_errors(item, depth + 1)),
            _ => false,
        }
    }
    flow.messages()
        .is_some_and(|value| message_errors(value, 0))
        || flow
            .steps()
            .iter()
            .any(|step| contains_errors(step.schema(), 0))
}

pub(super) fn verification_completed(
    flow: &AuthFlow,
    previous_step: &str,
    previous_authenticator: &str,
) -> bool {
    if has_validation_errors(flow) {
        return false;
    }
    match flow.status() {
        okta::AuthStatus::Success => true,
        okta::AuthStatus::Pending => {
            current_authenticator(flow) != previous_authenticator
                || !flow.steps().iter().any(|step| step.name() == previous_step)
        }
        _ => false,
    }
}

pub(super) fn enrollment(flow: &AuthFlow) -> Option<crate::unix_proto::EnrollmentPresentation> {
    let current = authenticator(flow);
    let qr = current
        .pointer("/contextualData/qrcode/href")
        .or_else(|| current.pointer("/activationData/qrCode/href"));
    let key = current
        .pointer("/contextualData/sharedSecret")
        .or_else(|| current.pointer("/activationData/sharedSecret"));
    if qr.is_none() && key.is_none() {
        return None;
    }
    Some(crate::unix_proto::EnrollmentPresentation {
        qr: qr
            .and_then(Value::as_str)
            .filter(|s| s.len() <= crate::enrollment::MAX_QR_SOURCE_BYTES)
            .map(str::to_owned),
        setup_key: key
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 2048 && !s.chars().any(char::is_control))
            .map(str::to_owned),
    })
}

fn instructions(flow: &AuthFlow) -> String {
    let mut output = messages(flow);
    if let Some(value) = authenticator(flow).pointer("/contextualData/challenge/value") {
        if let Some(value) = value
            .as_str()
            .map(str::to_owned)
            .or_else(|| value.as_u64().map(|v| v.to_string()))
        {
            output.push_str(&format!(
                "\n{}: {}",
                tr("Authenticator verification number"),
                text(&value)
            ));
        }
    }
    output
}

fn put(root: &mut Value, path: &[String], value: Value) -> Result<(), IdpError> {
    let (name, rest) = path.split_first().ok_or(IdpError::BadRequest)?;
    if let Value::Array(items) = root {
        let index = name.parse::<usize>().map_err(|_| IdpError::BadRequest)?;
        let item = items.get_mut(index).ok_or(IdpError::BadRequest)?;
        if rest.is_empty() {
            erase(item);
            *item = value;
        } else {
            put(item, rest, value)?;
        }
        return Ok(());
    }
    if !root.is_object() {
        *root = Value::Object(Map::new());
    }
    let object = root.as_object_mut().ok_or(IdpError::BadRequest)?;
    if rest.is_empty() {
        if let Some(mut previous) = object.insert(name.clone(), value) {
            erase(&mut previous);
        }
    } else {
        put(
            object.entry(name.clone()).or_insert_with(|| json!({})),
            rest,
            value,
        )?;
    }
    Ok(())
}

fn nested_fields(schema: &Value) -> Option<&Vec<Value>> {
    schema
        .get("form")
        .and_then(|f| f.get("value"))
        .and_then(Value::as_array)
        .or_else(|| schema.get("value").and_then(Value::as_array))
        .or_else(|| schema.get("form").and_then(Value::as_array))
}

fn flatten(
    schema: &Value,
    parent: &[String],
    queue: &mut VecDeque<Field>,
    depth: usize,
) -> Result<(), IdpError> {
    if depth > MAX_DEPTH || queue.len() >= MAX_FIELDS {
        return Err(IdpError::BadRequest);
    }
    let name = schema["name"].as_str().ok_or(IdpError::BadRequest)?;
    if matches!(
        name,
        "stateHandle"
            | "state"
            | "nonce"
            | "clientId"
            | "clientSecret"
            | "issuer"
            | "redirectUri"
            | "scopes"
            | "step"
            | "actions"
            | "flow"
    ) {
        return Ok(());
    }
    let mut path = parent.to_vec();
    path.push(name.to_string());
    if schema.get("options").is_none() && schema["type"] != "array" {
        if let Some(children) = nested_fields(schema) {
            for child in children {
                let mut child = child.clone();
                if child.get("required").is_none() && schema["required"] == true {
                    child["required"] = Value::Bool(true);
                }
                flatten(&child, &path, queue, depth + 1)?;
                erase(&mut child);
            }
            return Ok(());
        }
    }
    queue.push_back(Field {
        path,
        schema: schema.clone(),
    });
    Ok(())
}

impl Form {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn is_polling(&self) -> bool {
        self.poll
    }

    pub fn selected_name(&self) -> &str {
        &self.step_name
    }

    pub fn show_steps(&mut self, flow: &AuthFlow, unavailable: bool) -> Next {
        self.reset();
        let step_names = flow
            .steps()
            .iter()
            .map(|step| diagnostics::step(step.name()))
            .collect::<Vec<_>>();
        warn!(
            steps = ?step_names,
            "No automatic Okta IDX path matched; presenting the sanitized provider choices"
        );
        let mut msg = instructions(flow);
        if unavailable {
            msg.push_str(&format!(
                "\n{}\n",
                tr("This method is unavailable. Choose another authentication method.")
            ));
        }
        self.choices = (0..flow.steps().len()).collect();
        if self.choices.is_empty() {
            return Next::Unsupported;
        }
        msg.push_str(&format!("\n{}\n", tr("Choose an authentication step:")));
        for (number, index) in self.choices.iter().enumerate() {
            msg.push_str(&format!(
                "{}. {}\n",
                number + 1,
                step_label(flow.steps()[*index].name())
            ));
        }
        msg.push_str(&tr("Selection: "));
        self.prompt = Some(Prompt::Step);
        Next::Prompt(AuthRequest::Input {
            enrollment: None,
            msg,
            echo_on: true,
        })
    }

    pub fn start(
        &mut self,
        flow: &AuthFlow,
        previous: Option<&str>,
        account: &str,
        origin: &str,
        policy: &mut FlowPolicy,
    ) -> Result<Next, IdpError> {
        self.reset();
        // Repeated polling must not insert another menu on every server response.
        if let Some(index) = previous.and_then(|name| {
            flow.steps()
                .iter()
                .position(|s| s.name() == name && s.kind == StepKind::Poll)
        }) {
            let next = self.select(flow, index, account, origin, policy)?;
            return Ok(match next {
                Next::Prompt(AuthRequest::MFAPoll { .. }) => Next::Prompt(AuthRequest::MFAPollWait),
                next => next,
            });
        }
        if let Some(preferred) = policy.preferred_method.as_deref() {
            if let Some(index) = flow
                .steps()
                .iter()
                .position(|step| step.name().eq_ignore_ascii_case(preferred))
            {
                policy.preference_matched = true;
                debug!("Selected configured Okta remediation preference");
                return self.select(flow, index, account, origin, policy);
            }
        }
        for name in [
            "identify",
            "challenge-authenticator",
            "select-authenticator-authenticate",
        ] {
            if let Some(index) = flow.steps().iter().position(|step| step.name() == name) {
                return self.select(flow, index, account, origin, policy);
            }
        }
        let primary: Vec<_> = flow
            .steps()
            .iter()
            .enumerate()
            .filter(|(_, step)| step.name() != "cancel")
            .collect();
        if primary.len() == 1
            && (primary[0].1.name() == "identify" || primary[0].1.kind == StepKind::Poll)
        {
            return self.select(flow, primary[0].0, account, origin, policy);
        }
        Ok(self.show_steps(flow, false))
    }

    fn select(
        &mut self,
        flow: &AuthFlow,
        index: usize,
        account: &str,
        origin: &str,
        policy: &mut FlowPolicy,
    ) -> Result<Next, IdpError> {
        let step = flow
            .steps()
            .get(index)
            .ok_or_else(|| diagnostics::invalid("step_unavailable"))?;
        if step.kind == StepKind::Poll {
            trace!(
                step = diagnostics::step(step.name()),
                "Selected Okta polling step"
            );
        } else {
            debug!(step = diagnostics::step(step.name()), kind = ?step.kind,
                factor = ?factor_kind(flow), authenticator = authenticator_category(flow),
                "Selected Okta authentication step");
        }
        self.selected = Some(step.id().clone());
        self.step_name = step.name().to_string();
        self.values = json!({});
        self.factor = factor_kind(flow);
        self.verified_input = false;
        match step.kind {
            StepKind::Redirect | StepKind::External => {
                warn!(kind = ?step.kind, "Okta policy requires external authentication");
                return Ok(Next::Unsupported);
            }
            StepKind::Poll => {
                self.poll = true;
                let millis = step.schema()["refresh"].as_u64().unwrap_or(3000);
                let interval = millis.div_ceil(1000).clamp(1, 60) as u32;
                self.prompt = Some(Prompt::Submit);
                return Ok(Next::Prompt(AuthRequest::MFAPoll {
                    enrollment: None,
                    msg: format!(
                        "{}\n{}",
                        instructions(flow),
                        tr("Approve the request in your authenticator.")
                    ),
                    polling_interval: interval,
                    show_push_hint: false,
                }));
            }
            StepKind::Form => (),
        }
        let fields = step
            .schema()
            .get("inputs")
            .or_else(|| step.schema().get("value"));
        if let Some(fields) = fields.and_then(Value::as_array) {
            for field in fields {
                flatten(field, &[], &mut self.fields, 0)?;
            }
        }
        // Only interpret WebAuthn when the current authenticator identifies it.
        let context = flow.context().cloned().unwrap_or(Value::Null);
        let authenticator = authenticator(flow);
        if matches!(
            self.step_name.as_str(),
            "challenge-authenticator" | "enroll-authenticator" | "reenroll-authenticator"
        ) && (authenticator["type"] == "security_key" || authenticator["key"] == "webauthn")
        {
            if policy.remote {
                debug!("Okta WebAuthn unavailable for remote service; selecting another method");
                return Ok(Next::Unsupported);
            }
            let adapter =
                okta::webauthn::WebAuthnAdapter::new().map_err(|_| IdpError::BadRequest)?;
            let enrollments = context
                .get("authenticatorEnrollments")
                .map(|v| v.get("value").unwrap_or(v))
                .cloned()
                .unwrap_or_else(|| json!([]));
            let (operation, options) = if let Some(challenge) = authenticator.get("challengeData") {
                (
                    WebAuthnOperation::Get,
                    adapter.request_options(challenge, &enrollments),
                )
            } else if let Some(activation) = authenticator.get("activationData") {
                (
                    WebAuthnOperation::Create,
                    adapter.creation_options(activation, &enrollments),
                )
            } else {
                warn!("Okta WebAuthn challenge or activation data missing");
                return Ok(Next::Unsupported);
            };
            debug!(
                ?operation,
                "Requesting Okta WebAuthn authentication or enrollment"
            );
            let path = self
                .fields
                .iter()
                .find(|f| {
                    f.path.last().is_some_and(|n| {
                        matches!(
                            n.as_str(),
                            "authenticatorData" | "attestation" | "clientData"
                        )
                    })
                })
                .map(|f| f.path[..f.path.len() - 1].to_vec())
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| vec!["credentials".into()]);
            self.webauthn_path = Some(path);
            self.prompt = Some(Prompt::WebAuthn);
            return Ok(Next::Prompt(AuthRequest::WebAuthn {
                enrollment: None,
                operation,
                origin: origin.into(),
                options: options.map_err(|_| IdpError::BadRequest)?,
            }));
        }
        self.next_field(flow, account, policy)
    }

    fn next_field(
        &mut self,
        flow: &AuthFlow,
        account: &str,
        policy: &mut FlowPolicy,
    ) -> Result<Next, IdpError> {
        while let Some(field) = self.fields.pop_front() {
            if field.path.len() > MAX_DEPTH {
                return Err(IdpError::BadRequest);
            }
            let schema = &field.schema;
            if schema["mutable"] == false {
                if let Some(value) = schema.get("value") {
                    put(&mut self.values, &field.path, value.clone())?;
                }
                continue;
            }
            if self.step_name == "identify"
                && field.path.len() == 1
                && matches!(field.path[0].as_str(), "identifier" | "username")
            {
                put(&mut self.values, &field.path, Value::String(account.into()))?;
                continue;
            }
            let field_name = field.path.last().map(String::as_str).unwrap_or("");
            let field_label = label(schema);
            if is_remember_device_field(field_name, schema) {
                /* TODO: Implement `allow_console_password_only` by setting
                 * this to `true` for consoles which do not match
                 * `password_only_remote_services_deny_list`. We also need
                 * to implement cookie caching to preserve the user's cookie
                 * state, otherwise the choice here is lost. We'll need to
                 * handle this carefully, since we don't want a local `remember
                 * device` selection to influence remote (e.g. SSH)
                 * authentication. */
                put(&mut self.values, &field.path, Value::Bool(false))?;
                continue;
            }
            if matches!(field_name, "authenticator" | "methodType") {
                if let Some(options) = schema["options"].as_array() {
                    if !options.is_empty() {
                        let index = self.choose_option(field_name, options, policy);
                        self.apply_option(&field, &options[index])?;
                        continue;
                    }
                }
            }
            let mut msg = field_label;
            let flow_message = messages(flow);
            if !flow_message.is_empty() {
                msg = format!("{flow_message}\n{msg}");
            }
            if schema["type"] == "array" {
                msg.push_str(&format!("\n{}", tr("How many entries? (0–32): ")));
                self.prompt = Some(Prompt::ArrayCount(field));
                return Ok(Next::Prompt(AuthRequest::Input {
                    enrollment: None,
                    msg,
                    echo_on: true,
                }));
            }
            if let Some(messages) = schema.get("messages") {
                let values = messages.get("value").unwrap_or(messages);
                if let Some(values) = values.as_array() {
                    for message in values {
                        if let Some(message) = message["message"].as_str() {
                            msg.push_str(&format!("\n{}", text(message)));
                        }
                    }
                }
            }
            if let Some(options) = schema["options"].as_array() {
                for (i, option) in options.iter().enumerate() {
                    msg.push_str(&format!("\n{}. {}", i + 1, label(option)));
                }
            }
            if schema["required"] != true {
                msg.push_str(&format!(" ({})", tr("optional; leave blank to skip")));
            }
            msg.push_str(": ");
            let mut secret = schema["secret"] == true || schema["type"] == "password";
            if self.factor == Some(FactorKind::Password)
                && secret
                && is_verification_step(&self.step_name)
                && is_credential_field(&field)
            {
                self.prompt = Some(Prompt::Password(field));
                return Ok(Next::Prompt(AuthRequest::Password {
                    prompt: None,
                    long_prompt: (!flow_message.is_empty()).then_some(flow_message),
                }));
            }
            if self.factor == Some(FactorKind::Authenticator)
                && (is_otp_schema(schema)
                    || matches!(
                        field_name,
                        "passcode" | "verificationCode" | "verification_code"
                    ))
            {
                debug!("Requesting Okta authenticator verification code");
                msg = if flow_message.is_empty() {
                    tr("Enter the verification code provided by your authenticator.")
                } else {
                    format!(
                        "{flow_message}\n{}",
                        tr("Enter the verification code provided by your authenticator.")
                    )
                };
                secret = true;
            }
            if self.factor.is_none() {
                warn!(
                    step = diagnostics::step(&self.step_name),
                    "Unrecognized Okta IDX prompt; using the sanitized generic PAM renderer"
                );
            }
            self.prompt = Some(Prompt::Field(field));
            return Ok(Next::Prompt(AuthRequest::Input {
                enrollment: None,
                msg,
                echo_on: !secret,
            }));
        }
        self.submit()
    }

    fn choose_option(
        &mut self,
        field_name: &str,
        options: &[Value],
        policy: &mut FlowPolicy,
    ) -> usize {
        if let Some(preferred) = policy.preferred_method.as_deref() {
            if let Some(index) = options
                .iter()
                .position(|option| exact_schema_match(option, preferred))
            {
                policy.preference_matched = true;
                debug!("Selected configured Okta authenticator or method preference");
                return index;
            }
            if let Some(index) = options
                .iter()
                .position(|option| mapped_preference_matches(option, preferred) == Some(true))
            {
                policy.preference_matched = true;
                debug!("Selected configured Okta authenticator or method preference");
                return index;
            }
            if field_name == "authenticator"
                && !is_known_step_preference(preferred)
                && !preferred.eq_ignore_ascii_case("password")
            {
                if let Some(index) = options
                    .iter()
                    .position(|option| !is_password_schema(option))
                {
                    debug!("Configured Okta method unavailable; preferring a non-password authenticator");
                    return index;
                }
            }
        }

        if field_name == "authenticator" {
            let password = options.iter().position(is_password_schema);
            let authenticator = options
                .iter()
                .position(|option| !is_password_schema(option));
            if policy.prefer_authenticator() {
                debug!(
                    non_password_available = authenticator.is_some(),
                    "Preferring Okta non-password authentication"
                );
                return authenticator.or(password).unwrap_or(0);
            }
            debug!(
                password_available = password.is_some(),
                "Preferring Okta password authentication before additional factors"
            );
            return password.or(authenticator).unwrap_or(0);
        }
        0
    }

    fn apply_option(&mut self, field: &Field, option: &Value) -> Result<(), IdpError> {
        let value = option.get("value").ok_or(IdpError::BadRequest)?;
        if let Some(children) = value.as_array() {
            let mut selected_fields = VecDeque::new();
            for child in children {
                flatten(child, &field.path, &mut selected_fields, 0)?;
            }
            selected_fields.append(&mut self.fields);
            self.fields = selected_fields;
        } else {
            put(&mut self.values, &field.path, value.clone())?;
        }
        Ok(())
    }

    fn submit(&mut self) -> Result<Next, IdpError> {
        let step = self.selected.clone().ok_or(IdpError::BadRequest)?;
        if self.poll {
            return Ok(Next::Submit(step, AuthInput::Poll, self.factor));
        }
        let values = std::mem::replace(&mut self.values, json!({}));
        let form = FormInput::new(values).map_err(|_| IdpError::BadRequest)?;
        Ok(Next::Submit(
            step,
            AuthInput::Form(form),
            self.factor
                .filter(|_| self.verified_input && is_verification_step(&self.step_name)),
        ))
    }

    pub fn answer(
        &mut self,
        request: PamAuthRequest,
        flow: &AuthFlow,
        account: &str,
        origin: &str,
        policy: &mut FlowPolicy,
    ) -> Result<Next, IdpError> {
        if matches!(request, PamAuthRequest::WebAuthnUnavailable)
            && matches!(self.prompt, Some(Prompt::WebAuthn))
        {
            debug!("Okta WebAuthn hardware unavailable; offering alternative methods");
            return Ok(self.show_steps(flow, true));
        }
        let prompt = self.prompt.take().ok_or(IdpError::BadRequest)?;
        match (prompt, request) {
            (Prompt::Step, PamAuthRequest::Input { cred }) => {
                let index = cred
                    .trim()
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|i| self.choices.get(i))
                    .copied();
                match index {
                    Some(index) => self.select(flow, index, account, origin, policy),
                    None => Ok(self.show_steps(flow, false)),
                }
            }
            (Prompt::Submit, PamAuthRequest::MFAPoll { .. }) => self.submit(),
            (Prompt::WebAuthn, PamAuthRequest::WebAuthn { response }) => {
                self.verified_input = true;
                let path = self.webauthn_path.take().ok_or(IdpError::BadRequest)?;
                put(&mut self.values, &path, response)?;
                self.submit()
            }
            (Prompt::ArrayCount(field), PamAuthRequest::Input { cred }) => {
                let count = cred
                    .trim()
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n <= 32)
                    .filter(|n| *n != 0 || field.schema["required"] != true);
                let Some(count) = count else {
                    self.fields.push_front(field);
                    return self.next_field(flow, account, policy);
                };
                put(
                    &mut self.values,
                    &field.path,
                    Value::Array(vec![Value::Null; count]),
                )?;
                let mut entries = VecDeque::new();
                for index in 0..count {
                    let mut path = field.path.clone();
                    path.push(index.to_string());
                    if let Some(children) = nested_fields(&field.schema)
                        .or_else(|| field.schema.get("items").and_then(nested_fields))
                    {
                        for child in children {
                            flatten(child, &path, &mut entries, path.len())?;
                        }
                    } else {
                        let mut schema = field
                            .schema
                            .get("items")
                            .cloned()
                            .unwrap_or_else(|| json!({"type":"string"}));
                        schema["label"] =
                            Value::String(format!("{} ({})", label(&field.schema), index + 1));
                        schema["required"] = Value::Bool(true);
                        if let Some(options) = field.schema.get("options") {
                            schema["options"] = options.clone();
                        }
                        if field.schema["secret"] == true {
                            schema["secret"] = Value::Bool(true);
                        }
                        entries.push_back(Field { path, schema });
                    }
                }
                if entries.len() + self.fields.len() > MAX_FIELDS {
                    return Err(IdpError::BadRequest);
                }
                entries.append(&mut self.fields);
                self.fields = entries;
                self.next_field(flow, account, policy)
            }
            (Prompt::Password(field), PamAuthRequest::Password { cred }) => {
                self.verified_input = !cred.is_empty();
                let cred = zeroize::Zeroizing::new(cred);
                self.password = Some(cred.clone());
                put(
                    &mut self.values,
                    &field.path,
                    Value::String(cred.to_string()),
                )?;
                self.next_field(flow, account, policy)
            }
            (Prompt::Field(field), PamAuthRequest::Input { cred }) => {
                let cred = zeroize::Zeroizing::new(cred);
                if cred.is_empty() {
                    if field.schema["required"] == true {
                        self.fields.push_front(field);
                    }
                    return self.next_field(flow, account, policy);
                }
                if let Some(options) = field.schema["options"].as_array() {
                    let option = cred
                        .trim()
                        .parse::<usize>()
                        .ok()
                        .and_then(|n| n.checked_sub(1))
                        .and_then(|i| options.get(i));
                    let Some(option) = option else {
                        self.fields.push_front(field);
                        return self.next_field(flow, account, policy);
                    };
                    self.apply_option(&field, option)?;
                    return self.next_field(flow, account, policy);
                }
                let new_password = field
                    .path
                    .last()
                    .is_some_and(|n| matches!(n.as_str(), "newPassword" | "new_password"))
                    || (is_password(flow)
                        && (self.step_name.contains("enroll")
                            || matches!(
                                self.step_name.as_str(),
                                "reset-authenticator" | "update-authenticator" | "change-password"
                            ))
                        && field.schema["secret"] == true);
                if new_password {
                    self.prompt = Some(Prompt::Confirm { field, value: cred });
                    return Ok(Next::Prompt(AuthRequest::Input {
                        enrollment: None,
                        msg: tr("Confirm new password: "),
                        echo_on: false,
                    }));
                }
                self.verified_input |= is_credential_field(&field);
                let value = match field.schema["type"].as_str().unwrap_or("string") {
                    "string" | "password" => Value::String(cred.to_string()),
                    "boolean" => match cred.trim().to_ascii_lowercase().as_str() {
                        "true" | "yes" | "y" | "1" => Value::Bool(true),
                        "false" | "no" | "n" | "0" => Value::Bool(false),
                        _ => {
                            self.fields.push_front(field);
                            return self.next_field(flow, account, policy);
                        }
                    },
                    "number" | "integer" => match cred.trim().parse::<serde_json::Number>() {
                        Ok(n) if field.schema["type"] != "integer" || n.is_i64() || n.is_u64() => {
                            Value::Number(n)
                        }
                        Ok(_) => {
                            self.fields.push_front(field);
                            return self.next_field(flow, account, policy);
                        }
                        Err(_) => {
                            self.fields.push_front(field);
                            return self.next_field(flow, account, policy);
                        }
                    },
                    // Unknown compound types need an explicitly supported adapter.
                    _ => return Ok(Next::Unsupported),
                };
                if is_password(flow)
                    && self.step_name == "challenge-authenticator"
                    && field.schema["secret"] == true
                {
                    self.password = Some(cred);
                }
                put(&mut self.values, &field.path, value)?;
                self.next_field(flow, account, policy)
            }
            (Prompt::Confirm { field, value }, PamAuthRequest::Input { cred }) => {
                let cred = zeroize::Zeroizing::new(cred);
                if *cred != *value {
                    self.fields.push_front(field);
                    return self.next_field(flow, account, policy);
                }
                self.password = Some(cred);
                put(
                    &mut self.values,
                    &field.path,
                    Value::String(value.to_string()),
                )?;
                self.next_field(flow, account, policy)
            }
            _ => Err(IdpError::BadRequest),
        }
    }
}

fn is_password(flow: &AuthFlow) -> bool {
    let current = current_authenticator(flow);
    current.split(':').any(|value| {
        value.eq_ignore_ascii_case("password") || value.eq_ignore_ascii_case("okta_password")
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Fixture failures should fail the test immediately.
mod tests {
    use super::*;

    #[test]
    fn nested_fields_preserve_paths_and_do_not_expose_protocol_state() {
        let mut fields = VecDeque::new();
        flatten(
            &json!({"name":"credentials","type":"object","form":{"value":[
                {"name":"passcode","secret":true,"required":true},
                {"name":"stateHandle","value":"secret-state"}
            ]}}),
            &[],
            &mut fields,
            0,
        )
        .unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].path, ["credentials", "passcode"]);
        let mut values = json!({});
        put(&mut values, &fields[0].path, json!("123456")).unwrap();
        assert_eq!(values, json!({"credentials":{"passcode":"123456"}}));
    }

    #[test]
    fn terminal_labels_cannot_inject_escape_sequences() {
        assert_eq!(text("hello\u{1b}[31m\rworld"), "hello[31mworld");
    }

    #[test]
    fn nested_array_entries_keep_separate_values() {
        let mut value = json!({"phones":[null,null]});
        put(
            &mut value,
            &["phones".into(), "0".into(), "number".into()],
            json!("first"),
        )
        .unwrap();
        put(
            &mut value,
            &["phones".into(), "1".into(), "number".into()],
            json!("second"),
        )
        .unwrap();
        assert_eq!(
            value,
            json!({"phones":[{"number":"first"},{"number":"second"}]})
        );
        assert!(put(&mut value, &["phones".into(), "2".into()], json!("outside")).is_err());
    }

    #[test]
    fn nested_required_fields_inherit_parent_requirement() {
        let mut fields = VecDeque::new();
        flatten(
            &json!({"name":"profile","required":true,"form":{"value":[
                {"name":"firstName"}, {"name":"nickname","required":false}
            ]}}),
            &[],
            &mut fields,
            0,
        )
        .unwrap();
        assert_eq!(fields[0].schema["required"], true);
        assert_eq!(fields[1].schema["required"], false);
    }

    #[test]
    fn policy_prefers_passwordless_authenticator_when_enabled() {
        let options = json!([
            {"label":"Okta Verify","value":"okta_verify"},
            {"label":"Password","value":"okta_password"}
        ]);
        let mut form = Form::default();
        let mut policy = FlowPolicy::new(true, true, true, None);
        assert_eq!(
            form.choose_option("authenticator", options.as_array().unwrap(), &mut policy),
            0
        );
    }

    #[test]
    fn policy_prefers_password_before_required_mfa_when_passwordless_is_disabled() {
        let options = json!([
            {"label":"Okta Verify","value":"okta_verify"},
            {"label":"Password","value":"okta_password"}
        ]);
        let mut form = Form::default();
        let mut policy = FlowPolicy::new(true, false, true, None);
        assert_eq!(
            form.choose_option("authenticator", options.as_array().unwrap(), &mut policy),
            1
        );
        policy.record(Some(FactorKind::Password), true);
        assert_eq!(
            form.choose_option("authenticator", options.as_array().unwrap(), &mut policy),
            0
        );
        assert!(!policy.authenticator_complete);
    }

    #[test]
    fn remote_policy_requires_a_successful_non_password_factor() {
        let mut remote = FlowPolicy::new(true, false, true, None);
        assert!(remote.requires_authenticator());
        remote.record(Some(FactorKind::Password), true);
        assert!(!remote.authenticator_complete);
        remote.record(Some(FactorKind::Authenticator), false);
        assert!(!remote.authenticator_complete);
        remote.record(Some(FactorKind::Authenticator), true);
        assert!(remote.authenticator_complete);

        let local = FlowPolicy::new(false, false, true, None);
        assert!(!local.requires_authenticator());
    }

    #[test]
    fn compatibility_preferences_select_the_matching_authenticator_and_method() {
        for field in ["authenticator", "methodType"] {
            for (preferred, other, desired) in [
                ("PhoneAppOTP", "push", "otp"),
                ("PhoneAppNotification", "otp", "push"),
                ("CompanionAppsNotification", "otp", "push"),
            ] {
                let options = json!([
                    {"label":"Password","value":"okta_password"},
                    {"value":other},
                    {"value":desired}
                ]);
                let mut form = Form::default();
                let mut policy = FlowPolicy::new(true, true, true, Some(preferred.into()));
                assert_eq!(
                    form.choose_option(field, options.as_array().unwrap(), &mut policy),
                    2,
                    "{field}: {preferred}"
                );
                assert!(policy.preference_matched, "{field}: {preferred}");
            }
        }
    }

    #[test]
    fn exact_match_precedes_a_compatibility_match() {
        for field in ["authenticator", "methodType"] {
            let options = json!([{"value":"otp"}, {"value":"PhoneAppOTP"}]);
            let mut policy = FlowPolicy::new(true, true, true, Some("PhoneAppOTP".into()));
            assert_eq!(
                Form::default().choose_option(field, options.as_array().unwrap(), &mut policy),
                1
            );
            assert!(policy.preference_matched);
        }
    }

    #[test]
    fn unavailable_compatibility_match_preserves_authenticator_fallback() {
        let options = json!([
            {"value":"okta_password"}, {"value":"webauthn"}, {"value":"push"}
        ]);
        let mut policy = FlowPolicy::new(true, true, true, Some("PhoneAppOTP".into()));
        assert_eq!(
            Form::default().choose_option(
                "authenticator",
                options.as_array().unwrap(),
                &mut policy
            ),
            1
        );
        assert!(!policy.preference_matched);
    }

    #[test]
    fn message_classification_preserves_errors_and_unknown_messages() {
        for message in [
            json!({"class":"ERROR","message":"Invalid code"}),
            json!({"message":"Invalid code"}),
            json!({"class":"UNKNOWN","message":"Unrecognized notice"}),
        ] {
            for messages in [json!([message.clone()]), json!({"value":[message]})] {
                assert!(message_errors(&messages, 0));
            }
        }
        assert!(!message_errors(&json!([]), 0));
        assert!(!message_errors(&json!({"value":[]}), 0));
        assert!(!message_errors(
            &json!([{ "class":"INFO", "message":"Notice" }]),
            0
        ));
        assert!(!message_errors(
            &json!({"value":[{"class":"INFO","message":"Notice"}]}),
            0
        ));
        assert!(message_errors(
            &json!([
                {"class":"INFO","message":"Notice"},
                {"class":"ERROR","message":"Invalid code"}
            ]),
            0
        ));
    }

    #[test]
    fn excessively_nested_messages_fail_closed() {
        let mut messages = json!({"class":"INFO","message":"Notice"});
        for _ in 0..=MAX_DEPTH {
            messages = json!({"value":messages});
        }
        assert!(message_errors(&messages, 0));
    }

    #[test]
    fn exact_okta_method_name_takes_precedence() {
        let options = json!([
            {"label":"Get a push notification","value":"push"},
            {"label":"Enter a code","value":"otp"}
        ]);
        let mut form = Form::default();
        let mut policy = FlowPolicy::new(true, true, true, Some("otp".to_string()));
        assert_eq!(
            form.choose_option("methodType", options.as_array().unwrap(), &mut policy),
            1
        );
        assert!(policy.preference_matched);
    }

    #[test]
    fn unavailable_okta_method_keeps_policy_fallback() {
        let options = json!([
            {"label":"Get a push notification","value":"push"},
            {"label":"Enter a code","value":"otp"}
        ]);
        let mut form = Form::default();
        let mut policy = FlowPolicy::new(true, true, true, Some("voice-call".to_string()));
        assert_eq!(
            form.choose_option("methodType", options.as_array().unwrap(), &mut policy),
            0
        );
        assert!(!policy.preference_matched);
        policy.warn_unmatched_preference();
        assert!(policy.preference_warning_emitted);
    }

    #[test]
    fn remember_device_fields_are_recognized() {
        assert!(is_remember_device_field(
            "rememberDevice",
            &json!({"name":"rememberDevice","type":"boolean"})
        ));
        assert!(is_remember_device_field(
            "providerSpecificName",
            &json!({"name":"providerSpecificName","type":"boolean","label":"Remember this device"})
        ));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Fixture failures should fail the test immediately.
mod regression_tests {
    use super::*;
    use okta::{AuthOptions, ClientConfig, PublicClientApplication};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Exercise the pinned SDK's real schema normalization at its HTTP boundary.
    async fn fixture_flow(step: &str, fields: Value, current: Value) -> AuthFlow {
        fixture_flow_in_context(step, fields, "currentAuthenticator", current).await
    }

    async fn fixture_flow_in_context(
        step: &str,
        fields: Value,
        context_name: &str,
        current: Value,
    ) -> AuthFlow {
        let response = fixture_response(step, fields, context_name, current);
        let (_, flow, server) = fixture_client_flow(response, None).await;
        server.await.unwrap();
        flow
    }

    fn fixture_response(step: &str, fields: Value, context_name: &str, current: Value) -> Value {
        let mut response = json!({"version":"1.0.0","stateHandle":"fixture-state",
            "remediation":{"type":"array","value":[{
                "name":step,"rel":["create-form"],"method":"POST"
            }]},(context_name):{"type":"object"}});
        response["remediation"]["value"][0]["value"] = fields;
        response[context_name]["value"] = current;
        response
    }

    async fn fixture_client_flow(
        response: Value,
        continuation: Option<Value>,
    ) -> (
        PublicClientApplication,
        AuthFlow,
        tokio::task::JoinHandle<()>,
    ) {
        fixture_script(
            std::iter::once(response)
                .chain(continuation)
                .map(Some)
                .collect(),
        )
        .await
    }

    async fn fixture_script(
        script: Vec<Option<Value>>,
    ) -> (
        PublicClientApplication,
        AuthFlow,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let mut responses = vec![
            Some(
                json!({"issuer":format!("{origin}/oauth2/default"),"code_challenge_methods_supported":["S256"]}),
            ),
            Some(json!({"interaction_handle":"fixture-interaction"})),
        ];
        for mut body in script {
            if let Some(body) = body.as_mut() {
                body["remediation"]["value"][0]["href"] = json!(format!("{origin}/idp/idx/answer"));
            }
            responses.push(body);
        }
        let server = tokio::spawn(async move {
            let mut reconcile = false;
            for body in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert_ne!(count, 0);
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&request[..end]);
                        let length = header
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                if reconcile {
                    assert!(
                        request.starts_with(b"POST /idp/idx/introspect "),
                        "Lost submissions must be introspected, never replayed"
                    );
                    reconcile = false;
                }
                let Some(body) = body else {
                    reconcile = true;
                    continue;
                };
                let body = body.to_string();
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let mut config = ClientConfig::new(
            format!("{origin}/oauth2/default"),
            "fixture-client",
            "http://localhost/callback",
        );
        config.allow_loopback_http = true;
        let client = PublicClientApplication::new(config).unwrap();
        let flow = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.initiate_auth_flow(AuthOptions::default()),
        )
        .await
        .unwrap()
        .unwrap();
        (client, flow, server)
    }

    #[tokio::test]
    async fn informational_notices_allow_completed_factors_at_flow_and_field_level() {
        for field_level in [false, true] {
            let mut response = fixture_response(
                "enroll-profile",
                json!([{"name":"nickname","required":true}]),
                "currentAuthenticator",
                json!({"id":"otp-id","key":"google_otp","type":"app"}),
            );
            let notice =
                json!({"type":"array","value":[{"class":"INFO","message":"Setup continues"}]});
            if field_level {
                response["remediation"]["value"][0]["value"][0]["messages"] = notice;
            } else {
                response["messages"] = notice;
            }
            let (_, flow, server) = fixture_client_flow(response, None).await;
            server.await.unwrap();
            assert!(!has_validation_errors(&flow));
            assert!(verification_completed(
                &flow,
                "challenge-authenticator",
                "otp-id:google_otp:app"
            ));
            if !field_level {
                assert!(messages(&flow).contains("Setup continues"));
            }
        }
    }

    #[tokio::test]
    async fn flow_errors_override_informational_notices_after_a_transition() {
        let mut response = fixture_response(
            "enroll-profile",
            json!([{"name":"nickname","required":true}]),
            "currentAuthenticator",
            json!({"id":"otp-id","key":"google_otp","type":"app"}),
        );
        response["messages"] = json!({"type":"array","value":[
            {"class":"INFO","message":"Setup continues"},
            {"class":"ERROR","message":"Invalid code"}
        ]});
        let (_, flow, server) = fixture_client_flow(response, None).await;
        server.await.unwrap();
        assert!(has_validation_errors(&flow));
        assert!(!verification_completed(
            &flow,
            "challenge-authenticator",
            "otp-id:google_otp:app"
        ));
    }

    #[tokio::test]
    async fn password_submission_retains_only_accepted_credentials() {
        use super::super::{LocalPhase, NativeAuthSession, OidcProvider, OktaProvider};
        use crate::config::HimmelblauConfig;
        use idmap::Idmap;
        use std::sync::Arc;
        use tokio::sync::{broadcast, Mutex};
        use zeroize::Zeroizing;

        use super::super::diagnostics::testing::Capture;
        use tracing::instrument::WithSubscriber;
        for class in ["INFO", "ERROR"] {
            let logs = Capture::default();
            async {
                let current = json!({"id":"password-id","key":"okta_password","type":"password"});
                let initial = fixture_response(
                    "challenge-authenticator",
                    credential_fields(Some("Password")),
                    "currentAuthenticator",
                    current.clone(),
                );
                let mut continuation = fixture_response(
                    "enroll-profile",
                    json!([{"name":"nickname","required":true}]),
                    "currentAuthenticator",
                    current,
                );
                continuation["stateHandle"] = json!("next-state");
                continuation["messages"] =
                    json!({"type":"array","value":[{"class":class,"message":"Notice"}]});
                let (client, flow, server) = fixture_client_flow(initial, Some(continuation)).await;
                let client = Arc::new(client);
                let mut cfg = HimmelblauConfig::new(Some("/dev/null")).unwrap();
                cfg.set(
                    "global",
                    "oidc_issuer_url",
                    "https://example.okta.com/oauth2/default",
                );
                cfg.set("oidc", "app_id", "fixture-client");
                let cfg = Arc::new(Mutex::new(cfg));
                let idmap = Arc::new(Mutex::new(Idmap::new().unwrap()));
                let standard = OidcProvider::new(&cfg, "oidc", &idmap).unwrap();
                let mut provider = OktaProvider::new(&cfg, "oidc", &idmap, &standard)
                    .await
                    .unwrap();
                provider.client = client.clone();
                let mut session = NativeAuthSession {
                    client,
                    flow,
                    form: Form::default(),
                    account: "user@example.com".into(),
                    origin: "https://example.okta.com".into(),
                    remote: true,
                    policy: FlowPolicy::new(true, false, false, None),
                    deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(5),
                    password: Some(Zeroizing::new("previous password".into())),
                    reauth_pin: None,
                    pending: None,
                    phase: LocalPhase::Native,
                };
                assert!(matches!(
                    session
                        .form
                        .start(
                            &session.flow,
                            None,
                            &session.account,
                            &session.origin,
                            &mut session.policy
                        )
                        .unwrap(),
                    Next::Prompt(AuthRequest::Password { .. })
                ));
                let next = session
                    .form
                    .answer(
                        PamAuthRequest::Password {
                            cred: "submitted password".into(),
                        },
                        &session.flow,
                        &session.account,
                        &session.origin,
                        &mut session.policy,
                    )
                    .unwrap();
                let (_sender, receiver) = broadcast::channel(1);
                let prompt = provider
                    .advance(&mut session, next, &receiver)
                    .await
                    .unwrap();
                server.await.unwrap();
                assert!(matches!(prompt, Some(AuthRequest::Input { .. })));
                assert_eq!(session.policy.password_complete, class == "INFO");
                assert_eq!(
                    session.password.as_ref().map(|password| password.as_str()),
                    (class == "INFO").then_some("submitted password")
                );
                assert!(!session.policy.authenticator_complete);
            }
            .with_subscriber(logs.subscriber())
            .await;
            assert!(logs.contains("step", "challenge-authenticator"));
            assert!(logs.contains("factor", "Some(Password)"));
            assert!(logs.contains(
                "validation_errors",
                if class == "ERROR" { "true" } else { "false" }
            ));
            assert!(logs.contains(
                "factor_completed",
                if class == "INFO" { "true" } else { "false" }
            ));
            assert!(!logs.contains("outcome", "success"));
            let output = logs.output();
            for secret in [
                "submitted password",
                "previous password",
                "fixture-state",
                "fixture-interaction",
                "user@example.com",
                "password-id",
                "Notice",
            ] {
                assert!(
                    !output.contains(secret),
                    "Sensitive fixture value appeared in logs: {secret}"
                );
            }
        }
    }

    fn credential_fields(label: Option<&str>) -> Value {
        let mut field = json!({"name":"passcode","secret":true,"required":true});
        if let Some(label) = label {
            field["label"] = json!(label);
        }
        json!([{"name":"credentials","type":"object","form":{"value":[field]}}])
    }

    #[tokio::test]
    async fn localized_password_cannot_satisfy_mfa() {
        let flow = fixture_flow(
            "challenge-authenticator",
            credential_fields(Some("Mot de passe")),
            json!({"id":"password-id","key":"okta_password","type":"password"}),
        )
        .await;
        let mut form = Form::default();
        let mut policy = FlowPolicy::new(true, false, false, None);
        let prompt = form
            .start(
                &flow,
                None,
                "user@example.com",
                "https://example.com",
                &mut policy,
            )
            .unwrap();
        assert!(matches!(prompt, Next::Prompt(AuthRequest::Password { .. })));
        let submission = form
            .answer(
                PamAuthRequest::Password {
                    cred: "fixture-password".into(),
                },
                &flow,
                "user@example.com",
                "https://example.com",
                &mut policy,
            )
            .unwrap();
        assert!(matches!(
            submission,
            Next::Submit(_, _, Some(FactorKind::Password))
        ));
        assert!(!policy.authenticator_complete);
    }

    #[tokio::test]
    async fn okta_verify_totp_before_password_establishes_mfa_only_after_acceptance() {
        // Okta Verify uses credentials.totp without a secret/type annotation.
        // The following password challenge keeps the same remediation name.
        for accepted in [false, true] {
            let mut initial = fixture_response(
                "challenge-authenticator",
                json!([{"name":"credentials","type":"object","required":true,
                    "form":{"value":[{"name":"totp","label":"Enter code","required":true}]}}]),
                "currentAuthenticator",
                json!({"id":"verify-id","key":"okta_verify","type":"app"}),
            );
            initial["remediation"]["value"][0]["relatesTo"] = json!(["$.currentAuthenticator"]);
            let mut continuation = if accepted {
                let mut response = fixture_response(
                    "challenge-authenticator",
                    credential_fields(Some("Password")),
                    "currentAuthenticatorEnrollment",
                    json!({"id":"password-id","key":"okta_password","type":"password"}),
                );
                response["remediation"]["value"][0]["relatesTo"] =
                    json!(["$.currentAuthenticatorEnrollment"]);
                response
            } else {
                let mut response = initial.clone();
                response["messages"] = json!({"type":"array","value":[
                    {"class":"ERROR","message":"Invalid code"}
                ]});
                response
            };
            continuation["stateHandle"] = json!("next-state");
            let (client, mut flow, server) = fixture_client_flow(initial, Some(continuation)).await;
            let mut form = Form::default();
            let mut policy = FlowPolicy::new(true, true, false, None);
            assert!(matches!(
                form.start(
                    &flow,
                    None,
                    "user@example.com",
                    "https://example.com",
                    &mut policy
                )
                .unwrap(),
                Next::Prompt(AuthRequest::Input { echo_on: false, .. })
            ));
            let previous_authenticator = current_authenticator(&flow);
            let Next::Submit(step, input, factor) = form
                .answer(
                    PamAuthRequest::Input {
                        cred: "123456".into(),
                    },
                    &flow,
                    "user@example.com",
                    "https://example.com",
                    &mut policy,
                )
                .unwrap()
            else {
                panic!("Expected code submission");
            };
            assert!(!policy.authenticator_complete);
            client
                .continue_auth_flow(&mut flow, &step, input)
                .await
                .unwrap();
            server.await.unwrap();
            policy.record(
                factor,
                verification_completed(&flow, "challenge-authenticator", &previous_authenticator),
            );
            assert_eq!(policy.authenticator_complete, accepted);
            assert!(!policy.password_complete);
            if accepted {
                assert!(matches!(
                    form.start(
                        &flow,
                        Some("challenge-authenticator"),
                        "user@example.com",
                        "https://example.com",
                        &mut policy
                    )
                    .unwrap(),
                    Next::Prompt(AuthRequest::Password { .. })
                ));
            }
        }
    }

    #[tokio::test]
    async fn otp_enrollment_submits_non_password_verification() {
        let flow = fixture_flow(
            "enroll-authenticator",
            credential_fields(Some("Enter code")),
            json!({"id":"otp-id","key":"google_otp","type":"app"}),
        )
        .await;
        let mut form = Form::default();
        let mut policy = FlowPolicy::new(true, true, false, Some("enroll-authenticator".into()));
        form.start(
            &flow,
            None,
            "user@example.com",
            "https://example.com",
            &mut policy,
        )
        .unwrap();
        let submission = form
            .answer(
                PamAuthRequest::Input {
                    cred: "123456".into(),
                },
                &flow,
                "user@example.com",
                "https://example.com",
                &mut policy,
            )
            .unwrap();
        assert!(matches!(
            submission,
            Next::Submit(_, _, Some(FactorKind::Authenticator))
        ));
    }
    #[tokio::test]
    async fn webauthn_enrollment_submits_non_password_verification() {
        let flow = fixture_flow(
            "enroll-authenticator",
            json!([]),
            json!({"id":"key-id","key":"webauthn","type":"security_key",
            "activationData":{
                "challenge":"AQID", "rp":{"id":"example.com","name":"Example"},
                "user":{"id":"AQID","name":"user@example.com","displayName":"User"},
                "pubKeyCredParams":[{"type":"public-key","alg":-7}],
                "attestation":"none","authenticatorSelection":{"userVerification":"preferred"}
            }}),
        )
        .await;
        let mut form = Form::default();
        let mut policy = FlowPolicy::new(false, true, false, Some("enroll-authenticator".into()));
        let prompt = form
            .start(
                &flow,
                None,
                "user@example.com",
                "https://example.com",
                &mut policy,
            )
            .unwrap();
        assert!(matches!(
            prompt,
            Next::Prompt(AuthRequest::WebAuthn {
                operation: WebAuthnOperation::Create,
                ..
            })
        ));
        assert!(!policy.authenticator_complete);
        let submission = form.answer(
            PamAuthRequest::WebAuthn { response: json!({"attestation":"fixture-attestation","clientData":"fixture-client-data"}) },
            &flow, "user@example.com", "https://example.com", &mut policy,
        ).unwrap();
        assert!(matches!(
            submission,
            Next::Submit(_, _, Some(FactorKind::Authenticator))
        ));
        // Submitting credentials alone must not satisfy policy before acceptance.
        assert!(!policy.authenticator_complete);
    }

    #[tokio::test]
    async fn password_enrollment_context_and_missing_label_stay_password() {
        let flow = fixture_flow_in_context(
            "challenge-authenticator",
            credential_fields(None),
            "currentAuthenticatorEnrollment",
            json!({"id":"password-id","key":"okta_password","type":"password"}),
        )
        .await;
        let mut form = Form::default();
        let mut policy = FlowPolicy::new(true, false, false, None);
        assert!(matches!(
            form.start(
                &flow,
                None,
                "user@example.com",
                "https://example.com",
                &mut policy
            )
            .unwrap(),
            Next::Prompt(AuthRequest::Password { .. })
        ));
    }

    #[tokio::test]
    async fn unknown_authenticator_and_otp_label_do_not_establish_mfa() {
        let flow = fixture_flow(
            "challenge-authenticator",
            credential_fields(Some("Verification code")),
            json!({"id":"unknown-id","type":"unknown"}),
        )
        .await;
        let mut form = Form::default();
        let mut policy = FlowPolicy::new(true, true, false, None);
        form.start(
            &flow,
            None,
            "user@example.com",
            "https://example.com",
            &mut policy,
        )
        .unwrap();
        let submission = form
            .answer(
                PamAuthRequest::Input {
                    cred: "123456".into(),
                },
                &flow,
                "user@example.com",
                "https://example.com",
                &mut policy,
            )
            .unwrap();
        assert!(matches!(submission, Next::Submit(_, _, None)));
    }

    #[tokio::test]
    async fn enrollment_profile_input_does_not_establish_mfa() {
        let flow = fixture_flow(
            "enroll-authenticator",
            json!([{"name":"nickname","required":true}]),
            json!({"id":"otp-id","key":"google_otp","type":"app"}),
        )
        .await;
        let mut form = Form::default();
        let mut policy = FlowPolicy::new(true, true, false, Some("enroll-authenticator".into()));
        form.start(
            &flow,
            None,
            "user@example.com",
            "https://example.com",
            &mut policy,
        )
        .unwrap();
        let submission = form
            .answer(
                PamAuthRequest::Input {
                    cred: "My phone".into(),
                },
                &flow,
                "user@example.com",
                "https://example.com",
                &mut policy,
            )
            .unwrap();
        assert!(matches!(submission, Next::Submit(_, _, None)));
    }

    #[tokio::test]
    async fn accepted_verification_survives_profile_step_with_same_authenticator() {
        let flow = fixture_flow(
            "enroll-profile",
            json!([{"name":"nickname","required":true}]),
            json!({"id":"otp-id","key":"google_otp","type":"app"}),
        )
        .await;
        let mut policy = FlowPolicy::new(true, true, false, None);
        policy.record(
            Some(FactorKind::Authenticator),
            verification_completed(&flow, "challenge-authenticator", "otp-id:google_otp:app"),
        );
        assert!(policy.authenticator_complete);
    }

    #[tokio::test]
    async fn repeated_verification_with_no_messages_is_not_completion() {
        let flow = fixture_flow(
            "challenge-authenticator",
            credential_fields(Some("Code")),
            json!({"id":"otp-id","key":"google_otp","type":"app"}),
        )
        .await;
        assert!(!verification_completed(
            &flow,
            "challenge-authenticator",
            "otp-id:google_otp:app"
        ));
    }

    #[tokio::test]
    async fn field_errors_prevent_factor_credit_even_after_context_changes() {
        let mut fields = credential_fields(Some("Code"));
        fields[0]["form"]["value"][0]["messages"] =
            json!({"type":"array","value":[{"message":"Invalid code"}]});
        let flow = fixture_flow(
            "challenge-authenticator",
            fields,
            json!({"id":"otp-id","key":"google_otp","type":"app"}),
        )
        .await;
        assert!(!verification_completed(
            &flow,
            "challenge-authenticator",
            "different-id:google_otp:app"
        ));
    }

    #[tokio::test]
    async fn outstanding_poll_uses_wait_response_and_earns_no_credit() {
        let flow = fixture_flow(
            "challenge-poll",
            json!([]),
            json!({"id":"verify-id","key":"okta_verify","type":"app"}),
        )
        .await;
        let mut form = Form::default();
        let mut policy = FlowPolicy::new(true, true, false, None);
        assert!(matches!(
            form.start(
                &flow,
                None,
                "user@example.com",
                "https://example.com",
                &mut policy
            )
            .unwrap(),
            Next::Prompt(AuthRequest::MFAPoll { .. })
        ));
        assert!(matches!(
            form.start(
                &flow,
                Some("challenge-poll"),
                "user@example.com",
                "https://example.com",
                &mut policy
            )
            .unwrap(),
            Next::Prompt(AuthRequest::MFAPollWait)
        ));
        assert!(!verification_completed(
            &flow,
            "challenge-poll",
            "verify-id:okta_verify:app"
        ));
    }

    #[tokio::test]
    async fn contextual_qr_and_key_are_kept_out_of_generic_messages() {
        let flow = fixture_flow(
            "enroll-authenticator",
            credential_fields(Some("Code")),
            json!({"id":"otp-id","key":"google_otp","type":"app", "contextualData":{
                "qrcode":{"href":"data:image/png;base64,fixture"},"sharedSecret":"FIXTUREKEY"}}),
        )
        .await;
        let presentation = enrollment(&flow).unwrap();
        assert_eq!(
            presentation.qr.as_deref(),
            Some("data:image/png;base64,fixture")
        );
        assert_eq!(presentation.setup_key.as_deref(), Some("FIXTUREKEY"));
        assert!(!instructions(&flow).contains("FIXTUREKEY"));
        assert!(!format!("{presentation:?}").contains("fixture"));
    }
    async fn diagnostic_session(
        script: Vec<Option<Value>>,
    ) -> (
        super::super::OktaProvider,
        super::super::NativeAuthSession,
        tokio::task::JoinHandle<()>,
    ) {
        use super::super::{LocalPhase, NativeAuthSession, OidcProvider, OktaProvider};
        use crate::config::HimmelblauConfig;
        use idmap::Idmap;
        use std::sync::Arc;
        use tokio::sync::Mutex;
        let (client, flow, server) = fixture_script(script).await;
        let client = Arc::new(client);
        let mut cfg = HimmelblauConfig::new(Some("/dev/null")).unwrap();
        cfg.set(
            "global",
            "oidc_issuer_url",
            "https://example.okta.com/oauth2/default",
        );
        cfg.set("oidc", "app_id", "fixture-client");
        let cfg = Arc::new(Mutex::new(cfg));
        let idmap = Arc::new(Mutex::new(Idmap::new().unwrap()));
        let standard = OidcProvider::new(&cfg, "oidc", &idmap).unwrap();
        let mut provider = OktaProvider::new(&cfg, "oidc", &idmap, &standard)
            .await
            .unwrap();
        provider.client = client.clone();
        let session = NativeAuthSession {
            client,
            flow,
            form: Form::default(),
            account: "SECRET-ACCOUNT".into(),
            origin: "https://example.okta.com".into(),
            remote: true,
            policy: FlowPolicy::new(true, false, false, None),
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            password: None,
            reauth_pin: None,
            pending: None,
            phase: LocalPhase::Native,
        };
        (provider, session, server)
    }

    #[tokio::test]
    async fn unknown_steps_and_preferences_do_not_expose_server_data() {
        use super::super::diagnostics::testing::Capture;
        let flow = fixture_flow(
            "SECRET-STEP",
            json!([{ "name":"SECRET-FIELD", "label":"SECRET-LABEL" }]),
            json!({"id":"SECRET-AUTHENTICATOR"}),
        )
        .await;
        let logs = Capture::default();
        tracing::dispatcher::with_default(&logs.subscriber(), || {
            let mut form = Form::default();
            let mut policy = FlowPolicy::new(true, false, false, Some("SECRET-PREFERENCE".into()));
            assert!(matches!(
                form.start(
                    &flow,
                    None,
                    "SECRET-ACCOUNT",
                    "https://example.com",
                    &mut policy
                )
                .unwrap(),
                Next::Prompt(_)
            ));
            let _ = form
                .answer(
                    PamAuthRequest::Input { cred: "1".into() },
                    &flow,
                    "SECRET-ACCOUNT",
                    "https://example.com",
                    &mut policy,
                )
                .unwrap();
            policy.warn_unmatched_preference();
        });
        assert!(logs.contains("step", "unknown"));
        assert!(logs.contains("level", "WARN"));
        assert!(!logs.output().contains("SECRET-"));
    }

    #[tokio::test]
    async fn expired_session_explains_failure_without_submitting() {
        use super::super::diagnostics::testing::Capture;
        use tracing::instrument::WithSubscriber;
        let response = fixture_response(
            "challenge-authenticator",
            credential_fields(None),
            "currentAuthenticator",
            json!({"key":"okta_password","type":"password"}),
        );
        let (provider, mut session, server) = diagnostic_session(vec![Some(response)]).await;
        server.await.unwrap();
        session.deadline = tokio::time::Instant::now();
        let logs = Capture::default();
        let (_sender, receiver) = tokio::sync::broadcast::channel(1);
        let result = provider
            .advance(&mut session, Next::Unsupported, &receiver)
            .with_subscriber(logs.subscriber())
            .await;
        assert!(matches!(result, Err(IdpError::BadRequest)));
        assert!(logs.contains("reason", "session_expired"));
        assert!(logs.contains("level", "WARN"));
        assert!(!logs.contains("outcome", "success"));
        assert!(!logs.output().contains("SECRET-"));
    }

    #[tokio::test]
    async fn lost_submission_logs_reconciliation_and_never_replays_password() {
        use super::super::diagnostics::testing::Capture;
        use tracing::instrument::WithSubscriber;
        let password = fixture_response(
            "challenge-authenticator",
            credential_fields(None),
            "currentAuthenticator",
            json!({"id":"SECRET-ID","key":"okta_password","type":"password"}),
        );
        let otp = fixture_response(
            "challenge-authenticator",
            credential_fields(Some("Code")),
            "currentAuthenticator",
            json!({"id":"SECRET-OTP-ID","key":"google_otp","type":"app"}),
        );
        let (provider, mut session, server) =
            diagnostic_session(vec![Some(password), None, Some(otp)]).await;
        let logs = Capture::default();
        let (_sender, receiver) = tokio::sync::broadcast::channel(1);
        let request = async {
            let _ = session
                .form
                .start(
                    &session.flow,
                    None,
                    &session.account,
                    &session.origin,
                    &mut session.policy,
                )
                .unwrap();
            let next = session
                .form
                .answer(
                    PamAuthRequest::Password {
                        cred: "SECRET-PASSWORD".into(),
                    },
                    &session.flow,
                    &session.account,
                    &session.origin,
                    &mut session.policy,
                )
                .unwrap();
            provider
                .advance(&mut session, next, &receiver)
                .await
                .unwrap()
        }
        .with_subscriber(logs.subscriber())
        .await;
        server.await.unwrap();
        assert!(matches!(request, Some(AuthRequest::Input { .. })));
        assert!(logs.contains("operation", "uncertain_submission"));
        assert!(logs.contains("recovery", "introspect_once"));
        assert!(!logs.contains("recovery", "retry_later"));
        assert!(logs.contains("status", "Pending"));
        assert!(logs.contains("factor", "Some(Authenticator)"));
        assert!(session.policy.password_complete);
        assert!(!logs.contains("outcome", "success"));
        assert!(!logs.output().contains("SECRET-"));
    }
    #[tokio::test]
    async fn pin_setup_logs_success_only_after_required_local_factor() {
        use super::super::diagnostics::testing::Capture;
        use super::super::{AuthCredHandler, AuthResult, LocalPhase, RefreshCacheEntry, UserToken};
        use crate::db::{Cache, CacheTxn};
        use crate::idprovider::interface::{tpm, IdProvider};
        use tpm::{provider::SoftTpm, provider::Tpm, AuthValue};
        use tracing::instrument::WithSubscriber;
        for require_totp in [false, true] {
            let response = fixture_response(
                "challenge-authenticator",
                credential_fields(None),
                "currentAuthenticator",
                json!({"key":"okta_password","type":"password"}),
            );
            let (provider, mut session, server) = diagnostic_session(vec![Some(response)]).await;
            server.await.unwrap();
            provider.config.lock().await.set(
                "global",
                "enable_hello_totp",
                if require_totp { "true" } else { "false" },
            );
            let identity = UserToken {
                name: "SECRET-ACCOUNT".into(),
                spn: "SECRET-SPN".into(),
                uuid: uuid::Uuid::nil(),
                real_gidnumber: None,
                gidnumber: 1000,
                displayname: "SECRET-NAME".into(),
                shell: None,
                groups: vec![],
                tenant_id: None,
                valid: true,
            };
            session.pending = Some(identity.clone());
            session.phase = LocalPhase::SetupPin;
            provider
                .refresh_cache
                .add(
                    &session.account,
                    &RefreshCacheEntry::RefreshToken("SECRET-REFRESH".into()),
                )
                .await;
            let mut handler = AuthCredHandler::InteractionCode(Box::new(session));
            let db = crate::db::Db::new("").unwrap();
            let mut txn = db.write().await;
            txn.migrate().unwrap();
            let mut tpm = tpm::provider::BoxedDynTpm::new(SoftTpm::new());
            let auth = AuthValue::ephemeral().unwrap();
            let loadable = tpm.root_storage_key_create(&auth).unwrap();
            let key = tpm.root_storage_key_load(&auth, &loadable).unwrap();
            let (_sender, receiver) = tokio::sync::broadcast::channel(1);
            let logs = Capture::default();
            let (result, _) = provider
                .unix_user_online_auth_step(
                    "SECRET-ACCOUNT",
                    &identity,
                    "login",
                    false,
                    &mut handler,
                    PamAuthRequest::SetupPin {
                        pin: "SECRET-PIN".into(),
                    },
                    &mut txn,
                    &mut tpm,
                    &key,
                    &receiver,
                )
                .with_subscriber(logs.subscriber())
                .await
                .unwrap();
            assert_eq!(matches!(result, AuthResult::Success { .. }), !require_totp);
            assert_eq!(logs.contains("outcome", "success"), !require_totp);
            assert!(logs.contains("span", "unix_user_online_auth_step"));
            assert!(!logs.output().contains("SECRET-"));
        }
    }
}
