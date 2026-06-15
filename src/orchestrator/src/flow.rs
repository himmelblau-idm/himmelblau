use crate::podman::{InspectedAction, InspectedField, InspectedForm, PageInspection, PodmanClient};
use crate::session::{input_sensitive, CollectedInput, PendingAction, PendingField, Session};
use crate::types::{FlowResponse, InputType, LogLevel, ProvidedInput, RequiredInput, SessionState};
use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

const MAX_AUTO_CLICKS_PER_TURN: usize = 4;

pub struct FlowExecutor {
    podman: Arc<PodmanClient>,
}

impl FlowExecutor {
    pub fn new(podman: Arc<PodmanClient>) -> Self {
        Self { podman }
    }

    pub async fn start_session(&self, session: Arc<Session>) -> Result<FlowResponse> {
        session
            .log(LogLevel::Info, "Starting generic browser DAG flow")
            .await;

        let dag_auth_url = {
            let runtime = session.runtime.lock().await;
            runtime.metadata.get("dag_auth_url").cloned()
        }
        .ok_or_else(|| anyhow!("start_session requires dag_auth_url"))?;

        self.podman
            .navigate(&session.container, &dag_auth_url)
            .await
            .context("initial DAG browser navigation failed")?;

        self.advance(session).await
    }

    pub async fn continue_session(
        &self,
        session: Arc<Session>,
        interaction_id: Option<String>,
        mut provided_inputs: Vec<ProvidedInput>,
    ) -> Result<FlowResponse> {
        {
            let mut runtime = session.runtime.lock().await;
            runtime.auto_clicks_this_turn = 0;
            runtime.state = SessionState::InProgress;
            runtime.detail = Some("Continuing browser flow".to_string());
            runtime.last_activity = std::time::Instant::now();
        }

        if !provided_inputs.is_empty() {
            self.accept_provided_input(&session, interaction_id, &mut provided_inputs)
                .await?;
        }

        self.advance(session).await
    }

    async fn accept_provided_input(
        &self,
        session: &Arc<Session>,
        interaction_id: Option<String>,
        provided_inputs: &mut [ProvidedInput],
    ) -> Result<()> {
        let mut runtime = session.runtime.lock().await;
        for input in provided_inputs {
            if let Some(action) = runtime.pending_action.take() {
                if interaction_id
                    .as_deref()
                    .map(|id| id != action.interaction_id)
                    .unwrap_or(false)
                {
                    return Err(anyhow!(
                        "provided confirmation interaction_id does not match"
                    ));
                }
                if input.value.eq_ignore_ascii_case("true") || input.value == "1" {
                    runtime.confirmed_action = Some(action);
                    continue;
                }
                return Err(anyhow!("confirmation declined"));
            }

            let active = runtime
                .active_field
                .take()
                .ok_or_else(|| anyhow!("provided input but no field is waiting"))?;
            if interaction_id
                .as_deref()
                .map(|id| id != active.interaction_id)
                .unwrap_or(false)
            {
                return Err(anyhow!("provided input interaction_id does not match"));
            }
            if input.name != active.field.name {
                return Err(anyhow!(
                    "provided input '{}' does not match active field '{}'",
                    input.name,
                    active.field.name
                ));
            }
            let value = std::mem::take(&mut input.value);
            runtime.collected_inputs.insert(
                active.field.name.clone(),
                CollectedInput::new(value, active.field.sensitive),
            );
        }
        Ok(())
    }

    async fn advance(&self, session: Arc<Session>) -> Result<FlowResponse> {
        loop {
            if let Some(response) = self.next_queued_prompt(&session).await {
                return Ok(response);
            }

            if self.try_submit_collected_form(&session).await? {
                continue;
            }

            if self.try_click_pending_action(&session).await? {
                continue;
            }

            let inspection = self
                .podman
                .inspect_page(&session.container)
                .await
                .context("failed inspecting browser page")?;

            if self
                .queue_fields_from_inspection(&session, &inspection)
                .await?
            {
                continue;
            }

            if let Some(response) = self
                .terminal_browser_error_from_inspection(&session, &inspection)
                .await
            {
                return Ok(response);
            }

            if self
                .try_auto_click_from_inspection(&session, &inspection)
                .await?
            {
                continue;
            }

            if self
                .queue_confirmation_from_inspection(&session, &inspection)
                .await?
            {
                continue;
            }

            {
                let mut runtime = session.runtime.lock().await;
                runtime.state = SessionState::WaitingForBrowser;
                runtime.detail = Some(format!(
                    "Waiting for browser interaction at {}",
                    display_page_location(&inspection)
                ));
                runtime.last_activity = std::time::Instant::now();
            }

            return Ok(FlowResponse::Waiting {
                session_id: session.session_id.clone(),
                message: Some("Waiting for browser authentication to continue".to_string()),
            });
        }
    }

    async fn next_queued_prompt(&self, session: &Arc<Session>) -> Option<FlowResponse> {
        let mut runtime = session.runtime.lock().await;
        if runtime.active_field.is_none() {
            runtime.active_field = runtime.pending_fields.pop_front();
        }
        if let Some(active) = runtime.active_field.clone() {
            runtime.state = SessionState::WaitingForInput;
            runtime.detail = Some(format!("Awaiting input '{}'", active.field.name));
            runtime.last_activity = std::time::Instant::now();
            return Some(FlowResponse::NextStep {
                session_id: session.session_id.clone(),
                required_inputs: vec![active.field],
                message: Some("Browser authentication requires input".to_string()),
            });
        }

        if let Some(action) = runtime.pending_action.clone() {
            runtime.state = SessionState::WaitingForInput;
            runtime.detail = Some("Awaiting browser confirmation".to_string());
            runtime.last_activity = std::time::Instant::now();
            return Some(FlowResponse::NextStep {
                session_id: session.session_id.clone(),
                required_inputs: vec![RequiredInput {
                    name: "confirmation".to_string(),
                    input_type: InputType::Confirmation,
                    prompt: Some(action.prompt),
                    optional: false,
                    sensitive: false,
                    interaction_id: Some(action.interaction_id),
                }],
                message: Some("Browser authentication requires confirmation".to_string()),
            });
        }

        None
    }

    async fn try_submit_collected_form(&self, session: &Arc<Session>) -> Result<bool> {
        let (fields, submit_selector) = {
            let runtime = session.runtime.lock().await;
            if runtime.active_field.is_some()
                || !runtime.pending_fields.is_empty()
                || runtime.collected_inputs.is_empty()
            {
                return Ok(false);
            }
            let submit_selector = runtime
                .collected_inputs
                .keys()
                .find_map(|name| {
                    runtime
                        .pending_fields
                        .iter()
                        .find(|field| field.field.name == *name)
                        .and_then(|field| field.submit_selector.clone())
                })
                .or_else(|| runtime.metadata.get("last_submit_selector").cloned());
            let fields = runtime
                .collected_inputs
                .iter()
                .map(|(name, value)| (name.clone(), value.value().to_string()))
                .collect::<Vec<_>>();
            (fields, submit_selector)
        };

        if fields.is_empty() {
            return Ok(false);
        }

        let selectors = {
            let runtime = session.runtime.lock().await;
            fields
                .iter()
                .filter_map(|(name, _)| runtime.metadata.get(&format!("selector:{name}")).cloned())
                .collect::<Vec<_>>()
        };

        if selectors.len() != fields.len() {
            return Ok(false);
        }

        for ((name, value), selector) in fields.iter().zip(selectors.iter()) {
            session
                .log(
                    LogLevel::Debug,
                    format!("Filling browser field '{}' via generic inspection", name),
                )
                .await;
            self.podman
                .fill(&session.container, selector, value)
                .await
                .with_context(|| format!("failed filling browser field '{}'", name))?;
        }

        {
            let mut runtime = session.runtime.lock().await;
            runtime.collected_inputs.clear();
            runtime.metadata.remove("last_submit_selector");
            runtime
                .metadata
                .retain(|key, _| !key.starts_with("selector:"));
        }

        if let Some(selector) = submit_selector {
            if let Err(error) = self.podman.click(&session.container, &selector).await {
                let Some(first_field_selector) = selectors.first() else {
                    return Err(error).context("failed submitting browser form");
                };
                session
                    .log(
                        LogLevel::Debug,
                        "Submit button click failed; submitting enclosing form via filled field",
                    )
                    .await;
                if let Err(submit_error) = self
                    .podman
                    .submit_form(&session.container, first_field_selector)
                    .await
                {
                    session
                        .log(
                            LogLevel::Debug,
                            format!(
                                "Form submit fallback failed after click error: {}; {}",
                                error, submit_error
                            ),
                        )
                        .await;
                    self.podman
                        .wait_for_settle(&session.container)
                        .await
                        .context("failed waiting after browser submit fallback")?;
                }
            }
        } else {
            if let Some(first_field_selector) = selectors.first() {
                if self
                    .podman
                    .submit_form(&session.container, first_field_selector)
                    .await
                    .is_err()
                {
                    self.podman
                        .wait_for_settle(&session.container)
                        .await
                        .context("failed waiting after browser field fill")?;
                }
            } else {
                self.podman
                    .wait_for_settle(&session.container)
                    .await
                    .context("failed waiting after browser field fill")?;
            }
        }

        sleep(Duration::from_millis(500)).await;
        Ok(true)
    }

    async fn try_click_pending_action(&self, session: &Arc<Session>) -> Result<bool> {
        let action = {
            let mut runtime = session.runtime.lock().await;
            runtime.confirmed_action.take()
        };
        let Some(action) = action else {
            return Ok(false);
        };

        session
            .log(
                LogLevel::Debug,
                format!("Clicking confirmed browser action '{}'", action.prompt),
            )
            .await;
        self.podman
            .click(&session.container, &action.selector)
            .await
            .context("failed clicking confirmed browser action")?;
        Ok(true)
    }

    async fn queue_fields_from_inspection(
        &self,
        session: &Arc<Session>,
        inspection: &PageInspection,
    ) -> Result<bool> {
        let Some(form) = select_active_form(inspection) else {
            return Ok(false);
        };

        let fields = form
            .fields
            .iter()
            .filter(|field| field_is_promptable(field))
            .collect::<Vec<_>>();
        if fields.is_empty() {
            return Ok(false);
        }

        let submit_selector = select_submit_action(&form.actions)
            .or_else(|| select_submit_action(&inspection.actions));
        let interaction_id = session.next_interaction_id().await;
        let username = {
            let runtime = session.runtime.lock().await;
            runtime.metadata.get("username").cloned()
        };
        let mut pending = Vec::with_capacity(fields.len());
        let mut used_names = Vec::<String>::new();
        let mut auto_collected = Vec::<(String, String, String)>::new();
        let mut auto_collected_logs = Vec::<(String, InputType)>::new();
        for field in fields {
            let input_type = classify_field(field);
            let prompt = prompt_for_field(field, &input_type);
            let sensitive = input_sensitive(&input_type, Some(&prompt));
            let name = unique_field_name(stable_field_name(field, &input_type), &mut used_names);
            if let Some(username) =
                auto_fill_value_for_field(field, &input_type, username.as_deref())
            {
                auto_collected_logs.push((name.clone(), input_type.clone()));
                auto_collected.push((name, username, field.selector.clone()));
                continue;
            }
            pending.push(PendingField {
                interaction_id: interaction_id.clone(),
                field: RequiredInput {
                    name: name.clone(),
                    input_type,
                    prompt: Some(prompt),
                    optional: false,
                    sensitive,
                    interaction_id: Some(interaction_id.clone()),
                },
                selector: field.selector.clone(),
                submit_selector: submit_selector.clone(),
            });
        }

        {
            let mut runtime = session.runtime.lock().await;
            runtime.pending_fields.clear();
            runtime.active_field = None;
            runtime.collected_inputs.clear();
            runtime.pending_action = None;
            runtime.confirmed_action = None;
            runtime.metadata.remove("last_submit_selector");
            runtime
                .metadata
                .retain(|key, _| !key.starts_with("selector:"));
            for field in &pending {
                runtime.metadata.insert(
                    format!("selector:{}", field.field.name),
                    field.selector.clone(),
                );
            }
            for (name, value, selector) in auto_collected {
                runtime
                    .metadata
                    .insert(format!("selector:{name}"), selector);
                runtime
                    .collected_inputs
                    .insert(name, CollectedInput::new(value, false));
            }
            if let Some(selector) = submit_selector {
                runtime
                    .metadata
                    .insert("last_submit_selector".to_string(), selector);
            }
            runtime.pending_fields.extend(pending);
            runtime.state = SessionState::WaitingForInput;
            runtime.detail = Some(format!(
                "Queued {} browser input prompt(s) at {}",
                runtime.pending_fields.len(),
                display_page_location(inspection)
            ));
            runtime.last_activity = std::time::Instant::now();
        }

        for (name, input_type) in auto_collected_logs {
            session
                .log(
                    LogLevel::Debug,
                    format!(
                        "Auto-filled browser field '{}' from session username as {:?}",
                        name, input_type
                    ),
                )
                .await;
        }

        Ok(true)
    }

    async fn terminal_browser_error_from_inspection(
        &self,
        session: &Arc<Session>,
        inspection: &PageInspection,
    ) -> Option<FlowResponse> {
        let error = terminal_browser_error(inspection)?.to_string();

        {
            let mut runtime = session.runtime.lock().await;
            runtime.state = SessionState::Failed;
            runtime.detail = Some(error.clone());
            runtime.last_activity = std::time::Instant::now();
            runtime.terminal_since = Some(std::time::Instant::now());
        }

        session
            .log(
                LogLevel::Error,
                format!("Browser authentication failed: {}", error),
            )
            .await;

        Some(FlowResponse::SessionError {
            session_id: session.session_id.clone(),
            error,
        })
    }

    async fn try_auto_click_from_inspection(
        &self,
        session: &Arc<Session>,
        inspection: &PageInspection,
    ) -> Result<bool> {
        let Some(action) = single_auto_click_action(&inspection.actions) else {
            return Ok(false);
        };

        {
            let mut runtime = session.runtime.lock().await;
            if runtime.auto_clicks_this_turn >= MAX_AUTO_CLICKS_PER_TURN {
                return Ok(false);
            }
            runtime.auto_clicks_this_turn += 1;
            runtime.state = SessionState::InProgress;
            runtime.detail = Some(format!("Auto-clicking '{}'", action.text));
            runtime.last_activity = std::time::Instant::now();
        }

        session
            .log(
                LogLevel::Debug,
                format!("Auto-clicking generic browser action '{}'", action.text),
            )
            .await;
        self.podman
            .click(&session.container, &action.selector)
            .await
            .with_context(|| format!("failed auto-clicking '{}'", action.text))?;
        Ok(true)
    }

    async fn queue_confirmation_from_inspection(
        &self,
        session: &Arc<Session>,
        inspection: &PageInspection,
    ) -> Result<bool> {
        let candidates = inspection
            .actions
            .iter()
            .filter(|action| action_is_forward(action))
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return Ok(false);
        }

        let action = candidates[0];
        let interaction_id = session.next_interaction_id().await;
        let prompt = if action.text.is_empty() {
            "Continue".to_string()
        } else {
            action.text.clone()
        };
        let mut runtime = session.runtime.lock().await;
        runtime.pending_action = Some(PendingAction {
            interaction_id,
            prompt,
            selector: action.selector.clone(),
        });
        runtime.state = SessionState::WaitingForInput;
        runtime.detail = Some(format!(
            "Queued browser confirmation at {}",
            display_page_location(inspection)
        ));
        runtime.last_activity = std::time::Instant::now();
        Ok(true)
    }
}

fn select_active_form(inspection: &PageInspection) -> Option<&InspectedForm> {
    inspection
        .forms
        .iter()
        .filter(|form| form.fields.iter().any(field_is_promptable))
        .max_by_key(|form| {
            let required = form.fields.iter().filter(|field| field.required).count();
            required * 10 + form.fields.len()
        })
}

fn field_is_promptable(field: &InspectedField) -> bool {
    field_is_promptable_value(field)
}

fn field_is_promptable_value(field: &InspectedField) -> bool {
    if field.selector.is_empty() {
        return false;
    }
    !matches!(
        field.input_type.as_str(),
        "checkbox" | "radio" | "file" | "range" | "color"
    )
}

fn terminal_browser_error(inspection: &PageInspection) -> Option<&str> {
    let error = inspection.browser_error.as_deref()?.trim();
    if error.is_empty() {
        return None;
    }
    let has_promptable_fields = inspection
        .forms
        .iter()
        .flat_map(|form| form.fields.iter())
        .any(field_is_promptable);
    if has_promptable_fields {
        return None;
    }
    Some(error)
}

fn classify_field(field: &InspectedField) -> InputType {
    let haystack = field_haystack(field);

    if field.input_type == "password" || contains_wordish(&haystack, "password") {
        return InputType::Password;
    }
    if field.autocomplete.contains("one-time-code")
        || contains_wordish(&haystack, "otp")
        || contains_wordish(&haystack, "totp")
        || contains_wordish(&haystack, "mfa")
        || haystack.contains("verification code")
        || contains_wordish(&haystack, "authenticator")
    {
        return InputType::Otp;
    }
    if field_looks_like_login_identifier(field, &haystack) {
        return InputType::Username;
    }
    if field.tag == "input" || field.tag == "textarea" || field.tag == "select" {
        return InputType::Text;
    }
    InputType::Unknown
}

fn auto_fill_value_for_field(
    field: &InspectedField,
    input_type: &InputType,
    username: Option<&str>,
) -> Option<String> {
    let username = username?.trim();
    if username.is_empty() {
        return None;
    }

    if matches!(input_type, InputType::Username) {
        return Some(username.to_string());
    }

    if field_looks_like_profile_email(field) && username_looks_like_email(username) {
        return Some(username.to_string());
    }

    None
}

fn field_haystack(field: &InspectedField) -> String {
    format!(
        "{} {} {} {} {} {}",
        field.input_type,
        field.name,
        field.autocomplete,
        field.id_attr,
        field.label,
        field.placeholder
    )
    .to_ascii_lowercase()
}

fn field_looks_like_login_identifier(field: &InspectedField, haystack: &str) -> bool {
    if field.autocomplete == "username" {
        return true;
    }

    let name = field.name.to_ascii_lowercase();
    let id_attr = field.id_attr.to_ascii_lowercase();
    let label = field.label.to_ascii_lowercase();
    let placeholder = field.placeholder.to_ascii_lowercase();

    name == "username"
        || id_attr == "username"
        || contains_wordish(&label, "username")
        || contains_wordish(&placeholder, "username")
        || contains_wordish(haystack, "login")
        || contains_wordish(haystack, "loginfmt")
        || contains_wordish(haystack, "account")
}

fn field_looks_like_profile_email(field: &InspectedField) -> bool {
    let name = field.name.trim().to_ascii_lowercase();
    let id_attr = field.id_attr.trim().to_ascii_lowercase();
    let autocomplete = field.autocomplete.trim().to_ascii_lowercase();
    let label = field.label.trim().to_ascii_lowercase();
    let placeholder = field.placeholder.trim().to_ascii_lowercase();

    autocomplete == "email"
        || name == "email"
        || id_attr == "email"
        || label == "email"
        || placeholder == "email"
}

fn username_looks_like_email(value: &str) -> bool {
    let trimmed = value.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return false;
    };

    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
}

fn contains_wordish(haystack: &str, needle: &str) -> bool {
    haystack
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|part| part == needle)
}

fn prompt_for_field(field: &InspectedField, input_type: &InputType) -> String {
    for candidate in [
        field.label.as_str(),
        field.aria_label.as_str(),
        field.placeholder.as_str(),
        field.name.as_str(),
        field.id_attr.as_str(),
    ] {
        let trimmed = candidate.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    match input_type {
        InputType::Username => "Username".to_string(),
        InputType::Password => "Password".to_string(),
        InputType::Otp => "Verification code".to_string(),
        InputType::Text => "Additional information".to_string(),
        InputType::Confirmation => "Continue".to_string(),
        InputType::Unknown => "Input required".to_string(),
    }
}

fn stable_field_name(field: &InspectedField, input_type: &InputType) -> String {
    for candidate in [field.name.as_str(), field.id_attr.as_str()] {
        let sanitized = sanitize_name(candidate);
        if !sanitized.is_empty() {
            return sanitized;
        }
    }
    match input_type {
        InputType::Username => "username".to_string(),
        InputType::Password => "password".to_string(),
        InputType::Otp => "otp".to_string(),
        InputType::Text => format!("text_{}", field.id),
        InputType::Confirmation => "confirmation".to_string(),
        InputType::Unknown => format!("input_{}", field.id),
    }
}

fn unique_field_name(mut base: String, used_names: &mut Vec<String>) -> String {
    if base.is_empty() {
        base = "input".to_string();
    }
    if !used_names.iter().any(|name| name == &base) {
        used_names.push(base.clone());
        return base;
    }
    let mut idx = 2_u64;
    loop {
        let candidate = format!("{base}_{idx}");
        if !used_names.iter().any(|name| name == &candidate) {
            used_names.push(candidate.clone());
            return candidate;
        }
        idx = idx.saturating_add(1);
    }
}

fn sanitize_name(value: &str) -> String {
    let mut output = String::new();
    let mut last_sep = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            last_sep = false;
        } else if !last_sep {
            output.push('_');
            last_sep = true;
        }
    }
    output.trim_matches('_').to_string()
}

fn select_submit_action(actions: &[InspectedAction]) -> Option<String> {
    actions
        .iter()
        .find(|action| action_is_forward(action))
        .map(|action| action.selector.clone())
        .filter(|selector| !selector.is_empty())
}

fn single_auto_click_action(actions: &[InspectedAction]) -> Option<&InspectedAction> {
    let candidates = actions
        .iter()
        .filter(|action| action_is_forward(action))
        .collect::<Vec<_>>();
    if candidates.len() == 1 {
        Some(candidates[0])
    } else {
        None
    }
}

fn action_is_forward(action: &&InspectedAction) -> bool {
    action_is_forward_value(action)
}

fn action_is_forward_value(action: &InspectedAction) -> bool {
    if action.selector.is_empty() {
        return false;
    }
    let text = action.text.to_ascii_lowercase();
    if text.is_empty() && action.kind != "submit" {
        return false;
    }
    let deny = ["cancel", "back", "deny", "decline", "no", "reject"];
    if deny.iter().any(|needle| text.contains(needle)) {
        return false;
    }
    let allow = [
        "continue", "next", "submit", "sign in", "signin", "verify", "done", "allow", "accept",
        "approve", "yes", "ok", "use code", "log in", "login",
    ];
    action.kind == "submit" || allow.iter().any(|needle| text.contains(needle))
}

fn display_page_location(inspection: &PageInspection) -> String {
    if !inspection.title.trim().is_empty() {
        return inspection.title.clone();
    }
    if !inspection.origin.trim().is_empty() {
        return inspection.origin.clone();
    }
    inspection.url.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::podman::ContainerInstance;
    use std::path::PathBuf;

    fn field(
        selector: &str,
        input_type: &str,
        name: &str,
        autocomplete: &str,
        id_attr: &str,
        label: &str,
    ) -> InspectedField {
        InspectedField {
            id: name.to_string(),
            selector: selector.to_string(),
            tag: "input".to_string(),
            input_type: input_type.to_string(),
            name: name.to_string(),
            autocomplete: autocomplete.to_string(),
            id_attr: id_attr.to_string(),
            label: label.to_string(),
            required: true,
            ..Default::default()
        }
    }

    fn inspection(fields: Vec<InspectedField>) -> PageInspection {
        PageInspection {
            title: "test page".to_string(),
            forms: vec![InspectedForm {
                fields,
                actions: vec![InspectedAction {
                    selector: "[data-submit]".to_string(),
                    text: "Submit".to_string(),
                    kind: "submit".to_string(),
                }],
            }],
            actions: vec![InspectedAction {
                selector: "[data-submit]".to_string(),
                text: "Submit".to_string(),
                kind: "submit".to_string(),
            }],
            ..Default::default()
        }
    }

    fn inspection_with_error(fields: Vec<InspectedField>, browser_error: &str) -> PageInspection {
        PageInspection {
            browser_error: Some(browser_error.to_string()),
            ..inspection(fields)
        }
    }

    fn executor() -> FlowExecutor {
        FlowExecutor::new(Arc::new(PodmanClient::new(
            "podman", "image", None, "/tmp", 1, 1, true, None,
        )))
    }

    fn session(username: &str) -> Arc<Session> {
        let session = Arc::new(Session::new(
            "session-1".to_string(),
            0,
            ContainerInstance {
                id: "container-1".to_string(),
                name: "container-1".to_string(),
                session_dir: PathBuf::from("/tmp/session-1"),
                bridge_socket_path: PathBuf::from("/tmp/session-1/bridge.sock"),
            },
        ));
        futures::executor::block_on(async {
            session
                .runtime
                .lock()
                .await
                .metadata
                .insert("username".to_string(), username.to_string());
        });
        session
    }

    #[test]
    fn pure_email_field_is_text_not_username() {
        let email = field("[data-email]", "text", "email", "email", "email", "Email");

        assert_eq!(classify_field(&email), InputType::Text);
    }

    #[test]
    fn username_or_email_login_field_is_username() {
        let username = field(
            "[data-username]",
            "text",
            "username",
            "username",
            "username",
            "Username or email",
        );

        assert_eq!(classify_field(&username), InputType::Username);
    }

    #[test]
    fn no_input_browser_error_is_terminal() {
        let inspection =
            inspection_with_error(Vec::new(), "Failed to send email, please try again later.");

        assert_eq!(
            terminal_browser_error(&inspection),
            Some("Failed to send email, please try again later.")
        );
    }

    #[test]
    fn field_level_browser_error_is_not_terminal() {
        let inspection = inspection_with_error(
            vec![field(
                "[data-password]",
                "password",
                "password",
                "current-password",
                "password",
                "Password",
            )],
            "Invalid username or password.",
        );

        assert_eq!(terminal_browser_error(&inspection), None);
    }

    #[test]
    fn no_input_page_without_browser_error_is_not_terminal() {
        let inspection = inspection(Vec::new());

        assert_eq!(terminal_browser_error(&inspection), None);
    }

    #[tokio::test]
    async fn login_form_autofills_username_and_prompts_password() {
        let session = session("tux2");
        let inspection = inspection(vec![
            field(
                "[data-username]",
                "text",
                "username",
                "username",
                "username",
                "Username or email",
            ),
            field(
                "[data-password]",
                "password",
                "password",
                "current-password",
                "password",
                "Password",
            ),
        ]);

        assert!(executor()
            .queue_fields_from_inspection(&session, &inspection)
            .await
            .unwrap());

        let runtime = session.runtime.lock().await;
        assert!(runtime.collected_inputs.contains_key("username"));
        assert_eq!(runtime.pending_fields.len(), 1);
        assert_eq!(runtime.pending_fields[0].field.name, "password");
        assert_eq!(
            runtime.pending_fields[0].field.input_type,
            InputType::Password
        );
    }

    #[tokio::test]
    async fn profile_form_with_short_username_prompts_email_first_and_last_name() {
        let session = session("tux2");
        let inspection = inspection(vec![
            field("[data-email]", "text", "email", "email", "email", "Email"),
            field(
                "[data-first-name]",
                "text",
                "firstName",
                "",
                "firstName",
                "First name",
            ),
            field(
                "[data-last-name]",
                "text",
                "lastName",
                "",
                "lastName",
                "Last name",
            ),
        ]);

        assert!(executor()
            .queue_fields_from_inspection(&session, &inspection)
            .await
            .unwrap());

        let runtime = session.runtime.lock().await;
        assert!(runtime.collected_inputs.is_empty());
        let names = runtime
            .pending_fields
            .iter()
            .map(|field| field.field.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["email", "firstname", "lastname"]);
    }

    #[tokio::test]
    async fn profile_form_with_email_username_autofills_email() {
        let session = session("user@example.com");
        let inspection = inspection(vec![
            field("[data-email]", "text", "email", "email", "email", "Email"),
            field(
                "[data-first-name]",
                "text",
                "firstName",
                "",
                "firstName",
                "First name",
            ),
            field(
                "[data-last-name]",
                "text",
                "lastName",
                "",
                "lastName",
                "Last name",
            ),
        ]);

        assert!(executor()
            .queue_fields_from_inspection(&session, &inspection)
            .await
            .unwrap());

        let runtime = session.runtime.lock().await;
        assert_eq!(
            runtime
                .collected_inputs
                .get("email")
                .map(|input| input.value()),
            Some("user@example.com")
        );
        let names = runtime
            .pending_fields
            .iter()
            .map(|field| field.field.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["firstname", "lastname"]);
    }
}
