use crate::podman::PodmanClient;
use crate::provider_definitions::{
    BranchCondition, ExtractTarget, FlowAction, ProviderStep, SuccessCondition, WaitCondition,
};
use crate::session::{CollectedInput, Session};
use crate::types::{FlowResponse, InputType, LogLevel, ProvidedInput, SessionState};
use anyhow::{anyhow, Context, Result};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use zeroize::Zeroizing;

pub struct FlowExecutor {
    podman: Arc<PodmanClient>,
}

impl FlowExecutor {
    pub fn new(podman: Arc<PodmanClient>) -> Self {
        Self { podman }
    }

    pub async fn start_session(&self, session: Arc<Session>) -> Result<FlowResponse> {
        session
            .log(
                LogLevel::Info,
                format!("Starting provider flow '{}'", session.provider),
            )
            .await;

        self.initialize_session_navigation(&session)
            .await
            .context("failed to initialize browser navigation for session")?;

        self.advance_until_blocked_or_complete(session).await
    }

    async fn initialize_session_navigation(&self, session: &Arc<Session>) -> Result<()> {
        let provider_start_url = {
            let definition = session.definition.read().await;
            definition.start_url.clone()
        };

        let dag_auth_url = {
            let runtime = session.runtime.lock().await;
            runtime.metadata.get("dag_auth_url").cloned()
        };

        let (navigation_source, navigation_url) = if let Some(url) = dag_auth_url {
            ("dag_auth_url", url)
        } else if let Some(url) = provider_start_url {
            let Some(resolved) = self.resolve_navigation_url(session, &url).await else {
                session
                    .log(
                        LogLevel::Debug,
                        format!(
                            "Skipping initial navigation: provider_start_url '{}' could not be resolved",
                            url
                        ),
                    )
                    .await;
                return Ok(());
            };
            ("provider_start_url", resolved)
        } else {
            session
                .log(
                    LogLevel::Debug,
                    "No initial navigation URL available; relying on in-step navigation"
                        .to_string(),
                )
                .await;
            return Ok(());
        };

        let navigation_url_for_debug = redact_url_parameters(&navigation_url);

        session
            .log(
                LogLevel::Debug,
                format!(
                    "Initial navigation using {}='{}'",
                    navigation_source, navigation_url_for_debug
                ),
            )
            .await;

        self.podman
            .navigate(&session.container, &navigation_url)
            .await
            .with_context(|| {
                format!(
                    "initial navigation failed using {}='{}'",
                    navigation_source, navigation_url
                )
            })
    }

    pub async fn continue_session(
        &self,
        session: Arc<Session>,
        provided_inputs: Vec<ProvidedInput>,
    ) -> Result<FlowResponse> {
        if !provided_inputs.is_empty() {
            let provided_summary = provided_inputs
                .iter()
                .map(|input| format!("{}(len={})", input.name, input.value.len()))
                .collect::<Vec<_>>();
            session
                .log(
                    LogLevel::Debug,
                    format!(
                        "Received next_step inputs for session continuation: {:?}",
                        provided_summary
                    ),
                )
                .await;

            let sensitive_input_names = sensitive_input_names(&session).await;
            let mut runtime = session.runtime.lock().await;
            for mut input in provided_inputs {
                let sensitive = sensitive_input_names.contains(input.name.as_str());
                let name = std::mem::take(&mut input.name);
                let value = std::mem::take(&mut input.value);
                runtime
                    .collected_inputs
                    .insert(name, CollectedInput::new(value, sensitive));
            }
            runtime.state = SessionState::InProgress;
            runtime.detail = Some("Continuing browser flow".to_string());
            runtime.last_activity = std::time::Instant::now();
        }

        self.advance_until_blocked_or_complete(session).await
    }

    async fn advance_until_blocked_or_complete(
        &self,
        session: Arc<Session>,
    ) -> Result<FlowResponse> {
        loop {
            let (current_step_index, collected_input_keys) = {
                let runtime = session.runtime.lock().await;
                (
                    runtime.current_step_index,
                    runtime.collected_inputs.keys().cloned().collect::<Vec<_>>(),
                )
            };
            let (step, definition_len) = {
                let definition = session.definition.read().await;
                (
                    definition.steps.get(current_step_index).cloned(),
                    definition.steps.len(),
                )
            };

            let Some(step) = step else {
                session
                    .log(
                        LogLevel::Debug,
                        format!(
                            "No step at index {} (definition has {} steps)",
                            current_step_index, definition_len
                        ),
                    )
                    .await;
                return self
                    .complete_session(session, "Flow reached terminal step")
                    .await;
            };

            session
                .log(
                    LogLevel::Debug,
                    format!(
                        "Step '{}' context: step_index={} collected_inputs={:?} required_inputs={:?} actions={}",
                        step.name,
                        current_step_index,
                        collected_input_keys,
                        step.required_inputs
                            .iter()
                            .map(|input| input.name.clone())
                            .collect::<Vec<_>>(),
                        step.actions.len(),
                    ),
                )
                .await;

            session
                .log(LogLevel::Info, format!("Executing step '{}'", step.name))
                .await;

            if !self
                .optional_step_wait_condition_satisfied(&session, &step)
                .await?
            {
                if let Some(next_step_index) = self
                    .evaluate_branch_excluding(&session, &step, Some(step.name.as_str()))
                    .await?
                {
                    let next_step_name = {
                        let definition = session.definition.read().await;
                        definition
                            .steps
                            .get(next_step_index)
                            .map(|candidate| candidate.name.clone())
                            .unwrap_or_else(|| "<unknown>".to_string())
                    };
                    session
                        .log(
                            LogLevel::Debug,
                            format!(
                                "Optional step '{}' wait_for not satisfied; following fallback branch to '{}'",
                                step.name, next_step_name
                            ),
                        )
                        .await;
                    let mut runtime = session.runtime.lock().await;
                    runtime.current_step_index = next_step_index;
                    runtime.last_activity = std::time::Instant::now();
                    continue;
                }

                session
                    .log(
                        LogLevel::Debug,
                        format!(
                            "Optional step '{}' wait_for not satisfied; advancing sequentially",
                            step.name
                        ),
                    )
                    .await;

                let mut runtime = session.runtime.lock().await;
                runtime.current_step_index += 1;
                runtime.last_activity = std::time::Instant::now();
                continue;
            }

            if let Some(response) = self.maybe_request_inputs(&session, &step).await {
                return Ok(response);
            }

            if let Err(error) = self
                .execute_step_actions(&session, current_step_index, &step)
                .await
                .with_context(|| format!("provider step '{}' failed", step.name))
            {
                if !step.optional {
                    return Err(error);
                }

                session
                    .log(
                        LogLevel::Warn,
                        format!(
                            "Optional step '{}' failed and will be skipped: {}",
                            step.name, error
                        ),
                    )
                    .await;

                if let Some(next_step_index) = self.evaluate_branch(&session, &step).await? {
                    let next_step_name = {
                        let definition = session.definition.read().await;
                        definition
                            .steps
                            .get(next_step_index)
                            .map(|candidate| candidate.name.clone())
                            .unwrap_or_else(|| "<unknown>".to_string())
                    };
                    session
                        .log(
                            LogLevel::Debug,
                            format!(
                                "Optional step '{}' fallback branch: next_step_index={} next_step='{}'",
                                step.name, next_step_index, next_step_name
                            ),
                        )
                        .await;
                    let mut runtime = session.runtime.lock().await;
                    runtime.current_step_index = next_step_index;
                    runtime.last_activity = std::time::Instant::now();
                    continue;
                }

                session
                    .log(
                        LogLevel::Debug,
                        format!(
                            "Optional step '{}' has no fallback branch; advancing sequentially",
                            step.name
                        ),
                    )
                    .await;

                let mut runtime = session.runtime.lock().await;
                runtime.current_step_index += 1;
                runtime.last_activity = std::time::Instant::now();
                continue;
            }

            if self.step_successful(&session, &step).await? {
                return self
                    .complete_session(session, "Flow reported successful authentication")
                    .await;
            }

            if let Some(next_step_index) = self.evaluate_branch(&session, &step).await? {
                let next_step_name = {
                    let definition = session.definition.read().await;
                    definition
                        .steps
                        .get(next_step_index)
                        .map(|candidate| candidate.name.clone())
                        .unwrap_or_else(|| "<unknown>".to_string())
                };
                session
                    .log(
                        LogLevel::Debug,
                        format!(
                            "Branch transition after step '{}': next_step_index={} next_step='{}'",
                            step.name, next_step_index, next_step_name
                        ),
                    )
                    .await;
                let mut runtime = session.runtime.lock().await;
                runtime.current_step_index = next_step_index;
                runtime.last_activity = std::time::Instant::now();
                continue;
            }

            session
                .log(
                    LogLevel::Debug,
                    format!(
                        "No branch matched after step '{}'; advancing sequentially",
                        step.name
                    ),
                )
                .await;

            let mut runtime = session.runtime.lock().await;
            runtime.current_step_index += 1;
            runtime.last_activity = std::time::Instant::now();
        }
    }

    async fn optional_step_wait_condition_satisfied(
        &self,
        session: &Arc<Session>,
        step: &ProviderStep,
    ) -> Result<bool> {
        if !step.optional {
            return Ok(true);
        }

        let Some(wait_for) = &step.wait_for else {
            return Ok(true);
        };

        self.wait_condition_satisfied(session, &step.name, wait_for)
            .await
    }

    async fn wait_condition_satisfied(
        &self,
        session: &Arc<Session>,
        step_name: &str,
        wait_for: &WaitCondition,
    ) -> Result<bool> {
        let probe = SuccessCondition {
            url_contains: wait_for.pattern.clone(),
            dom_selector: wait_for.selector.clone(),
            token_key: None,
        };

        if probe.url_contains.is_none() && probe.dom_selector.is_none() {
            return Ok(true);
        }

        let matched = self
            .podman
            .check_success_condition(&session.container, &probe)
            .await
            .with_context(|| {
                format!(
                    "failed to evaluate wait_for condition before step '{}'",
                    step_name
                )
            })?;

        session
            .log(
                LogLevel::Debug,
                format!(
                    "Step '{}' wait_for probe result: matched={} selector={:?} pattern={:?}",
                    step_name, matched, wait_for.selector, wait_for.pattern
                ),
            )
            .await;

        Ok(matched)
    }

    async fn maybe_request_inputs(
        &self,
        session: &Arc<Session>,
        step: &ProviderStep,
    ) -> Option<FlowResponse> {
        let (required_inputs, input_presence) = {
            let runtime = session.runtime.lock().await;
            let missing = step
                .required_inputs
                .iter()
                .filter(|required| {
                    if required.optional {
                        return false;
                    }

                    match runtime.collected_inputs.get(&required.name) {
                        Some(value) => value.is_empty(),
                        None => true,
                    }
                })
                .cloned()
                .collect::<Vec<_>>();
            let presence = step
                .required_inputs
                .iter()
                .map(|required| {
                    let status = match runtime.collected_inputs.get(&required.name) {
                        Some(value) if value.is_empty() => "present-empty",
                        Some(_) => "present",
                        None => "missing",
                    };
                    format!("{}:{}", required.name, status)
                })
                .collect::<Vec<_>>();
            (missing, presence)
        };

        if required_inputs.is_empty() {
            session
                .log(
                    LogLevel::Debug,
                    format!(
                        "Step '{}' has all required inputs satisfied: {:?}",
                        step.name, input_presence
                    ),
                )
                .await;
            return None;
        }

        session
            .log(
                LogLevel::Debug,
                format!(
                    "Step '{}' blocking for inputs. Presence: {:?}; missing_required={:?}",
                    step.name,
                    input_presence,
                    required_inputs
                        .iter()
                        .map(|input| input.name.as_str())
                        .collect::<Vec<_>>()
                ),
            )
            .await;

        {
            let mut runtime = session.runtime.lock().await;
            runtime.state = SessionState::WaitingForInput;
            runtime.detail = Some(format!("Awaiting input for step '{}'", step.name));
            runtime.last_activity = std::time::Instant::now();
        }

        Some(FlowResponse::NextStep {
            session_id: session.session_id.clone(),
            required_inputs: {
                let mut response_inputs = Vec::with_capacity(required_inputs.len());
                for input in required_inputs {
                    response_inputs.push(crate::types::RequiredInput {
                        name: input.name,
                        input_type: input.input_type,
                        // Normalize the prompt, removing whitespace
                        prompt: self
                            .resolve_required_input_prompt(session, input.prompt)
                            .await
                            .map(|prompt| prompt.trim().to_string().replace("\n\n", "\n")),
                        optional: input.optional,
                    });
                }
                response_inputs
            },
            message: Some(format!("Step '{}' requires additional inputs", step.name)),
        })
    }

    async fn resolve_required_input_prompt(
        &self,
        session: &Arc<Session>,
        prompt: Option<String>,
    ) -> Option<String> {
        let mut resolved = prompt?;
        let placeholders = prompt_placeholders(&resolved);
        if placeholders.is_empty() {
            return Some(resolved);
        }

        for placeholder in placeholders {
            match self.extract_value(session, &placeholder.source).await {
                Ok(Some(value)) => {
                    resolved = resolved.replace(&placeholder.token, &value);
                }
                Ok(None) => {}
                Err(error) => {
                    session
                        .log(
                            LogLevel::Warn,
                            format!(
                                "Failed resolving required input prompt placeholder '{}': {}",
                                placeholder.token, error
                            ),
                        )
                        .await;
                }
            }
        }

        Some(resolved)
    }

    async fn execute_step_actions(
        &self,
        session: &Arc<Session>,
        current_step_index: usize,
        step: &ProviderStep,
    ) -> Result<()> {
        let total_actions = step.actions.len();
        for (idx, action) in step.actions.iter().enumerate() {
            let action_idx = idx + 1;
            let action_summary = summarize_action(action);
            session
                .log(
                    LogLevel::Debug,
                    format!(
                        "Step '{}' action {}/{}: {}",
                        step.name, action_idx, total_actions, action_summary
                    ),
                )
                .await;

            self.execute_action(session, action)
                .await
                .with_context(|| {
                    format!(
                        "step '{}' action {}/{} failed ({})",
                        step.name, action_idx, total_actions, action_summary
                    )
                })?;
            if let FlowAction::Fill { input, .. } = action {
                self.forget_sensitive_input_if_unreferenced(
                    session,
                    current_step_index,
                    idx,
                    input,
                )
                .await;
            }
        }
        Ok(())
    }

    async fn execute_action(&self, session: &Arc<Session>, action: &FlowAction) -> Result<()> {
        match action {
            FlowAction::Fill { selector, input } => {
                let (value, available_inputs) = {
                    let runtime = session.runtime.lock().await;
                    (
                        runtime
                            .collected_inputs
                            .get(input)
                            .map(|value| Zeroizing::new(value.value().to_string())),
                        runtime.collected_inputs.keys().cloned().collect::<Vec<_>>(),
                    )
                };
                let value = value.ok_or_else(|| {
                    anyhow!(
                        "missing required input '{}' (available inputs: {:?})",
                        input,
                        available_inputs
                    )
                })?;

                session
                    .log(
                        LogLevel::Debug,
                        format!("Fill '{}' with '{}'", selector, input),
                    )
                    .await;
                self.podman
                    .fill(&session.container, selector, value.as_str())
                    .await
                    .with_context(|| {
                        format!(
                            "bridge fill failed for selector '{}' and input '{}'",
                            selector, input
                        )
                    })?;
            }
            FlowAction::Click { selector } => {
                session
                    .log(LogLevel::Debug, format!("Click '{}'", selector))
                    .await;
                self.podman
                    .click(&session.container, selector)
                    .await
                    .with_context(|| format!("bridge click failed for selector '{}'", selector))?;
            }
            FlowAction::Wait { millis } => {
                session
                    .log(LogLevel::Debug, format!("Wait {}ms", millis))
                    .await;
                sleep(Duration::from_millis(*millis)).await;
            }
            FlowAction::Navigate { url } => {
                let resolved_url =
                    self.resolve_navigation_url(session, url)
                        .await
                        .ok_or_else(|| {
                            anyhow!(
                        "navigation URL '{}' requires dag_auth_url metadata but none is available",
                        url
                    )
                        })?;
                session
                    .log(LogLevel::Debug, format!("Navigate to '{}'", resolved_url))
                    .await;
                self.podman
                    .navigate(&session.container, &resolved_url)
                    .await
                    .with_context(|| {
                        format!("bridge navigate failed for url '{}'", resolved_url)
                    })?;
            }
            FlowAction::Extract { target, source } => {
                let value = self
                    .extract_value(session, source)
                    .await
                    .with_context(|| format!("extract failed for source '{}'", source))?;
                if let Some(value) = value {
                    let mut runtime = session.runtime.lock().await;
                    match target {
                        ExtractTarget::AccessToken => runtime.tokens.access_token = Some(value),
                        ExtractTarget::IdToken => runtime.tokens.id_token = Some(value),
                        ExtractTarget::RefreshToken => runtime.tokens.refresh_token = Some(value),
                        ExtractTarget::AuthorizationCode => {
                            runtime.tokens.authorization_code = Some(value)
                        }
                    }
                    runtime.last_activity = std::time::Instant::now();
                }
            }
            FlowAction::Log { message } => {
                session.log(LogLevel::Info, message.clone()).await;
            }
        }

        Ok(())
    }

    async fn extract_value(&self, session: &Arc<Session>, source: &str) -> Result<Option<String>> {
        if let Some(input_name) = source.strip_prefix("input:") {
            let runtime = session.runtime.lock().await;
            return Ok(runtime
                .collected_inputs
                .get(input_name)
                .map(|value| value.value().to_string()));
        }

        if let Some(value) = source.strip_prefix("static:") {
            return Ok(Some(value.to_string()));
        }

        let totp_account = if source.starts_with("browser:totp-uri:") {
            let runtime = session.runtime.lock().await;
            runtime
                .collected_inputs
                .get("username")
                .map(|value| value.value().to_string())
        } else {
            None
        };

        self.podman
            .capture_artifact_with_totp_account(&session.container, source, totp_account.as_deref())
            .await
    }

    async fn resolve_navigation_url(&self, session: &Arc<Session>, url: &str) -> Option<String> {
        if url == "$dag_auth_url" {
            let runtime = session.runtime.lock().await;
            if let Some(value) = runtime.metadata.get("dag_auth_url") {
                return Some(value.clone());
            }
            return None;
        }

        Some(url.to_string())
    }

    async fn step_successful(&self, session: &Arc<Session>, step: &ProviderStep) -> Result<bool> {
        let Some(success) = &step.success else {
            return Ok(false);
        };

        if let Some(token_key) = &success.token_key {
            let runtime = session.runtime.lock().await;
            let has_token = match token_key.as_str() {
                "access_token" => runtime.tokens.access_token.is_some(),
                "id_token" => runtime.tokens.id_token.is_some(),
                "refresh_token" => runtime.tokens.refresh_token.is_some(),
                "authorization_code" => runtime.tokens.authorization_code.is_some(),
                _ => false,
            };

            if has_token {
                session
                    .log(
                        LogLevel::Debug,
                        format!(
                            "Step '{}' success condition satisfied by token_key='{}'",
                            step.name, token_key
                        ),
                    )
                    .await;
                return Ok(true);
            }

            session
                .log(
                    LogLevel::Debug,
                    format!(
                        "Step '{}' success token_key='{}' not yet available",
                        step.name, token_key
                    ),
                )
                .await;
        }

        if success.dom_selector.is_some() || success.url_contains.is_some() {
            let matched = self
                .podman
                .check_success_condition(&session.container, success)
                .await?;
            session
                .log(
                    LogLevel::Debug,
                    format!(
                        "Step '{}' success probe result via dom/url condition: {}",
                        step.name, matched
                    ),
                )
                .await;
            return Ok(matched);
        }

        Ok(false)
    }

    async fn evaluate_branch(
        &self,
        session: &Arc<Session>,
        step: &ProviderStep,
    ) -> Result<Option<usize>> {
        self.evaluate_branch_excluding(session, step, None).await
    }

    async fn evaluate_branch_excluding(
        &self,
        session: &Arc<Session>,
        step: &ProviderStep,
        excluded_target_step: Option<&str>,
    ) -> Result<Option<usize>> {
        if step.branches.is_empty() {
            return Ok(None);
        }

        let matched_target = {
            let runtime = session.runtime.lock().await;
            step.branches.iter().find_map(|branch| {
                let matched = match &branch.condition {
                    BranchCondition::Always => true,
                    BranchCondition::InputPresent { input } => runtime
                        .collected_inputs
                        .get(input)
                        .map(|value| !value.is_empty())
                        .unwrap_or(false),
                    BranchCondition::InputEquals { input, value } => runtime
                        .collected_inputs
                        .get(input)
                        .map(|current| current.value() == value)
                        .unwrap_or(false),
                };

                if !matched {
                    return None;
                }

                if excluded_target_step
                    .map(|excluded| branch.goto_step == excluded)
                    .unwrap_or(false)
                {
                    return None;
                }

                Some(branch.goto_step.clone())
            })
        };

        let Some(goto_step) = matched_target else {
            return Ok(None);
        };

        let next_index = {
            let definition = session.definition.read().await;
            definition
                .steps
                .iter()
                .position(|candidate| candidate.name == goto_step)
                .ok_or_else(|| {
                    anyhow!(
                        "step '{}' branches to unknown step '{}'",
                        step.name,
                        goto_step
                    )
                })?
        };

        Ok(Some(next_index))
    }

    async fn forget_sensitive_input_if_unreferenced(
        &self,
        session: &Arc<Session>,
        current_step_index: usize,
        current_action_index: usize,
        input_name: &str,
    ) {
        let should_forget = {
            let definition = session.definition.read().await;
            if !definition.steps.iter().any(|step| {
                step.required_inputs.iter().any(|input| {
                    input.name == input_name
                        && matches!(input.input_type, InputType::Password | InputType::Otp)
                })
            }) {
                return;
            }

            !definition
                .steps
                .iter()
                .enumerate()
                .any(|(step_index, step)| {
                    if step_index < current_step_index {
                        return false;
                    }

                    if step_index == current_step_index {
                        step_references_input_after_action(step, current_action_index, input_name)
                    } else {
                        step_references_input(step, input_name)
                    }
                })
        };

        if should_forget {
            let mut runtime = session.runtime.lock().await;
            if let Some(removed) = runtime.collected_inputs.remove(input_name) {
                drop(removed);
                runtime.last_activity = std::time::Instant::now();
            }
        }
    }

    async fn complete_session(
        &self,
        session: Arc<Session>,
        detail: impl Into<String>,
    ) -> Result<FlowResponse> {
        {
            let mut runtime = session.runtime.lock().await;
            runtime.state = SessionState::Completed;
            runtime.detail = Some(detail.into());
            runtime.last_activity = std::time::Instant::now();
            runtime.terminal_since = Some(std::time::Instant::now());
        }

        session.log(LogLevel::Info, "Session completed").await;

        let mut runtime = session.runtime.lock().await;
        let tokens = std::mem::take(&mut runtime.tokens);
        let metadata = std::mem::take(&mut runtime.metadata);
        Ok(FlowResponse::SessionComplete {
            session_id: session.session_id.clone(),
            success: true,
            tokens,
            metadata,
        })
    }
}

fn redact_url_parameters(url: &str) -> String {
    let Some((base, query_and_fragment)) = url.split_once('?') else {
        return url.to_string();
    };

    if let Some((_, fragment)) = query_and_fragment.split_once('#') {
        format!("{}?<redacted>#{}", base, fragment)
    } else {
        format!("{}?<redacted>", base)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PromptPlaceholder {
    token: String,
    source: String,
}

fn prompt_placeholders(prompt: &str) -> Vec<PromptPlaceholder> {
    let mut placeholders = Vec::new();
    let mut cursor = 0;

    while let Some(start_offset) = prompt[cursor..].find("{{") {
        let start = cursor + start_offset;
        let value_start = start + 2;
        let Some(end_offset) = prompt[value_start..].find("}}") else {
            break;
        };
        let end = value_start + end_offset;
        let token_end = end + 2;
        let source = prompt[value_start..end].trim();

        if !source.is_empty() {
            placeholders.push(PromptPlaceholder {
                token: prompt[start..token_end].to_string(),
                source: source.to_string(),
            });
        }

        cursor = token_end;
    }

    placeholders
}

async fn sensitive_input_names(session: &Arc<Session>) -> HashSet<String> {
    let definition = session.definition.read().await;
    definition
        .steps
        .iter()
        .flat_map(|step| step.required_inputs.iter())
        .filter(|input| matches!(input.input_type, InputType::Password | InputType::Otp))
        .map(|input| input.name.clone())
        .collect()
}

fn summarize_action(action: &FlowAction) -> String {
    match action {
        FlowAction::Fill { selector, input } => {
            format!("fill selector='{}' input='{}'", selector, input)
        }
        FlowAction::Click { selector } => format!("click selector='{}'", selector),
        FlowAction::Wait { millis } => format!("wait {}ms", millis),
        FlowAction::Navigate { url } => format!("navigate url='{}'", url),
        FlowAction::Extract { target, source } => {
            format!("extract target='{:?}' source='{}'", target, source)
        }
        FlowAction::Log { message } => format!("log '{}'", message),
    }
}

fn step_references_input_after_action(
    step: &ProviderStep,
    current_action_index: usize,
    input_name: &str,
) -> bool {
    step.actions
        .iter()
        .skip(current_action_index + 1)
        .any(|action| action_references_input(action, input_name))
        || branches_reference_input(step, input_name)
}

fn step_references_input(step: &ProviderStep, input_name: &str) -> bool {
    step.required_inputs
        .iter()
        .any(|input| input.name == input_name)
        || step
            .actions
            .iter()
            .any(|action| action_references_input(action, input_name))
        || branches_reference_input(step, input_name)
}

fn action_references_input(action: &FlowAction, input_name: &str) -> bool {
    match action {
        FlowAction::Fill { input, .. } => input == input_name,
        FlowAction::Extract { source, .. } => source
            .strip_prefix("input:")
            .map(|source_input| source_input == input_name)
            .unwrap_or(false),
        FlowAction::Click { .. }
        | FlowAction::Wait { .. }
        | FlowAction::Navigate { .. }
        | FlowAction::Log { .. } => false,
    }
}

fn branches_reference_input(step: &ProviderStep, input_name: &str) -> bool {
    step.branches.iter().any(|branch| match &branch.condition {
        BranchCondition::InputPresent { input } | BranchCondition::InputEquals { input, .. } => {
            input == input_name
        }
        BranchCondition::Always => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_placeholders_include_existing_browser_url_source() {
        assert_eq!(
            prompt_placeholders("Use {{browser:url}}"),
            vec![PromptPlaceholder {
                token: "{{browser:url}}".to_string(),
                source: "browser:url".to_string(),
            }]
        );
    }

    #[test]
    fn prompt_placeholders_include_generic_page_sources() {
        assert_eq!(
            prompt_placeholders(
                "Manual link: {{browser:page:a#mode-manual:attr:href}}; title={{ browser:title }}"
            ),
            vec![
                PromptPlaceholder {
                    token: "{{browser:page:a#mode-manual:attr:href}}".to_string(),
                    source: "browser:page:a#mode-manual:attr:href".to_string(),
                },
                PromptPlaceholder {
                    token: "{{ browser:title }}".to_string(),
                    source: "browser:title".to_string(),
                },
            ]
        );
    }

    #[test]
    fn prompt_placeholders_ignore_empty_and_unclosed_tokens() {
        assert_eq!(prompt_placeholders("{{}} {{   }} {{browser:url"), vec![]);
    }
}
