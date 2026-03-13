use crate::podman::PodmanClient;
use crate::provider_definitions::{
    BranchCondition, ExtractTarget, FlowAction, ProviderStep, SuccessCondition, WaitCondition,
};
use crate::session::Session;
use crate::types::{FlowResponse, LogLevel, ProvidedInput, SessionState};
use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

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
            let resolved = self.resolve_navigation_url(session, &url).await;
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

        session
            .log(
                LogLevel::Debug,
                format!(
                    "Initial navigation using {}='{}'",
                    navigation_source, navigation_url
                ),
            )
            .await;

        self.podman
            .execute_flow_action(
                &session.container.id,
                &format!(
                    "{{\"action\":\"navigate\",\"url\":\"{}\"}}",
                    escape_json(&navigation_url)
                ),
            )
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

            let mut runtime = session.runtime.lock().await;
            for input in provided_inputs {
                runtime.collected_inputs.insert(input.name, input.value);
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
            let (step, current_step_index, collected_input_keys, definition_len) = {
                let runtime = session.runtime.lock().await;
                let definition = session.definition.read().await;
                (
                    definition.steps.get(runtime.current_step_index).cloned(),
                    runtime.current_step_index,
                    runtime.collected_inputs.keys().cloned().collect::<Vec<_>>(),
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
                .execute_step_actions(&session, &step)
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
            .check_success_condition(&session.container.id, &probe)
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
                        prompt: self
                            .resolve_required_input_prompt(session, input.prompt)
                            .await,
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
        const BROWSER_URL_PLACEHOLDER: &str = "{{browser:url}}";

        let mut resolved = prompt?;
        if !resolved.contains(BROWSER_URL_PLACEHOLDER) {
            return Some(resolved);
        }

        match self.extract_value(session, "browser:url").await {
            Ok(Some(browser_url)) => {
                resolved = resolved.replace(BROWSER_URL_PLACEHOLDER, &browser_url);
            }
            Ok(None) => {}
            Err(error) => {
                session
                    .log(
                        LogLevel::Warn,
                        format!(
                            "Failed resolving required input prompt placeholder '{{browser:url}}': {}",
                            error
                        ),
                    )
                    .await;
            }
        }

        Some(resolved)
    }

    async fn execute_step_actions(
        &self,
        session: &Arc<Session>,
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
        }
        Ok(())
    }

    async fn execute_action(&self, session: &Arc<Session>, action: &FlowAction) -> Result<()> {
        match action {
            FlowAction::Fill { selector, input } => {
                let (value, available_inputs) = {
                    let runtime = session.runtime.lock().await;
                    (
                        runtime.collected_inputs.get(input).cloned(),
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
                    .execute_flow_action(
                        &session.container.id,
                        &format!(
                            "{{\"action\":\"fill\",\"selector\":\"{}\",\"value\":\"{}\"}}",
                            escape_json(selector),
                            escape_json(&value)
                        ),
                    )
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
                    .execute_flow_action(
                        &session.container.id,
                        &format!(
                            "{{\"action\":\"click\",\"selector\":\"{}\"}}",
                            escape_json(selector)
                        ),
                    )
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
                let resolved_url = self.resolve_navigation_url(session, url).await;
                session
                    .log(LogLevel::Debug, format!("Navigate to '{}'", resolved_url))
                    .await;
                self.podman
                    .execute_flow_action(
                        &session.container.id,
                        &format!(
                            "{{\"action\":\"navigate\",\"url\":\"{}\"}}",
                            escape_json(&resolved_url)
                        ),
                    )
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
            return Ok(runtime.collected_inputs.get(input_name).cloned());
        }

        if let Some(value) = source.strip_prefix("static:") {
            return Ok(Some(value.to_string()));
        }

        self.podman
            .capture_artifact(&session.container.id, source)
            .await
    }

    async fn resolve_navigation_url(&self, session: &Arc<Session>, url: &str) -> String {
        if url == "$dag_auth_url" {
            let runtime = session.runtime.lock().await;
            if let Some(value) = runtime.metadata.get("dag_auth_url") {
                return value.clone();
            }
        }

        url.to_string()
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
                .check_success_condition(&session.container.id, success)
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

        let runtime = session.runtime.lock().await;
        for branch in &step.branches {
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
                    .map(|current| current == value)
                    .unwrap_or(false),
            };

            if matched {
                if excluded_target_step
                    .map(|excluded| branch.goto_step == excluded)
                    .unwrap_or(false)
                {
                    continue;
                }

                let next_index = {
                    let definition = session.definition.read().await;
                    definition
                        .steps
                        .iter()
                        .position(|candidate| candidate.name == branch.goto_step)
                        .ok_or_else(|| {
                            anyhow!(
                                "step '{}' branches to unknown step '{}'",
                                step.name,
                                branch.goto_step
                            )
                        })?
                };
                return Ok(Some(next_index));
            }
        }

        Ok(None)
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

        let runtime = session.runtime.lock().await;
        Ok(FlowResponse::SessionComplete {
            session_id: session.session_id.clone(),
            success: true,
            tokens: runtime.tokens.clone(),
            metadata: runtime.metadata.clone(),
        })
    }
}

fn escape_json(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
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
