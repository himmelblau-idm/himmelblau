use crate::types::InputType;
use anyhow::{anyhow, Context, Result};
use himmelblau_unix_common::config::{split_username, HimmelblauConfig};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use url::Url;

const BUILTIN_PROVIDER_KEYS: [&str; 4] = ["entra", "okta", "google", "keycloak"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMatchers {
    #[serde(default)]
    pub issuer_contains: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub url_contains: Vec<String>,
    #[serde(default)]
    pub page_title_contains: Vec<String>,
    #[serde(default)]
    pub dom_selectors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDefinition {
    pub provider: String,
    pub display_name: String,
    #[serde(default)]
    pub matchers: Option<ProviderMatchers>,
    #[serde(default)]
    pub start_url: Option<String>,
    #[serde(default)]
    pub steps: Vec<ProviderStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderStep {
    pub name: String,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub wait_for: Option<WaitCondition>,
    #[serde(default)]
    pub required_inputs: Vec<ProviderInput>,
    #[serde(default)]
    pub actions: Vec<FlowAction>,
    #[serde(default)]
    pub branches: Vec<BranchRule>,
    #[serde(default)]
    pub success: Option<SuccessCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitCondition {
    #[serde(default)]
    pub selector: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInput {
    pub name: String,
    #[serde(rename = "type")]
    pub input_type: InputType,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FlowAction {
    Fill {
        selector: String,
        input: String,
    },
    Click {
        selector: String,
    },
    Wait {
        millis: u64,
    },
    Navigate {
        url: String,
    },
    Extract {
        target: ExtractTarget,
        source: String,
    },
    Log {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractTarget {
    AccessToken,
    IdToken,
    RefreshToken,
    AuthorizationCode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchRule {
    pub condition: BranchCondition,
    pub goto_step: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BranchCondition {
    Always,
    InputPresent { input: String },
    InputEquals { input: String, value: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessCondition {
    #[serde(default)]
    pub url_contains: Option<String>,
    #[serde(default)]
    pub dom_selector: Option<String>,
    #[serde(default)]
    pub token_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProviderRegistry {
    by_name: HashMap<String, Arc<ProviderDefinition>>,
}

impl ProviderRegistry {
    pub async fn load(override_path: Option<&Path>) -> Result<Self> {
        let mut definitions = Vec::new();

        if let Some(path) = override_path {
            let raw = fs::read_to_string(path).await.with_context(|| {
                format!("failed to read provider override file: {}", path.display())
            })?;
            let mut parsed = parse_provider_override(&raw)?;
            definitions.append(&mut parsed);
        }

        let mut by_name: HashMap<String, Arc<ProviderDefinition>> = HashMap::new();
        for definition in definitions {
            validate_provider_definition(&definition)?;
            by_name.insert(definition.provider.clone(), Arc::new(definition));
        }

        Ok(Self { by_name })
    }

    pub fn get(&self, provider: &str) -> Option<Arc<ProviderDefinition>> {
        self.by_name.get(provider).cloned()
    }

    pub fn providers(&self) -> Vec<String> {
        let mut keys = self.by_name.keys().cloned().collect::<Vec<_>>();
        for key in BUILTIN_PROVIDER_KEYS {
            if !keys.iter().any(|existing| existing == key) {
                keys.push(key.to_string());
            }
        }
        keys.sort();
        keys
    }

    pub fn detect_provider(
        &self,
        requested_provider: Option<&str>,
        username: Option<&str>,
        issuer_url: Option<&str>,
        config: &HimmelblauConfig,
    ) -> String {
        if let Some(provider) = requested_provider {
            return provider.to_string();
        }

        if let Some(url) = issuer_url {
            for candidate in self.by_name.values() {
                let Some(matchers) = &candidate.matchers else {
                    continue;
                };
                if matchers
                    .issuer_contains
                    .iter()
                    .any(|probe| url.contains(probe))
                {
                    return candidate.provider.clone();
                }
                if matchers
                    .url_contains
                    .iter()
                    .any(|probe| url.contains(probe))
                {
                    return candidate.provider.clone();
                }
            }
        }

        if let Some(username) = username {
            if let Some((_, domain)) = split_username(username) {
                if let Some(provider) = config.get(domain, "orchestrator_provider") {
                    return provider;
                }

                for candidate in self.by_name.values() {
                    let Some(matchers) = &candidate.matchers else {
                        continue;
                    };
                    if matchers.domains.iter().any(|entry| entry == domain) {
                        return candidate.provider.clone();
                    }
                }
            }
        }

        if let Some(provider) = config.get("global", "orchestrator_provider") {
            return provider;
        }

        if let Some(provider) = detect_builtin_provider(username, issuer_url) {
            return provider;
        }

        infer_provider_from_context(username, issuer_url).unwrap_or_else(|| "unknown".to_string())
    }
}

fn detect_builtin_provider(username: Option<&str>, issuer_url: Option<&str>) -> Option<String> {
    if let Some(issuer_url) = issuer_url {
        let issuer = issuer_url.to_lowercase();
        if issuer.contains("login.microsoftonline.com") || issuer.contains("microsoftonline") {
            return Some("entra".to_string());
        }
        if issuer.contains("accounts.google.com") {
            return Some("google".to_string());
        }
        if issuer.contains("okta.com") {
            return Some("okta".to_string());
        }
        if issuer.contains("keycloak")
            || issuer.contains("/realms/")
            || issuer.contains("/protocol/openid-connect")
        {
            return Some("keycloak".to_string());
        }
    }

    if let Some(username) = username {
        if let Some((_, domain)) = split_username(username) {
            let domain = domain.to_lowercase();
            if domain == "gmail.com" || domain == "googlemail.com" {
                return Some("google".to_string());
            }
            if domain.ends_with(".okta.com") || domain == "okta.com" {
                return Some("okta".to_string());
            }
        }
    }

    None
}

fn infer_provider_from_context(username: Option<&str>, issuer_url: Option<&str>) -> Option<String> {
    if let Some(issuer_url) = issuer_url {
        if let Ok(parsed) = Url::parse(issuer_url) {
            if let Some(host) = parsed.host_str() {
                if let Some(key) = normalize_provider_key(host) {
                    return Some(key);
                }
            }
        }
    }

    if let Some(username) = username {
        if let Some((_, domain)) = split_username(username) {
            return normalize_provider_key(domain);
        }
    }

    None
}

fn normalize_provider_key(value: &str) -> Option<String> {
    let mut output = String::new();
    let mut last_was_sep = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            last_was_sep = false;
        } else if !last_was_sep {
            output.push('_');
            last_was_sep = true;
        }
    }

    let normalized = output.trim_matches('_').to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

pub fn validate_provider_definition(definition: &ProviderDefinition) -> Result<()> {
    if definition.provider.trim().is_empty() {
        return Err(anyhow!("provider key must not be empty"));
    }

    if definition.steps.is_empty() {
        return Err(anyhow!(
            "provider '{}' has no steps in flow definition",
            definition.provider
        ));
    }

    let mut seen_steps = HashSet::new();

    if let Some(matchers) = &definition.matchers {
        validate_matchers(matchers).with_context(|| {
            format!(
                "provider '{}' contains invalid matchers",
                definition.provider
            )
        })?;
    }

    for step in &definition.steps {
        if step.name.trim().is_empty() {
            return Err(anyhow!(
                "provider '{}' has a step with empty name",
                definition.provider
            ));
        }

        if !seen_steps.insert(step.name.clone()) {
            return Err(anyhow!(
                "provider '{}' contains duplicate step '{}'",
                definition.provider,
                step.name
            ));
        }

        for action in &step.actions {
            match action {
                FlowAction::Fill { selector, .. } | FlowAction::Click { selector } => {
                    validate_selector(selector).with_context(|| {
                        format!(
                            "provider '{}' step '{}' contains invalid selector",
                            definition.provider, step.name
                        )
                    })?;
                }
                _ => {}
            }
        }
    }

    for step in &definition.steps {
        for branch in &step.branches {
            if !seen_steps.contains(&branch.goto_step) {
                return Err(anyhow!(
                    "provider '{}' step '{}' branches to unknown step '{}'",
                    definition.provider,
                    step.name,
                    branch.goto_step
                ));
            }
        }
    }

    Ok(())
}

fn validate_selector(selector: &str) -> Result<()> {
    let trimmed = selector.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("selector must not be empty"));
    }
    if trimmed.len() > 256 {
        return Err(anyhow!("selector exceeds maximum length"));
    }
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(anyhow!("selector must be single-line"));
    }
    if trimmed.contains("javascript:") {
        return Err(anyhow!("selector contains forbidden javascript scheme"));
    }
    Ok(())
}

fn validate_matchers(matchers: &ProviderMatchers) -> Result<()> {
    for selector in &matchers.dom_selectors {
        validate_selector(selector).context("matcher dom_selector is invalid")?;
    }
    Ok(())
}

fn parse_provider_override(raw: &str) -> Result<Vec<ProviderDefinition>> {
    if let Ok(single) = serde_json::from_str::<ProviderDefinition>(raw) {
        return Ok(vec![single]);
    }

    if let Ok(list) = serde_json::from_str::<Vec<ProviderDefinition>>(raw) {
        return Ok(list);
    }

    #[derive(Debug, Deserialize)]
    struct Wrapper {
        providers: Vec<ProviderDefinition>,
    }

    if let Ok(wrapper) = serde_json::from_str::<Wrapper>(raw) {
        return Ok(wrapper.providers);
    }

    Err(anyhow!(
        "provider override file must be a provider object, provider array, or {{\"providers\":[...]}}"
    ))
}
