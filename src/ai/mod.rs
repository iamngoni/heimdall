//
//  heimdall
//  src/ai/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod claude;
pub mod claude_code;
pub mod codex;
pub mod fallback;
pub mod ollama;
pub mod openai;
pub mod types;
pub mod xai_oauth;

use std::collections::BTreeMap;

use crate::config::AiConfig;
use crate::models::HeimdallResult;
use types::{CompletionRequest, CompletionResponse};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderKind {
    Anthropic,
    ClaudeCode,
    Codex,
    XaiOAuth,
    Xai,
    OpenAi,
    OpenAiCompatible,
    Ollama,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::ClaudeCode => "claude_code",
            Self::Codex => "codex",
            Self::XaiOAuth => "xai_oauth",
            Self::Xai => "xai",
            Self::OpenAi => "openai",
            Self::OpenAiCompatible => "openai_compatible",
            Self::Ollama => "ollama",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
            Self::XaiOAuth => "Grok Subscription",
            Self::Xai => "Grok API",
            Self::OpenAi => "OpenAI",
            Self::OpenAiCompatible => "OpenAI Compatible",
            Self::Ollama => "Ollama",
        }
    }

    pub fn fallback_model(self) -> &'static str {
        match self {
            Self::Anthropic => "claude-sonnet-4-20250514",
            Self::ClaudeCode => "claude-sonnet-4-20250514",
            Self::Codex => "gpt-5.4",
            Self::XaiOAuth => "grok-build-0.1",
            Self::Xai => "grok-build-0.1",
            Self::OpenAi => "gpt-4o",
            Self::OpenAiCompatible => "gpt-4o",
            Self::Ollama => "llama3.3",
        }
    }

    pub fn matches_model(self, model: &str) -> bool {
        let model = model.to_ascii_lowercase();
        match self {
            Self::Anthropic => model.contains("claude"),
            Self::ClaudeCode => model.contains("claude"),
            Self::Codex => {
                model.contains("codex")
                    || model.starts_with("gpt")
                    || model.starts_with("o1")
                    || model.starts_with("o3")
                    || model.starts_with("o4")
                    || model.starts_with("o5")
            }
            Self::XaiOAuth => model.contains("grok") || model.starts_with("xai/"),
            Self::Xai => model.contains("grok") || model.starts_with("xai/"),
            Self::OpenAi => {
                model.starts_with("gpt")
                    || model.starts_with("o1")
                    || model.starts_with("o3")
                    || model.starts_with("o4")
            }
            Self::OpenAiCompatible => false,
            Self::Ollama => [
                "llama",
                "mistral",
                "mixtral",
                "qwen",
                "deepseek",
                "phi",
                "gemma",
                "codellama",
            ]
            .iter()
            .any(|candidate| model.contains(candidate)),
        }
    }
}

pub fn provider_kind_from_name(name: &str) -> Option<ProviderKind> {
    match name.trim().to_ascii_lowercase().as_str() {
        "anthropic" | "claude" => Some(ProviderKind::Anthropic),
        "claude_code" | "claude-code" | "claudecode" => Some(ProviderKind::ClaudeCode),
        "codex" | "chatgpt" => Some(ProviderKind::Codex),
        "xai_oauth" | "xai-oauth" | "grok_oauth" | "grok-oauth" | "supergrok"
        | "grok_subscription" | "grok-subscription" => Some(ProviderKind::XaiOAuth),
        "xai" | "grok" | "grok_build" | "grok-build" | "grokbuild" => Some(ProviderKind::Xai),
        "openai" => Some(ProviderKind::OpenAi),
        "openai_compatible"
        | "openai-compatible"
        | "custom_openai"
        | "custom-openai"
        | "custom_openai_compatible"
        | "custom-openai-compatible" => Some(ProviderKind::OpenAiCompatible),
        "ollama" | "local" => Some(ProviderKind::Ollama),
        _ => None,
    }
}

pub fn default_provider_order() -> Vec<ProviderKind> {
    vec![
        ProviderKind::ClaudeCode,
        ProviderKind::Codex,
        ProviderKind::XaiOAuth,
        ProviderKind::Xai,
        ProviderKind::Anthropic,
        ProviderKind::OpenAi,
        ProviderKind::OpenAiCompatible,
        ProviderKind::Ollama,
    ]
}

pub fn normalize_provider_order(value: &str) -> Vec<ProviderKind> {
    let mut order = Vec::new();

    for raw in value.split(',') {
        if let Some(provider) = provider_kind_from_name(raw) {
            push_provider_once(&mut order, provider);
        }
    }

    for provider in default_provider_order() {
        push_provider_once(&mut order, provider);
    }

    order
}

pub fn provider_order_csv(order: &[ProviderKind]) -> String {
    order
        .iter()
        .map(|provider| provider.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

pub fn push_provider_once(order: &mut Vec<ProviderKind>, provider: ProviderKind) {
    if !order.contains(&provider) {
        order.push(provider);
    }
}

pub fn provider_kind_from_model(model: &str) -> Option<ProviderKind> {
    ProviderKind::ordered()
        .into_iter()
        .find(|provider| provider.matches_model(model))
}

pub fn configured_provider_kind(config: &AiConfig) -> Option<ProviderKind> {
    default_provider_order()
        .into_iter()
        .find(|provider| env_credential(config, *provider).is_some())
}

pub fn model_for_provider(provider: ProviderKind, configured_model: &str) -> String {
    let configured_model = configured_model.trim();

    if !configured_model.is_empty() && provider.matches_model(configured_model) {
        configured_model.to_string()
    } else {
        provider.fallback_model().to_string()
    }
}

/// Decide which model to use for a provider, preferring an explicit user override.
/// `override_model` takes precedence when non-empty; otherwise falls back to
/// `model_for_provider`.
pub fn resolve_model_for_provider(
    provider: ProviderKind,
    override_model: Option<&str>,
    configured_model: &str,
) -> String {
    if let Some(override_model) = override_model {
        let trimmed = override_model.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    model_for_provider(provider, configured_model)
}

/// Parse a per-provider model overrides map from its JSON-encoded form.
/// Returns an empty map when the input is empty or malformed.
pub fn parse_provider_models(value: &str) -> BTreeMap<ProviderKind, String> {
    let value = value.trim();
    if value.is_empty() {
        return BTreeMap::new();
    }

    let parsed: serde_json::Value = match serde_json::from_str(value) {
        Ok(parsed) => parsed,
        Err(_) => return BTreeMap::new(),
    };

    let Some(object) = parsed.as_object() else {
        return BTreeMap::new();
    };

    let mut models = BTreeMap::new();
    for (key, val) in object {
        let Some(provider) = provider_kind_from_name(key) else {
            continue;
        };
        let Some(model) = val.as_str() else { continue };
        let trimmed = model.trim();
        if trimmed.is_empty() {
            continue;
        }
        models.insert(provider, trimmed.to_string());
    }
    models
}

/// Encode a per-provider model overrides map back to JSON.
pub fn serialize_provider_models(models: &BTreeMap<ProviderKind, String>) -> String {
    let map: serde_json::Map<String, serde_json::Value> = models
        .iter()
        .map(|(provider, model)| {
            (
                provider.as_str().to_string(),
                serde_json::Value::String(model.clone()),
            )
        })
        .collect();
    serde_json::Value::Object(map).to_string()
}

pub fn build_provider_for_kind(
    provider: ProviderKind,
    credential: String,
) -> Box<dyn ModelProvider> {
    match provider {
        ProviderKind::Anthropic => Box::new(claude::ClaudeProvider::new(credential)),
        ProviderKind::ClaudeCode => Box::new(
            claude_code::ClaudeCodeProvider::from_secret(credential)
                .expect("Claude Code provider requires stored OAuth tokens"),
        ),
        ProviderKind::Codex => Box::new(
            codex::CodexProvider::from_secret(credential)
                .expect("Codex provider requires stored ChatGPT auth tokens"),
        ),
        ProviderKind::XaiOAuth => Box::new(
            xai_oauth::XaiOAuthProvider::from_secret(credential)
                .expect("Grok Subscription provider requires stored OAuth tokens"),
        ),
        ProviderKind::Xai => Box::new(
            openai::OpenAiProvider::new(credential)
                .with_base_url("https://api.x.ai".to_string())
                .with_provider_identity("xai", "xAI"),
        ),
        ProviderKind::OpenAi => Box::new(openai::OpenAiProvider::new(credential)),
        ProviderKind::OpenAiCompatible => {
            let credential = openai::decode_openai_compatible_secret(&credential)
                .expect("OpenAI-compatible provider requires encoded base URL");
            Box::new(openai::OpenAiProvider::openai_compatible(
                credential.api_key,
                credential.base_url,
            ))
        }
        ProviderKind::Ollama => Box::new(ollama::OllamaProvider::new(credential)),
    }
}

impl ProviderKind {
    pub fn ordered() -> [ProviderKind; 8] {
        [
            Self::Anthropic,
            Self::ClaudeCode,
            Self::Codex,
            Self::XaiOAuth,
            Self::Xai,
            Self::OpenAi,
            Self::OpenAiCompatible,
            Self::Ollama,
        ]
    }
}

/// Model-agnostic AI provider trait. All AI backends (Claude, Codex, OpenAI, Ollama)
/// implement this trait to provide a unified completion interface.
#[async_trait::async_trait]
pub trait ModelProvider: Send + Sync {
    async fn complete(&self, request: CompletionRequest) -> HeimdallResult<CompletionResponse>;

    /// Returns the provider name for logging and diagnostics.
    fn provider_name(&self) -> &str;
}

/// Builds a single environment AI provider from config.
/// Returns None if no provider is configured (BYOK — user hasn't set keys yet).
pub fn build_provider(config: &AiConfig) -> Option<Box<dyn ModelProvider>> {
    let mut order = Vec::new();

    match provider_kind_from_model(&config.default_model) {
        Some(ProviderKind::Codex) => push_provider_once(&mut order, ProviderKind::OpenAi),
        Some(provider) => push_provider_once(&mut order, provider),
        None => {}
    }

    for provider in default_provider_order() {
        push_provider_once(&mut order, provider);
    }

    for provider in order {
        if let Some(credential) = env_credential(config, provider) {
            return Some(build_provider_for_kind(provider, credential));
        }
    }

    None
}

fn env_credential(config: &AiConfig, provider: ProviderKind) -> Option<String> {
    match provider {
        ProviderKind::Anthropic => config.anthropic_api_key.clone(),
        ProviderKind::Xai => config.xai_api_key.clone(),
        ProviderKind::OpenAi => config.openai_api_key.clone(),
        ProviderKind::OpenAiCompatible => {
            config
                .openai_compatible_base_url
                .as_deref()
                .and_then(|base_url| {
                    openai::encode_openai_compatible_secret(
                        config
                            .openai_compatible_api_key
                            .as_deref()
                            .unwrap_or_default(),
                        base_url,
                    )
                    .ok()
                })
        }
        ProviderKind::Ollama => config.ollama_url.clone(),
        ProviderKind::ClaudeCode | ProviderKind::Codex | ProviderKind::XaiOAuth => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_provider_from_model_name() {
        assert_eq!(
            provider_kind_from_model("claude-sonnet-4-20250514"),
            Some(ProviderKind::Anthropic)
        );
        assert_eq!(
            provider_kind_from_model("gpt-4o"),
            Some(ProviderKind::Codex)
        );
        assert_eq!(
            provider_kind_from_model("gpt-5.2-codex"),
            Some(ProviderKind::Codex)
        );
        assert_eq!(
            provider_kind_from_model("grok-4.3"),
            Some(ProviderKind::XaiOAuth)
        );
        assert_eq!(
            provider_kind_from_model("grok-build-0.1"),
            Some(ProviderKind::XaiOAuth)
        );
        assert_eq!(
            provider_kind_from_model("llama3.2:latest"),
            Some(ProviderKind::Ollama)
        );
    }

    #[test]
    fn falls_back_to_provider_safe_model_when_default_model_mismatches() {
        assert_eq!(
            model_for_provider(ProviderKind::OpenAi, "claude-sonnet-4-20250514"),
            "gpt-4o"
        );
        assert_eq!(
            model_for_provider(ProviderKind::Codex, "claude-sonnet-4-20250514"),
            "gpt-5.4"
        );
        assert_eq!(
            model_for_provider(ProviderKind::Anthropic, "claude-sonnet-4-20250514"),
            "claude-sonnet-4-20250514"
        );
        assert_eq!(
            model_for_provider(ProviderKind::Xai, "claude-sonnet-4-20250514"),
            "grok-build-0.1"
        );
        assert_eq!(
            model_for_provider(ProviderKind::XaiOAuth, "claude-sonnet-4-20250514"),
            "grok-build-0.1"
        );
        assert_eq!(
            model_for_provider(ProviderKind::OpenAiCompatible, "claude-sonnet-4-20250514"),
            "gpt-4o"
        );
    }

    #[test]
    fn falls_back_to_provider_safe_model_when_default_model_is_blank() {
        assert_eq!(
            model_for_provider(ProviderKind::Anthropic, ""),
            "claude-sonnet-4-20250514"
        );
        assert_eq!(model_for_provider(ProviderKind::OpenAi, "   "), "gpt-4o");
    }

    #[test]
    fn provider_name_normalization_is_case_insensitive() {
        assert_eq!(
            provider_kind_from_name("OpenAI"),
            Some(ProviderKind::OpenAi)
        );
        assert_eq!(provider_kind_from_name("codex"), Some(ProviderKind::Codex));
        assert_eq!(
            provider_kind_from_name("Claude"),
            Some(ProviderKind::Anthropic)
        );
        assert_eq!(
            provider_kind_from_name(" ollama "),
            Some(ProviderKind::Ollama)
        );
        assert_eq!(provider_kind_from_name("grok"), Some(ProviderKind::Xai));
        assert_eq!(
            provider_kind_from_name("grok-oauth"),
            Some(ProviderKind::XaiOAuth)
        );
        assert_eq!(
            provider_kind_from_name("custom-openai"),
            Some(ProviderKind::OpenAiCompatible)
        );
        assert_eq!(provider_kind_from_name("unknown"), None);
    }

    #[test]
    fn resolve_model_prefers_explicit_override() {
        assert_eq!(
            resolve_model_for_provider(
                ProviderKind::OpenAi,
                Some("gpt-4o-mini"),
                "claude-sonnet-4-20250514"
            ),
            "gpt-4o-mini"
        );
    }

    #[test]
    fn resolve_model_falls_back_when_override_blank() {
        assert_eq!(
            resolve_model_for_provider(ProviderKind::Anthropic, Some("   "), ""),
            "claude-sonnet-4-20250514"
        );
        assert_eq!(
            resolve_model_for_provider(ProviderKind::OpenAi, None, ""),
            "gpt-4o"
        );
    }

    #[test]
    fn build_xai_provider_uses_xai_identity() {
        let provider = build_provider_for_kind(ProviderKind::Xai, "xai-test".to_string());
        assert_eq!(provider.provider_name(), "xai");
    }

    #[test]
    fn build_openai_compatible_provider_uses_custom_identity() {
        let credential =
            openai::encode_openai_compatible_secret("sk-custom", "http://localhost:1234/v1")
                .unwrap();
        let provider = build_provider_for_kind(ProviderKind::OpenAiCompatible, credential);
        assert_eq!(provider.provider_name(), "openai_compatible");
    }

    #[test]
    fn build_openai_compatible_provider_accepts_base_url_without_api_key() {
        let config = AiConfig {
            anthropic_api_key: None,
            openai_api_key: None,
            openai_compatible_api_key: None,
            openai_compatible_base_url: Some("http://localhost:1234/v1".to_string()),
            xai_api_key: None,
            ollama_url: None,
            default_model: "custom-model".to_string(),
        };

        let provider = build_provider(&config).expect("provider should be configured");

        assert_eq!(provider.provider_name(), "openai_compatible");
        assert_eq!(
            configured_provider_kind(&config),
            Some(ProviderKind::OpenAiCompatible)
        );
    }

    #[test]
    fn build_provider_prefers_xai_in_default_env_order() {
        let config = AiConfig {
            anthropic_api_key: Some("sk-ant-test".to_string()),
            openai_api_key: Some("sk-openai-test".to_string()),
            openai_compatible_api_key: None,
            openai_compatible_base_url: None,
            xai_api_key: Some("xai-test".to_string()),
            ollama_url: None,
            default_model: "unknown-model".to_string(),
        };

        let provider = build_provider(&config).expect("provider should be configured");

        assert_eq!(provider.provider_name(), "xai");
        assert_eq!(configured_provider_kind(&config), Some(ProviderKind::Xai));
    }

    #[test]
    fn parse_provider_models_round_trip() {
        let mut original = BTreeMap::new();
        original.insert(ProviderKind::OpenAi, "gpt-4o-mini".to_string());
        original.insert(ProviderKind::Anthropic, "claude-sonnet-4-5".to_string());
        let serialized = serialize_provider_models(&original);
        let parsed = parse_provider_models(&serialized);
        assert_eq!(parsed, original);
    }

    #[test]
    fn parse_provider_models_handles_garbage() {
        assert!(parse_provider_models("").is_empty());
        assert!(parse_provider_models("not-json").is_empty());
        let parsed = parse_provider_models(
            r#"{"openai":"gpt-4o","unknown":"x","ollama":"  ","anthropic":42}"#,
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed.get(&ProviderKind::OpenAi).map(String::as_str),
            Some("gpt-4o")
        );
    }

    #[test]
    fn normalizes_provider_order_with_defaults_and_aliases() {
        assert_eq!(
            normalize_provider_order("openai, claude, openai"),
            vec![
                ProviderKind::OpenAi,
                ProviderKind::Anthropic,
                ProviderKind::ClaudeCode,
                ProviderKind::Codex,
                ProviderKind::XaiOAuth,
                ProviderKind::Xai,
                ProviderKind::OpenAiCompatible,
                ProviderKind::Ollama,
            ]
        );
    }

    #[test]
    fn provider_kind_from_name_recognizes_claude_code_aliases() {
        assert_eq!(
            provider_kind_from_name("claude_code"),
            Some(ProviderKind::ClaudeCode)
        );
        assert_eq!(
            provider_kind_from_name("claude-code"),
            Some(ProviderKind::ClaudeCode)
        );
        assert_eq!(
            provider_kind_from_name("ClaudeCode"),
            Some(ProviderKind::ClaudeCode)
        );
    }
}
