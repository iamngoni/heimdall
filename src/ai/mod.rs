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

use std::collections::BTreeMap;

use crate::config::AiConfig;
use crate::models::HeimdallResult;
use types::{CompletionRequest, CompletionResponse};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderKind {
    Anthropic,
    ClaudeCode,
    Codex,
    OpenAi,
    Ollama,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::ClaudeCode => "claude_code",
            Self::Codex => "codex",
            Self::OpenAi => "openai",
            Self::Ollama => "ollama",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
            Self::OpenAi => "OpenAI",
            Self::Ollama => "Ollama",
        }
    }

    pub fn fallback_model(self) -> &'static str {
        match self {
            Self::Anthropic => "claude-sonnet-4-20250514",
            Self::ClaudeCode => "claude-sonnet-4-20250514",
            Self::Codex => "gpt-5.4",
            Self::OpenAi => "gpt-4o",
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
            Self::OpenAi => {
                model.starts_with("gpt")
                    || model.starts_with("o1")
                    || model.starts_with("o3")
                    || model.starts_with("o4")
            }
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
        "openai" => Some(ProviderKind::OpenAi),
        "ollama" | "local" => Some(ProviderKind::Ollama),
        _ => None,
    }
}

pub fn default_provider_order() -> Vec<ProviderKind> {
    vec![
        ProviderKind::ClaudeCode,
        ProviderKind::Codex,
        ProviderKind::Anthropic,
        ProviderKind::OpenAi,
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
    if config.anthropic_api_key.is_some() {
        return Some(ProviderKind::Anthropic);
    }
    if config.openai_api_key.is_some() {
        return Some(ProviderKind::OpenAi);
    }
    if config.ollama_url.is_some() {
        return Some(ProviderKind::Ollama);
    }
    None
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
        ProviderKind::OpenAi => Box::new(openai::OpenAiProvider::new(credential)),
        ProviderKind::Ollama => Box::new(ollama::OllamaProvider::new(credential)),
    }
}

impl ProviderKind {
    pub fn ordered() -> [ProviderKind; 5] {
        [
            Self::Anthropic,
            Self::ClaudeCode,
            Self::Codex,
            Self::OpenAi,
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

    for provider in [
        ProviderKind::Anthropic,
        ProviderKind::OpenAi,
        ProviderKind::Ollama,
    ] {
        push_provider_once(&mut order, provider);
    }

    for provider in order {
        let credential = match provider {
            ProviderKind::Anthropic => config.anthropic_api_key.clone(),
            ProviderKind::OpenAi => config.openai_api_key.clone(),
            ProviderKind::Ollama => config.ollama_url.clone(),
            ProviderKind::Codex | ProviderKind::ClaudeCode => None,
        };

        if let Some(credential) = credential {
            return Some(build_provider_for_kind(provider, credential));
        }
    }

    None
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
