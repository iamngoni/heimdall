//
//  heimdall
//  src/ai/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod claude;
pub mod ollama;
pub mod openai;
pub mod types;

use crate::config::AiConfig;
use crate::models::HeimdallResult;
use types::{CompletionRequest, CompletionResponse};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Anthropic,
    OpenAi,
    Ollama,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
            Self::Ollama => "ollama",
        }
    }

    pub fn fallback_model(self) -> &'static str {
        match self {
            Self::Anthropic => "claude-sonnet-4-20250514",
            Self::OpenAi => "gpt-4o-mini",
            Self::Ollama => "llama3.2",
        }
    }

    pub fn matches_model(self, model: &str) -> bool {
        let model = model.to_ascii_lowercase();
        match self {
            Self::Anthropic => model.contains("claude"),
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
        "anthropic" => Some(ProviderKind::Anthropic),
        "openai" => Some(ProviderKind::OpenAi),
        "ollama" => Some(ProviderKind::Ollama),
        _ => None,
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
    if provider.matches_model(configured_model) {
        configured_model.to_string()
    } else {
        provider.fallback_model().to_string()
    }
}

pub fn build_provider_for_kind(
    provider: ProviderKind,
    credential: String,
) -> Box<dyn ModelProvider> {
    match provider {
        ProviderKind::Anthropic => Box::new(claude::ClaudeProvider::new(credential)),
        ProviderKind::OpenAi => Box::new(openai::OpenAiProvider::new(credential)),
        ProviderKind::Ollama => Box::new(ollama::OllamaProvider::new(credential)),
    }
}

impl ProviderKind {
    pub fn ordered() -> [ProviderKind; 3] {
        [Self::Anthropic, Self::OpenAi, Self::Ollama]
    }
}

/// Model-agnostic AI provider trait. All AI backends (Claude, OpenAI, Ollama)
/// implement this trait to provide a unified completion interface.
#[async_trait::async_trait]
pub trait ModelProvider: Send + Sync {
    async fn complete(&self, request: CompletionRequest) -> HeimdallResult<CompletionResponse>;

    /// Returns the provider name for logging and diagnostics.
    fn provider_name(&self) -> &str;
}

/// Builds the best available AI provider from config.
/// Priority: Anthropic > OpenAI > Ollama.
/// Returns None if no provider is configured (BYOK — user hasn't set keys yet).
pub fn build_provider(config: &AiConfig) -> Option<Box<dyn ModelProvider>> {
    if let Some(ref key) = config.anthropic_api_key {
        return Some(build_provider_for_kind(
            ProviderKind::Anthropic,
            key.clone(),
        ));
    }
    if let Some(ref key) = config.openai_api_key {
        return Some(build_provider_for_kind(ProviderKind::OpenAi, key.clone()));
    }
    if let Some(ref url) = config.ollama_url {
        return Some(build_provider_for_kind(ProviderKind::Ollama, url.clone()));
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
            provider_kind_from_model("gpt-4o-mini"),
            Some(ProviderKind::OpenAi)
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
            "gpt-4o-mini"
        );
        assert_eq!(
            model_for_provider(ProviderKind::Anthropic, "claude-sonnet-4-20250514"),
            "claude-sonnet-4-20250514"
        );
    }

    #[test]
    fn provider_name_normalization_is_case_insensitive() {
        assert_eq!(
            provider_kind_from_name("OpenAI"),
            Some(ProviderKind::OpenAi)
        );
        assert_eq!(
            provider_kind_from_name(" ollama "),
            Some(ProviderKind::Ollama)
        );
        assert_eq!(provider_kind_from_name("unknown"), None);
    }
}
