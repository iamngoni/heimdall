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
        return Some(Box::new(claude::ClaudeProvider::new(key.clone())));
    }
    if let Some(ref key) = config.openai_api_key {
        return Some(Box::new(openai::OpenAiProvider::new(key.clone())));
    }
    if let Some(ref url) = config.ollama_url {
        return Some(Box::new(ollama::OllamaProvider::new(url.clone())));
    }
    None
}
