//
//  heimdall
//  src/ai/fallback.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/12.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use log::{info, warn};

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, CompletionResponse};
use crate::models::HeimdallResult;

/// A provider entry in the fallback chain, pairing a provider with its default model.
struct ProviderEntry {
    provider: Box<dyn ModelProvider>,
    default_model: String,
}

/// A `ModelProvider` that tries multiple providers in order.
/// On retryable errors (429, 500, 502, 503, 529), it falls through to the next
/// configured provider, rewriting the model field to match that provider.
pub struct FallbackProvider {
    providers: Vec<ProviderEntry>,
}

impl FallbackProvider {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Add a provider with its default model to the fallback chain.
    pub fn add(mut self, provider: Box<dyn ModelProvider>, default_model: String) -> Self {
        self.providers.push(ProviderEntry {
            provider,
            default_model,
        });
        self
    }

    /// Returns true if at least one provider is configured.
    pub fn has_providers(&self) -> bool {
        !self.providers.is_empty()
    }
}

/// Check if an error message indicates a retryable HTTP status.
/// Provider errors include the status code in their message, e.g.:
///   "Claude API error (429): rate_limit_error — ..."
///   "OpenAI API error (429): ..."
fn is_retryable_error(err: &anyhow::Error) -> bool {
    let msg = format!("{err}");
    // Match status codes in parentheses from our provider error format
    for code in ["(429)", "(500)", "(502)", "(503)", "(529)"] {
        if msg.contains(code) {
            return true;
        }
    }
    // Also catch connection/timeout errors that suggest the provider is down
    let lower = msg.to_ascii_lowercase();
    lower.contains("connection refused")
        || lower.contains("timed out")
        || lower.contains("connection reset")
}

#[async_trait::async_trait]
impl ModelProvider for FallbackProvider {
    async fn complete(&self, request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
        let mut last_error: Option<anyhow::Error> = None;

        for (i, entry) in self.providers.iter().enumerate() {
            // Rewrite the model field to match this provider's default
            let mut req = request.clone();
            if i > 0 {
                // Only rewrite model when falling back — the primary provider uses
                // whatever model the caller specified
                req.model = entry.default_model.clone();
            }

            match entry.provider.complete(req).await {
                Ok(response) => {
                    if i > 0 {
                        info!(
                            "Fallback to {} succeeded (provider #{})",
                            entry.provider.provider_name(),
                            i + 1,
                        );
                    }
                    return Ok(response);
                }
                Err(e) => {
                    if is_retryable_error(&e) && i + 1 < self.providers.len() {
                        let next = &self.providers[i + 1];
                        warn!(
                            "{} failed with retryable error: {e:#} — falling back to {} (model: {})",
                            entry.provider.provider_name(),
                            next.provider.provider_name(),
                            next.default_model,
                        );
                        last_error = Some(e);
                        continue;
                    }
                    // Non-retryable error or last provider — propagate immediately
                    return Err(e);
                }
            }
        }

        // Should only reach here if providers is empty
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No AI providers configured")))
    }

    fn provider_name(&self) -> &str {
        // Return the primary provider's name
        self.providers
            .first()
            .map(|e| e.provider.provider_name())
            .unwrap_or("fallback(none)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::types::{CompletionRequest, CompletionResponse, Message, StopReason, TokenUsage};

    /// A mock provider that always fails with a specific error.
    struct FailingProvider {
        name: &'static str,
        error_msg: String,
    }

    #[async_trait::async_trait]
    impl ModelProvider for FailingProvider {
        async fn complete(&self, _request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
            anyhow::bail!("{}", self.error_msg)
        }
        fn provider_name(&self) -> &str {
            self.name
        }
    }

    /// A mock provider that always succeeds.
    struct SuccessProvider {
        name: &'static str,
    }

    #[async_trait::async_trait]
    impl ModelProvider for SuccessProvider {
        async fn complete(&self, _request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
            Ok(CompletionResponse {
                content: format!("response from {}", self.name),
                tool_calls: None,
                stop_reason: StopReason::EndTurn,
                usage: TokenUsage {
                    prompt_tokens: 10,
                    completion_tokens: 5,
                    total_tokens: 15,
                },
                provider: self.name.to_string(),
                model: "test-model".to_string(),
            })
        }
        fn provider_name(&self) -> &str {
            self.name
        }
    }

    fn test_request() -> CompletionRequest {
        CompletionRequest {
            model: "test-model".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: "hello".to_string(),
            }],
            tools: None,
            max_tokens: None,
            temperature: None,
        }
    }

    #[tokio::test]
    async fn primary_provider_success_does_not_fallback() {
        let provider = FallbackProvider::new()
            .add(Box::new(SuccessProvider { name: "primary" }), "model-a".into())
            .add(Box::new(SuccessProvider { name: "secondary" }), "model-b".into());

        let result = provider.complete(test_request()).await.unwrap();
        assert_eq!(result.content, "response from primary");
    }

    #[tokio::test]
    async fn falls_back_on_429() {
        let provider = FallbackProvider::new()
            .add(
                Box::new(FailingProvider {
                    name: "primary",
                    error_msg: "Claude API error (429): rate_limit_error — too many requests".into(),
                }),
                "model-a".into(),
            )
            .add(Box::new(SuccessProvider { name: "secondary" }), "model-b".into());

        let result = provider.complete(test_request()).await.unwrap();
        assert_eq!(result.content, "response from secondary");
    }

    #[tokio::test]
    async fn does_not_fallback_on_401() {
        let provider = FallbackProvider::new()
            .add(
                Box::new(FailingProvider {
                    name: "primary",
                    error_msg: "Claude API error (401): authentication_error — invalid api key".into(),
                }),
                "model-a".into(),
            )
            .add(Box::new(SuccessProvider { name: "secondary" }), "model-b".into());

        let result = provider.complete(test_request()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("401"));
    }

    #[tokio::test]
    async fn falls_back_on_connection_refused() {
        let provider = FallbackProvider::new()
            .add(
                Box::new(FailingProvider {
                    name: "primary",
                    error_msg: "connection refused".into(),
                }),
                "model-a".into(),
            )
            .add(Box::new(SuccessProvider { name: "secondary" }), "model-b".into());

        let result = provider.complete(test_request()).await.unwrap();
        assert_eq!(result.content, "response from secondary");
    }

    #[tokio::test]
    async fn all_providers_fail_returns_last_error() {
        let provider = FallbackProvider::new()
            .add(
                Box::new(FailingProvider {
                    name: "primary",
                    error_msg: "Claude API error (429): rate limit".into(),
                }),
                "model-a".into(),
            )
            .add(
                Box::new(FailingProvider {
                    name: "secondary",
                    error_msg: "OpenAI API error (429): rate limit".into(),
                }),
                "model-b".into(),
            );

        let result = provider.complete(test_request()).await;
        assert!(result.is_err());
        // Should get the last provider's error
        assert!(result.unwrap_err().to_string().contains("OpenAI"));
    }

    #[tokio::test]
    async fn is_retryable_detects_status_codes() {
        assert!(is_retryable_error(&anyhow::anyhow!("API error (429): rate limit")));
        assert!(is_retryable_error(&anyhow::anyhow!("API error (500): internal")));
        assert!(is_retryable_error(&anyhow::anyhow!("API error (502): bad gateway")));
        assert!(is_retryable_error(&anyhow::anyhow!("API error (503): unavailable")));
        assert!(is_retryable_error(&anyhow::anyhow!("API error (529): overloaded")));
        assert!(!is_retryable_error(&anyhow::anyhow!("API error (401): unauthorized")));
        assert!(!is_retryable_error(&anyhow::anyhow!("API error (400): bad request")));
        assert!(is_retryable_error(&anyhow::anyhow!("connection refused")));
        assert!(is_retryable_error(&anyhow::anyhow!("request timed out")));
    }
}
