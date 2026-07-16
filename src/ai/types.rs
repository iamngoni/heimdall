//
//  heimdall
//  src/ai/types.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ToolDefinition>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    pub stop_reason: StopReason,
    pub usage: TokenUsage,
    /// Which provider actually served this response (e.g. "claude", "openai", "ollama").
    /// Set by the provider or fallback layer.
    #[serde(default)]
    pub provider: String,
    /// Which model actually handled the request. May differ from the requested model
    /// if a fallback occurred.
    #[serde(default)]
    pub model: String,
    /// Providers attempted before another provider completed the request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_attempts: Vec<FallbackAttempt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FallbackAttempt {
    pub provider: String,
    pub model: String,
    pub reason: String,
}

impl CompletionResponse {
    pub fn routing_metadata(&self) -> Option<serde_json::Value> {
        if self.fallback_attempts.is_empty() {
            return None;
        }

        Some(serde_json::json!({
            "fallback_used": true,
            "attempts": &self.fallback_attempts,
            "completed_by": {
                "provider": self.provider,
                "provider_label": provider_label(&self.provider),
                "model": self.model,
            },
        }))
    }

    pub fn fallback_summary(&self) -> Option<String> {
        if self.fallback_attempts.is_empty() {
            return None;
        }

        let failed = self
            .fallback_attempts
            .iter()
            .map(|attempt| {
                format!(
                    "{} ({}) {}",
                    provider_label(&attempt.provider),
                    attempt.model,
                    reason_label(&attempt.reason)
                )
            })
            .collect::<Vec<_>>()
            .join("; ");

        Some(format!(
            "{failed}; continued with {} ({}).",
            provider_label(&self.provider),
            self.model
        ))
    }
}

fn provider_label(provider: &str) -> String {
    crate::ai::provider_kind_from_name(provider)
        .map(|kind| kind.label().to_string())
        .unwrap_or_else(|| {
            provider
                .split(['_', '-'])
                .filter(|part| !part.is_empty())
                .map(|part| {
                    let mut chars = part.chars();
                    chars
                        .next()
                        .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
}

fn reason_label(reason: &str) -> &'static str {
    match reason {
        "rate_limited" => "was rate limited",
        "authentication_failed" => "rejected authentication",
        "access_denied" => "denied access",
        "quota_exhausted" => "exhausted its quota",
        "provider_unavailable" => "was unavailable",
        "timed_out" => "timed out",
        "connection_failed" => "could not be reached",
        _ => "failed",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    MaxTokens,
    ToolUse,
    StopSequence,
}
