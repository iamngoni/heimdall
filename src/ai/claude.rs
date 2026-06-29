//
//  heimdall
//  src/ai/claude.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, CompletionResponse, StopReason, TokenUsage, ToolCall};
use crate::models::HeimdallResult;
use log::debug;
use serde::{Deserialize, Serialize};

pub struct ClaudeProvider {
    api_key: String,
    base_url: String,
    client: reqwest::Client,
}

impl ClaudeProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            base_url: "https://api.anthropic.com".to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url;
        self
    }
}

/// Returns true when the Claude model still accepts a `temperature` parameter.
/// Anthropic deprecated `temperature` on the newer generation (`claude-opus-4-7`
/// is the first one where it returns 400). Older models still accept it.
///
/// Heuristic: parse the trailing `<major>-<minor>` version from the model id
/// (e.g. `claude-opus-4-7` → `(4, 7)`). If we can extract a version and it's
/// `>= (4, 7)`, the model rejects custom temperatures.
fn model_supports_custom_temperature(model: &str) -> bool {
    let m = model.trim().to_ascii_lowercase();
    let m = m.split('/').next_back().unwrap_or(&m);
    // Walk segments right-to-left, looking for the most-recent
    // "<major>-<minor>" pair. A trailing segment may be a date suffix
    // (e.g. `claude-haiku-4-5-20251001`); skip non-version digit chunks.
    let segments: Vec<&str> = m.split('-').collect();
    let mut major: Option<u32> = None;
    let mut minor: Option<u32> = None;
    for window in segments.windows(2).rev() {
        let (a, b) = (window[0], window[1]);
        // Ignore long numeric suffixes (date stamps); versions are 1-2 digits.
        if a.len() <= 2
            && b.len() <= 2
            && let (Ok(maj), Ok(min)) = (a.parse::<u32>(), b.parse::<u32>())
        {
            major = Some(maj);
            minor = Some(min);
            break;
        }
    }
    match (major, minor) {
        (Some(maj), Some(min)) => (maj, min) < (4, 7),
        _ => true,
    }
}

// --- Anthropic API request/response types ---

#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<AnthropicTool>>,
}

#[derive(Serialize)]
struct AnthropicMessage {
    role: String,
    content: AnthropicContent,
}

#[derive(Serialize)]
#[serde(untagged)]
#[allow(dead_code)]
enum AnthropicContent {
    Text(String),
    Blocks(Vec<AnthropicContentBlock>),
}

#[derive(Serialize)]
#[serde(tag = "type")]
#[allow(dead_code)]
enum AnthropicContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
    },
}

#[derive(Serialize)]
struct AnthropicTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicResponseBlock>,
    stop_reason: String,
    usage: AnthropicUsage,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum AnthropicResponseBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

#[derive(Deserialize)]
struct AnthropicUsage {
    input_tokens: u32,
    output_tokens: u32,
}

#[derive(Deserialize)]
struct AnthropicError {
    error: AnthropicErrorDetail,
}

#[derive(Deserialize)]
struct AnthropicErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
}

#[async_trait::async_trait]
impl ModelProvider for ClaudeProvider {
    async fn complete(&self, request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
        let mut system_prompt = None;
        let mut messages = Vec::new();

        for msg in &request.messages {
            if msg.role == "system" {
                system_prompt = Some(msg.content.clone());
            } else {
                messages.push(AnthropicMessage {
                    role: msg.role.clone(),
                    content: AnthropicContent::Text(msg.content.clone()),
                });
            }
        }

        let tools = request.tools.as_ref().map(|ts| {
            ts.iter()
                .map(|t| AnthropicTool {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    input_schema: t.parameters.clone(),
                })
                .collect()
        });

        let temperature = if model_supports_custom_temperature(&request.model) {
            request.temperature
        } else {
            None
        };

        let body = AnthropicRequest {
            model: request.model.clone(),
            max_tokens: request.max_tokens.unwrap_or(4096),
            messages,
            system: system_prompt,
            temperature,
            tools,
        };

        debug!(
            "Claude API request: model={}, messages={}",
            body.model,
            body.messages.len()
        );

        let resp = self
            .client
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let error_body = resp.text().await.unwrap_or_default();
            if let Ok(err) = serde_json::from_str::<AnthropicError>(&error_body) {
                anyhow::bail!(
                    "Claude API error ({}): {} — {}",
                    status,
                    err.error.error_type,
                    err.error.message
                );
            }
            anyhow::bail!("Claude API error ({}): {}", status, error_body);
        }

        let api_resp: AnthropicResponse = resp.json().await?;

        let mut text_parts = Vec::new();
        let mut tool_calls = Vec::new();

        for block in &api_resp.content {
            match block {
                AnthropicResponseBlock::Text { text } => text_parts.push(text.clone()),
                AnthropicResponseBlock::ToolUse { id, name, input } => {
                    tool_calls.push(ToolCall {
                        id: id.clone(),
                        name: name.clone(),
                        arguments: input.clone(),
                    });
                }
            }
        }

        let stop_reason = match api_resp.stop_reason.as_str() {
            "end_turn" => StopReason::EndTurn,
            "max_tokens" => StopReason::MaxTokens,
            "tool_use" => StopReason::ToolUse,
            "stop_sequence" => StopReason::StopSequence,
            _ => StopReason::EndTurn,
        };

        Ok(CompletionResponse {
            content: text_parts.join(""),
            tool_calls: if tool_calls.is_empty() {
                None
            } else {
                Some(tool_calls)
            },
            stop_reason,
            usage: TokenUsage {
                prompt_tokens: api_resp.usage.input_tokens,
                completion_tokens: api_resp.usage.output_tokens,
                total_tokens: api_resp.usage.input_tokens + api_resp.usage.output_tokens,
            },
            provider: "claude".to_string(),
            model: request.model,
        })
    }

    fn provider_name(&self) -> &str {
        "claude"
    }
}

#[cfg(test)]
mod tests {
    use super::model_supports_custom_temperature;

    #[test]
    fn old_models_allow_custom_temperature() {
        for m in [
            "claude-3-opus-20240229",
            "claude-3-5-sonnet-20240620",
            "claude-3-5-haiku-20241022",
            "claude-sonnet-4-6",
            "claude-haiku-4-5-20251001",
            "claude-opus-4-6",
        ] {
            assert!(
                model_supports_custom_temperature(m),
                "{m} should allow custom temperature"
            );
        }
    }

    #[test]
    fn new_models_disallow_custom_temperature() {
        for m in [
            "claude-opus-4-7",
            "claude-opus-4-7-20260101",
            "claude-sonnet-4-7",
            "claude-haiku-4-7",
            "claude-opus-5-0",
            "claude-sonnet-5-2",
        ] {
            assert!(
                !model_supports_custom_temperature(m),
                "{m} should reject custom temperature"
            );
        }
    }

    #[test]
    fn handles_namespacing_and_unknown_names() {
        assert!(!model_supports_custom_temperature(
            "anthropic/claude-opus-4-7"
        ));
        assert!(model_supports_custom_temperature("anthropic/claude-3-opus"));
        // No extractable version → assume legacy behavior (allow).
        assert!(model_supports_custom_temperature("claude-some-future-name"));
    }
}
