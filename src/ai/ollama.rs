//
//  heimdall
//  src/ai/ollama.rs
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

pub struct OllamaProvider {
    base_url: String,
    client: reqwest::Client,
}

impl OllamaProvider {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    pub fn default_local() -> Self {
        Self::new("http://localhost:11434".to_string())
    }
}

// --- Ollama API types (OpenAI-compatible chat endpoint) ---

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<OllamaTool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
}

#[derive(Serialize)]
struct OllamaMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct OllamaTool {
    #[serde(rename = "type")]
    tool_type: String,
    function: OllamaFunction,
}

#[derive(Serialize)]
struct OllamaFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Serialize)]
struct OllamaOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<u32>,
}

#[derive(Deserialize)]
struct OllamaResponse {
    message: OllamaResponseMessage,
    #[serde(default)]
    done_reason: Option<String>,
    #[serde(default)]
    prompt_eval_count: Option<u32>,
    #[serde(default)]
    eval_count: Option<u32>,
}

#[derive(Deserialize)]
struct OllamaResponseMessage {
    #[serde(default)]
    content: String,
    #[serde(default)]
    tool_calls: Option<Vec<OllamaToolCall>>,
}

#[derive(Deserialize)]
struct OllamaToolCall {
    function: OllamaFunctionCall,
}

#[derive(Deserialize)]
struct OllamaFunctionCall {
    name: String,
    arguments: serde_json::Value,
}

#[async_trait::async_trait]
impl ModelProvider for OllamaProvider {
    async fn complete(&self, request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
        let messages: Vec<OllamaMessage> = request
            .messages
            .iter()
            .map(|m| OllamaMessage {
                role: m.role.clone(),
                content: m.content.clone(),
            })
            .collect();

        let tools = request.tools.as_ref().map(|ts| {
            ts.iter()
                .map(|t| OllamaTool {
                    tool_type: "function".to_string(),
                    function: OllamaFunction {
                        name: t.name.clone(),
                        description: t.description.clone(),
                        parameters: t.parameters.clone(),
                    },
                })
                .collect()
        });

        let options = if request.temperature.is_some() || request.max_tokens.is_some() {
            Some(OllamaOptions {
                temperature: request.temperature,
                num_predict: request.max_tokens,
            })
        } else {
            None
        };

        let body = OllamaRequest {
            model: request.model.clone(),
            messages,
            stream: false,
            tools,
            options,
        };

        debug!(
            "Ollama API request: model={}, messages={}",
            body.model,
            body.messages.len()
        );

        let resp = self
            .client
            .post(format!("{}/api/chat", self.base_url))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let error_body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ollama API error ({}): {}", status, error_body);
        }

        let api_resp: OllamaResponse = resp.json().await?;

        let tool_calls = api_resp.message.tool_calls.map(|calls| {
            calls
                .into_iter()
                .enumerate()
                .map(|(i, tc)| ToolCall {
                    id: format!("ollama_tc_{i}"),
                    name: tc.function.name,
                    arguments: tc.function.arguments,
                })
                .collect()
        });

        let prompt_tokens = api_resp.prompt_eval_count.unwrap_or(0);
        let completion_tokens = api_resp.eval_count.unwrap_or(0);

        let stop_reason = match api_resp.done_reason.as_deref() {
            Some("stop") => StopReason::EndTurn,
            Some("length") => StopReason::MaxTokens,
            _ if tool_calls.is_some() => StopReason::ToolUse,
            _ => StopReason::EndTurn,
        };

        Ok(CompletionResponse {
            content: api_resp.message.content,
            tool_calls,
            stop_reason,
            usage: TokenUsage {
                prompt_tokens,
                completion_tokens,
                total_tokens: prompt_tokens + completion_tokens,
            },
            provider: "ollama".to_string(),
            model: request.model,
        })
    }

    fn provider_name(&self) -> &str {
        "ollama"
    }
}
