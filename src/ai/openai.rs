//
//  heimdall
//  src/ai/openai.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, CompletionResponse, StopReason, TokenUsage, ToolCall};
use crate::models::HeimdallResult;
use anyhow::Context;
use log::debug;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAiCompatibleCredential {
    pub api_key: String,
    pub base_url: String,
}

pub struct OpenAiProvider {
    api_key: String,
    base_url: String,
    provider_name: String,
    display_name: String,
    client: reqwest::Client,
}

impl OpenAiProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            base_url: "https://api.openai.com".to_string(),
            provider_name: "openai".to_string(),
            display_name: "OpenAI".to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub fn openai_compatible(api_key: String, base_url: String) -> Self {
        Self::new(api_key)
            .with_base_url(base_url)
            .with_provider_identity("openai_compatible", "OpenAI Compatible")
    }

    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url;
        self
    }

    pub fn with_provider_identity(mut self, provider_name: &str, display_name: &str) -> Self {
        self.provider_name = provider_name.to_string();
        self.display_name = display_name.to_string();
        self
    }

    fn chat_completions_url(&self) -> String {
        let base_url = self.base_url.trim_end_matches('/');
        if base_url.ends_with("/v1") {
            format!("{base_url}/chat/completions")
        } else {
            format!("{base_url}/v1/chat/completions")
        }
    }
}

pub fn normalize_openai_compatible_base_url(raw: &str) -> HeimdallResult<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        anyhow::bail!("Base URL is required for OpenAI-compatible providers");
    }

    let parsed = reqwest::Url::parse(trimmed)
        .with_context(|| format!("Invalid OpenAI-compatible base URL: {trimmed}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("OpenAI-compatible base URL must use http or https");
    }
    if parsed.host_str().is_none() {
        anyhow::bail!("OpenAI-compatible base URL must include a host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("OpenAI-compatible base URL must not contain credentials");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        anyhow::bail!("OpenAI-compatible base URL must not include query strings or fragments");
    }

    Ok(trimmed.to_string())
}

pub fn encode_openai_compatible_secret(api_key: &str, base_url: &str) -> HeimdallResult<String> {
    let credential = OpenAiCompatibleCredential {
        api_key: api_key.to_string(),
        base_url: normalize_openai_compatible_base_url(base_url)?,
    };
    serde_json::to_string(&credential)
        .context("Failed to encode OpenAI-compatible provider credential")
}

pub fn decode_openai_compatible_secret(secret: &str) -> HeimdallResult<OpenAiCompatibleCredential> {
    let mut credential: OpenAiCompatibleCredential = serde_json::from_str(secret)
        .context("OpenAI-compatible provider credential is not valid JSON")?;
    credential.api_key = credential.api_key.trim().to_string();
    credential.base_url = normalize_openai_compatible_base_url(&credential.base_url)?;
    if credential.api_key.is_empty() {
        anyhow::bail!("OpenAI-compatible provider credential is missing an API key");
    }
    Ok(credential)
}

/// Returns true when the model accepts a non-default `temperature`. The
/// o-series reasoning models and the gpt-5 family reject any value other than
/// the default (1) with a 400. Match by name prefix so unreleased variants in
/// those families (gpt-5-something, o4-mini-yyyy-mm-dd, ...) are caught too.
fn model_supports_custom_temperature(model: &str) -> bool {
    let m = model.trim().to_ascii_lowercase();
    // Strip a leading provider prefix like "openai/".
    let m = m.split('/').next_back().unwrap_or(&m);
    if m.starts_with("gpt-5") {
        return false;
    }
    // Match `o1`, `o3`, `o4`, `o5`, ... and their suffixed variants
    // (`o1-mini`, `o3-2026-01-01`). Plain `o<digit>` at start of the name.
    let bytes = m.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'o' && bytes[1].is_ascii_digit() {
        return false;
    }
    true
}

// --- OpenAI API request/response types ---

#[derive(Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    // `max_tokens` is rejected by o-series and newer reasoning models;
    // `max_completion_tokens` is accepted by both legacy chat models and the
    // new ones, so always send the new name.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<OpenAiTool>>,
}

#[derive(Serialize)]
struct OpenAiMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct OpenAiTool {
    #[serde(rename = "type")]
    tool_type: String,
    function: OpenAiFunction,
}

#[derive(Serialize)]
struct OpenAiFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
    usage: OpenAiUsage,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiResponseMessage,
    finish_reason: String,
}

#[derive(Deserialize)]
struct OpenAiResponseMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<OpenAiToolCall>>,
}

#[derive(Deserialize)]
struct OpenAiToolCall {
    id: String,
    function: OpenAiFunctionCall,
}

#[derive(Deserialize)]
struct OpenAiFunctionCall {
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct OpenAiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

#[derive(Deserialize)]
struct OpenAiError {
    error: OpenAiErrorDetail,
}

#[derive(Deserialize)]
struct OpenAiErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
}

#[async_trait::async_trait]
impl ModelProvider for OpenAiProvider {
    async fn complete(&self, request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
        let messages: Vec<OpenAiMessage> = request
            .messages
            .iter()
            .map(|m| OpenAiMessage {
                role: m.role.clone(),
                content: m.content.clone(),
            })
            .collect();

        let tools = request.tools.as_ref().map(|ts| {
            ts.iter()
                .map(|t| OpenAiTool {
                    tool_type: "function".to_string(),
                    function: OpenAiFunction {
                        name: t.name.clone(),
                        description: t.description.clone(),
                        parameters: t.parameters.clone(),
                    },
                })
                .collect()
        });

        // o-series reasoning models (o1, o3, o4-mini, ...) and gpt-5 family
        // only support the default temperature (1). Sending any other value
        // returns a 400. Strip it for those models; legacy chat models still
        // get the caller's chosen value for deterministic output.
        let temperature = if model_supports_custom_temperature(&request.model) {
            request.temperature
        } else {
            None
        };

        let body = OpenAiRequest {
            model: request.model.clone(),
            messages,
            max_completion_tokens: request.max_tokens,
            temperature,
            tools,
        };

        debug!(
            "{} API request: model={}, messages={}",
            self.display_name,
            body.model,
            body.messages.len()
        );

        let resp = self
            .client
            .post(self.chat_completions_url())
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let error_body = resp.text().await.unwrap_or_default();
            if let Ok(err) = serde_json::from_str::<OpenAiError>(&error_body) {
                anyhow::bail!(
                    "{} API error ({}): {} — {}",
                    self.display_name,
                    status,
                    err.error.error_type,
                    err.error.message
                );
            }
            anyhow::bail!(
                "{} API error ({}): {}",
                self.display_name,
                status,
                error_body
            );
        }

        let api_resp: OpenAiResponse = resp.json().await?;

        let choice = api_resp
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("OpenAI returned no choices"))?;

        let content = choice.message.content.unwrap_or_default();

        let tool_calls = choice.message.tool_calls.map(|calls| {
            calls
                .into_iter()
                .map(|tc| {
                    let arguments = serde_json::from_str(&tc.function.arguments)
                        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
                    ToolCall {
                        id: tc.id,
                        name: tc.function.name,
                        arguments,
                    }
                })
                .collect()
        });

        let stop_reason = match choice.finish_reason.as_str() {
            "stop" => StopReason::EndTurn,
            "length" => StopReason::MaxTokens,
            "tool_calls" => StopReason::ToolUse,
            _ => StopReason::EndTurn,
        };

        Ok(CompletionResponse {
            content,
            tool_calls,
            stop_reason,
            usage: TokenUsage {
                prompt_tokens: api_resp.usage.prompt_tokens,
                completion_tokens: api_resp.usage.completion_tokens,
                total_tokens: api_resp.usage.total_tokens,
            },
            provider: self.provider_name.clone(),
            model: request.model,
        })
    }

    fn provider_name(&self) -> &str {
        &self.provider_name
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OpenAiProvider, decode_openai_compatible_secret, encode_openai_compatible_secret,
        model_supports_custom_temperature, normalize_openai_compatible_base_url,
    };

    #[test]
    fn legacy_chat_models_allow_custom_temperature() {
        for m in [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4.1",
            "gpt-3.5-turbo",
            "chatgpt-4o-latest",
        ] {
            assert!(
                model_supports_custom_temperature(m),
                "{m} should allow custom temperature"
            );
        }
    }

    #[test]
    fn reasoning_and_gpt5_models_disallow_custom_temperature() {
        for m in [
            "o1",
            "o1-mini",
            "o1-preview",
            "o3",
            "o3-mini",
            "o4-mini",
            "gpt-5",
            "gpt-5-mini",
            "gpt-5-nano",
            "gpt-5-chat",
            "gpt-5-2026-01-01",
            "o3-2026-01-01",
        ] {
            assert!(
                !model_supports_custom_temperature(m),
                "{m} should reject custom temperature"
            );
        }
    }

    #[test]
    fn handles_provider_prefix_and_casing() {
        assert!(!model_supports_custom_temperature("openai/gpt-5"));
        assert!(!model_supports_custom_temperature("OpenAI/o3-mini"));
        assert!(model_supports_custom_temperature("OpenAI/gpt-4o"));
    }

    #[test]
    fn normalizes_openai_compatible_base_url() {
        assert_eq!(
            normalize_openai_compatible_base_url(" http://localhost:1234/v1/ ").unwrap(),
            "http://localhost:1234/v1"
        );
        assert!(normalize_openai_compatible_base_url("ftp://localhost:1234").is_err());
        assert!(normalize_openai_compatible_base_url("https://user@example.com").is_err());
    }

    #[test]
    fn openai_compatible_secret_round_trips() {
        let encoded = encode_openai_compatible_secret("sk-custom", "http://localhost:1234/v1")
            .expect("secret should encode");
        let decoded = decode_openai_compatible_secret(&encoded).expect("secret should decode");
        assert_eq!(decoded.api_key, "sk-custom");
        assert_eq!(decoded.base_url, "http://localhost:1234/v1");
    }

    #[test]
    fn chat_completions_url_accepts_root_or_v1_base_url() {
        let root = OpenAiProvider::openai_compatible(
            "sk-custom".to_string(),
            "http://localhost:1234".to_string(),
        );
        let v1 = OpenAiProvider::openai_compatible(
            "sk-custom".to_string(),
            "http://localhost:1234/v1".to_string(),
        );

        assert_eq!(
            root.chat_completions_url(),
            "http://localhost:1234/v1/chat/completions"
        );
        assert_eq!(
            v1.chat_completions_url(),
            "http://localhost:1234/v1/chat/completions"
        );
    }
}
