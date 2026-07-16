//
//  heimdall
//  src/ai/codex.rs
//
//  Created by Ngonidzashe Mangudya on 2026/04/30.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use rand::Rng;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, CompletionResponse, StopReason, TokenUsage, ToolCall};
use crate::crypto;
use crate::db::DatabaseOperations;
use crate::models::HeimdallResult;

const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const CODEX_ISSUER: &str = "https://auth.openai.com";
const CODEX_AUTH_SCOPE: &str =
    "openid profile email offline_access api.connectors.read api.connectors.invoke";
const CODEX_ORIGINATOR: &str = "codex_cli_rs";
/// Ports the OpenAI Codex OAuth client accepts as redirect URIs. The first
/// available port is bound at startup; the second is used as a fallback if
/// another process (e.g. the Codex CLI) already holds the primary port.
pub const CODEX_CALLBACK_PORTS: [u16; 2] = [1455, 1457];
pub const CODEX_CALLBACK_PATH: &str = "/auth/callback";
const CODEX_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";
const TOKEN_REFRESH_WINDOW_MINUTES: i64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodexAuthTokens {
    id_token: String,
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    plan_type: Option<String>,
    #[serde(default)]
    is_fedramp_account: bool,
    #[serde(default)]
    access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    last_refresh: Option<DateTime<Utc>>,
}

impl CodexAuthTokens {
    fn from_exchange(
        id_token: String,
        access_token: String,
        refresh_token: String,
    ) -> HeimdallResult<Self> {
        let mut tokens = Self {
            id_token,
            access_token,
            refresh_token,
            account_id: None,
            email: None,
            plan_type: None,
            is_fedramp_account: false,
            access_token_expires_at: None,
            last_refresh: Some(Utc::now()),
        };
        tokens.refresh_metadata_from_tokens()?;
        Ok(tokens)
    }

    pub fn from_secret(secret: &str) -> HeimdallResult<Self> {
        let mut tokens: Self =
            serde_json::from_str(secret).context("Stored Codex credential is not valid JSON")?;
        tokens.refresh_metadata_from_tokens()?;
        Ok(tokens)
    }

    fn to_secret(&self) -> HeimdallResult<String> {
        serde_json::to_string(self).context("Failed to serialize Codex credential")
    }

    fn access_token(&self) -> &str {
        &self.access_token
    }

    fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    fn is_fedramp_account(&self) -> bool {
        self.is_fedramp_account
    }

    fn needs_refresh(&self) -> bool {
        let Some(expires_at) = self.access_token_expires_at else {
            return false;
        };
        expires_at <= Utc::now() + chrono::Duration::minutes(TOKEN_REFRESH_WINDOW_MINUTES)
    }

    fn apply_refresh(&mut self, response: CodexRefreshResponse) -> HeimdallResult<()> {
        if let Some(id_token) = response.id_token {
            self.id_token = id_token;
        }
        if let Some(access_token) = response.access_token {
            self.access_token = access_token;
        }
        if let Some(refresh_token) = response.refresh_token {
            self.refresh_token = refresh_token;
        }
        self.last_refresh = Some(Utc::now());
        self.refresh_metadata_from_tokens()
    }

    fn refresh_metadata_from_tokens(&mut self) -> HeimdallResult<()> {
        let id_payload = jwt_payload(&self.id_token).context("Failed to parse Codex ID token")?;
        let access_exp = jwt_expiration(&self.access_token).unwrap_or(None);
        let auth_claims = id_payload
            .get("https://api.openai.com/auth")
            .and_then(Value::as_object);
        let profile_claims = id_payload
            .get("https://api.openai.com/profile")
            .and_then(Value::as_object);

        self.email = id_payload
            .get("email")
            .and_then(Value::as_str)
            .or_else(|| {
                profile_claims
                    .and_then(|profile| profile.get("email"))
                    .and_then(Value::as_str)
            })
            .map(str::to_string);

        if let Some(auth) = auth_claims {
            self.account_id = auth
                .get("chatgpt_account_id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| self.account_id.clone());
            self.plan_type = auth
                .get("chatgpt_plan_type")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| self.plan_type.clone());
            self.is_fedramp_account = auth
                .get("chatgpt_account_is_fedramp")
                .and_then(Value::as_bool)
                .unwrap_or(self.is_fedramp_account);
        }

        self.access_token_expires_at = access_exp;
        Ok(())
    }
}

#[derive(Clone)]
pub struct CodexTokenPersistence {
    pub db: Arc<DatabaseOperations>,
    pub api_key_id: Uuid,
    pub encryption_key: Option<[u8; 32]>,
}

pub struct CodexProvider {
    base_url: String,
    client: reqwest::Client,
    tokens: Mutex<CodexAuthTokens>,
    persistence: Option<CodexTokenPersistence>,
}

impl CodexProvider {
    pub fn from_secret(secret: String) -> HeimdallResult<Self> {
        let tokens = CodexAuthTokens::from_secret(&secret)?;
        Ok(Self::new_with_tokens(tokens, None))
    }

    pub fn with_persistence(
        secret: String,
        persistence: CodexTokenPersistence,
    ) -> HeimdallResult<Self> {
        let tokens = CodexAuthTokens::from_secret(&secret)?;
        Ok(Self::new_with_tokens(tokens, Some(persistence)))
    }

    fn new_with_tokens(
        tokens: CodexAuthTokens,
        persistence: Option<CodexTokenPersistence>,
    ) -> Self {
        Self {
            base_url: CODEX_BASE_URL.to_string(),
            client: reqwest::Client::new(),
            tokens: Mutex::new(tokens),
            persistence,
        }
    }

    async fn current_tokens(&self, force_refresh: bool) -> HeimdallResult<CodexAuthTokens> {
        let mut guard = self.tokens.lock().await;
        if force_refresh || guard.needs_refresh() {
            self.refresh_tokens(&mut guard).await?;
        }
        Ok(guard.clone())
    }

    async fn refresh_tokens(&self, tokens: &mut CodexAuthTokens) -> HeimdallResult<()> {
        let response = self
            .client
            .post(format!("{}/oauth/token", CODEX_ISSUER))
            .header("Content-Type", "application/json")
            .header("originator", CODEX_ORIGINATOR)
            .json(&json!({
                "client_id": CODEX_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": tokens.refresh_token.as_str(),
            }))
            .send()
            .await
            .context("Codex token refresh request failed")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Codex token refresh failed ({status}): {body}");
        }

        let refresh_response: CodexRefreshResponse = response
            .json()
            .await
            .context("Codex token refresh returned invalid JSON")?;
        tokens.apply_refresh(refresh_response)?;
        self.persist_tokens(tokens).await
    }

    async fn persist_tokens(&self, tokens: &CodexAuthTokens) -> HeimdallResult<()> {
        let Some(persistence) = self.persistence.as_ref() else {
            return Ok(());
        };
        let secret = tokens.to_secret()?;
        let key_hash = hash_secret(&secret);
        let encrypted = encrypt_secret(&secret, persistence.encryption_key.as_ref());
        let updated = persistence
            .db
            .update_api_key_secret(persistence.api_key_id, &key_hash, &encrypted)
            .await
            .context("Failed to persist refreshed Codex tokens")?;
        if !updated {
            anyhow::bail!("Stored Codex connection no longer exists");
        }
        Ok(())
    }

    async fn send_completion(
        &self,
        request: CompletionRequest,
        tokens: &CodexAuthTokens,
    ) -> Result<CompletionResponse, CodexRequestError> {
        let body = build_responses_body(&request);
        let mut builder = self
            .client
            .post(format!("{}/responses", self.base_url.trim_end_matches('/')))
            .header("Authorization", format!("Bearer {}", tokens.access_token()))
            .header("Content-Type", "application/json")
            .header("Accept", "text/event-stream")
            .header("originator", CODEX_ORIGINATOR)
            .header("User-Agent", "codex_cli_rs/heimdall");

        if let Some(account_id) = tokens.account_id() {
            builder = builder.header("ChatGPT-Account-ID", account_id);
        }
        if tokens.is_fedramp_account() {
            builder = builder.header("X-OpenAI-Fedramp", "true");
        }

        let response = builder
            .json(&body)
            .send()
            .await
            .map_err(CodexRequestError::from)?;
        let status = response.status();
        let response_text = response.text().await.map_err(CodexRequestError::from)?;

        if !status.is_success() {
            if status == StatusCode::UNAUTHORIZED {
                return Err(CodexRequestError::Unauthorized(response_text));
            }
            return Err(CodexRequestError::Other(anyhow::anyhow!(
                "Codex API error ({status}): {response_text}"
            )));
        }

        parse_responses_sse(&response_text, request.model, "codex")
            .map_err(CodexRequestError::Other)
    }
}

#[async_trait::async_trait]
impl ModelProvider for CodexProvider {
    async fn complete(&self, request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
        let tokens = self.current_tokens(false).await?;
        match self.send_completion(request.clone(), &tokens).await {
            Ok(response) => Ok(response),
            Err(CodexRequestError::Unauthorized(body)) => {
                log::warn!("Codex access token rejected; refreshing and retrying once: {body}");
                let tokens = self.current_tokens(true).await?;
                self.send_completion(request, &tokens)
                    .await
                    .map_err(|error| match error {
                        CodexRequestError::Unauthorized(body) => {
                            anyhow::anyhow!("Codex API rejected refreshed credentials: {body}")
                        }
                        CodexRequestError::Other(error) => error,
                    })
            }
            Err(CodexRequestError::Other(error)) => Err(error),
        }
    }

    fn provider_name(&self) -> &str {
        "codex"
    }
}

#[derive(Debug)]
enum CodexRequestError {
    Unauthorized(String),
    Other(anyhow::Error),
}

impl From<reqwest::Error> for CodexRequestError {
    fn from(error: reqwest::Error) -> Self {
        Self::Other(error.into())
    }
}

#[derive(Deserialize)]
struct CodexRefreshResponse {
    id_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct CodexTokenResponse {
    id_token: String,
    access_token: String,
    refresh_token: String,
}

#[derive(Debug, Clone)]
struct PkceCodes {
    code_verifier: String,
    code_challenge: String,
}

/// Result of preparing a Codex OAuth login: the URL to redirect the user to,
/// plus the OAuth `state` and PKCE `code_verifier` the caller must persist
/// until the redirect callback returns with the same state.
pub struct CodexAuthorizationRequest {
    pub authorize_url: String,
    pub state: String,
    pub code_verifier: String,
}

/// Build an OpenAI authorize URL for the Codex OAuth flow. The caller is
/// responsible for storing `state` → `code_verifier` and matching them up when
/// the redirect callback fires on `http://localhost:{callback_port}/auth/callback`
/// or when a hosted user pastes that callback URL back into Settings.
pub fn prepare_codex_authorization(
    callback_port: u16,
) -> HeimdallResult<CodexAuthorizationRequest> {
    let pkce = generate_pkce();
    let state = generate_login_state();
    let redirect_uri = format!("http://localhost:{callback_port}{CODEX_CALLBACK_PATH}");
    let authorize_url = build_authorize_url(&redirect_uri, &pkce, &state)?;
    Ok(CodexAuthorizationRequest {
        authorize_url,
        state,
        code_verifier: pkce.code_verifier,
    })
}

/// Exchange the OAuth authorization `code` for tokens and persist them
/// against the user. The `code_verifier` and `callback_port` must match the
/// values handed to [`prepare_codex_authorization`] for this login attempt.
pub async fn complete_codex_login(
    db: Arc<DatabaseOperations>,
    encryption_key: Option<[u8; 32]>,
    user_id: Uuid,
    code_verifier: &str,
    callback_port: u16,
    code: &str,
) -> HeimdallResult<CodexAuthTokens> {
    let redirect_uri = format!("http://localhost:{callback_port}{CODEX_CALLBACK_PATH}");
    let tokens = exchange_code_for_tokens(&redirect_uri, code_verifier, code).await?;
    store_codex_tokens(db, user_id, encryption_key, tokens.clone()).await?;
    Ok(tokens)
}

async fn exchange_code_for_tokens(
    redirect_uri: &str,
    code_verifier: &str,
    code: &str,
) -> HeimdallResult<CodexAuthTokens> {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/oauth/token", CODEX_ISSUER))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("originator", CODEX_ORIGINATOR)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", CODEX_CLIENT_ID),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .context("Codex token exchange request failed")?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Codex token exchange failed ({status}): {body}");
    }

    let token_response: CodexTokenResponse = response
        .json()
        .await
        .context("Codex token exchange returned invalid JSON")?;
    CodexAuthTokens::from_exchange(
        token_response.id_token,
        token_response.access_token,
        token_response.refresh_token,
    )
}

async fn store_codex_tokens(
    db: Arc<DatabaseOperations>,
    user_id: Uuid,
    encryption_key: Option<[u8; 32]>,
    tokens: CodexAuthTokens,
) -> HeimdallResult<()> {
    let secret = tokens.to_secret()?;
    let key_hash = hash_secret(&secret);
    let encrypted = encrypt_secret(&secret, encryption_key.as_ref());
    let label = tokens
        .email
        .as_deref()
        .map(|email| format!("ChatGPT subscription ({email})"))
        .unwrap_or_else(|| "ChatGPT subscription".to_string());

    db.delete_api_keys_by_provider(user_id, "codex")
        .await
        .context("Failed to replace existing Codex connection")?;
    db.create_api_key(
        user_id,
        "llm_provider",
        "codex",
        Some(&label),
        &key_hash,
        &encrypted,
    )
    .await
    .context("Failed to store Codex connection")?;
    Ok(())
}

fn build_authorize_url(
    redirect_uri: &str,
    pkce: &PkceCodes,
    state: &str,
) -> HeimdallResult<String> {
    let mut url = reqwest::Url::parse(&format!("{}/oauth/authorize", CODEX_ISSUER))
        .context("Failed to build Codex authorize URL")?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", CODEX_CLIENT_ID)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", CODEX_AUTH_SCOPE)
        .append_pair("code_challenge", &pkce.code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("id_token_add_organizations", "true")
        .append_pair("codex_cli_simplified_flow", "true")
        .append_pair("state", state)
        .append_pair("originator", CODEX_ORIGINATOR);
    Ok(url.to_string())
}

/// Codex browser redirects land on a fixed localhost callback URL. Hosted
/// Heimdall cannot receive that browser request directly, so users can paste
/// the full callback URL back into Settings. Accept the full URL, `code#state`,
/// or a bare code plus separately supplied state.
pub fn split_pasted_callback(pasted: &str) -> (String, Option<String>) {
    let trimmed = pasted.trim();
    if trimmed.is_empty() {
        return (String::new(), None);
    }

    if let Ok(url) = reqwest::Url::parse(trimmed) {
        let mut code = None;
        let mut state = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "code" => code = Some(value.trim().to_string()),
                "state" => state = Some(value.trim().to_string()),
                _ => {}
            }
        }
        if code.is_some() || state.is_some() {
            return (
                code.unwrap_or_default(),
                state.filter(|value| !value.is_empty()),
            );
        }
    }

    let after_code = trimmed
        .rsplit_once("code=")
        .map(|(_, tail)| tail)
        .unwrap_or(trimmed);

    let (code_part, query_tail) = after_code
        .split_once('&')
        .map(|(code, tail)| (code, Some(tail)))
        .unwrap_or((after_code, None));

    let query_state = query_tail.and_then(|tail| {
        tail.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == "state" && !value.trim().is_empty()).then(|| value.trim().to_string())
        })
    });

    let mut parts = code_part.splitn(2, '#');
    let code = parts.next().unwrap_or("").trim().to_string();
    let hash_state = parts
        .next()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    (code, query_state.or(hash_state))
}

fn generate_pkce() -> PkceCodes {
    let bytes: [u8; 64] = rand::rng().random();
    let code_verifier = URL_SAFE_NO_PAD.encode(bytes);
    let digest = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(digest);

    PkceCodes {
        code_verifier,
        code_challenge,
    }
}

fn generate_login_state() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn build_responses_body(request: &CompletionRequest) -> Value {
    let instructions = request
        .messages
        .iter()
        .filter(|message| message.role.eq_ignore_ascii_case("system"))
        .map(|message| message.content.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");

    let input = request
        .messages
        .iter()
        .filter(|message| !message.role.eq_ignore_ascii_case("system"))
        .map(|message| {
            let role = if message.role.eq_ignore_ascii_case("assistant") {
                "assistant"
            } else {
                "user"
            };
            let content_type = if role == "assistant" {
                "output_text"
            } else {
                "input_text"
            };
            json!({
                "type": "message",
                "role": role,
                "content": [{
                    "type": content_type,
                    "text": message.content.as_str(),
                }],
            })
        })
        .collect::<Vec<_>>();

    let tools = request
        .tools
        .as_ref()
        .map(|tools| {
            tools
                .iter()
                .map(|tool| {
                    json!({
                        "type": "function",
                        "name": tool.name.as_str(),
                        "description": tool.description.as_str(),
                        "parameters": tool.parameters.clone(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut body = json!({
        "model": request.model.as_str(),
        "instructions": instructions,
        "input": input,
        "reasoning": null,
        "store": false,
        "stream": true,
        "include": [],
        "client_metadata": {
            "application": "heimdall",
        },
    });

    if !tools.is_empty() {
        body["tools"] = json!(tools);
        body["tool_choice"] = json!("auto");
        body["parallel_tool_calls"] = json!(true);
    }

    body
}

pub(crate) fn parse_responses_sse(
    body: &str,
    model: String,
    provider: &str,
) -> HeimdallResult<CompletionResponse> {
    let mut content = String::new();
    let mut tool_calls = Vec::new();
    let mut usage = TokenUsage {
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0,
    };
    let mut data_lines = Vec::new();

    for line in body.lines() {
        if line.trim().is_empty() {
            flush_sse_event(&mut data_lines, &mut content, &mut tool_calls, &mut usage)?;
            continue;
        }

        if let Some(data) = line.strip_prefix("data:") {
            data_lines.push(data.trim_start().to_string());
        }
    }
    flush_sse_event(&mut data_lines, &mut content, &mut tool_calls, &mut usage)?;

    let stop_reason = if tool_calls.is_empty() {
        StopReason::EndTurn
    } else {
        StopReason::ToolUse
    };
    let tool_calls = if tool_calls.is_empty() {
        None
    } else {
        Some(tool_calls)
    };

    Ok(CompletionResponse {
        content,
        tool_calls,
        stop_reason,
        usage,
        provider: provider.to_string(),
        model,
        fallback_attempts: Vec::new(),
    })
}

fn flush_sse_event(
    data_lines: &mut Vec<String>,
    content: &mut String,
    tool_calls: &mut Vec<ToolCall>,
    usage: &mut TokenUsage,
) -> HeimdallResult<()> {
    if data_lines.is_empty() {
        return Ok(());
    }

    let data = data_lines.join("\n");
    data_lines.clear();

    if data == "[DONE]" {
        return Ok(());
    }

    let event: Value = serde_json::from_str(&data)
        .with_context(|| format!("Failed to parse Codex SSE event: {data}"))?;
    match event
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "response.output_text.delta" => {
            if let Some(delta) = event.get("delta").and_then(Value::as_str) {
                content.push_str(delta);
            }
        }
        "response.output_item.done" => {
            if let Some(item) = event.get("item") {
                parse_output_item(item, content, tool_calls);
            }
        }
        "response.completed" => {
            if let Some(response) = event.get("response") {
                *usage = parse_usage(response);
            }
        }
        "response.failed" | "error" => {
            let message = event
                .pointer("/response/error/message")
                .or_else(|| event.pointer("/error/message"))
                .or_else(|| event.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("Codex request failed");
            anyhow::bail!("{message}");
        }
        _ => {}
    }

    Ok(())
}

fn parse_output_item(item: &Value, content: &mut String, tool_calls: &mut Vec<ToolCall>) {
    match item.get("type").and_then(Value::as_str).unwrap_or_default() {
        "function_call" => {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let id = item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let arguments = item
                .get("arguments")
                .and_then(Value::as_str)
                .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
            if !name.is_empty() && !id.is_empty() {
                tool_calls.push(ToolCall {
                    id,
                    name,
                    arguments,
                });
            }
        }
        "message" if content.is_empty() => {
            if let Some(items) = item.get("content").and_then(Value::as_array) {
                for content_item in items {
                    if let Some(text) = content_item.get("text").and_then(Value::as_str) {
                        content.push_str(text);
                    }
                }
            }
        }
        _ => {}
    }
}

fn parse_usage(response: &Value) -> TokenUsage {
    let usage = response.get("usage").unwrap_or(&Value::Null);
    let input_tokens = usage
        .get("input_tokens")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let output_tokens = usage
        .get("output_tokens")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let total_tokens = usage
        .get("total_tokens")
        .and_then(Value::as_i64)
        .unwrap_or(input_tokens + output_tokens);

    TokenUsage {
        prompt_tokens: to_u32(input_tokens),
        completion_tokens: to_u32(output_tokens),
        total_tokens: to_u32(total_tokens),
    }
}

fn to_u32(value: i64) -> u32 {
    u32::try_from(value.max(0)).unwrap_or(u32::MAX)
}

fn jwt_payload(jwt: &str) -> HeimdallResult<Value> {
    let mut parts = jwt.split('.');
    let (_header, payload, _signature) = match (parts.next(), parts.next(), parts.next()) {
        (Some(header), Some(payload), Some(signature))
            if !header.is_empty() && !payload.is_empty() && !signature.is_empty() =>
        {
            (header, payload, signature)
        }
        _ => anyhow::bail!("Invalid JWT format"),
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .context("Failed to decode JWT payload")?;
    serde_json::from_slice(&bytes).context("Failed to parse JWT payload")
}

fn jwt_expiration(jwt: &str) -> HeimdallResult<Option<DateTime<Utc>>> {
    let payload = jwt_payload(jwt)?;
    Ok(payload
        .get("exp")
        .and_then(Value::as_i64)
        .and_then(|exp| DateTime::<Utc>::from_timestamp(exp, 0)))
}

fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn encrypt_secret(secret: &str, encryption_key: Option<&[u8; 32]>) -> String {
    match encryption_key {
        Some(enc_key) => match crypto::encrypt(secret.as_bytes(), enc_key) {
            Ok(encrypted) => encrypted,
            Err(error) => {
                log::error!(
                    "AES-256-GCM encryption failed for Codex tokens ({error:#}); falling back to hex encoding"
                );
                hex::encode(secret.as_bytes())
            }
        },
        None => {
            log::warn!("No ENCRYPTION_KEY configured; Codex tokens stored with hex encoding");
            hex::encode(secret.as_bytes())
        }
    }
}

pub fn login_success_html(tokens: &CodexAuthTokens, return_url: &str) -> String {
    let account = tokens
        .email
        .as_deref()
        .or(tokens.account_id.as_deref())
        .unwrap_or("ChatGPT");
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Codex connected</title>\
         <meta http-equiv=\"refresh\" content=\"1.25;url={}\"></head>\
         <body style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:32px;color:#0f172a\">\
         <h1 style=\"font-size:20px;margin:0 0 8px\">Codex connected</h1>\
         <p style=\"margin:0 0 20px;color:#475569\">Heimdall can now use your ChatGPT subscription for Codex model requests as {}.</p>\
         <a href=\"{}\" style=\"color:#2563eb;font-weight:600\">Return to Heimdall</a>\
         </body></html>",
        escape_html(return_url),
        escape_html(account),
        escape_html(return_url)
    )
}

pub fn login_error_html(message: &str, return_url: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Codex connection failed</title></head>\
         <body style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:32px;color:#0f172a\">\
         <h1 style=\"font-size:20px;margin:0 0 8px\">Codex connection failed</h1>\
         <p style=\"margin:0 0 20px;color:#475569\">{}</p>\
         <a href=\"{}\" style=\"color:#2563eb;font-weight:600\">Return to Heimdall</a>\
         </body></html>",
        escape_html(message),
        escape_html(return_url)
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses_body_omits_tool_choice_without_tools() {
        let request = CompletionRequest {
            model: "grok-build-0.1".to_string(),
            messages: vec![crate::ai::types::Message {
                role: "user".to_string(),
                content: "summarize this".to_string(),
            }],
            max_tokens: Some(128),
            temperature: None,
            tools: None,
        };

        let body = build_responses_body(&request);

        assert!(body.get("tools").is_none());
        assert!(body.get("tool_choice").is_none());
        assert!(body.get("parallel_tool_calls").is_none());
    }

    #[test]
    fn split_pasted_callback_handles_localhost_url() {
        let pasted = "http://localhost:1455/auth/callback?code=ac_qL-7BzQw.token&scope=openid+profile&state=egi_bt-I1CvhSppw3";
        let (code, state) = split_pasted_callback(pasted);

        assert_eq!(code, "ac_qL-7BzQw.token");
        assert_eq!(state.as_deref(), Some("egi_bt-I1CvhSppw3"));
    }

    #[test]
    fn split_pasted_callback_handles_code_hash_state() {
        let (code, state) = split_pasted_callback("ac_abc123#state_456");

        assert_eq!(code, "ac_abc123");
        assert_eq!(state.as_deref(), Some("state_456"));
    }

    #[test]
    fn split_pasted_callback_handles_bare_code() {
        let (code, state) = split_pasted_callback("ac_bare_code");

        assert_eq!(code, "ac_bare_code");
        assert!(state.is_none());
    }

    #[test]
    fn parses_responses_sse_text_and_tool_calls() {
        let sse = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n\
                   data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_1\",\"name\":\"inspect\",\"arguments\":\"{\\\"path\\\":\\\"Cargo.toml\\\"}\"}}\n\n\
                   data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":4,\"total_tokens\":7}}}\n\n";

        let response = parse_responses_sse(sse, "gpt-5.6-terra".to_string(), "codex").unwrap();

        assert_eq!(response.content, "hello");
        assert_eq!(response.stop_reason, StopReason::ToolUse);
        assert_eq!(response.usage.total_tokens, 7);
        let tool_call = response.tool_calls.unwrap().into_iter().next().unwrap();
        assert_eq!(tool_call.id, "call_1");
        assert_eq!(tool_call.name, "inspect");
        assert_eq!(tool_call.arguments["path"], "Cargo.toml");
    }
}
