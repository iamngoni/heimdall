//
//  heimdall
//  src/ai/claude_code.rs
//
//  Created by Ngonidzashe Mangudya on 2026/05/14.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

//! Claude Code (Claude.ai subscription) provider.
//!
//! This is the Anthropic analog of [`codex`](super::codex): instead of an
//! Anthropic API key (pay-per-token), we use the OAuth tokens that the
//! `claude` CLI obtains from Claude.ai when the user logs in with their
//! Pro/Max subscription. Requests bill against that subscription rather than
//! API credits.
//!
//! ## OAuth flow
//!
//! The production Claude OAuth client does not accept arbitrary localhost
//! redirect URIs, so we can't run an in-process callback the way we do for
//! Codex. Instead the redirect target is the hosted Anthropic platform page
//! `https://platform.claude.com/oauth/code/callback`, which displays a
//! `code#state` string for the user to copy. We then accept that string
//! through a server-rendered form on the settings page.

use std::sync::Arc;
use std::time::Duration;

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

/// Public OAuth client ID used by the Claude Code CLI.
const CLAUDE_CODE_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const CLAUDE_CODE_AUTHORIZE_URL: &str = "https://platform.claude.com/oauth/authorize";
const CLAUDE_CODE_TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
/// The Anthropic platform page that displays the authorization code for the
/// user to paste back. This is the only redirect URI the Claude OAuth client
/// accepts for public PKCE flows.
const CLAUDE_CODE_REDIRECT_URI: &str = "https://platform.claude.com/oauth/code/callback";
const CLAUDE_CODE_SCOPE: &str =
    "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";
const CLAUDE_CODE_SESSION_SCOPE: &str = "user:sessions:claude_code";
const CLAUDE_CODE_API_BASE: &str = "https://api.anthropic.com";
const CLAUDE_CODE_ANTHROPIC_VERSION: &str = "2023-06-01";
/// Beta headers used by Claude Code when authenticating to the Messages API
/// with subscription OAuth tokens.
// These values intentionally track the installed Claude CLI transport contract.
// The ignored Nexus/Tyr live test catches upstream contract drift.
const CLAUDE_CODE_BETAS: &str = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,effort-2025-11-24,extended-cache-ttl-2025-04-11";
const CLAUDE_CODE_USER_AGENT: &str = "claude-cli/2.1.211 (external, sdk-cli)";
const CLAUDE_CODE_BILLING_HEADER: &str =
    "x-anthropic-billing-header: cc_version=2.1.211.cfa; cc_entrypoint=sdk-cli;";
const CLAUDE_CODE_MAX_REQUEST_ATTEMPTS: usize = 6;
/// System prompt prefix used by the Claude Agent SDK request path.
const CLAUDE_CODE_SYSTEM_PREFIX: &str =
    "You are a Claude agent, built on Anthropic's Claude Agent SDK.";
const TOKEN_REFRESH_WINDOW_MINUTES: i64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeCodeAuthTokens {
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    account_uuid: Option<String>,
    #[serde(default)]
    organization_uuid: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    /// Absolute time `access_token` expires at, when known. Populated from
    /// the token endpoint's `expires_in` (seconds) field.
    #[serde(default)]
    access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    last_refresh: Option<DateTime<Utc>>,
}

impl ClaudeCodeAuthTokens {
    fn from_exchange(response: ClaudeCodeTokenResponse) -> Self {
        let now = Utc::now();
        let expires_at = response
            .expires_in
            .map(|seconds| now + chrono::Duration::seconds(seconds.max(0)));
        let scopes = response
            .scope
            .as_deref()
            .map(|scope| {
                scope
                    .split_whitespace()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Self {
            access_token: response.access_token,
            refresh_token: response.refresh_token.unwrap_or_default(),
            email: response
                .account
                .as_ref()
                .and_then(|a| a.email_address.clone()),
            account_uuid: response.account.as_ref().and_then(|a| a.uuid.clone()),
            organization_uuid: response.organization.as_ref().and_then(|o| o.uuid.clone()),
            scopes,
            access_token_expires_at: expires_at,
            last_refresh: Some(now),
        }
    }

    pub fn from_secret(secret: &str) -> HeimdallResult<Self> {
        serde_json::from_str(secret).context("Stored Claude Code credential is not valid JSON")
    }

    fn to_secret(&self) -> HeimdallResult<String> {
        serde_json::to_string(self).context("Failed to serialize Claude Code credential")
    }

    fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    pub fn account_uuid(&self) -> Option<&str> {
        self.account_uuid.as_deref()
    }

    fn needs_refresh(&self) -> bool {
        if !self.refresh_token.is_empty()
            && !self
                .scopes
                .iter()
                .any(|scope| scope == CLAUDE_CODE_SESSION_SCOPE)
        {
            return true;
        }

        let Some(expires_at) = self.access_token_expires_at else {
            return false;
        };
        expires_at <= Utc::now() + chrono::Duration::minutes(TOKEN_REFRESH_WINDOW_MINUTES)
    }

    fn apply_refresh(&mut self, response: ClaudeCodeTokenResponse) {
        let now = Utc::now();
        self.access_token = response.access_token;
        if let Some(refresh_token) = response.refresh_token {
            self.refresh_token = refresh_token;
        }
        if let Some(expires_in) = response.expires_in {
            self.access_token_expires_at = Some(now + chrono::Duration::seconds(expires_in.max(0)));
        }
        if let Some(scope) = response.scope {
            self.scopes = scope.split_whitespace().map(str::to_string).collect();
        }
        if let Some(account) = response.account {
            if let Some(email) = account.email_address {
                self.email = Some(email);
            }
            if let Some(uuid) = account.uuid {
                self.account_uuid = Some(uuid);
            }
        }
        if let Some(organization) = response.organization
            && let Some(uuid) = organization.uuid
        {
            self.organization_uuid = Some(uuid);
        }
        self.last_refresh = Some(now);
    }
}

#[derive(Clone)]
pub struct ClaudeCodeTokenPersistence {
    pub db: Arc<DatabaseOperations>,
    pub api_key_id: Uuid,
    pub encryption_key: Option<[u8; 32]>,
}

pub struct ClaudeCodeProvider {
    base_url: String,
    client: reqwest::Client,
    session_id: Uuid,
    tokens: Mutex<ClaudeCodeAuthTokens>,
    persistence: Option<ClaudeCodeTokenPersistence>,
}

impl ClaudeCodeProvider {
    pub fn from_secret(secret: String) -> HeimdallResult<Self> {
        let tokens = ClaudeCodeAuthTokens::from_secret(&secret)?;
        Ok(Self::new_with_tokens(tokens, None))
    }

    pub fn with_persistence(
        secret: String,
        persistence: ClaudeCodeTokenPersistence,
    ) -> HeimdallResult<Self> {
        let tokens = ClaudeCodeAuthTokens::from_secret(&secret)?;
        Ok(Self::new_with_tokens(tokens, Some(persistence)))
    }

    fn new_with_tokens(
        tokens: ClaudeCodeAuthTokens,
        persistence: Option<ClaudeCodeTokenPersistence>,
    ) -> Self {
        Self {
            base_url: CLAUDE_CODE_API_BASE.to_string(),
            client: reqwest::Client::new(),
            session_id: Uuid::now_v7(),
            tokens: Mutex::new(tokens),
            persistence,
        }
    }

    async fn current_tokens(&self, force_refresh: bool) -> HeimdallResult<ClaudeCodeAuthTokens> {
        let mut guard = self.tokens.lock().await;
        if force_refresh || guard.needs_refresh() {
            self.refresh_tokens(&mut guard).await?;
        }
        Ok(guard.clone())
    }

    async fn refresh_tokens(&self, tokens: &mut ClaudeCodeAuthTokens) -> HeimdallResult<()> {
        if tokens.refresh_token.is_empty() {
            anyhow::bail!(
                "Claude Code session has no refresh token stored — reconnect from Settings."
            );
        }

        let response = self
            .client
            .post(CLAUDE_CODE_TOKEN_URL)
            .header("Content-Type", "application/json")
            .json(&build_refresh_body(tokens))
            .send()
            .await
            .context("Claude Code token refresh request failed")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Claude Code token refresh failed ({status}): {body}");
        }

        let refresh_response: ClaudeCodeTokenResponse = response
            .json()
            .await
            .context("Claude Code token refresh returned invalid JSON")?;
        tokens.apply_refresh(refresh_response);
        self.persist_tokens(tokens).await
    }

    async fn persist_tokens(&self, tokens: &ClaudeCodeAuthTokens) -> HeimdallResult<()> {
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
            .context("Failed to persist refreshed Claude Code tokens")?;
        if !updated {
            anyhow::bail!("Stored Claude Code connection no longer exists");
        }
        Ok(())
    }

    async fn send_completion(
        &self,
        request: CompletionRequest,
        tokens: &ClaudeCodeAuthTokens,
    ) -> Result<CompletionResponse, ClaudeCodeRequestError> {
        let mut body = build_messages_body(&request);
        attach_claude_code_metadata(&mut body, tokens, self.session_id);

        let response = self
            .client
            .post(format!(
                "{}/v1/messages?beta=true",
                self.base_url.trim_end_matches('/')
            ))
            .header("Authorization", format!("Bearer {}", tokens.access_token()))
            .header("anthropic-version", CLAUDE_CODE_ANTHROPIC_VERSION)
            .header("anthropic-beta", CLAUDE_CODE_BETAS)
            .header("anthropic-dangerous-direct-browser-access", "true")
            .header("user-agent", CLAUDE_CODE_USER_AGENT)
            .header("x-app", "cli")
            .header("x-claude-code-session-id", self.session_id.to_string())
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(ClaudeCodeRequestError::from)?;

        let status = response.status();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs);
        let response_text = response
            .text()
            .await
            .map_err(ClaudeCodeRequestError::from)?;

        if !status.is_success() {
            if status == StatusCode::UNAUTHORIZED {
                return Err(ClaudeCodeRequestError::Unauthorized(response_text));
            }
            if is_transient_status(status) {
                return Err(ClaudeCodeRequestError::Transient {
                    status,
                    body: response_text,
                    retry_after,
                });
            }
            return Err(ClaudeCodeRequestError::Other(anyhow::anyhow!(
                "Claude Code API error ({status}): {response_text}"
            )));
        }

        parse_messages_response(&response_text, request.model)
            .map_err(ClaudeCodeRequestError::Other)
    }
}

fn attach_claude_code_metadata(body: &mut Value, tokens: &ClaudeCodeAuthTokens, session_id: Uuid) {
    let account_uuid = tokens.account_uuid.as_deref().unwrap_or_default();
    let device_id = format!(
        "{:x}",
        Sha256::digest(format!("heimdall:{account_uuid}").as_bytes())
    );
    let user_id = json!({
        "device_id": device_id,
        "account_uuid": account_uuid,
        "session_id": session_id,
    })
    .to_string();

    body["metadata"] = json!({ "user_id": user_id });
}

fn build_refresh_body(tokens: &ClaudeCodeAuthTokens) -> Value {
    json!({
        "grant_type": "refresh_token",
        "client_id": CLAUDE_CODE_CLIENT_ID,
        "refresh_token": tokens.refresh_token.as_str(),
        "scope": CLAUDE_CODE_SCOPE,
    })
}

#[async_trait::async_trait]
impl ModelProvider for ClaudeCodeProvider {
    async fn complete(&self, request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
        let mut tokens = self.current_tokens(false).await?;
        let mut refreshed = false;

        for attempt in 1..=CLAUDE_CODE_MAX_REQUEST_ATTEMPTS {
            match self.send_completion(request.clone(), &tokens).await {
                Ok(response) => return Ok(response),
                Err(ClaudeCodeRequestError::Unauthorized(body)) if !refreshed => {
                    log::warn!(
                        "Claude Code access token rejected; refreshing and retrying once: {body}"
                    );
                    tokens = self.current_tokens(true).await?;
                    refreshed = true;
                }
                Err(ClaudeCodeRequestError::Unauthorized(body)) => {
                    anyhow::bail!("Claude Code API rejected refreshed credentials: {body}");
                }
                Err(ClaudeCodeRequestError::Transient {
                    status,
                    body,
                    retry_after,
                }) if attempt < CLAUDE_CODE_MAX_REQUEST_ATTEMPTS => {
                    let delay = claude_code_retry_delay(attempt, retry_after);
                    log::warn!(
                        "Claude Code API returned {status} (attempt {attempt}/{CLAUDE_CODE_MAX_REQUEST_ATTEMPTS}); retrying in {:.1}s: {body}",
                        delay.as_secs_f64()
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(ClaudeCodeRequestError::Transient { status, body, .. }) => {
                    anyhow::bail!("Claude Code API error ({status}): {body}");
                }
                Err(ClaudeCodeRequestError::Other(error)) => return Err(error),
            }
        }

        unreachable!("Claude Code request loop always returns on its final attempt")
    }

    fn provider_name(&self) -> &str {
        "claude_code"
    }
}

#[derive(Debug)]
enum ClaudeCodeRequestError {
    Unauthorized(String),
    Transient {
        status: StatusCode,
        body: String,
        retry_after: Option<Duration>,
    },
    Other(anyhow::Error),
}

fn is_transient_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::INTERNAL_SERVER_ERROR
        || status == StatusCode::BAD_GATEWAY
        || status == StatusCode::SERVICE_UNAVAILABLE
        || status.as_u16() == 529
}

fn claude_code_retry_delay(attempt: usize, retry_after: Option<Duration>) -> Duration {
    let exponent = attempt.saturating_sub(1).min(4) as u32;
    let backoff = Duration::from_millis(500 * 2_u64.pow(exponent));
    retry_after
        .map(|delay| delay.max(backoff).min(Duration::from_secs(15)))
        .unwrap_or(backoff)
}

impl From<reqwest::Error> for ClaudeCodeRequestError {
    fn from(error: reqwest::Error) -> Self {
        Self::Other(error.into())
    }
}

#[derive(Deserialize)]
struct ClaudeCodeTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    /// Lifetime of `access_token` in seconds.
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    account: Option<ClaudeCodeAccount>,
    #[serde(default)]
    organization: Option<ClaudeCodeOrganization>,
}

#[derive(Deserialize)]
struct ClaudeCodeAccount {
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    email_address: Option<String>,
}

#[derive(Deserialize)]
struct ClaudeCodeOrganization {
    #[serde(default)]
    uuid: Option<String>,
}

#[derive(Debug, Clone)]
struct PkceCodes {
    code_verifier: String,
    code_challenge: String,
}

/// The information the caller needs to drive the manual-paste OAuth flow:
/// the URL to open in the browser, plus the `state` and PKCE `code_verifier`
/// that must be persisted until the user pastes the resulting code back.
pub struct ClaudeCodeAuthorizationRequest {
    pub authorize_url: String,
    pub state: String,
    pub code_verifier: String,
}

/// Build the Claude.ai authorize URL for the OAuth flow. The caller is
/// responsible for storing `state` → `code_verifier` and matching them up
/// when the user pastes back the `code#state` string from the redirect page.
pub fn prepare_claude_code_authorization() -> HeimdallResult<ClaudeCodeAuthorizationRequest> {
    let pkce = generate_pkce();
    let state = generate_login_state();
    let authorize_url = build_authorize_url(&pkce, &state)?;
    Ok(ClaudeCodeAuthorizationRequest {
        authorize_url,
        state,
        code_verifier: pkce.code_verifier,
    })
}

/// Exchange the OAuth `code` for tokens and persist them against the user.
/// `code_verifier` must match the value handed to
/// [`prepare_claude_code_authorization`] for this login attempt.
pub async fn complete_claude_code_login(
    db: Arc<DatabaseOperations>,
    encryption_key: Option<[u8; 32]>,
    user_id: Uuid,
    code_verifier: &str,
    state: &str,
    code: &str,
) -> HeimdallResult<ClaudeCodeAuthTokens> {
    let tokens = exchange_code_for_tokens(code_verifier, state, code).await?;
    store_claude_code_tokens(db, user_id, encryption_key, tokens.clone()).await?;
    Ok(tokens)
}

async fn exchange_code_for_tokens(
    code_verifier: &str,
    state: &str,
    code: &str,
) -> HeimdallResult<ClaudeCodeAuthTokens> {
    let client = reqwest::Client::new();
    let response = client
        .post(CLAUDE_CODE_TOKEN_URL)
        .header("Content-Type", "application/json")
        .json(&json!({
            "grant_type": "authorization_code",
            "client_id": CLAUDE_CODE_CLIENT_ID,
            "code": code,
            "redirect_uri": CLAUDE_CODE_REDIRECT_URI,
            "code_verifier": code_verifier,
            "state": state,
        }))
        .send()
        .await
        .context("Claude Code token exchange request failed")?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Claude Code token exchange failed ({status}): {body}");
    }

    let token_response: ClaudeCodeTokenResponse = response
        .json()
        .await
        .context("Claude Code token exchange returned invalid JSON")?;
    Ok(ClaudeCodeAuthTokens::from_exchange(token_response))
}

async fn store_claude_code_tokens(
    db: Arc<DatabaseOperations>,
    user_id: Uuid,
    encryption_key: Option<[u8; 32]>,
    tokens: ClaudeCodeAuthTokens,
) -> HeimdallResult<()> {
    let secret = tokens.to_secret()?;
    let key_hash = hash_secret(&secret);
    let encrypted = encrypt_secret(&secret, encryption_key.as_ref());
    let label = tokens
        .email
        .as_deref()
        .map(|email| format!("Claude.ai subscription ({email})"))
        .unwrap_or_else(|| "Claude.ai subscription".to_string());

    db.delete_api_keys_by_provider(user_id, "claude_code")
        .await
        .context("Failed to replace existing Claude Code connection")?;
    db.create_api_key(
        user_id,
        "llm_provider",
        "claude_code",
        Some(&label),
        &key_hash,
        &encrypted,
    )
    .await
    .context("Failed to store Claude Code connection")?;
    Ok(())
}

fn build_authorize_url(pkce: &PkceCodes, state: &str) -> HeimdallResult<String> {
    let mut url = reqwest::Url::parse(CLAUDE_CODE_AUTHORIZE_URL)
        .context("Failed to build Claude Code authorize URL")?;
    url.query_pairs_mut()
        .append_pair("code", "true")
        .append_pair("client_id", CLAUDE_CODE_CLIENT_ID)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", CLAUDE_CODE_REDIRECT_URI)
        .append_pair("scope", CLAUDE_CODE_SCOPE)
        .append_pair("code_challenge", &pkce.code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state);
    Ok(url.to_string())
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

fn build_messages_body(request: &CompletionRequest) -> Value {
    let user_system = request
        .messages
        .iter()
        .filter(|message| message.role.eq_ignore_ascii_case("system"))
        .map(|message| message.content.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");

    let mut system = vec![
        json!({
            "type": "text",
            "text": CLAUDE_CODE_BILLING_HEADER,
        }),
        json!({
            "type": "text",
            "text": CLAUDE_CODE_SYSTEM_PREFIX,
            "cache_control": { "type": "ephemeral", "ttl": "1h" },
        }),
    ];
    if !user_system.is_empty() {
        system.push(json!({
            "type": "text",
            "text": user_system,
            "cache_control": { "type": "ephemeral", "ttl": "1h" },
        }));
    }

    let messages = request
        .messages
        .iter()
        .filter(|message| !message.role.eq_ignore_ascii_case("system"))
        .map(|message| {
            let role = if message.role.eq_ignore_ascii_case("assistant") {
                "assistant"
            } else {
                "user"
            };
            json!({
                "role": role,
                "content": [{
                    "type": "text",
                    "text": message.content.as_str(),
                }],
            })
        })
        .collect::<Vec<_>>();

    let mut body = json!({
        "model": request.model.as_str(),
        "max_tokens": request.max_tokens.unwrap_or(4096),
        "system": system,
        "messages": messages,
        "tools": [],
        "thinking": {
            "type": "adaptive",
            "display": "omitted",
        },
        "context_management": {
            "edits": [{
                "type": "clear_thinking_20251015",
                "keep": "all",
            }],
        },
        "output_config": { "effort": "high" },
        "stream": false,
    });

    if let Some(tools) = request.tools.as_ref() {
        let tool_payload = tools
            .iter()
            .map(|tool| {
                json!({
                    "name": tool.name.as_str(),
                    "description": tool.description.as_str(),
                    "input_schema": tool.parameters.clone(),
                })
            })
            .collect::<Vec<_>>();
        if !tool_payload.is_empty() {
            body["tools"] = json!(tool_payload);
        }
    }

    body
}

fn parse_messages_response(body: &str, model: String) -> HeimdallResult<CompletionResponse> {
    let response: Value = serde_json::from_str(body)
        .with_context(|| format!("Failed to parse Claude Code response: {body}"))?;

    let mut content = String::new();
    let mut tool_calls = Vec::new();

    if let Some(blocks) = response.get("content").and_then(Value::as_array) {
        for block in blocks {
            match block
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
            {
                "text" => {
                    if let Some(text) = block.get("text").and_then(Value::as_str) {
                        content.push_str(text);
                    }
                }
                "tool_use" => {
                    let id = block
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let name = block
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let arguments = block
                        .get("input")
                        .cloned()
                        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
                    if !id.is_empty() && !name.is_empty() {
                        tool_calls.push(ToolCall {
                            id,
                            name,
                            arguments,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    let stop_reason = match response
        .get("stop_reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "end_turn" => StopReason::EndTurn,
        "max_tokens" => StopReason::MaxTokens,
        "tool_use" => StopReason::ToolUse,
        "stop_sequence" => StopReason::StopSequence,
        _ => {
            if tool_calls.is_empty() {
                StopReason::EndTurn
            } else {
                StopReason::ToolUse
            }
        }
    };

    let usage = response.get("usage").cloned().unwrap_or(Value::Null);
    let prompt_tokens = usage
        .get("input_tokens")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let completion_tokens = usage
        .get("output_tokens")
        .and_then(Value::as_i64)
        .unwrap_or(0);

    Ok(CompletionResponse {
        content,
        tool_calls: if tool_calls.is_empty() {
            None
        } else {
            Some(tool_calls)
        },
        stop_reason,
        usage: TokenUsage {
            prompt_tokens: to_u32(prompt_tokens),
            completion_tokens: to_u32(completion_tokens),
            total_tokens: to_u32(prompt_tokens + completion_tokens),
        },
        provider: "claude_code".to_string(),
        model,
        fallback_attempts: Vec::new(),
    })
}

fn to_u32(value: i64) -> u32 {
    u32::try_from(value.max(0)).unwrap_or(u32::MAX)
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
                    "AES-256-GCM encryption failed for Claude Code tokens ({error:#}); falling back to hex encoding"
                );
                hex::encode(secret.as_bytes())
            }
        },
        None => {
            log::warn!("No ENCRYPTION_KEY configured; Claude Code tokens stored with hex encoding");
            hex::encode(secret.as_bytes())
        }
    }
}

/// Pasted authorization codes from the Anthropic console come back as
/// `code#state`. Some users may also paste a full URL or just the bare code.
/// This splits the pasted blob into `(code, optional state)`.
pub fn split_pasted_code(pasted: &str) -> (String, Option<String>) {
    let trimmed = pasted.trim();
    // Strip a leading URL prefix if the user pasted the whole address bar.
    let after_url = trimmed
        .rsplit("code=")
        .next()
        .map(|tail| {
            // tail may still contain &state=... or trailing junk
            tail.split('&').next().unwrap_or(tail)
        })
        .unwrap_or(trimmed);

    let mut parts = after_url.splitn(2, '#');
    let code = parts.next().unwrap_or("").trim().to_string();
    let state = parts
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    (code, state)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn login_success_html(tokens: &ClaudeCodeAuthTokens, return_url: &str) -> String {
    let account = tokens
        .email
        .as_deref()
        .or(tokens.account_uuid.as_deref())
        .unwrap_or("your Claude.ai account");
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Claude Code connected</title>\
         <meta http-equiv=\"refresh\" content=\"1.25;url={}\"></head>\
         <body style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:32px;color:#0f172a\">\
         <h1 style=\"font-size:20px;margin:0 0 8px\">Claude Code connected</h1>\
         <p style=\"margin:0 0 20px;color:#475569\">Heimdall can now bill Anthropic model requests to {} via your Claude.ai subscription.</p>\
         <a href=\"{}\" style=\"color:#2563eb;font-weight:600\">Return to Heimdall</a>\
         </body></html>",
        escape_html(return_url),
        escape_html(account),
        escape_html(return_url)
    )
}

pub fn login_error_html(message: &str, return_url: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Claude Code connection failed</title></head>\
         <body style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:32px;color:#0f172a\">\
         <h1 style=\"font-size:20px;margin:0 0 8px\">Claude Code connection failed</h1>\
         <p style=\"margin:0 0 20px;color:#475569\">{}</p>\
         <a href=\"{}\" style=\"color:#2563eb;font-weight:600\">Return to Heimdall</a>\
         </body></html>",
        escape_html(message),
        escape_html(return_url)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tokens(scopes: &[&str]) -> ClaudeCodeAuthTokens {
        ClaudeCodeAuthTokens {
            access_token: "access-token".to_string(),
            refresh_token: "refresh-token".to_string(),
            email: None,
            account_uuid: None,
            organization_uuid: None,
            scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
            access_token_expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            last_refresh: None,
        }
    }

    #[tokio::test]
    #[ignore = "requires HEIMDALL_CLAUDE_CODE_TEST_SECRET and live Anthropic access"]
    async fn live_completion_with_external_secret() {
        let secret = std::env::var("HEIMDALL_CLAUDE_CODE_TEST_SECRET")
            .expect("HEIMDALL_CLAUDE_CODE_TEST_SECRET must be set");
        let provider = ClaudeCodeProvider::from_secret(secret).unwrap();
        let response = provider
            .complete(CompletionRequest {
                model: "claude-sonnet-5".to_string(),
                messages: vec![crate::ai::types::Message {
                    role: "user".to_string(),
                    content: "Reply with exactly HEIMDALL_PROVIDER_OK and nothing else."
                        .to_string(),
                }],
                tools: None,
                max_tokens: Some(64),
                temperature: Some(0.0),
            })
            .await
            .unwrap();

        assert_eq!(response.content.trim(), "HEIMDALL_PROVIDER_OK");
        assert_eq!(response.provider, "claude_code");
        assert_eq!(response.model, "claude-sonnet-5");
    }

    #[test]
    fn authorization_uses_current_claude_code_oauth_contract() {
        let request = prepare_claude_code_authorization().unwrap();
        let url = reqwest::Url::parse(&request.authorize_url).unwrap();
        let query = url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(
            url.origin().ascii_serialization(),
            "https://platform.claude.com"
        );
        assert_eq!(url.path(), "/oauth/authorize");
        assert_eq!(
            query.get("redirect_uri").map(|value| value.as_ref()),
            Some(CLAUDE_CODE_REDIRECT_URI)
        );
        assert_eq!(
            query.get("scope").map(|value| value.as_ref()),
            Some(CLAUDE_CODE_SCOPE)
        );
        assert_eq!(
            CLAUDE_CODE_TOKEN_URL,
            "https://platform.claude.com/v1/oauth/token"
        );
    }

    #[test]
    fn legacy_oauth_credentials_are_refreshed_with_current_scopes() {
        let tokens = test_tokens(&["org:create_api_key", "user:profile", "user:inference"]);

        assert!(tokens.needs_refresh());
        assert_eq!(build_refresh_body(&tokens)["scope"], CLAUDE_CODE_SCOPE);
    }

    #[test]
    fn current_unexpired_oauth_credentials_do_not_refresh() {
        let tokens = test_tokens(&[
            "user:profile",
            "user:inference",
            CLAUDE_CODE_SESSION_SCOPE,
            "user:mcp_servers",
            "user:file_upload",
        ]);

        assert!(!tokens.needs_refresh());
    }

    #[test]
    fn retries_transient_claude_code_statuses_with_bounded_backoff() {
        assert!(is_transient_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_transient_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(is_transient_status(StatusCode::from_u16(529).unwrap()));
        assert!(!is_transient_status(StatusCode::BAD_REQUEST));

        assert_eq!(claude_code_retry_delay(1, None), Duration::from_millis(500));
        assert_eq!(claude_code_retry_delay(3, None), Duration::from_secs(2));
        assert_eq!(
            claude_code_retry_delay(1, Some(Duration::from_secs(60))),
            Duration::from_secs(15)
        );
    }

    #[test]
    fn attaches_claude_code_session_metadata() {
        let mut tokens = test_tokens(&[CLAUDE_CODE_SESSION_SCOPE]);
        tokens.account_uuid = Some("account-123".to_string());
        let session_id = Uuid::nil();
        let mut body = json!({});

        attach_claude_code_metadata(&mut body, &tokens, session_id);

        let user_id: Value = serde_json::from_str(body["metadata"]["user_id"].as_str().unwrap())
            .expect("metadata user_id should be encoded JSON");
        assert_eq!(user_id["account_uuid"], "account-123");
        assert_eq!(user_id["session_id"], session_id.to_string());
        assert_eq!(user_id["device_id"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn build_messages_body_injects_claude_code_identity() {
        assert!(CLAUDE_CODE_BETAS.contains("claude-code-20250219"));
        assert!(CLAUDE_CODE_BETAS.contains("oauth-2025-04-20"));
        assert_eq!(
            CLAUDE_CODE_SYSTEM_PREFIX,
            "You are a Claude agent, built on Anthropic's Claude Agent SDK."
        );

        let request = CompletionRequest {
            model: "claude-sonnet-4-6".to_string(),
            messages: vec![
                crate::ai::types::Message {
                    role: "system".to_string(),
                    content: "Be terse.".to_string(),
                },
                crate::ai::types::Message {
                    role: "user".to_string(),
                    content: "Hi.".to_string(),
                },
            ],
            tools: None,
            max_tokens: Some(64),
            temperature: Some(0.0),
        };

        let body = build_messages_body(&request);
        assert_eq!(body["system"][0]["text"], CLAUDE_CODE_BILLING_HEADER);
        assert_eq!(body["system"][1]["text"], CLAUDE_CODE_SYSTEM_PREFIX);
        assert_eq!(body["system"][2]["text"], "Be terse.");
        assert_eq!(body["system"][1]["cache_control"]["ttl"], "1h");
        let messages = body.get("messages").and_then(Value::as_array).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[0]["content"][0]["text"], "Hi.");
        assert_eq!(body["thinking"]["type"], "adaptive");
        assert_eq!(body["stream"], false);
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn build_messages_body_omits_temperature_for_claude_code() {
        let request = CompletionRequest {
            model: "claude-sonnet-5".to_string(),
            messages: vec![crate::ai::types::Message {
                role: "user".to_string(),
                content: "Hi.".to_string(),
            }],
            tools: None,
            max_tokens: None,
            temperature: Some(0.7),
        };
        let body = build_messages_body(&request);
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn split_pasted_code_handles_code_hash_state() {
        let (code, state) = split_pasted_code("abc123#xyz789");
        assert_eq!(code, "abc123");
        assert_eq!(state.as_deref(), Some("xyz789"));
    }

    #[test]
    fn split_pasted_code_handles_full_url() {
        let blob = "https://platform.claude.com/oauth/code/callback?code=abc123#xyz789";
        let (code, state) = split_pasted_code(blob);
        assert_eq!(code, "abc123");
        assert_eq!(state.as_deref(), Some("xyz789"));
    }

    #[test]
    fn split_pasted_code_handles_bare_code() {
        let (code, state) = split_pasted_code("just-the-code");
        assert_eq!(code, "just-the-code");
        assert!(state.is_none());
    }

    #[test]
    fn parse_messages_response_extracts_text_and_tool_calls() {
        let body = r#"{
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "hi "},
                {"type": "text", "text": "there"},
                {"type": "tool_use", "id": "tu_1", "name": "search", "input": {"q": "foo"}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 7, "output_tokens": 11}
        }"#;
        let response = parse_messages_response(body, "claude-sonnet-4-6".to_string()).unwrap();
        assert_eq!(response.content, "hi there");
        assert_eq!(response.stop_reason, StopReason::ToolUse);
        assert_eq!(response.usage.prompt_tokens, 7);
        assert_eq!(response.usage.completion_tokens, 11);
        assert_eq!(response.usage.total_tokens, 18);
        let calls = response.tool_calls.unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "search");
        assert_eq!(calls[0].arguments["q"], "foo");
    }
}
