//
//  heimdall
//  src/ai/xai_oauth.rs
//
//  Created by Ngonidzashe Mangudya on 2026/06/30.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

//! Grok subscription provider backed by xAI OAuth tokens.
//!
//! This is separate from the xAI API-key provider. It follows the public
//! Grok/SuperGrok PKCE flow used by Grok CLI-compatible clients and stores
//! refreshable OAuth tokens against the Heimdall user.

use std::sync::Arc;

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use rand::Rng;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, CompletionResponse};
use crate::crypto;
use crate::db::DatabaseOperations;
use crate::models::HeimdallResult;

const XAI_OAUTH_DISCOVERY_URL: &str = "https://auth.x.ai/.well-known/openid-configuration";
const XAI_OAUTH_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
const XAI_OAUTH_SCOPE: &str = "openid profile email offline_access grok-cli:access api:access";
const XAI_OAUTH_BASE_URL: &str = "https://api.x.ai/v1";
/// xAI's Grok OAuth client is registered for this exact loopback callback.
pub const XAI_OAUTH_CALLBACK_PORT: u16 = 56121;
pub const XAI_OAUTH_CALLBACK_PATH: &str = "/callback";
/// Grok OAuth access tokens are short lived. Refresh up to one hour early so
/// long-running scan workers do not hit token expiry mid-run.
const TOKEN_REFRESH_WINDOW_MINUTES: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XaiOAuthTokens {
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default = "default_token_type")]
    token_type: String,
    token_endpoint: String,
    redirect_uri: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    last_refresh: Option<DateTime<Utc>>,
}

impl XaiOAuthTokens {
    fn from_exchange(
        response: XaiOAuthTokenResponse,
        token_endpoint: String,
        redirect_uri: String,
    ) -> HeimdallResult<Self> {
        let mut tokens = Self {
            access_token: response.access_token,
            refresh_token: response.refresh_token,
            id_token: response.id_token,
            token_type: response.token_type.unwrap_or_else(default_token_type),
            token_endpoint,
            redirect_uri,
            email: None,
            access_token_expires_at: None,
            last_refresh: Some(Utc::now()),
        };
        tokens.refresh_metadata_from_tokens();
        Ok(tokens)
    }

    pub fn from_secret(secret: &str) -> HeimdallResult<Self> {
        let mut tokens: Self = serde_json::from_str(secret)
            .context("Stored Grok Subscription credential is not valid JSON")?;
        tokens.refresh_metadata_from_tokens();
        Ok(tokens)
    }

    fn to_secret(&self) -> HeimdallResult<String> {
        serde_json::to_string(self).context("Failed to serialize Grok Subscription credential")
    }

    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    fn access_token(&self) -> &str {
        &self.access_token
    }

    fn needs_refresh(&self) -> bool {
        let Some(expires_at) = self.access_token_expires_at else {
            return false;
        };
        expires_at <= Utc::now() + chrono::Duration::minutes(TOKEN_REFRESH_WINDOW_MINUTES)
    }

    fn apply_refresh(&mut self, response: XaiOAuthRefreshResponse) {
        if let Some(access_token) = response.access_token {
            self.access_token = access_token;
        }
        if let Some(refresh_token) = response.refresh_token {
            self.refresh_token = refresh_token;
        }
        if let Some(id_token) = response.id_token {
            self.id_token = Some(id_token);
        }
        if let Some(token_type) = response.token_type {
            self.token_type = token_type;
        }
        self.last_refresh = Some(Utc::now());
        self.refresh_metadata_from_tokens();
    }

    fn refresh_metadata_from_tokens(&mut self) {
        self.access_token_expires_at = jwt_expiration(&self.access_token).ok().flatten();

        if let Some(id_token) = self.id_token.as_deref()
            && let Ok(payload) = jwt_payload(id_token)
        {
            self.email = payload
                .get("email")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| self.email.clone());
        }
    }
}

#[derive(Clone)]
pub struct XaiOAuthTokenPersistence {
    pub db: Arc<DatabaseOperations>,
    pub api_key_id: Uuid,
    pub encryption_key: Option<[u8; 32]>,
}

pub struct XaiOAuthProvider {
    base_url: String,
    client: reqwest::Client,
    tokens: Mutex<XaiOAuthTokens>,
    persistence: Option<XaiOAuthTokenPersistence>,
}

impl XaiOAuthProvider {
    pub fn from_secret(secret: String) -> HeimdallResult<Self> {
        let tokens = XaiOAuthTokens::from_secret(&secret)?;
        Ok(Self::new_with_tokens(tokens, None))
    }

    pub fn with_persistence(
        secret: String,
        persistence: XaiOAuthTokenPersistence,
    ) -> HeimdallResult<Self> {
        let tokens = XaiOAuthTokens::from_secret(&secret)?;
        Ok(Self::new_with_tokens(tokens, Some(persistence)))
    }

    fn new_with_tokens(
        tokens: XaiOAuthTokens,
        persistence: Option<XaiOAuthTokenPersistence>,
    ) -> Self {
        Self {
            base_url: XAI_OAUTH_BASE_URL.to_string(),
            client: reqwest::Client::new(),
            tokens: Mutex::new(tokens),
            persistence,
        }
    }

    async fn current_tokens(&self, force_refresh: bool) -> HeimdallResult<XaiOAuthTokens> {
        let mut guard = self.tokens.lock().await;
        if force_refresh || guard.needs_refresh() {
            self.refresh_tokens(&mut guard).await?;
        }
        Ok(guard.clone())
    }

    async fn refresh_tokens(&self, tokens: &mut XaiOAuthTokens) -> HeimdallResult<()> {
        let token_endpoint = if tokens.token_endpoint.trim().is_empty() {
            discover_oauth()
                .await
                .context("Failed to discover xAI OAuth token endpoint")?
                .token_endpoint
        } else {
            tokens.token_endpoint.clone()
        };
        validate_xai_endpoint(&token_endpoint, "token_endpoint")?;

        let response = self
            .client
            .post(token_endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", XAI_OAUTH_CLIENT_ID),
                ("refresh_token", tokens.refresh_token.as_str()),
            ])
            .send()
            .await
            .context("Grok Subscription token refresh request failed")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            if status == StatusCode::FORBIDDEN {
                anyhow::bail!(
                    "Grok Subscription token refresh failed ({status}): {body}. \
                     xAI may restrict OAuth API access to specific SuperGrok or X Premium+ tiers; \
                     use XAI_API_KEY if this account is not entitled."
                );
            }
            anyhow::bail!("Grok Subscription token refresh failed ({status}): {body}");
        }

        let refresh_response: XaiOAuthRefreshResponse = response
            .json()
            .await
            .context("Grok Subscription token refresh returned invalid JSON")?;
        tokens.apply_refresh(refresh_response);
        self.persist_tokens(tokens).await
    }

    async fn persist_tokens(&self, tokens: &XaiOAuthTokens) -> HeimdallResult<()> {
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
            .context("Failed to persist refreshed Grok Subscription tokens")?;
        if !updated {
            anyhow::bail!("Stored Grok Subscription connection no longer exists");
        }
        Ok(())
    }

    async fn send_completion(
        &self,
        request: CompletionRequest,
        tokens: &XaiOAuthTokens,
    ) -> Result<CompletionResponse, XaiOAuthRequestError> {
        let body = crate::ai::codex::build_responses_body(&request);
        let response = self
            .client
            .post(format!("{}/responses", self.base_url.trim_end_matches('/')))
            .header("Authorization", format!("Bearer {}", tokens.access_token()))
            .header("Content-Type", "application/json")
            .header("Accept", "text/event-stream")
            .header("User-Agent", "heimdall")
            .json(&body)
            .send()
            .await
            .map_err(XaiOAuthRequestError::from)?;

        let status = response.status();
        let response_text = response.text().await.map_err(XaiOAuthRequestError::from)?;

        if !status.is_success() {
            if status == StatusCode::UNAUTHORIZED {
                return Err(XaiOAuthRequestError::Unauthorized(response_text));
            }
            if status == StatusCode::FORBIDDEN {
                return Err(XaiOAuthRequestError::Other(anyhow::anyhow!(
                    "Grok Subscription API error ({status}): {response_text}. \
                     xAI may restrict OAuth API access to specific SuperGrok or X Premium+ tiers; \
                     use XAI_API_KEY if this account is not entitled."
                )));
            }
            return Err(XaiOAuthRequestError::Other(anyhow::anyhow!(
                "Grok Subscription API error ({status}): {response_text}"
            )));
        }

        crate::ai::codex::parse_responses_sse(&response_text, request.model, "xai_oauth")
            .map_err(XaiOAuthRequestError::Other)
    }
}

#[async_trait::async_trait]
impl ModelProvider for XaiOAuthProvider {
    async fn complete(&self, request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
        let tokens = self.current_tokens(false).await?;
        match self.send_completion(request.clone(), &tokens).await {
            Ok(response) => Ok(response),
            Err(XaiOAuthRequestError::Unauthorized(body)) => {
                log::warn!(
                    "Grok Subscription access token rejected; refreshing and retrying once: {body}"
                );
                let tokens = self.current_tokens(true).await?;
                self.send_completion(request, &tokens)
                    .await
                    .map_err(|error| match error {
                        XaiOAuthRequestError::Unauthorized(body) => anyhow::anyhow!(
                            "Grok Subscription API rejected refreshed credentials: {body}"
                        ),
                        XaiOAuthRequestError::Other(error) => error,
                    })
            }
            Err(XaiOAuthRequestError::Other(error)) => Err(error),
        }
    }

    fn provider_name(&self) -> &str {
        "xai_oauth"
    }
}

#[derive(Debug)]
enum XaiOAuthRequestError {
    Unauthorized(String),
    Other(anyhow::Error),
}

impl From<reqwest::Error> for XaiOAuthRequestError {
    fn from(error: reqwest::Error) -> Self {
        Self::Other(error.into())
    }
}

#[derive(Deserialize)]
struct XaiOAuthDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct XaiOAuthTokenResponse {
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
}

#[derive(Deserialize)]
struct XaiOAuthRefreshResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
}

#[derive(Debug, Clone)]
struct PkceCodes {
    code_verifier: String,
    code_challenge: String,
}

pub struct XaiOAuthAuthorizationRequest {
    pub authorize_url: String,
    pub state: String,
    pub code_verifier: String,
    pub code_challenge: String,
    pub token_endpoint: String,
}

pub async fn prepare_xai_oauth_authorization() -> HeimdallResult<XaiOAuthAuthorizationRequest> {
    let discovery = discover_oauth().await?;
    let pkce = generate_pkce();
    let state = generate_login_state();
    let nonce = generate_login_state();
    let redirect_uri = callback_redirect_uri();
    let authorize_url = build_authorize_url(
        &discovery.authorization_endpoint,
        &redirect_uri,
        &pkce,
        &state,
        &nonce,
    )?;

    Ok(XaiOAuthAuthorizationRequest {
        authorize_url,
        state,
        code_verifier: pkce.code_verifier,
        code_challenge: pkce.code_challenge,
        token_endpoint: discovery.token_endpoint,
    })
}

pub async fn complete_xai_oauth_login(
    db: Arc<DatabaseOperations>,
    encryption_key: Option<[u8; 32]>,
    user_id: Uuid,
    code_verifier: &str,
    code_challenge: &str,
    token_endpoint: &str,
    code: &str,
) -> HeimdallResult<XaiOAuthTokens> {
    let redirect_uri = callback_redirect_uri();
    let tokens = exchange_code_for_tokens(
        token_endpoint,
        &redirect_uri,
        code_verifier,
        code_challenge,
        code,
    )
    .await?;
    store_xai_oauth_tokens(db, user_id, encryption_key, tokens.clone()).await?;
    Ok(tokens)
}

async fn discover_oauth() -> HeimdallResult<XaiOAuthDiscovery> {
    let response = reqwest::Client::new()
        .get(XAI_OAUTH_DISCOVERY_URL)
        .header("Accept", "application/json")
        .send()
        .await
        .context("xAI OAuth discovery request failed")?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("xAI OAuth discovery failed ({status}): {body}");
    }

    let discovery: XaiOAuthDiscovery = response
        .json()
        .await
        .context("xAI OAuth discovery returned invalid JSON")?;
    validate_xai_endpoint(&discovery.authorization_endpoint, "authorization_endpoint")?;
    validate_xai_endpoint(&discovery.token_endpoint, "token_endpoint")?;
    Ok(discovery)
}

fn validate_xai_endpoint(value: &str, field: &str) -> HeimdallResult<()> {
    let url = reqwest::Url::parse(value)
        .with_context(|| format!("xAI OAuth {field} is not a valid URL"))?;
    if url.scheme() != "https" {
        anyhow::bail!("xAI OAuth {field} must use HTTPS");
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if host != "x.ai" && !host.ends_with(".x.ai") {
        anyhow::bail!("xAI OAuth {field} must be hosted on x.ai");
    }
    Ok(())
}

fn build_authorize_url(
    authorization_endpoint: &str,
    redirect_uri: &str,
    pkce: &PkceCodes,
    state: &str,
    nonce: &str,
) -> HeimdallResult<String> {
    let mut url = reqwest::Url::parse(authorization_endpoint)
        .context("Failed to build Grok Subscription authorize URL")?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", XAI_OAUTH_CLIENT_ID)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", XAI_OAUTH_SCOPE)
        .append_pair("code_challenge", &pkce.code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("plan", "generic")
        .append_pair("referrer", "heimdall");
    Ok(url.to_string())
}

async fn exchange_code_for_tokens(
    token_endpoint: &str,
    redirect_uri: &str,
    code_verifier: &str,
    code_challenge: &str,
    code: &str,
) -> HeimdallResult<XaiOAuthTokens> {
    validate_xai_endpoint(token_endpoint, "token_endpoint")?;
    let response = reqwest::Client::new()
        .post(token_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", XAI_OAUTH_CLIENT_ID),
            ("code_verifier", code_verifier),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .context("Grok Subscription token exchange request failed")?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        if status == StatusCode::FORBIDDEN {
            anyhow::bail!(
                "Grok Subscription token exchange failed ({status}): {body}. \
                 xAI may restrict OAuth API access to specific SuperGrok or X Premium+ tiers; \
                 use XAI_API_KEY if this account is not entitled."
            );
        }
        anyhow::bail!("Grok Subscription token exchange failed ({status}): {body}");
    }

    let token_response: XaiOAuthTokenResponse = response
        .json()
        .await
        .context("Grok Subscription token exchange returned invalid JSON")?;
    XaiOAuthTokens::from_exchange(
        token_response,
        token_endpoint.to_string(),
        redirect_uri.to_string(),
    )
}

async fn store_xai_oauth_tokens(
    db: Arc<DatabaseOperations>,
    user_id: Uuid,
    encryption_key: Option<[u8; 32]>,
    tokens: XaiOAuthTokens,
) -> HeimdallResult<()> {
    let secret = tokens.to_secret()?;
    let key_hash = hash_secret(&secret);
    let encrypted = encrypt_secret(&secret, encryption_key.as_ref());
    let label = tokens
        .email
        .as_deref()
        .map(|email| format!("Grok subscription ({email})"))
        .unwrap_or_else(|| "Grok subscription".to_string());

    db.delete_api_keys_by_provider(user_id, "xai_oauth")
        .await
        .context("Failed to replace existing Grok Subscription connection")?;
    db.create_api_key(
        user_id,
        "llm_provider",
        "xai_oauth",
        Some(&label),
        &key_hash,
        &encrypted,
    )
    .await
    .context("Failed to store Grok Subscription connection")?;
    Ok(())
}

fn callback_redirect_uri() -> String {
    format!("http://127.0.0.1:{XAI_OAUTH_CALLBACK_PORT}{XAI_OAUTH_CALLBACK_PATH}")
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
                    "AES-256-GCM encryption failed for Grok Subscription tokens ({error:#}); falling back to hex encoding"
                );
                hex::encode(secret.as_bytes())
            }
        },
        None => {
            log::warn!(
                "No ENCRYPTION_KEY configured; Grok Subscription tokens stored with hex encoding"
            );
            hex::encode(secret.as_bytes())
        }
    }
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn login_success_html(tokens: &XaiOAuthTokens, return_url: &str) -> String {
    let account = tokens.email().unwrap_or("your xAI account");
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Grok connected</title>\
         <meta http-equiv=\"refresh\" content=\"1.25;url={}\"></head>\
         <body style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:32px;color:#0f172a\">\
         <h1 style=\"font-size:20px;margin:0 0 8px\">Grok connected</h1>\
         <p style=\"margin:0 0 20px;color:#475569\">Heimdall can now use your SuperGrok or X Premium+ subscription for Grok model requests as {}.</p>\
         <a href=\"{}\" style=\"color:#2563eb;font-weight:600\">Return to Heimdall</a>\
         </body></html>",
        escape_html(return_url),
        escape_html(account),
        escape_html(return_url)
    )
}

pub fn login_error_html(message: &str, return_url: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Grok connection failed</title></head>\
         <body style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:32px;color:#0f172a\">\
         <h1 style=\"font-size:20px;margin:0 0 8px\">Grok connection failed</h1>\
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

    #[test]
    fn authorize_url_contains_xai_oauth_parameters() {
        let pkce = PkceCodes {
            code_verifier: "verifier".to_string(),
            code_challenge: "challenge".to_string(),
        };
        let url = build_authorize_url(
            "https://auth.x.ai/oauth2/authorize",
            "http://127.0.0.1:56121/callback",
            &pkce,
            "state",
            "nonce",
        )
        .unwrap();

        assert!(url.contains("client_id=b1a00492-073a-47ea-816f-4c329264a828"));
        assert!(url.contains("code_challenge=challenge"));
        assert!(url.contains("plan=generic"));
        assert!(url.contains("referrer=heimdall"));
    }

    #[test]
    fn validates_xai_endpoint_hosts() {
        assert!(validate_xai_endpoint("https://auth.x.ai/oauth2/token", "token_endpoint").is_ok());
        assert!(validate_xai_endpoint("https://evil.example/token", "token_endpoint").is_err());
        assert!(validate_xai_endpoint("http://auth.x.ai/token", "token_endpoint").is_err());
    }
}
