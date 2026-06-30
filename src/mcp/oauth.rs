//
//  heimdall
//  src/mcp/oauth.rs
//
//  Created by Ngonidzashe Mangudya on 2026/06/30.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use axum::extract::{Form, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth;
use crate::middleware::auth::SESSION_COOKIE_NAME;
use crate::models::db_models::{McpOAuthClient, User};
use crate::state::AppState;

const MCP_SCOPE: &str = "mcp";
const AUTHORIZATION_CODE_TTL_MINUTES: i64 = 10;
const ACCESS_TOKEN_TTL_HOURS: i64 = 12;

#[derive(Debug, Clone)]
pub struct AuthenticatedMcpUser {
    pub user_id: Uuid,
    pub client_id: String,
    pub scope: String,
}

#[derive(Clone)]
pub struct OAuthServerState {
    pub app_state: Arc<AppState>,
    pub public_base_url: String,
    pub web_app_base_url: String,
}

#[derive(Debug, Deserialize)]
struct ClientRegistrationRequest {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    scope: Option<String>,
    token_endpoint_auth_method: Option<String>,
}

#[derive(Debug, Serialize)]
struct ClientRegistrationResponse {
    client_id: String,
    client_id_issued_at: i64,
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    scope: String,
    token_endpoint_auth_method: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    code_verifier: String,
    resource: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    scope: String,
}

pub fn router(state: OAuthServerState) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/mcp",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-configuration",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-configuration/mcp",
            get(authorization_server_metadata),
        )
        .route("/oauth/register", post(register_client))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/token", post(exchange_token))
        .with_state(state)
}

pub async fn require_oauth(
    State(state): State<OAuthServerState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(token) = bearer_token(request.headers()) else {
        return oauth_error_response(
            &state,
            StatusCode::UNAUTHORIZED,
            Some("invalid_token"),
            Some("Missing OAuth bearer token"),
        );
    };

    let token_hash = auth::hash_token(&token);
    let access_token = match state
        .app_state
        .db
        .get_mcp_oauth_access_token_by_hash(&token_hash)
        .await
    {
        Ok(Some(access_token)) => access_token,
        Ok(None) => {
            return oauth_error_response(
                &state,
                StatusCode::UNAUTHORIZED,
                Some("invalid_token"),
                Some("Invalid or expired OAuth bearer token"),
            );
        }
        Err(error) => {
            log::warn!("Failed to validate MCP OAuth access token: {error:#}");
            return oauth_error_response(
                &state,
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
                Some("MCP OAuth validation failed"),
            );
        }
    };

    if let Err(error) = state
        .app_state
        .db
        .touch_mcp_oauth_access_token(access_token.id)
        .await
    {
        log::warn!("Failed to update MCP OAuth token last_used_at: {error:#}");
    }

    request.extensions_mut().insert(AuthenticatedMcpUser {
        user_id: access_token.user_id,
        client_id: access_token.client_id,
        scope: access_token.scope,
    });

    next.run(request).await
}

async fn protected_resource_metadata(
    State(state): State<OAuthServerState>,
) -> Json<serde_json::Value> {
    Json(json!({
        "resource": format!("{}/mcp", state.public_base_url),
        "resource_name": "Heimdall MCP",
        "authorization_servers": [state.public_base_url],
        "scopes_supported": [MCP_SCOPE],
        "bearer_methods_supported": ["header"],
    }))
}

async fn authorization_server_metadata(
    State(state): State<OAuthServerState>,
) -> Json<serde_json::Value> {
    Json(json!({
        "issuer": state.public_base_url,
        "authorization_endpoint": format!("{}/oauth/authorize", state.public_base_url),
        "token_endpoint": format!("{}/oauth/token", state.public_base_url),
        "registration_endpoint": format!("{}/oauth/register", state.public_base_url),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [MCP_SCOPE],
    }))
}

async fn register_client(
    State(state): State<OAuthServerState>,
    Json(req): Json<ClientRegistrationRequest>,
) -> Response {
    if req.redirect_uris.is_empty() {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "redirect_uris must contain at least one URI",
        );
    }

    let redirect_uris = match validate_redirect_uris(&req.redirect_uris) {
        Ok(uris) => uris,
        Err(message) => {
            return oauth_json_error(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                message.as_str(),
            );
        }
    };

    let grant_types = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);
    if grant_types
        .iter()
        .any(|value| value != "authorization_code")
    {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "Only authorization_code grant is supported",
        );
    }

    let response_types = req
        .response_types
        .unwrap_or_else(|| vec!["code".to_string()]);
    if response_types.iter().any(|value| value != "code") {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "Only code response type is supported",
        );
    }

    let token_endpoint_auth_method = req
        .token_endpoint_auth_method
        .unwrap_or_else(|| "none".to_string());
    if token_endpoint_auth_method != "none" {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "Only public clients with token_endpoint_auth_method=none are supported",
        );
    }

    let scope = normalize_scope(req.scope.as_deref());
    let client_id = format!("mcp_{}", auth::generate_session_token());
    let redirect_uris_json = json!(redirect_uris);
    let grant_types_csv = grant_types.join(" ");
    let response_types_csv = response_types.join(" ");

    let client = match state
        .app_state
        .db
        .create_mcp_oauth_client(
            &client_id,
            req.client_name.as_deref(),
            &redirect_uris_json,
            &grant_types_csv,
            &response_types_csv,
            &scope,
            &token_endpoint_auth_method,
        )
        .await
    {
        Ok(client) => client,
        Err(error) => {
            log::error!("Failed to register MCP OAuth client: {error:#}");
            return oauth_json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to register OAuth client",
            );
        }
    };

    (
        StatusCode::CREATED,
        Json(ClientRegistrationResponse {
            client_id: client.client_id,
            client_id_issued_at: client.created_at.timestamp(),
            client_name: client.client_name,
            redirect_uris,
            grant_types,
            response_types,
            scope,
            token_endpoint_auth_method,
        }),
    )
        .into_response()
}

async fn authorize(
    State(state): State<OAuthServerState>,
    headers: HeaderMap,
    Query(req): Query<AuthorizeQuery>,
) -> Response {
    if req.response_type != "code" {
        return redirect_oauth_error(
            &req.redirect_uri,
            req.state.as_deref(),
            "unsupported_response_type",
            "Only response_type=code is supported",
        );
    }

    let client = match state
        .app_state
        .db
        .get_mcp_oauth_client(&req.client_id)
        .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return Html("Unknown MCP OAuth client. Reconnect the MCP client and try again.")
                .into_response();
        }
        Err(error) => {
            log::error!("Failed to load MCP OAuth client: {error:#}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if !client_allows_redirect_uri(&client, &req.redirect_uri) {
        return Html("The MCP OAuth redirect URI is not registered for this client.")
            .into_response();
    }

    if req.code_challenge.trim().is_empty()
        || req.code_challenge_method.as_deref().unwrap_or("plain") != "S256"
    {
        return redirect_oauth_error(
            &req.redirect_uri,
            req.state.as_deref(),
            "invalid_request",
            "PKCE S256 code_challenge is required",
        );
    }

    let scope = normalize_scope(req.scope.as_deref());
    let Some(user) = session_user(&state.app_state, &headers).await else {
        let login_url = format!(
            "{}/login?next={}",
            state.web_app_base_url,
            urlencoding(&format!(
                "{}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256{}{}",
                state.public_base_url,
                urlencoding(&req.client_id),
                urlencoding(&req.redirect_uri),
                urlencoding(&req.code_challenge),
                req.state
                    .as_deref()
                    .map(|value| format!("&state={}", urlencoding(value)))
                    .unwrap_or_default(),
                req.resource
                    .as_deref()
                    .map(|value| format!("&resource={}", urlencoding(value)))
                    .unwrap_or_default(),
            )),
        );
        return Redirect::temporary(&login_url).into_response();
    };

    let code = auth::generate_session_token();
    let code_hash = auth::hash_token(&code);
    let expires_at = Utc::now() + Duration::minutes(AUTHORIZATION_CODE_TTL_MINUTES);

    if let Err(error) = state
        .app_state
        .db
        .create_mcp_oauth_authorization_code(
            &code_hash,
            &req.client_id,
            user.id,
            &req.redirect_uri,
            &scope,
            &req.code_challenge,
            "S256",
            req.resource.as_deref(),
            expires_at,
        )
        .await
    {
        log::error!("Failed to create MCP OAuth authorization code: {error:#}");
        return redirect_oauth_error(
            &req.redirect_uri,
            req.state.as_deref(),
            "server_error",
            "Failed to create authorization code",
        );
    }

    redirect_with_code(&req.redirect_uri, &code, req.state.as_deref())
}

async fn exchange_token(
    State(state): State<OAuthServerState>,
    Form(req): Form<TokenRequest>,
) -> Response {
    if req.grant_type != "authorization_code" {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Only authorization_code grant is supported",
        );
    }

    let client = match state
        .app_state
        .db
        .get_mcp_oauth_client(&req.client_id)
        .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return oauth_json_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "Unknown OAuth client",
            );
        }
        Err(error) => {
            log::error!("Failed to fetch MCP OAuth client: {error:#}");
            return oauth_json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to fetch OAuth client",
            );
        }
    };

    if !client_allows_redirect_uri(&client, &req.redirect_uri) {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri is not registered for this client",
        );
    }

    let code_hash = auth::hash_token(&req.code);
    let code = match state
        .app_state
        .db
        .consume_mcp_oauth_authorization_code(&code_hash)
        .await
    {
        Ok(Some(code)) => code,
        Ok(None) => {
            return oauth_json_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Authorization code is invalid, expired, or already used",
            );
        }
        Err(error) => {
            log::error!("Failed to consume MCP OAuth authorization code: {error:#}");
            return oauth_json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to exchange authorization code",
            );
        }
    };

    if code.client_id != req.client_id || code.redirect_uri != req.redirect_uri {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code does not match this client",
        );
    }

    if code.code_challenge_method != "S256"
        || pkce_s256_challenge(&req.code_verifier) != code.code_challenge
    {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verifier did not match authorization code",
        );
    }

    if let Some(resource) = req.resource.as_deref()
        && let Some(code_resource) = code.resource.as_deref()
        && resource != code_resource
    {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "Requested resource does not match authorization code",
        );
    }

    let access_token = format!("hmcp_{}", auth::generate_session_token());
    let token_hash = auth::hash_token(&access_token);
    let expires_at = Utc::now() + Duration::hours(ACCESS_TOKEN_TTL_HOURS);

    if let Err(error) = state
        .app_state
        .db
        .create_mcp_oauth_access_token(
            &token_hash,
            &req.client_id,
            code.user_id,
            &code.scope,
            code.resource.as_deref(),
            expires_at,
        )
        .await
    {
        log::error!("Failed to create MCP OAuth access token: {error:#}");
        return oauth_json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Failed to create access token",
        );
    }

    Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_TTL_HOURS * 60 * 60,
        scope: code.scope,
    })
    .into_response()
}

fn oauth_json_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

fn oauth_error_response(
    state: &OAuthServerState,
    status: StatusCode,
    error: Option<&str>,
    description: Option<&str>,
) -> Response {
    let mut challenge = format!(
        "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\", scope=\"{}\"",
        state.public_base_url, MCP_SCOPE
    );
    if let Some(error) = error {
        challenge.push_str(&format!(", error=\"{error}\""));
    }
    if let Some(description) = description {
        challenge.push_str(&format!(
            ", error_description=\"{}\"",
            description.replace('"', "'")
        ));
    }

    (
        status,
        [(header::WWW_AUTHENTICATE, challenge)],
        description
            .unwrap_or("OAuth authorization required")
            .to_string(),
    )
        .into_response()
}

fn redirect_with_code(redirect_uri: &str, code: &str, state: Option<&str>) -> Response {
    match Url::parse(redirect_uri) {
        Ok(mut url) => {
            {
                let mut pairs = url.query_pairs_mut();
                pairs.append_pair("code", code);
                if let Some(state) = state {
                    pairs.append_pair("state", state);
                }
            }
            Redirect::temporary(url.as_str()).into_response()
        }
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

fn redirect_oauth_error(
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    description: &str,
) -> Response {
    match Url::parse(redirect_uri) {
        Ok(mut url) => {
            {
                let mut pairs = url.query_pairs_mut();
                pairs.append_pair("error", error);
                pairs.append_pair("error_description", description);
                if let Some(state) = state {
                    pairs.append_pair("state", state);
                }
            }
            Redirect::temporary(url.as_str()).into_response()
        }
        Err(_) => oauth_json_error(StatusCode::BAD_REQUEST, error, description),
    }
}

async fn session_user(app_state: &AppState, headers: &HeaderMap) -> Option<User> {
    let session_token = cookie_value(headers, SESSION_COOKIE_NAME)?;
    let token_hash = auth::hash_token(&session_token);
    let session = app_state
        .db
        .get_session_by_token_hash(&token_hash)
        .await
        .ok()??;
    if session.expires_at < Utc::now() {
        return None;
    }
    app_state.db.get_user_by_id(session.user_id).await.ok()?
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie_header
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(cookie_name, value)| {
            if cookie_name == name && !value.trim().is_empty() {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
}

fn normalize_scope(scope: Option<&str>) -> String {
    let requested = scope.unwrap_or(MCP_SCOPE);
    let scopes = requested
        .split_whitespace()
        .filter(|scope| *scope == MCP_SCOPE)
        .collect::<Vec<_>>();
    if scopes.is_empty() {
        MCP_SCOPE.to_string()
    } else {
        scopes.join(" ")
    }
}

fn validate_redirect_uris(values: &[String]) -> Result<Vec<String>, String> {
    let mut redirect_uris = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if !is_allowed_redirect_uri(value) {
            return Err(format!(
                "redirect_uri must be https or loopback http: {value}"
            ));
        }
        if !redirect_uris.iter().any(|existing| existing == value) {
            redirect_uris.push(value.to_string());
        }
    }
    if redirect_uris.is_empty() {
        return Err("redirect_uris did not contain a usable URI".to_string());
    }
    Ok(redirect_uris)
}

fn is_allowed_redirect_uri(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => url
            .host_str()
            .map(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"))
            .unwrap_or(false),
        _ => false,
    }
}

fn client_allows_redirect_uri(client: &McpOAuthClient, redirect_uri: &str) -> bool {
    client
        .redirect_uris_json
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .any(|value| value == redirect_uri)
        })
        .unwrap_or(false)
}

fn pkce_s256_challenge(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn urlencoding(value: &str) -> String {
    use std::fmt::Write;

    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                let _ = write!(&mut encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_challenge_matches_rfc_example() {
        assert_eq!(
            pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn redirect_uri_policy_allows_https_and_loopback_http() {
        assert!(is_allowed_redirect_uri("https://client.example/callback"));
        assert!(is_allowed_redirect_uri("http://127.0.0.1:49152/callback"));
        assert!(is_allowed_redirect_uri("http://localhost:49152/callback"));
        assert!(!is_allowed_redirect_uri("http://example.com/callback"));
        assert!(!is_allowed_redirect_uri("javascript:alert(1)"));
    }

    #[test]
    fn cookie_value_extracts_named_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "theme=sentinel; heimdall_session=abc123; other=value"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            cookie_value(&headers, SESSION_COOKIE_NAME),
            Some("abc123".to_string())
        );
    }
}
