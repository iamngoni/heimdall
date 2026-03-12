//
//  heimdall
//  src/routes/auth.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::cookie::time::Duration as CookieDuration;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpRequest, HttpResponse, web};
use chrono::{Duration, Utc};
use serde::Deserialize;
use validator::Validate;

use crate::auth;
use crate::crypto;
use crate::middleware::auth::SESSION_COOKIE_NAME;
use crate::models::ApiResponse;
use crate::state::AppState;

/// Session token lifetime: 7 days.
const SESSION_EXPIRY_DAYS: i64 = 7;

/// Cookie name for the OAuth state parameter (CSRF protection).
const OAUTH_STATE_COOKIE: &str = "_oauth_state";
/// Cookie name for the post-OAuth return target.
const OAUTH_NEXT_COOKIE: &str = "_oauth_next";

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/logout", web::post().to(logout))
            .route("/me", web::get().to(me))
            // GitHub OAuth
            .route("/github/authorize", web::get().to(github_authorize))
            .route("/github/callback", web::get().to(github_callback))
            // GitLab OAuth
            .route("/gitlab/authorize", web::get().to(gitlab_authorize))
            .route("/gitlab/callback", web::get().to(gitlab_callback)),
    );
}

/// Flat route registration (no nested `/auth` scope). Used when the parent
/// scope already provides the `/auth` prefix.
pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/register", web::post().to(register))
        .route("/login", web::post().to(login))
        .route("/logout", web::post().to(logout))
        .route("/me", web::get().to(me))
        .route("/github/authorize", web::get().to(github_authorize))
        .route("/github/callback", web::get().to(github_callback))
        .route("/gitlab/authorize", web::get().to(gitlab_authorize))
        .route("/gitlab/callback", web::get().to(gitlab_callback));
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the client IP address from the request.
fn client_ip(req: &HttpRequest) -> Option<String> {
    req.peer_addr().map(|addr| addr.ip().to_string())
}

/// Extract the User-Agent header from the request.
fn user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Build a session cookie with the given token.
fn session_cookie(token: &str, secure: bool) -> Cookie<'static> {
    Cookie::build(SESSION_COOKIE_NAME, token.to_string())
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::days(SESSION_EXPIRY_DAYS))
        .finish()
}

/// Create a new session for a user and return the raw token + session.
async fn create_user_session(
    state: &AppState,
    user_id: uuid::Uuid,
    req: &HttpRequest,
) -> Result<String, HttpResponse> {
    let token = auth::generate_session_token();
    let token_hash = auth::hash_token(&token);
    let expires_at = Utc::now() + Duration::days(SESSION_EXPIRY_DAYS);
    let ip = client_ip(req);
    let ua = user_agent(req);

    state
        .db
        .create_session(
            user_id,
            &token_hash,
            ip.as_deref(),
            ua.as_deref(),
            expires_at,
        )
        .await
        .map_err(|e| {
            log::error!("Failed to create session: {e:#}");
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Failed to create session"))
        })?;

    Ok(token)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /auth/register
///
/// Create a new user account and return a session token.
async fn register(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<RegisterRequest>,
) -> HttpResponse {
    // Validate input
    if let Err(errors) = body.validate() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            format!("Validation failed: {errors}"),
        ));
    }

    // Check if email is already taken
    match state.db.get_user_by_email(&body.email).await {
        Ok(Some(_)) => {
            return HttpResponse::Conflict().json(ApiResponse::<()>::error(
                409,
                "A user with this email already exists",
            ));
        }
        Err(e) => {
            log::error!("Database error checking email: {e:#}");
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Internal server error"));
        }
        Ok(None) => {} // Good — email is available
    }

    // Hash the password
    let password_hash = match auth::hash_password(&body.password) {
        Ok(hash) => hash,
        Err(e) => {
            log::error!("Failed to hash password: {e:#}");
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Internal server error"));
        }
    };

    // Create the user
    let user = match state
        .db
        .create_user(&body.email, &password_hash, body.display_name.as_deref())
        .await
    {
        Ok(user) => user,
        Err(e) => {
            log::error!("Failed to create user: {e:#}");
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Failed to create user"));
        }
    };

    // Create a session
    let token = match create_user_session(&state, user.id, &req).await {
        Ok(token) => token,
        Err(resp) => return resp,
    };

    let mut resp = HttpResponse::Created();
    resp.cookie(session_cookie(&token, state.config.app.tls_enabled));
    if req.headers().get("HX-Request").is_some() {
        resp.insert_header(("HX-Redirect", "/"));
    }
    resp.json(ApiResponse::ok(serde_json::json!({
        "token": token,
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "role": user.role,
            "created_at": user.created_at,
        }
    })))
}

/// POST /auth/login
///
/// Authenticate with email + password, create a session, return token.
async fn login(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<LoginRequest>,
) -> HttpResponse {
    // Validate input
    if let Err(errors) = body.validate() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            format!("Validation failed: {errors}"),
        ));
    }

    // Look up user by email
    let user = match state.db.get_user_by_email(&body.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error(401, "Invalid email or password"));
        }
        Err(e) => {
            log::error!("Database error during login: {e:#}");
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Internal server error"));
        }
    };

    // Verify password
    match auth::verify_password(&body.password, &user.password_hash) {
        Ok(true) => {} // Password matches
        Ok(false) => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error(401, "Invalid email or password"));
        }
        Err(e) => {
            log::error!("Password verification error: {e:#}");
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Internal server error"));
        }
    }

    // Create a session
    let token = match create_user_session(&state, user.id, &req).await {
        Ok(token) => token,
        Err(resp) => return resp,
    };

    let mut resp = HttpResponse::Ok();
    resp.cookie(session_cookie(&token, state.config.app.tls_enabled));
    if req.headers().get("HX-Request").is_some() {
        resp.insert_header(("HX-Redirect", "/"));
    }
    resp.json(ApiResponse::ok(serde_json::json!({
        "token": token,
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "role": user.role,
            "created_at": user.created_at,
        }
    })))
}

/// POST /auth/logout
///
/// Delete the current session. Requires a valid session token.
async fn logout(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    // Extract the token from the request
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .or_else(|| {
            req.cookie(SESSION_COOKIE_NAME)
                .map(|c| c.value().to_string())
        });

    let Some(token) = token else {
        return HttpResponse::Unauthorized()
            .json(ApiResponse::<()>::error(401, "No session token provided"));
    };

    let token_hash = auth::hash_token(&token);

    // Find the session
    let session = match state.db.get_session_by_token_hash(&token_hash).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            // Token is invalid/expired — treat logout as successful anyway
            return HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "message": "Logged out"
            })));
        }
        Err(e) => {
            log::error!("Failed to look up session for logout: {e:#}");
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Internal server error"));
        }
    };

    // Delete the session
    if let Err(e) = state.db.delete_session(session.id).await {
        log::error!("Failed to delete session: {e:#}");
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error(500, "Failed to delete session"));
    }

    // Clear the cookie
    let mut removal_cookie = Cookie::named(SESSION_COOKIE_NAME);
    removal_cookie.set_path("/");
    removal_cookie.make_removal();

    let mut response = HttpResponse::Ok();
    response.cookie(removal_cookie);
    if req.headers().contains_key("HX-Request") {
        response.insert_header(("HX-Redirect", "/login"));
    }
    response.json(ApiResponse::ok(serde_json::json!({
        "message": "Logged out"
    })))
}

/// GET /auth/me
///
/// Return the current authenticated user's info.
/// Requires a valid session (enforced here manually since auth middleware
/// is applied per-scope and /auth is public for login/register).
async fn me(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    // Extract token
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .or_else(|| {
            req.cookie(SESSION_COOKIE_NAME)
                .map(|c| c.value().to_string())
        });

    let Some(token) = token else {
        return HttpResponse::Unauthorized()
            .json(ApiResponse::<()>::error(401, "Authentication required"));
    };

    let token_hash = auth::hash_token(&token);

    let session = match state.db.get_session_by_token_hash(&token_hash).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error(401, "Invalid or expired session"));
        }
        Err(e) => {
            log::error!("Failed to look up session: {e:#}");
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Internal server error"));
        }
    };

    if session.expires_at < Utc::now() {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error(401, "Session expired"));
    }

    let user = match state.db.get_user_by_id(session.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error(401, "User not found"));
        }
        Err(e) => {
            log::error!("Failed to load user: {e:#}");
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Internal server error"));
        }
    };

    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
        "role": user.role,
        "created_at": user.created_at,
    })))
}

// ---------------------------------------------------------------------------
// OAuth helpers
// ---------------------------------------------------------------------------

/// Generate a random hex state string for CSRF protection.
fn generate_oauth_state() -> String {
    auth::generate_session_token()
}

/// Build a cookie to store the OAuth state parameter.
fn oauth_state_cookie(state: &str, secure: bool) -> Cookie<'static> {
    Cookie::build(OAUTH_STATE_COOKIE, state.to_string())
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(300))
        .finish()
}

fn oauth_next_cookie(next: &str, secure: bool) -> Cookie<'static> {
    Cookie::build(OAUTH_NEXT_COOKIE, next.to_string())
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(300))
        .finish()
}

fn clear_cookie(name: &str) -> Cookie<'static> {
    let mut cookie = Cookie::build(name.to_string(), "").path("/").finish();
    cookie.set_path("/");
    cookie.make_removal();
    cookie
}

fn sanitize_oauth_next(next: Option<&str>) -> Option<String> {
    next.filter(|value| value.starts_with('/') && !value.starts_with("//"))
        .map(str::to_string)
}

fn oauth_redirect_target(req: &HttpRequest, fallback: &str) -> String {
    sanitize_oauth_next(
        req.cookie(OAUTH_NEXT_COOKIE)
            .map(|cookie| cookie.value().to_string())
            .as_deref(),
    )
    .unwrap_or_else(|| fallback.to_string())
}

fn with_query_param(url: &str, key: &str, value: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}{key}={}", urlencoding(value))
}

async fn current_session_user(
    state: &AppState,
    req: &HttpRequest,
) -> Option<crate::models::db_models::User> {
    let token = req.cookie(SESSION_COOKIE_NAME)?.value().to_string();
    let token_hash = auth::hash_token(&token);
    let session = state
        .db
        .get_session_by_token_hash(&token_hash)
        .await
        .ok()??;
    if session.expires_at < Utc::now() {
        return None;
    }
    state.db.get_user_by_id(session.user_id).await.ok()?
}

fn encrypt_oauth_secret(secret: &str, key: Option<&[u8; 32]>) -> String {
    if let Some(key) = key {
        crypto::encrypt(secret.as_bytes(), key).unwrap_or_else(|_| hex::encode(secret.as_bytes()))
    } else {
        hex::encode(secret.as_bytes())
    }
}

async fn upsert_oauth_connection_for_user(
    state: &AppState,
    user_id: uuid::Uuid,
    provider: &str,
    provider_user_id: &str,
    access_token: &str,
    refresh_token: Option<&str>,
    scopes: Option<&str>,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> Result<(), HttpResponse> {
    let token_enc = encrypt_oauth_secret(access_token, state.encryption_key.as_ref());
    let refresh_enc =
        refresh_token.map(|token| encrypt_oauth_secret(token, state.encryption_key.as_ref()));

    state
        .db
        .upsert_oauth_connection(
            user_id,
            provider,
            provider_user_id,
            Some(&token_enc),
            refresh_enc.as_deref(),
            scopes,
            expires_at,
        )
        .await
        .map_err(|e| {
            log::error!("Failed to upsert OAuth connection: {e:#}");
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to save OAuth connection",
            ))
        })?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct OAuthAuthorizeParams {
    next: Option<String>,
}

/// Query params returned by OAuth providers on the callback URL.
#[derive(Debug, Deserialize)]
pub struct OAuthCallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// GitHub user info from the /user endpoint.
#[derive(Debug, Deserialize)]
struct GithubUser {
    id: i64,
    login: String,
    email: Option<String>,
    name: Option<String>,
    avatar_url: Option<String>,
}

/// GitHub email entry from the /user/emails endpoint.
#[derive(Debug, Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

/// GitLab user info from the /api/v4/user endpoint.
#[derive(Debug, Deserialize)]
struct GitlabUser {
    id: i64,
    username: String,
    email: Option<String>,
    name: Option<String>,
    avatar_url: Option<String>,
}

/// GitHub token exchange response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GithubTokenResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// GitLab token exchange response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GitlabTokenResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    scope: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Find or create the Heimdall user that should own this OAuth account.
async fn find_or_create_oauth_user(
    state: &AppState,
    provider: &str,
    provider_user_id: &str,
    email: &str,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
    access_token: &str,
    refresh_token: Option<&str>,
    scopes: Option<&str>,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> Result<crate::models::db_models::User, HttpResponse> {
    // 1) Check if we already have a user linked to this OAuth provider
    let existing = state
        .db
        .get_user_by_oauth_provider(provider, provider_user_id)
        .await
        .map_err(|e| {
            log::error!("DB error looking up OAuth user: {e:#}");
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Internal server error"))
        })?;

    let user = if let Some(user) = existing {
        // Update avatar if changed
        if let Some(url) = avatar_url {
            let _ = state.db.update_user_avatar(user.id, url).await;
        }
        user
    } else {
        // 2) Check if a user with this email already exists (password-registered)
        let by_email = state.db.get_user_by_email(email).await.map_err(|e| {
            log::error!("DB error looking up user by email: {e:#}");
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Internal server error"))
        })?;

        match by_email {
            Some(user) => {
                // Link OAuth to existing user
                if let Some(url) = avatar_url {
                    let _ = state.db.update_user_avatar(user.id, url).await;
                }
                user
            }
            None => {
                // 3) Create a new user with a random password hash (they won't use password login)
                let random_pw = auth::generate_session_token();
                let pw_hash = auth::hash_password(&random_pw).map_err(|e| {
                    log::error!("Failed to hash random password: {e:#}");
                    HttpResponse::InternalServerError()
                        .json(ApiResponse::<()>::error(500, "Internal server error"))
                })?;

                state
                    .db
                    .create_user_with_avatar(email, &pw_hash, display_name, avatar_url)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to create OAuth user: {e:#}");
                        HttpResponse::InternalServerError()
                            .json(ApiResponse::<()>::error(500, "Failed to create user"))
                    })?
            }
        }
    };

    // 4) Persist the OAuth connection for the resolved user.
    upsert_oauth_connection_for_user(
        state,
        user.id,
        provider,
        provider_user_id,
        access_token,
        refresh_token,
        scopes,
        expires_at,
    )
    .await?;

    Ok(user)
}

// ---------------------------------------------------------------------------
// GitHub OAuth
// ---------------------------------------------------------------------------

/// GET /auth/github/authorize
///
/// Redirect the user to GitHub's authorization page.
async fn github_authorize(
    state: web::Data<AppState>,
    query: web::Query<OAuthAuthorizeParams>,
) -> HttpResponse {
    let config = &state.config.github_oauth;

    let Some(client_id) = &config.client_id else {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "GitHub OAuth is not configured (GITHUB_CLIENT_ID missing)",
        ));
    };

    let oauth_state = generate_oauth_state();
    let redirect_uri = &config.redirect_uri;

    let auth_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope={}&state={}",
        urlencoding(client_id),
        urlencoding(redirect_uri),
        urlencoding("read:user user:email repo"),
        urlencoding(&oauth_state),
    );

    let mut response = HttpResponse::Found();
    response.cookie(oauth_state_cookie(
        &oauth_state,
        state.config.app.tls_enabled,
    ));
    if let Some(next) = sanitize_oauth_next(query.next.as_deref()) {
        response.cookie(oauth_next_cookie(&next, state.config.app.tls_enabled));
    }
    response.insert_header(("Location", auth_url)).finish()
}

/// GET /auth/github/callback?code=...&state=...
///
/// Exchange the authorization code for an access token, fetch user info,
/// find or create the user, create a session, and redirect to /.
async fn github_callback(
    state: web::Data<AppState>,
    req: HttpRequest,
    params: web::Query<OAuthCallbackParams>,
) -> HttpResponse {
    // Check for error from provider
    if let Some(err) = &params.error {
        let desc = params
            .error_description
            .as_deref()
            .unwrap_or("Unknown error");
        log::warn!("GitHub OAuth error: {err}: {desc}");
        return HttpResponse::Found()
            .insert_header(("Location", "/login"))
            .finish();
    }

    let Some(code) = &params.code else {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(400, "Missing authorization code"));
    };

    // Verify state parameter (CSRF protection)
    let stored_state = req
        .cookie(OAUTH_STATE_COOKIE)
        .map(|c| c.value().to_string());
    if stored_state.as_deref() != params.state.as_deref() || stored_state.is_none() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Invalid OAuth state parameter",
        ));
    }

    let config = &state.config.github_oauth;
    let Some(client_id) = &config.client_id else {
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error(500, "GitHub OAuth not configured"));
    };
    let Some(client_secret) = &config.client_secret else {
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error(500, "GitHub OAuth not configured"));
    };

    let http = reqwest::Client::new();

    // Exchange code for access token
    let token_resp = match http
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", config.redirect_uri.as_str()),
        ])
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            log::error!("GitHub token exchange failed: {e:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to exchange GitHub authorization code",
            ));
        }
    };

    let token_data: GithubTokenResponse = match token_resp.json().await {
        Ok(data) => data,
        Err(e) => {
            log::error!("Failed to parse GitHub token response: {e:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to parse GitHub token response",
            ));
        }
    };

    if let Some(err) = &token_data.error {
        let desc = token_data.error_description.as_deref().unwrap_or("Unknown");
        log::error!("GitHub token error: {err}: {desc}");
        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("GitHub token error: {desc}"),
        ));
    }

    let Some(access_token) = &token_data.access_token else {
        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            "No access token in GitHub response",
        ));
    };

    // Fetch user info
    let user_resp = match http
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "Heimdall")
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            log::error!("GitHub user info request failed: {e:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to fetch GitHub user info",
            ));
        }
    };

    let gh_user: GithubUser = match user_resp.json().await {
        Ok(u) => u,
        Err(e) => {
            log::error!("Failed to parse GitHub user info: {e:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to parse GitHub user info",
            ));
        }
    };

    // If the user profile doesn't have an email, try the /user/emails endpoint
    let email = if let Some(email) = &gh_user.email {
        email.clone()
    } else {
        let emails_resp = http
            .get("https://api.github.com/user/emails")
            .header("Authorization", format!("Bearer {access_token}"))
            .header("User-Agent", "Heimdall")
            .header("Accept", "application/json")
            .send()
            .await;

        match emails_resp {
            Ok(resp) => {
                let emails: Vec<GithubEmail> = resp.json().await.unwrap_or_default();
                emails
                    .iter()
                    .find(|e| e.primary && e.verified)
                    .or_else(|| emails.iter().find(|e| e.verified))
                    .map(|e| e.email.clone())
                    .unwrap_or_else(|| format!("{}@users.noreply.github.com", gh_user.login))
            }
            Err(_) => format!("{}@users.noreply.github.com", gh_user.login),
        }
    };

    let provider_user_id = gh_user.id.to_string();
    let display_name = gh_user.name.as_deref().or(Some(&gh_user.login));

    let session_user = current_session_user(&state, &req).await;
    let user = if let Some(current_user) = session_user.clone() {
        match state
            .db
            .get_user_by_oauth_provider("github", &provider_user_id)
            .await
        {
            Ok(Some(owner)) if owner.id != current_user.id => {
                let redirect_target =
                    with_query_param("/settings", "integration_error", "github-account-in-use");
                return HttpResponse::Found()
                    .cookie(clear_cookie(OAUTH_STATE_COOKIE))
                    .cookie(clear_cookie(OAUTH_NEXT_COOKIE))
                    .insert_header(("Location", redirect_target))
                    .finish();
            }
            Ok(_) => {}
            Err(e) => {
                log::error!("Failed to check GitHub OAuth ownership: {e:#}");
                return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                    500,
                    "Failed to verify GitHub connection",
                ));
            }
        }

        if let Some(url) = gh_user.avatar_url.as_deref() {
            let _ = state.db.update_user_avatar(current_user.id, url).await;
        }

        if let Err(resp) = upsert_oauth_connection_for_user(
            &state,
            current_user.id,
            "github",
            &provider_user_id,
            access_token,
            None,
            token_data.scope.as_deref(),
            None,
        )
        .await
        {
            return resp;
        }

        current_user
    } else {
        match find_or_create_oauth_user(
            &state,
            "github",
            &provider_user_id,
            &email,
            display_name,
            gh_user.avatar_url.as_deref(),
            access_token,
            None, // GitHub doesn't use refresh tokens in basic OAuth
            token_data.scope.as_deref(),
            None,
        )
        .await
        {
            Ok(user) => user,
            Err(resp) => return resp,
        }
    };

    let redirect_target = oauth_redirect_target(&req, "/repos/new");

    let mut response = HttpResponse::Found();
    if session_user.is_none() {
        let token = match create_user_session(&state, user.id, &req).await {
            Ok(token) => token,
            Err(resp) => return resp,
        };
        response.cookie(session_cookie(&token, state.config.app.tls_enabled));
    }

    response
        .cookie(clear_cookie(OAUTH_STATE_COOKIE))
        .cookie(clear_cookie(OAUTH_NEXT_COOKIE))
        .insert_header(("Location", redirect_target))
        .finish()
}

// ---------------------------------------------------------------------------
// GitLab OAuth
// ---------------------------------------------------------------------------

/// GET /auth/gitlab/authorize
///
/// Redirect the user to GitLab's authorization page.
async fn gitlab_authorize(
    state: web::Data<AppState>,
    query: web::Query<OAuthAuthorizeParams>,
) -> HttpResponse {
    let config = &state.config.gitlab_oauth;

    let Some(client_id) = &config.client_id else {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "GitLab OAuth is not configured (GITLAB_CLIENT_ID missing)",
        ));
    };

    let oauth_state = generate_oauth_state();
    let redirect_uri = &config.redirect_uri;
    let base_url = &config.base_url;

    let auth_url = format!(
        "{base_url}/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
        urlencoding(client_id),
        urlencoding(redirect_uri),
        urlencoding("read_user read_repository"),
        urlencoding(&oauth_state),
    );

    let mut response = HttpResponse::Found();
    response.cookie(oauth_state_cookie(
        &oauth_state,
        state.config.app.tls_enabled,
    ));
    if let Some(next) = sanitize_oauth_next(query.next.as_deref()) {
        response.cookie(oauth_next_cookie(&next, state.config.app.tls_enabled));
    }
    response.insert_header(("Location", auth_url)).finish()
}

/// GET /auth/gitlab/callback?code=...&state=...
///
/// Exchange the authorization code for an access token, fetch user info,
/// find or create the user, create a session, and redirect to /.
async fn gitlab_callback(
    state: web::Data<AppState>,
    req: HttpRequest,
    params: web::Query<OAuthCallbackParams>,
) -> HttpResponse {
    // Check for error from provider
    if let Some(err) = &params.error {
        let desc = params
            .error_description
            .as_deref()
            .unwrap_or("Unknown error");
        log::warn!("GitLab OAuth error: {err}: {desc}");
        return HttpResponse::Found()
            .insert_header(("Location", "/login"))
            .finish();
    }

    let Some(code) = &params.code else {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(400, "Missing authorization code"));
    };

    // Verify state parameter (CSRF protection)
    let stored_state = req
        .cookie(OAUTH_STATE_COOKIE)
        .map(|c| c.value().to_string());
    if stored_state.as_deref() != params.state.as_deref() || stored_state.is_none() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Invalid OAuth state parameter",
        ));
    }

    let config = &state.config.gitlab_oauth;
    let Some(client_id) = &config.client_id else {
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error(500, "GitLab OAuth not configured"));
    };
    let Some(client_secret) = &config.client_secret else {
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error(500, "GitLab OAuth not configured"));
    };
    let base_url = &config.base_url;

    let http = reqwest::Client::new();

    // Exchange code for access token
    let token_resp = match http
        .post(format!("{base_url}/oauth/token"))
        .header("Accept", "application/json")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", config.redirect_uri.as_str()),
        ])
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            log::error!("GitLab token exchange failed: {e:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to exchange GitLab authorization code",
            ));
        }
    };

    let token_data: GitlabTokenResponse = match token_resp.json().await {
        Ok(data) => data,
        Err(e) => {
            log::error!("Failed to parse GitLab token response: {e:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to parse GitLab token response",
            ));
        }
    };

    if let Some(err) = &token_data.error {
        let desc = token_data.error_description.as_deref().unwrap_or("Unknown");
        log::error!("GitLab token error: {err}: {desc}");
        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("GitLab token error: {desc}"),
        ));
    }

    let Some(access_token) = &token_data.access_token else {
        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            "No access token in GitLab response",
        ));
    };

    // Compute token expiry
    let expires_at = token_data
        .expires_in
        .map(|secs| Utc::now() + Duration::seconds(secs));

    // Fetch user info
    let user_resp = match http
        .get(format!("{base_url}/api/v4/user"))
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "Heimdall")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            log::error!("GitLab user info request failed: {e:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to fetch GitLab user info",
            ));
        }
    };

    let gl_user: GitlabUser = match user_resp.json().await {
        Ok(u) => u,
        Err(e) => {
            log::error!("Failed to parse GitLab user info: {e:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to parse GitLab user info",
            ));
        }
    };

    let email = gl_user
        .email
        .unwrap_or_else(|| format!("{}@users.noreply.gitlab.com", gl_user.username));
    let provider_user_id = gl_user.id.to_string();
    let display_name = gl_user.name.as_deref().or(Some(&gl_user.username));

    let session_user = current_session_user(&state, &req).await;
    let user = if let Some(current_user) = session_user.clone() {
        match state
            .db
            .get_user_by_oauth_provider("gitlab", &provider_user_id)
            .await
        {
            Ok(Some(owner)) if owner.id != current_user.id => {
                let redirect_target =
                    with_query_param("/settings", "integration_error", "gitlab-account-in-use");
                return HttpResponse::Found()
                    .cookie(clear_cookie(OAUTH_STATE_COOKIE))
                    .cookie(clear_cookie(OAUTH_NEXT_COOKIE))
                    .insert_header(("Location", redirect_target))
                    .finish();
            }
            Ok(_) => {}
            Err(e) => {
                log::error!("Failed to check GitLab OAuth ownership: {e:#}");
                return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                    500,
                    "Failed to verify GitLab connection",
                ));
            }
        }

        if let Some(url) = gl_user.avatar_url.as_deref() {
            let _ = state.db.update_user_avatar(current_user.id, url).await;
        }

        if let Err(resp) = upsert_oauth_connection_for_user(
            &state,
            current_user.id,
            "gitlab",
            &provider_user_id,
            access_token,
            token_data.refresh_token.as_deref(),
            token_data.scope.as_deref(),
            expires_at,
        )
        .await
        {
            return resp;
        }

        current_user
    } else {
        match find_or_create_oauth_user(
            &state,
            "gitlab",
            &provider_user_id,
            &email,
            display_name,
            gl_user.avatar_url.as_deref(),
            access_token,
            token_data.refresh_token.as_deref(),
            token_data.scope.as_deref(),
            expires_at,
        )
        .await
        {
            Ok(user) => user,
            Err(resp) => return resp,
        }
    };

    let redirect_target = oauth_redirect_target(&req, "/repos/new");

    let mut response = HttpResponse::Found();
    if session_user.is_none() {
        let token = match create_user_session(&state, user.id, &req).await {
            Ok(token) => token,
            Err(resp) => return resp,
        };
        response.cookie(session_cookie(&token, state.config.app.tls_enabled));
    }

    response
        .cookie(clear_cookie(OAUTH_STATE_COOKIE))
        .cookie(clear_cookie(OAUTH_NEXT_COOKIE))
        .insert_header(("Location", redirect_target))
        .finish()
}

// ---------------------------------------------------------------------------
// URL encoding helper
// ---------------------------------------------------------------------------

/// Percent-encode a string for use in URL query parameters.
fn urlencoding(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}
