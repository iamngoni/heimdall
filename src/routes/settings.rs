//
//  heimdall
//  src/routes/settings.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::collections::BTreeMap;

use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ai;
use crate::ai::ProviderKind;
use crate::ai::types::{CompletionRequest, Message};
use crate::middleware::auth::AuthenticatedUser;
use crate::models::{ApiKey, ApiResponse, User};
use crate::state::{AppState, ClaudeCodePendingLogin, CodexPendingLogin, XaiOAuthPendingLogin};

/// Pending Codex logins are dropped after this many minutes regardless of
/// whether the user completed the OAuth flow.
const CODEX_LOGIN_TTL_MINUTES: i64 = 5;
/// Pending Claude Code logins follow the same TTL as Codex — the user has to
/// approve the OAuth grant on claude.ai and paste the code back within this
/// window.
const CLAUDE_CODE_LOGIN_TTL_MINUTES: i64 = 10;
/// Pending Grok Subscription logins should be completed promptly after the
/// browser approval, whether local loopback or hosted callback mode is used.
const XAI_OAUTH_LOGIN_TTL_MINUTES: i64 = 10;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/settings")
            .route("", web::get().to(get_settings))
            .route("/profile", web::patch().to(update_profile))
            .route("/change-password", web::post().to(change_password))
            .route(
                "/integrations/{provider}",
                web::delete().to(disconnect_integration),
            )
            .route("/integrations/{provider}/pat", web::post().to(save_pat))
            .route("/api-keys", web::post().to(create_api_key))
            .route("/api-keys/{id}", web::delete().to(delete_api_key))
            .route(
                "/ai-providers/{provider}",
                web::delete().to(disconnect_ai_provider),
            )
            .route("/codex/authorize", web::get().to(codex_authorize))
            .route("/xai-oauth/authorize", web::get().to(xai_oauth_authorize))
            .route(
                "/claude-code/authorize",
                web::get().to(claude_code_authorize),
            )
            .route(
                "/claude-code/exchange",
                web::post().to(claude_code_exchange),
            )
            .route("/ai-routing", web::patch().to(update_ai_routing))
            .route("/theme", web::patch().to(update_theme))
            .route("/test-connection", web::post().to(test_connection))
            .route("/ai-status", web::get().to(ai_status)),
    );
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateApiKeyRequest {
    provider: String,
    key: Option<String>,
    base_url: Option<String>,
    model: Option<String>,
    label: Option<String>,
}

#[derive(Deserialize)]
struct SavePatRequest {
    token: String,
    username: Option<String>,
}

#[derive(Deserialize)]
struct TestConnectionRequest {
    provider: String,
    key: Option<String>,
    base_url: Option<String>,
    model: Option<String>,
}

#[derive(Deserialize)]
struct UpdateProfileRequest {
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct UpdateThemeRequest {
    theme: String,
}

#[derive(Deserialize)]
struct UpdateAiRoutingForm {
    preferred_provider: String,
    fallbacks_enabled: Option<String>,
    /// CSV of provider ids in priority order, e.g. "codex,xai_oauth,xai,openai,anthropic,ollama".
    fallback_order: Option<String>,
    model_anthropic: Option<String>,
    model_claude_code: Option<String>,
    model_codex: Option<String>,
    model_xai_oauth: Option<String>,
    model_xai: Option<String>,
    model_openai: Option<String>,
    model_openai_compatible: Option<String>,
    model_ollama: Option<String>,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Serialize)]
struct SettingsResponse {
    has_anthropic: bool,
    has_claude_code: bool,
    has_codex: bool,
    has_xai_oauth: bool,
    has_xai: bool,
    has_openai: bool,
    has_openai_compatible: bool,
    has_ollama: bool,
    stored_anthropic: bool,
    stored_claude_code: bool,
    stored_codex: bool,
    stored_xai_oauth: bool,
    stored_xai: bool,
    stored_openai: bool,
    stored_openai_compatible: bool,
    stored_ollama: bool,
    default_model: String,
    preferred_provider: Option<String>,
    fallbacks_enabled: bool,
    fallback_order: Vec<String>,
    provider_models: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize)]
struct ApiKeyResponse {
    id: Uuid,
    provider: Option<String>,
    label: Option<String>,
    key_preview: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
struct TestConnectionResponse {
    success: bool,
    provider: String,
    message: String,
}

#[derive(Serialize)]
struct AiStatusResponse {
    env_anthropic: bool,
    env_openai: bool,
    env_openai_compatible: bool,
    env_xai: bool,
    env_ollama: bool,
    stored_anthropic: bool,
    stored_claude_code: bool,
    stored_codex: bool,
    stored_xai_oauth: bool,
    stored_xai: bool,
    stored_openai: bool,
    stored_openai_compatible: bool,
    stored_ollama: bool,
    default_model: String,
    preferred_provider: Option<String>,
    fallbacks_enabled: bool,
    fallback_order: Vec<String>,
    provider_models: serde_json::Map<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Mask an API key for display: show first 7 and last 3 chars.
/// For keys shorter than 12 chars, show first 3 and last 2.
fn mask_key(key: &str) -> String {
    let len = key.len();
    if len <= 6 {
        return "***".to_string();
    }
    if len < 12 {
        format!("{}***{}", &key[..3], &key[len - 2..])
    } else {
        format!("{}***{}", &key[..7], &key[len - 3..])
    }
}

/// SHA-256 hash of a key, returned as hex string.
fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn provider_display_label(provider: &str) -> String {
    ai::provider_kind_from_name(provider)
        .map(|provider| provider.label().to_string())
        .unwrap_or_else(|| provider.to_string())
}

/// Encrypt an API key using AES-256-GCM if an encryption key is available,
/// otherwise fall back to hex encoding with a warning.
fn encrypt_key(key: &str, encryption_key: Option<&[u8; 32]>) -> String {
    match encryption_key {
        Some(enc_key) => match crate::crypto::encrypt(key.as_bytes(), enc_key) {
            Ok(encrypted) => encrypted,
            Err(e) => {
                log::error!("AES-256-GCM encryption failed ({e:#}); falling back to hex encoding");
                hex::encode(key.as_bytes())
            }
        },
        None => {
            log::warn!(
                "No ENCRYPTION_KEY configured; API key stored with hex encoding (NOT secure)"
            );
            hex::encode(key.as_bytes())
        }
    }
}

fn is_hx_request(req: &HttpRequest) -> bool {
    req.headers().contains_key("HX-Request")
}

fn render_api_key_row(
    state: &AppState,
    theme: &str,
    id: Uuid,
    provider: &str,
    label: Option<&str>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> HttpResponse {
    let ctx = minijinja::context! {
        key => minijinja::Value::from_serialize(serde_json::json!({
            "id": id,
            "provider": provider,
            "provider_label": provider_display_label(provider),
            "label": label,
            "created_at": created_at.format("%Y-%m-%d %H:%M").to_string(),
        })),
    };

    match state
        .themes
        .get(theme)
        .render("partials/api_key_row.html", ctx)
    {
        Ok(html) => HttpResponse::Created()
            .content_type("text/html; charset=utf-8")
            .body(html),
        Err(e) => {
            log::error!("Failed to render API key row: {e:#}");
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to render API key row.",
            ))
        }
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn test_connection_html(success: bool, message: &str) -> HttpResponse {
    let (classes, border_classes) = if success {
        ("text-emerald-700", "border-emerald-200 bg-emerald-50")
    } else {
        ("text-rose-700", "border-rose-200 bg-rose-50")
    };

    let body = format!(
        "<div class=\"rounded-xl border {border_classes} px-4 py-3 text-sm font-medium {classes}\">{}</div>",
        escape_html(message)
    );

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body)
}

fn inline_feedback_html(success: bool, message: &str) -> HttpResponse {
    let (classes, border_classes) = if success {
        ("text-emerald-700", "border-emerald-200 bg-emerald-50")
    } else {
        ("text-rose-700", "border-rose-200 bg-rose-50")
    };

    let body = format!(
        "<div class=\"rounded-xl border {border_classes} px-4 py-3 text-sm font-medium {classes}\">{}</div>",
        escape_html(message)
    );

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body)
}

fn settings_return_url(req: &HttpRequest) -> String {
    let connection_info = req.connection_info();
    format!(
        "{}://{}/settings#settings-providers",
        connection_info.scheme(),
        connection_info.host()
    )
}

fn stored_provider_configured(api_keys: &[ApiKey], provider: ProviderKind) -> bool {
    api_keys
        .iter()
        .any(|key| key.provider.as_deref() == Some(provider.as_str()))
}

fn provider_configured(
    ai_cfg: &crate::config::AiConfig,
    api_keys: &[ApiKey],
    provider: ProviderKind,
) -> bool {
    if stored_provider_configured(api_keys, provider) {
        return true;
    }

    match provider {
        ProviderKind::Anthropic => ai_cfg.anthropic_api_key.is_some(),
        ProviderKind::ClaudeCode | ProviderKind::Codex | ProviderKind::XaiOAuth => false,
        ProviderKind::Xai => ai_cfg.xai_api_key.is_some(),
        ProviderKind::OpenAi => ai_cfg.openai_api_key.is_some(),
        ProviderKind::OpenAiCompatible => {
            ai_cfg.openai_compatible_base_url.is_some() && ai_cfg.openai_compatible_model.is_some()
        }
        ProviderKind::Ollama => ai_cfg.ollama_url.is_some(),
    }
}

fn configured_ai_providers(
    ai_cfg: &crate::config::AiConfig,
    api_keys: &[ApiKey],
) -> Vec<ProviderKind> {
    ai::default_provider_order()
        .into_iter()
        .filter(|provider| provider_configured(ai_cfg, api_keys, *provider))
        .collect()
}

fn effective_preferred_ai_provider(
    user: Option<&User>,
    ai_cfg: &crate::config::AiConfig,
    api_keys: &[ApiKey],
) -> Option<ProviderKind> {
    if let Some(provider) = user
        .and_then(|user| user.preferred_ai_provider.as_deref())
        .and_then(ai::provider_kind_from_name)
        && provider_configured(ai_cfg, api_keys, provider)
    {
        return Some(provider);
    }

    if let Some(provider) = ai::provider_kind_from_model(&ai_cfg.default_model)
        && provider_configured(ai_cfg, api_keys, provider)
    {
        return Some(provider);
    }

    configured_ai_providers(ai_cfg, api_keys).into_iter().next()
}

fn effective_fallback_order(
    user: Option<&User>,
    ai_cfg: &crate::config::AiConfig,
    api_keys: &[ApiKey],
    preferred_provider: Option<ProviderKind>,
) -> Vec<ProviderKind> {
    let configured = configured_ai_providers(ai_cfg, api_keys);
    let mut order = Vec::new();

    if let Some(provider) = preferred_provider
        && configured.contains(&provider)
    {
        ai::push_provider_once(&mut order, provider);
    }

    let saved_order = user
        .map(|user| ai::normalize_provider_order(&user.ai_fallback_order))
        .unwrap_or_else(ai::default_provider_order);

    for provider in saved_order {
        if configured.contains(&provider) {
            ai::push_provider_once(&mut order, provider);
        }
    }

    for provider in ai::default_provider_order() {
        if configured.contains(&provider) {
            ai::push_provider_once(&mut order, provider);
        }
    }

    order
}

fn provider_order_strings(order: &[ProviderKind]) -> Vec<String> {
    order
        .iter()
        .map(|provider| provider.as_str().to_string())
        .collect()
}

fn provider_models_to_json_map(
    models: &BTreeMap<ProviderKind, String>,
) -> serde_json::Map<String, serde_json::Value> {
    models
        .iter()
        .map(|(provider, model)| {
            (
                provider.as_str().to_string(),
                serde_json::Value::String(model.clone()),
            )
        })
        .collect()
}

/// Merge per-provider model fields into the saved override map. Submitted
/// blank values clear an override; omitted fields preserve the existing value.
fn merge_provider_models_from_form(
    models: &mut BTreeMap<ProviderKind, String>,
    body: &UpdateAiRoutingForm,
) {
    let pairs = [
        (ProviderKind::Anthropic, body.model_anthropic.as_deref()),
        (ProviderKind::ClaudeCode, body.model_claude_code.as_deref()),
        (ProviderKind::Codex, body.model_codex.as_deref()),
        (ProviderKind::XaiOAuth, body.model_xai_oauth.as_deref()),
        (ProviderKind::Xai, body.model_xai.as_deref()),
        (ProviderKind::OpenAi, body.model_openai.as_deref()),
        (
            ProviderKind::OpenAiCompatible,
            body.model_openai_compatible.as_deref(),
        ),
        (ProviderKind::Ollama, body.model_ollama.as_deref()),
    ];
    for (provider, value) in pairs {
        if let Some(raw) = value {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                models.insert(provider, trimmed.to_string());
            } else {
                models.remove(&provider);
            }
        }
    }
}

fn routing_preferences_without_provider(
    user: &User,
    provider: ProviderKind,
) -> (Option<String>, String, String) {
    let preferred_provider = user
        .preferred_ai_provider
        .as_deref()
        .and_then(ai::provider_kind_from_name)
        .filter(|saved| *saved != provider)
        .map(|saved| saved.as_str().to_string());

    let mut fallback_order = Vec::new();
    for raw in user.ai_fallback_order.split(',') {
        if let Some(saved) = ai::provider_kind_from_name(raw)
            && saved != provider
        {
            ai::push_provider_once(&mut fallback_order, saved);
        }
    }
    let fallback_order_csv = ai::provider_order_csv(&fallback_order);

    let mut provider_models = ai::parse_provider_models(&user.ai_provider_models);
    provider_models.remove(&provider);
    let provider_models_json = ai::serialize_provider_models(&provider_models);

    (preferred_provider, fallback_order_csv, provider_models_json)
}

async fn clear_disconnected_provider_preferences(
    state: &AppState,
    user_id: Uuid,
    provider: ProviderKind,
) -> Result<(), anyhow::Error> {
    if let Some(user) = state.db.get_user_by_id(user_id).await? {
        let (preferred_provider, fallback_order_csv, provider_models_json) =
            routing_preferences_without_provider(&user, provider);
        state
            .db
            .update_user_ai_routing_preferences(
                user_id,
                preferred_provider.as_deref(),
                user.ai_fallbacks_enabled,
                &fallback_order_csv,
                &provider_models_json,
            )
            .await?;
    }
    Ok(())
}

fn required_openai_compatible_model(model: Option<&str>) -> Result<String, HttpResponse> {
    let Some(model) = model.map(str::trim).filter(|model| !model.is_empty()) else {
        return Err(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Model is required for OpenAI-compatible providers. Use the id from /v1/models.",
        )));
    };
    Ok(model.to_string())
}

async fn save_openai_compatible_model(
    state: &AppState,
    user_id: Uuid,
    model: &str,
) -> Result<(), HttpResponse> {
    let db_user = match state.db.get_user_by_id(user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err(
                HttpResponse::NotFound().json(ApiResponse::<()>::error(404, "User not found."))
            );
        }
        Err(error) => {
            log::error!("Failed to load user before saving OpenAI-compatible model: {error:#}");
            return Err(
                HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                    500,
                    "Failed to load provider settings.",
                )),
            );
        }
    };

    let mut provider_models = ai::parse_provider_models(&db_user.ai_provider_models);
    provider_models.insert(ProviderKind::OpenAiCompatible, model.to_string());
    let provider_models_json = ai::serialize_provider_models(&provider_models);

    match state
        .db
        .update_user_ai_provider_models(user_id, &provider_models_json)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => {
            Err(HttpResponse::NotFound().json(ApiResponse::<()>::error(404, "User not found.")))
        }
        Err(error) => {
            log::error!("Failed to save OpenAI-compatible model: {error:#}");
            Err(
                HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                    500,
                    "Failed to save OpenAI-compatible model.",
                )),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/// GET /settings — return current AI provider configuration (no secrets).
async fn get_settings(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let ai_cfg = &state.config.ai;
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    let api_keys = state
        .db
        .list_api_keys_by_user(user.id)
        .await
        .unwrap_or_default();
    let db_user = state.db.get_user_by_id(user.id).await.unwrap_or(None);
    let preferred_provider = effective_preferred_ai_provider(db_user.as_ref(), ai_cfg, &api_keys);
    let fallback_order =
        effective_fallback_order(db_user.as_ref(), ai_cfg, &api_keys, preferred_provider);

    let has_anthropic = provider_configured(ai_cfg, &api_keys, ProviderKind::Anthropic);
    let has_claude_code = provider_configured(ai_cfg, &api_keys, ProviderKind::ClaudeCode);
    let has_codex = provider_configured(ai_cfg, &api_keys, ProviderKind::Codex);
    let has_xai_oauth = provider_configured(ai_cfg, &api_keys, ProviderKind::XaiOAuth);
    let has_xai = provider_configured(ai_cfg, &api_keys, ProviderKind::Xai);
    let has_openai = provider_configured(ai_cfg, &api_keys, ProviderKind::OpenAi);
    let has_openai_compatible =
        provider_configured(ai_cfg, &api_keys, ProviderKind::OpenAiCompatible);
    let has_ollama = provider_configured(ai_cfg, &api_keys, ProviderKind::Ollama);
    let stored_anthropic = stored_provider_configured(&api_keys, ProviderKind::Anthropic);
    let stored_claude_code = stored_provider_configured(&api_keys, ProviderKind::ClaudeCode);
    let stored_codex = stored_provider_configured(&api_keys, ProviderKind::Codex);
    let stored_xai_oauth = stored_provider_configured(&api_keys, ProviderKind::XaiOAuth);
    let stored_xai = stored_provider_configured(&api_keys, ProviderKind::Xai);
    let stored_openai = stored_provider_configured(&api_keys, ProviderKind::OpenAi);
    let stored_openai_compatible =
        stored_provider_configured(&api_keys, ProviderKind::OpenAiCompatible);
    let stored_ollama = stored_provider_configured(&api_keys, ProviderKind::Ollama);

    let mut provider_models = db_user
        .as_ref()
        .map(|user| ai::parse_provider_models(&user.ai_provider_models))
        .unwrap_or_default();
    if let Some(model) = ai_cfg.openai_compatible_model.as_deref().map(str::trim)
        && !model.is_empty()
    {
        provider_models
            .entry(ProviderKind::OpenAiCompatible)
            .or_insert_with(|| model.to_string());
    }

    let resp = SettingsResponse {
        has_anthropic,
        has_claude_code,
        has_codex,
        has_xai_oauth,
        has_xai,
        has_openai,
        has_openai_compatible,
        has_ollama,
        stored_anthropic,
        stored_claude_code,
        stored_codex,
        stored_xai_oauth,
        stored_xai,
        stored_openai,
        stored_openai_compatible,
        stored_ollama,
        default_model: ai_cfg.default_model.clone(),
        preferred_provider: preferred_provider.map(|provider| provider.as_str().to_string()),
        fallbacks_enabled: db_user
            .as_ref()
            .map(|user| user.ai_fallbacks_enabled)
            .unwrap_or(false),
        fallback_order: provider_order_strings(&fallback_order),
        provider_models: provider_models_to_json_map(&provider_models),
    };
    HttpResponse::Ok().json(ApiResponse::ok(resp))
}

/// PATCH /settings/ai-routing — update provider routing preferences.
async fn update_ai_routing(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Form<UpdateAiRoutingForm>,
) -> HttpResponse {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    let db_user = match state.db.get_user_by_id(user.id).await {
        Ok(user) => user,
        Err(error) => {
            log::error!("Failed to load user for AI routing: {error:#}");
            if is_hx_request(&req) {
                return inline_feedback_html(false, "Failed to load provider settings.");
            }
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to load provider settings.",
            ));
        }
    };

    let api_keys = match state.db.list_api_keys_by_user(user.id).await {
        Ok(keys) => keys,
        Err(error) => {
            log::error!("Failed to load API keys for AI routing: {error:#}");
            if is_hx_request(&req) {
                return inline_feedback_html(false, "Failed to load provider settings.");
            }
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to load provider settings.",
            ));
        }
    };
    let configured = configured_ai_providers(&state.config.ai, &api_keys);
    if configured.is_empty() {
        if is_hx_request(&req) {
            return inline_feedback_html(false, "Configure at least one AI provider first.");
        }
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Configure at least one AI provider first.",
        ));
    }

    let Some(preferred_provider) = ai::provider_kind_from_name(&body.preferred_provider) else {
        if is_hx_request(&req) {
            return inline_feedback_html(false, "Choose a valid preferred provider.");
        }
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Choose a valid preferred provider.",
        ));
    };

    if !configured.contains(&preferred_provider) {
        let msg = format!(
            "{} is not configured yet. Configure it before selecting it as preferred.",
            preferred_provider.label()
        );
        if is_hx_request(&req) {
            return inline_feedback_html(false, &msg);
        }
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(400, msg));
    }

    let mut fallback_order = vec![preferred_provider];
    if let Some(raw) = body.fallback_order.as_deref() {
        for token in raw.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Some(provider) = ai::provider_kind_from_name(trimmed) else {
                let msg = format!("Unknown fallback provider: {trimmed}");
                if is_hx_request(&req) {
                    return inline_feedback_html(false, &msg);
                }
                return HttpResponse::BadRequest().json(ApiResponse::<()>::error(400, msg));
            };
            if !configured.contains(&provider) {
                let msg = format!(
                    "{} is not configured yet. Remove it from the fallback order or configure it first.",
                    provider.label()
                );
                if is_hx_request(&req) {
                    return inline_feedback_html(false, &msg);
                }
                return HttpResponse::BadRequest().json(ApiResponse::<()>::error(400, msg));
            }
            ai::push_provider_once(&mut fallback_order, provider);
        }
    }

    for provider in configured {
        ai::push_provider_once(&mut fallback_order, provider);
    }

    let fallbacks_enabled = body.fallbacks_enabled.is_some();
    let fallback_order_csv = ai::provider_order_csv(&fallback_order);
    let mut provider_models = db_user
        .as_ref()
        .map(|user| ai::parse_provider_models(&user.ai_provider_models))
        .unwrap_or_default();
    merge_provider_models_from_form(&mut provider_models, &body);
    let provider_models_json = ai::serialize_provider_models(&provider_models);

    match state
        .db
        .update_user_ai_routing_preferences(
            user.id,
            Some(preferred_provider.as_str()),
            fallbacks_enabled,
            &fallback_order_csv,
            &provider_models_json,
        )
        .await
    {
        Ok(true) => {
            if is_hx_request(&req) {
                return inline_feedback_html(true, "AI provider routing saved.");
            }
            HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "preferred_provider": preferred_provider.as_str(),
                "fallbacks_enabled": fallbacks_enabled,
                "fallback_order": provider_order_strings(&fallback_order),
                "provider_models": provider_models_to_json_map(&provider_models),
            })))
        }
        Ok(false) => {
            if is_hx_request(&req) {
                return inline_feedback_html(false, "User not found.");
            }
            HttpResponse::NotFound().json(ApiResponse::<()>::error(404, "User not found."))
        }
        Err(error) => {
            log::error!(
                "Failed to update AI routing for user {}: {error:#}",
                user.id
            );
            if is_hx_request(&req) {
                return inline_feedback_html(false, "Failed to save AI provider routing.");
            }
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to save AI provider routing.",
            ))
        }
    }
}

/// GET /settings/codex/authorize — start ChatGPT OAuth for Codex model access.
async fn codex_authorize(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    let return_url = settings_return_url(&req);

    let request = match ai::codex::prepare_codex_authorization(state.codex_callback_port) {
        Ok(request) => request,
        Err(error) => {
            log::error!("Failed to start Codex authorization: {error:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to start Codex authorization: {error:#}"),
            ));
        }
    };

    let pending = CodexPendingLogin {
        user_id: user.id,
        code_verifier: request.code_verifier,
        return_url,
        expires_at: Utc::now() + chrono::Duration::minutes(CODEX_LOGIN_TTL_MINUTES),
    };

    {
        let mut logins = state.codex_logins.lock().await;
        let now = Utc::now();
        logins.retain(|_, entry| entry.expires_at > now);
        logins.insert(request.state.clone(), pending);
    }

    HttpResponse::Found()
        .insert_header(("Location", request.authorize_url))
        .finish()
}

#[derive(Deserialize)]
pub struct CodexCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// GET /auth/callback — completes the Codex OAuth flow. The redirect URI is
/// fixed by the OpenAI OAuth client to `http://localhost:1455/auth/callback`
/// (or 1457). Anonymous; the OAuth `state` parameter authenticates the
/// request by matching back to a pending login stored at /authorize time.
pub async fn codex_callback(
    state: web::Data<AppState>,
    query: web::Query<CodexCallbackQuery>,
) -> HttpResponse {
    let fallback_return = "/settings#settings-providers";

    if let Some(error) = query.error.as_deref() {
        let description = query
            .error_description
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(error);
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=utf-8")
            .body(ai::codex::login_error_html(
                &format!("OpenAI authorization failed: {description}"),
                fallback_return,
            ));
    }

    let Some(state_param) = query.state.as_deref().filter(|s| !s.is_empty()) else {
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=utf-8")
            .body(ai::codex::login_error_html(
                "Codex callback was missing the OAuth state parameter.",
                fallback_return,
            ));
    };

    let Some(code) = query.code.as_deref().filter(|s| !s.is_empty()) else {
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=utf-8")
            .body(ai::codex::login_error_html(
                "Codex callback did not include an authorization code.",
                fallback_return,
            ));
    };

    let pending = {
        let mut logins = state.codex_logins.lock().await;
        let now = Utc::now();
        logins.retain(|_, entry| entry.expires_at > now);
        logins.remove(state_param)
    };

    let Some(pending) = pending else {
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=utf-8")
            .body(ai::codex::login_error_html(
                "Codex login session expired or was not initiated by this server. \
                 Please retry the connect flow from Settings.",
                fallback_return,
            ));
    };

    match ai::codex::complete_codex_login(
        state.db.clone(),
        state.encryption_key,
        pending.user_id,
        &pending.code_verifier,
        state.codex_callback_port,
        code,
    )
    .await
    {
        Ok(tokens) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(ai::codex::login_success_html(&tokens, &pending.return_url)),
        Err(error) => {
            log::error!("Codex OAuth callback failed: {error:#}");
            HttpResponse::BadRequest()
                .content_type("text/html; charset=utf-8")
                .body(ai::codex::login_error_html(
                    &format!("{error:#}"),
                    &pending.return_url,
                ))
        }
    }
}

/// GET /settings/xai-oauth/authorize — start Grok OAuth for SuperGrok / X Premium+ access.
async fn xai_oauth_authorize(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    let return_url = settings_return_url(&req);

    let request = match ai::xai_oauth::prepare_xai_oauth_authorization().await {
        Ok(request) => request,
        Err(error) => {
            log::error!("Failed to start Grok OAuth authorization: {error:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to start Grok OAuth authorization: {error:#}"),
            ));
        }
    };

    let pending = XaiOAuthPendingLogin {
        user_id: user.id,
        code_verifier: request.code_verifier,
        code_challenge: request.code_challenge,
        token_endpoint: request.token_endpoint,
        return_url,
        expires_at: Utc::now() + chrono::Duration::minutes(XAI_OAUTH_LOGIN_TTL_MINUTES),
    };

    {
        let mut logins = state.xai_oauth_logins.lock().await;
        let now = Utc::now();
        logins.retain(|_, entry| entry.expires_at > now);
        logins.insert(request.state.clone(), pending);
    }

    HttpResponse::Found()
        .insert_header(("Location", request.authorize_url))
        .finish()
}

#[derive(Deserialize)]
pub struct XaiOAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// Completes the Grok Subscription OAuth flow for both local loopback and
/// hosted callbacks. The OAuth `state` maps the request to the user who
/// initiated the Settings connection.
pub async fn xai_oauth_callback(
    state: web::Data<AppState>,
    query: web::Query<XaiOAuthCallbackQuery>,
) -> HttpResponse {
    let fallback_return = "/settings#settings-providers";

    if let Some(error) = query.error.as_deref() {
        let description = query
            .error_description
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(error);
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=utf-8")
            .body(ai::xai_oauth::login_error_html(
                &format!("Grok authorization failed: {description}"),
                fallback_return,
            ));
    }

    let Some(state_param) = query.state.as_deref().filter(|s| !s.is_empty()) else {
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=utf-8")
            .body(ai::xai_oauth::login_error_html(
                "Grok callback was missing the OAuth state parameter.",
                fallback_return,
            ));
    };

    let Some(code) = query.code.as_deref().filter(|s| !s.is_empty()) else {
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=utf-8")
            .body(ai::xai_oauth::login_error_html(
                "Grok callback did not include an authorization code.",
                fallback_return,
            ));
    };

    let pending = {
        let mut logins = state.xai_oauth_logins.lock().await;
        let now = Utc::now();
        logins.retain(|_, entry| entry.expires_at > now);
        logins.remove(state_param)
    };

    let Some(pending) = pending else {
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=utf-8")
            .body(ai::xai_oauth::login_error_html(
                "Grok login session expired or was not initiated by this server. \
                 Please retry the connect flow from Settings.",
                fallback_return,
            ));
    };

    match ai::xai_oauth::complete_xai_oauth_login(
        state.db.clone(),
        state.encryption_key,
        pending.user_id,
        &pending.code_verifier,
        &pending.code_challenge,
        &pending.token_endpoint,
        code,
    )
    .await
    {
        Ok(tokens) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(ai::xai_oauth::login_success_html(
                &tokens,
                &pending.return_url,
            )),
        Err(error) => {
            log::error!("Grok OAuth callback failed: {error:#}");
            HttpResponse::BadRequest()
                .content_type("text/html; charset=utf-8")
                .body(ai::xai_oauth::login_error_html(
                    &format!("{error:#}"),
                    &pending.return_url,
                ))
        }
    }
}

/// GET /settings/claude-code/authorize — start the Claude.ai OAuth flow for
/// subscription-backed Claude Code access. Stores a pending login keyed by
/// the OAuth `state` and redirects the user to claude.ai. The user approves
/// the grant, then pastes the resulting `code#state` blob back into the
/// settings page (handled by `claude_code_exchange`).
async fn claude_code_authorize(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    let return_url = settings_return_url(&req);

    let request = match ai::claude_code::prepare_claude_code_authorization() {
        Ok(request) => request,
        Err(error) => {
            log::error!("Failed to start Claude Code authorization: {error:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to start Claude Code authorization: {error:#}"),
            ));
        }
    };

    let pending = ClaudeCodePendingLogin {
        user_id: user.id,
        code_verifier: request.code_verifier,
        return_url,
        expires_at: Utc::now() + chrono::Duration::minutes(CLAUDE_CODE_LOGIN_TTL_MINUTES),
    };

    {
        let mut logins = state.claude_code_logins.lock().await;
        let now = Utc::now();
        logins.retain(|_, entry| entry.expires_at > now);
        logins.insert(request.state.clone(), pending);
    }

    HttpResponse::Found()
        .insert_header(("Location", request.authorize_url))
        .finish()
}

#[derive(Deserialize)]
pub struct ClaudeCodeExchangeForm {
    /// The `code#state` blob (or bare code, or full callback URL) the user
    /// pasted from the Anthropic console redirect page.
    code: String,
    /// Explicit `state` value, when the user pasted only the code without
    /// the trailing `#state`. Optional — overrides the value parsed out of
    /// `code` when present.
    #[serde(default)]
    state: Option<String>,
}

/// POST /settings/claude-code/exchange — accept the pasted authorization
/// code from the Anthropic console redirect page and exchange it for tokens.
async fn claude_code_exchange(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Form<ClaudeCodeExchangeForm>,
) -> HttpResponse {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    let (parsed_code, parsed_state) = ai::claude_code::split_pasted_code(&body.code);
    let supplied_state = body
        .state
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let state_value = supplied_state.or(parsed_state);

    let Some(state_param) = state_value.as_deref().filter(|s| !s.is_empty()) else {
        let message = "Paste the entire `code#state` string from the Anthropic console.";
        if is_hx_request(&req) {
            return inline_feedback_html(false, message);
        }
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(400, message));
    };

    if parsed_code.is_empty() {
        let message = "The pasted authorization code is empty.";
        if is_hx_request(&req) {
            return inline_feedback_html(false, message);
        }
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(400, message));
    }

    let pending = {
        let mut logins = state.claude_code_logins.lock().await;
        let now = Utc::now();
        logins.retain(|_, entry| entry.expires_at > now);
        logins.remove(state_param)
    };

    let Some(pending) = pending else {
        let message = "Claude Code login session expired or was not initiated by this server. \
             Please click Connect again from Settings.";
        if is_hx_request(&req) {
            return inline_feedback_html(false, message);
        }
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(400, message));
    };

    if pending.user_id != user.id {
        let message = "This Claude Code login belongs to a different account.";
        if is_hx_request(&req) {
            return inline_feedback_html(false, message);
        }
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error(403, message));
    }

    match ai::claude_code::complete_claude_code_login(
        state.db.clone(),
        state.encryption_key,
        pending.user_id,
        &pending.code_verifier,
        state_param,
        &parsed_code,
    )
    .await
    {
        Ok(tokens) => {
            if is_hx_request(&req) {
                let account = tokens
                    .email()
                    .or(tokens.account_uuid())
                    .unwrap_or("your Claude.ai account");
                let body = format!(
                    "<div class=\"rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-700\" \
                     hx-get=\"/settings\" hx-trigger=\"load delay:1.25s\" hx-target=\"body\" hx-push-url=\"true\">\
                     Connected to {} via Claude.ai. Refreshing settings…\
                     </div>",
                    escape_html(account)
                );
                return HttpResponse::Ok()
                    .content_type("text/html; charset=utf-8")
                    .body(body);
            }
            HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(ai::claude_code::login_success_html(
                    &tokens,
                    &pending.return_url,
                ))
        }
        Err(error) => {
            log::error!("Claude Code OAuth exchange failed: {error:#}");
            let message = format!("Claude Code connection failed: {error:#}");
            if is_hx_request(&req) {
                return inline_feedback_html(false, &message);
            }
            HttpResponse::BadRequest()
                .content_type("text/html; charset=utf-8")
                .body(ai::claude_code::login_error_html(
                    &message,
                    &pending.return_url,
                ))
        }
    }
}

/// POST /settings/api-keys — store an AI provider key.
async fn create_api_key(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CreateApiKeyRequest>,
) -> HttpResponse {
    let provider = body.provider.trim().to_ascii_lowercase();
    if !["anthropic", "openai", "openai_compatible", "xai", "ollama"].contains(&provider.as_str()) {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            format!(
                "Unsupported provider: {}. Must be anthropic, openai, openai_compatible, xai, or ollama.",
                provider
            ),
        ));
    }

    let key = body.key.as_deref().map(str::trim).unwrap_or_default();
    if provider != ProviderKind::OpenAiCompatible.as_str() && key.is_empty() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Key value must not be empty.",
        ));
    }

    let custom_base_url = if provider == ProviderKind::OpenAiCompatible.as_str() {
        let Some(base_url) = body.base_url.as_deref() else {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                "Base URL is required for OpenAI-compatible providers.",
            ));
        };
        match ai::openai::normalize_openai_compatible_base_url(base_url) {
            Ok(base_url) => Some(base_url),
            Err(error) => {
                return HttpResponse::BadRequest()
                    .json(ApiResponse::<()>::error(400, format!("{error:#}")));
            }
        }
    } else {
        None
    };
    let custom_model = if provider == ProviderKind::OpenAiCompatible.as_str() {
        match required_openai_compatible_model(body.model.as_deref()) {
            Ok(model) => Some(model),
            Err(response) => return response,
        }
    } else {
        None
    };

    let secret = if let Some(base_url) = custom_base_url.as_deref() {
        match ai::openai::encode_openai_compatible_secret(key, base_url) {
            Ok(secret) => secret,
            Err(error) => {
                return HttpResponse::BadRequest()
                    .json(ApiResponse::<()>::error(400, format!("{error:#}")));
            }
        }
    } else {
        key.to_string()
    };

    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");
    let user_id = user.id;

    if let Some(model) = custom_model.as_deref()
        && let Err(response) = save_openai_compatible_model(&state, user_id, model).await
    {
        return response;
    }

    let key_hash = hash_key(&secret);
    let encrypted = encrypt_key(&secret, state.encryption_key.as_ref());
    let label_owned = body
        .label
        .as_deref()
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .map(str::to_string)
        .or_else(|| custom_base_url.clone());
    let label = label_owned.as_deref();
    let key_preview = if key.is_empty() {
        "No API key".to_string()
    } else {
        mask_key(key)
    };

    match state
        .db
        .create_api_key(
            user_id,
            "llm_provider",
            &provider,
            label,
            &key_hash,
            &encrypted,
        )
        .await
    {
        Ok(api_key) => {
            if is_hx_request(&req) {
                return render_api_key_row(
                    &state,
                    &user.theme,
                    api_key.id,
                    api_key.provider.as_deref().unwrap_or(&provider),
                    api_key.label.as_deref(),
                    api_key.created_at,
                );
            }

            let resp = ApiKeyResponse {
                id: api_key.id,
                provider: api_key.provider,
                label: api_key.label,
                key_preview,
                created_at: api_key.created_at,
            };
            HttpResponse::Created().json(ApiResponse::ok(resp))
        }
        Err(e) => {
            log::error!("Failed to create API key: {e:#}");
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Failed to store API key."))
        }
    }
}

/// DELETE /settings/api-keys/{id} — soft-delete an API key.
async fn delete_api_key(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let id = path.into_inner();
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    match state.db.delete_api_key_for_user(user.id, id).await {
        Ok(true) => {
            if is_hx_request(&req) {
                return HttpResponse::Ok().finish();
            }

            HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "deleted": true,
                "id": id,
            })))
        }
        Ok(false) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            "API key not found or already deleted.",
        )),
        Err(e) => {
            log::error!("Failed to delete API key: {e:#}");
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Failed to delete API key."))
        }
    }
}

/// DELETE /settings/ai-providers/{provider} — disconnect a stored AI provider.
async fn disconnect_ai_provider(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let raw_provider = path.into_inner();
    let Some(provider) = ai::provider_kind_from_name(&raw_provider) else {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            format!("Unsupported AI provider: {raw_provider}"),
        ));
    };
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    let deleted = match state
        .db
        .delete_api_keys_by_provider(user.id, provider.as_str())
        .await
    {
        Ok(deleted) => deleted,
        Err(error) => {
            log::error!(
                "Failed to disconnect {} provider for user {}: {error:#}",
                provider.as_str(),
                user.id
            );
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to disconnect AI provider.",
            ));
        }
    };

    if deleted == 0 {
        return HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            format!("No stored {} connection was found.", provider.label()),
        ));
    }

    if let Err(error) = clear_disconnected_provider_preferences(&state, user.id, provider).await {
        log::error!(
            "Disconnected {} provider for user {} but failed to clear routing preferences: {error:#}",
            provider.as_str(),
            user.id
        );
        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            "Provider disconnected, but routing preferences could not be updated.",
        ));
    }

    if is_hx_request(&req) {
        return HttpResponse::Ok().finish();
    }

    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "deleted": deleted,
        "provider": provider.as_str(),
    })))
}

/// POST /settings/test-connection — test an AI provider connection.
async fn test_connection(req: HttpRequest, body: web::Json<TestConnectionRequest>) -> HttpResponse {
    let provider = body.provider.trim().to_ascii_lowercase();
    let key = body.key.as_deref().map(str::trim).unwrap_or_default();
    if provider != ProviderKind::OpenAiCompatible.as_str() && key.is_empty() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Key value must not be empty.",
        ));
    }

    let test_provider: Box<dyn ai::ModelProvider> = match provider.as_str() {
        "anthropic" => Box::new(ai::claude::ClaudeProvider::new(key.to_string())),
        "openai" => Box::new(ai::openai::OpenAiProvider::new(key.to_string())),
        "openai_compatible" => {
            let Some(base_url) = body.base_url.as_deref() else {
                return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                    400,
                    "Base URL is required for OpenAI-compatible providers.",
                ));
            };
            let base_url = match ai::openai::normalize_openai_compatible_base_url(base_url) {
                Ok(base_url) => base_url,
                Err(error) => {
                    return HttpResponse::BadRequest()
                        .json(ApiResponse::<()>::error(400, format!("{error:#}")));
                }
            };
            Box::new(ai::openai::OpenAiProvider::openai_compatible(
                key.to_string(),
                base_url,
            ))
        }
        "xai" => Box::new(
            ai::openai::OpenAiProvider::new(key.to_string())
                .with_base_url("https://api.x.ai".to_string())
                .with_provider_identity("xai", "xAI"),
        ),
        "ollama" => Box::new(ai::ollama::OllamaProvider::new(key.to_string())),
        _ => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                format!(
                    "Unsupported provider: {}. Must be anthropic, openai, openai_compatible, xai, or ollama.",
                    provider
                ),
            ));
        }
    };

    let model = match provider.as_str() {
        "anthropic" => "claude-sonnet-4-20250514".to_string(),
        "openai" => "gpt-4o-mini".to_string(),
        "openai_compatible" => match required_openai_compatible_model(body.model.as_deref()) {
            Ok(model) => model,
            Err(response) => return response,
        },
        "xai" => "grok-4.3".to_string(),
        "ollama" => "llama3.2".to_string(),
        _ => unreachable!(),
    };

    let request = CompletionRequest {
        model,
        messages: vec![Message {
            role: "user".to_string(),
            content: "Say hello in one word.".to_string(),
        }],
        tools: None,
        max_tokens: Some(32),
        temperature: Some(0.0),
    };

    match test_provider.complete(request).await {
        Ok(resp) => {
            let msg = format!(
                "Connection successful. Provider: {}. Response: {}",
                test_provider.provider_name(),
                resp.content.chars().take(100).collect::<String>(),
            );
            if is_hx_request(&req) {
                return test_connection_html(true, &msg);
            }
            HttpResponse::Ok().json(ApiResponse::ok(TestConnectionResponse {
                success: true,
                provider: test_provider.provider_name().to_string(),
                message: msg,
            }))
        }
        Err(e) => {
            let msg = format!("Connection failed: {e:#}");
            if is_hx_request(&req) {
                return test_connection_html(false, &msg);
            }
            HttpResponse::Ok().json(ApiResponse::ok(TestConnectionResponse {
                success: false,
                provider: test_provider.provider_name().to_string(),
                message: msg,
            }))
        }
    }
}

/// GET /settings/ai-status — return AI provider status from env and DB.
async fn ai_status(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let ai_cfg = &state.config.ai;
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");
    let user_id = user.id;

    let api_keys = state
        .db
        .list_api_keys_by_user(user_id)
        .await
        .unwrap_or_default();
    let db_user = state.db.get_user_by_id(user_id).await.unwrap_or(None);
    let preferred_provider = effective_preferred_ai_provider(db_user.as_ref(), ai_cfg, &api_keys);
    let fallback_order =
        effective_fallback_order(db_user.as_ref(), ai_cfg, &api_keys, preferred_provider);

    let stored_anthropic = stored_provider_configured(&api_keys, ProviderKind::Anthropic);
    let stored_claude_code = stored_provider_configured(&api_keys, ProviderKind::ClaudeCode);
    let stored_codex = stored_provider_configured(&api_keys, ProviderKind::Codex);
    let stored_xai_oauth = stored_provider_configured(&api_keys, ProviderKind::XaiOAuth);
    let stored_xai = stored_provider_configured(&api_keys, ProviderKind::Xai);
    let stored_openai = stored_provider_configured(&api_keys, ProviderKind::OpenAi);
    let stored_openai_compatible =
        stored_provider_configured(&api_keys, ProviderKind::OpenAiCompatible);
    let stored_ollama = stored_provider_configured(&api_keys, ProviderKind::Ollama);

    let mut provider_models = db_user
        .as_ref()
        .map(|user| ai::parse_provider_models(&user.ai_provider_models))
        .unwrap_or_default();
    if let Some(model) = ai_cfg.openai_compatible_model.as_deref().map(str::trim)
        && !model.is_empty()
    {
        provider_models
            .entry(ProviderKind::OpenAiCompatible)
            .or_insert_with(|| model.to_string());
    }

    let resp = AiStatusResponse {
        env_anthropic: ai_cfg.anthropic_api_key.is_some(),
        env_openai: ai_cfg.openai_api_key.is_some(),
        env_openai_compatible: ai_cfg.openai_compatible_base_url.is_some()
            && ai_cfg.openai_compatible_model.is_some(),
        env_xai: ai_cfg.xai_api_key.is_some(),
        env_ollama: ai_cfg.ollama_url.is_some(),
        stored_anthropic,
        stored_claude_code,
        stored_codex,
        stored_xai_oauth,
        stored_xai,
        stored_openai,
        stored_openai_compatible,
        stored_ollama,
        default_model: ai_cfg.default_model.clone(),
        preferred_provider: preferred_provider.map(|provider| provider.as_str().to_string()),
        fallbacks_enabled: db_user
            .as_ref()
            .map(|user| user.ai_fallbacks_enabled)
            .unwrap_or(false),
        fallback_order: provider_order_strings(&fallback_order),
        provider_models: provider_models_to_json_map(&provider_models),
    };

    HttpResponse::Ok().json(ApiResponse::ok(resp))
}

/// PATCH /settings/profile — update user display name.
async fn update_profile(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<UpdateProfileRequest>,
) -> HttpResponse {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    if let Some(ref display_name) = body.display_name {
        let name = display_name.trim();
        if name.is_empty() {
            if is_hx_request(&req) {
                return inline_feedback_html(false, "Display name must not be empty.");
            }
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                "Display name must not be empty.",
            ));
        }
        match state.db.update_user_display_name(user.id, name).await {
            Ok(true) => {}
            Ok(false) => {
                if is_hx_request(&req) {
                    return inline_feedback_html(false, "User not found.");
                }
                return HttpResponse::NotFound()
                    .json(ApiResponse::<()>::error(404, "User not found."));
            }
            Err(e) => {
                log::error!("Failed to update display name: {e:#}");
                if is_hx_request(&req) {
                    return inline_feedback_html(false, "Failed to update profile.");
                }
                return HttpResponse::InternalServerError()
                    .json(ApiResponse::<()>::error(500, "Failed to update profile."));
            }
        }
    }

    if is_hx_request(&req) {
        return inline_feedback_html(true, "Profile updated.");
    }

    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "success": true,
        "message": "Profile updated.",
    })))
}

/// POST /settings/change-password — change user password.
async fn change_password(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<ChangePasswordRequest>,
) -> HttpResponse {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    // Validate new password length
    if body.new_password.len() < 8 {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "New password must be at least 8 characters.",
        ));
    }

    // Load user from DB to get current password_hash
    let db_user = match state.db.get_user_by_id(user.id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(404, "User not found."));
        }
        Err(e) => {
            log::error!("Failed to load user: {e:#}");
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Failed to load user data."));
        }
    };

    // Verify current password
    match crate::auth::verify_password(&body.current_password, &db_user.password_hash) {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                "Current password is incorrect.",
            ));
        }
        Err(e) => {
            log::error!("Password verification failed: {e:#}");
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Failed to verify password."));
        }
    }

    // Hash new password
    let new_hash = match crate::auth::hash_password(&body.new_password) {
        Ok(h) => h,
        Err(e) => {
            log::error!("Failed to hash new password: {e:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to hash new password.",
            ));
        }
    };

    // Update in DB
    match state.db.update_user_password(user.id, &new_hash).await {
        Ok(true) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "success": true,
            "message": "Password changed successfully.",
        }))),
        Ok(false) => {
            HttpResponse::NotFound().json(ApiResponse::<()>::error(404, "User not found."))
        }
        Err(e) => {
            log::error!("Failed to update password: {e:#}");
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Failed to change password."))
        }
    }
}

/// DELETE /settings/integrations/{provider} — disconnect a source control integration.
async fn disconnect_integration(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let provider = path.into_inner().to_lowercase();
    if !matches!(provider.as_str(), "github" | "gitlab" | "bitbucket") {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Provider must be 'github', 'gitlab', or 'bitbucket'.",
        ));
    }

    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    let connection = match state.db.get_oauth_connection(user.id, &provider).await {
        Ok(Some(connection)) => connection,
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                "Integration is not connected.",
            ));
        }
        Err(e) => {
            log::error!("Failed to load integration for disconnect: {e:#}");
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Failed to load integration."));
        }
    };

    if let Err(e) = state.db.clear_repo_oauth_connection(connection.id).await {
        log::error!("Failed to unlink repos from integration: {e:#}");
        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            "Failed to unlink repositories from integration.",
        ));
    }

    match state.db.delete_oauth_connection(user.id, &provider).await {
        Ok(rows) if rows > 0 => {
            if is_hx_request(&req) {
                return HttpResponse::Ok()
                    .insert_header(("HX-Redirect", "/settings"))
                    .finish();
            }

            HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "success": true,
                "provider": provider,
            })))
        }
        Ok(_) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            "Integration is not connected.",
        )),
        Err(e) => {
            log::error!("Failed to disconnect integration: {e:#}");
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to disconnect integration.",
            ))
        }
    }
}

/// POST /settings/integrations/{provider}/pat — save a personal access token.
async fn save_pat(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<SavePatRequest>,
) -> HttpResponse {
    let provider = path.into_inner().to_lowercase();
    if !matches!(provider.as_str(), "github" | "gitlab" | "bitbucket") {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Provider must be 'github', 'gitlab', or 'bitbucket'.",
        ));
    }

    if body.token.trim().is_empty() {
        if is_hx_request(&req) {
            return inline_feedback_html(false, "Token must not be empty.");
        }
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(400, "Token must not be empty."));
    }

    // Bitbucket App Passwords require the account email for Basic auth.
    if provider == "bitbucket" {
        let email = body.username.as_deref().map(|u| u.trim()).unwrap_or("");
        if email.is_empty() || !email.contains('@') {
            let msg =
                "Bitbucket requires your account email (used for Basic auth with App Passwords).";
            if is_hx_request(&req) {
                return inline_feedback_html(false, msg);
            }
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(400, msg));
        }
    }

    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    let encrypted = encrypt_key(body.token.trim(), state.encryption_key.as_ref());

    let provider_user_id = body
        .username
        .as_deref()
        .map(|u| u.trim())
        .filter(|u| !u.is_empty())
        .unwrap_or("pat")
        .to_string();

    match state
        .db
        .upsert_pat_connection(user.id, &provider, &encrypted, &provider_user_id)
        .await
    {
        Ok(_) => {
            if is_hx_request(&req) {
                return HttpResponse::Ok()
                    .insert_header(("HX-Redirect", "/settings"))
                    .finish();
            }
            HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "success": true,
                "provider": provider,
            })))
        }
        Err(e) => {
            log::error!("Failed to save PAT for {provider}: {e:#}");
            if is_hx_request(&req) {
                return inline_feedback_html(false, "Failed to save token.");
            }
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Failed to save token."))
        }
    }
}

/// PATCH /settings/theme — update the authenticated user's theme preference.
async fn update_theme(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<UpdateThemeRequest>,
) -> HttpResponse {
    let user = match req.extensions().get::<AuthenticatedUser>().cloned() {
        Some(u) => u,
        None => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error(401, "Unauthorized"));
        }
    };

    let theme = crate::templates::normalize_theme(body.theme.trim()).to_string();
    if !crate::templates::KNOWN_THEMES.contains(&theme.as_str()) {
        let msg = format!(
            "Unknown theme '{}'. Available: {}",
            theme,
            crate::templates::KNOWN_THEMES.join(", ")
        );
        if is_hx_request(&req) {
            return inline_feedback_html(false, &msg);
        }
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(400, msg));
    }

    match state.db.update_user_theme(user.id, &theme).await {
        Ok(_) => {
            if is_hx_request(&req) {
                return HttpResponse::Ok()
                    .insert_header(("HX-Redirect", "/settings"))
                    .finish();
            }
            HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({ "theme": theme })))
        }
        Err(e) => {
            log::error!("Failed to update theme for user {}: {e:#}", user.id);
            if is_hx_request(&req) {
                return inline_feedback_html(false, "Failed to save theme.");
            }
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, "Failed to save theme."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user(preferred: Option<&str>, fallback_order: &str, provider_models: &str) -> User {
        let now = Utc::now();
        User {
            id: Uuid::nil(),
            email: "user@example.com".to_string(),
            password_hash: "hash".to_string(),
            display_name: None,
            avatar_url: None,
            role: "user".to_string(),
            theme: "sentinel".to_string(),
            preferred_ai_provider: preferred.map(str::to_string),
            ai_fallbacks_enabled: true,
            ai_fallback_order: fallback_order.to_string(),
            ai_provider_models: provider_models.to_string(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    #[test]
    fn removing_provider_clears_routing_and_model_override() {
        let user = test_user(
            Some("xai_oauth"),
            "xai_oauth,codex,openai",
            r#"{"xai_oauth":"grok-build-0.1","codex":"gpt-5.4"}"#,
        );

        let (preferred, fallback_order, provider_models) =
            routing_preferences_without_provider(&user, ProviderKind::XaiOAuth);
        let provider_models = ai::parse_provider_models(&provider_models);

        assert_eq!(preferred, None);
        assert_eq!(fallback_order, "codex,openai");
        assert!(!provider_models.contains_key(&ProviderKind::XaiOAuth));
        assert_eq!(
            provider_models.get(&ProviderKind::Codex),
            Some(&"gpt-5.4".to_string())
        );
    }
}
