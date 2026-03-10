//
//  heimdall
//  src/routes/settings.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ai;
use crate::ai::types::{CompletionRequest, Message};
use crate::middleware::auth::AuthenticatedUser;
use crate::models::ApiResponse;
use crate::state::AppState;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/settings")
            .route("", web::get().to(get_settings))
            .route("/profile", web::patch().to(update_profile))
            .route("/change-password", web::post().to(change_password))
            .route("/api-keys", web::post().to(create_api_key))
            .route("/api-keys/{id}", web::delete().to(delete_api_key))
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
    key: String,
    label: Option<String>,
}

#[derive(Deserialize)]
struct TestConnectionRequest {
    provider: String,
    key: String,
}

#[derive(Deserialize)]
struct UpdateProfileRequest {
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Serialize)]
struct SettingsResponse {
    has_anthropic: bool,
    has_openai: bool,
    has_ollama: bool,
    default_model: String,
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
    env_ollama: bool,
    stored_anthropic: bool,
    stored_openai: bool,
    stored_ollama: bool,
    default_model: String,
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

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/// GET /settings — return current AI provider configuration (no secrets).
async fn get_settings(state: web::Data<AppState>) -> HttpResponse {
    let ai_cfg = &state.config.ai;
    let resp = SettingsResponse {
        has_anthropic: ai_cfg.anthropic_api_key.is_some(),
        has_openai: ai_cfg.openai_api_key.is_some(),
        has_ollama: ai_cfg.ollama_url.is_some(),
        default_model: ai_cfg.default_model.clone(),
    };
    HttpResponse::Ok().json(ApiResponse::ok(resp))
}

/// POST /settings/api-keys — store an AI provider key.
async fn create_api_key(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CreateApiKeyRequest>,
) -> HttpResponse {
    let provider = body.provider.to_lowercase();
    if !["anthropic", "openai", "ollama"].contains(&provider.as_str()) {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            format!("Unsupported provider: {}. Must be anthropic, openai, or ollama.", provider),
        ));
    }

    if body.key.is_empty() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Key value must not be empty.",
        ));
    }

    let user = req.extensions().get::<AuthenticatedUser>().cloned()
        .expect("auth middleware ensures user exists");
    let user_id = user.id;
    let key_hash = hash_key(&body.key);
    let encrypted = encrypt_key(&body.key, state.encryption_key.as_ref());
    let label = body.label.as_deref();
    let key_preview = mask_key(&body.key);

    match state
        .db
        .create_api_key(user_id, "llm_provider", &provider, label, &key_hash, &encrypted)
        .await
    {
        Ok(api_key) => {
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
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to store API key.",
            ))
        }
    }
}

/// DELETE /settings/api-keys/{id} — soft-delete an API key.
async fn delete_api_key(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let id = path.into_inner();
    match state.db.delete_api_key(id).await {
        Ok(true) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "deleted": true,
            "id": id,
        }))),
        Ok(false) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            "API key not found or already deleted.",
        )),
        Err(e) => {
            log::error!("Failed to delete API key: {e:#}");
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to delete API key.",
            ))
        }
    }
}

/// POST /settings/test-connection — test an AI provider connection.
async fn test_connection(
    body: web::Json<TestConnectionRequest>,
) -> HttpResponse {
    let provider = body.provider.to_lowercase();

    let test_provider: Box<dyn ai::ModelProvider> = match provider.as_str() {
        "anthropic" => Box::new(ai::claude::ClaudeProvider::new(body.key.clone())),
        "openai" => Box::new(ai::openai::OpenAiProvider::new(body.key.clone())),
        "ollama" => Box::new(ai::ollama::OllamaProvider::new(body.key.clone())),
        _ => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                format!("Unsupported provider: {}. Must be anthropic, openai, or ollama.", provider),
            ));
        }
    };

    let model = match provider.as_str() {
        "anthropic" => "claude-sonnet-4-20250514".to_string(),
        "openai" => "gpt-4o-mini".to_string(),
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
            HttpResponse::Ok().json(ApiResponse::ok(TestConnectionResponse {
                success: true,
                provider: test_provider.provider_name().to_string(),
                message: msg,
            }))
        }
        Err(e) => {
            let msg = format!("Connection failed: {e:#}");
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
    let user = req.extensions().get::<AuthenticatedUser>().cloned()
        .expect("auth middleware ensures user exists");
    let user_id = user.id;

    let stored_anthropic = state
        .db
        .count_api_keys_by_provider(user_id, "anthropic")
        .await
        .unwrap_or(0)
        > 0;
    let stored_openai = state
        .db
        .count_api_keys_by_provider(user_id, "openai")
        .await
        .unwrap_or(0)
        > 0;
    let stored_ollama = state
        .db
        .count_api_keys_by_provider(user_id, "ollama")
        .await
        .unwrap_or(0)
        > 0;

    let resp = AiStatusResponse {
        env_anthropic: ai_cfg.anthropic_api_key.is_some(),
        env_openai: ai_cfg.openai_api_key.is_some(),
        env_ollama: ai_cfg.ollama_url.is_some(),
        stored_anthropic,
        stored_openai,
        stored_ollama,
        default_model: ai_cfg.default_model.clone(),
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
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                "Display name must not be empty.",
            ));
        }
        match state.db.update_user_display_name(user.id, name).await {
            Ok(true) => {}
            Ok(false) => {
                return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                    404,
                    "User not found.",
                ));
            }
            Err(e) => {
                log::error!("Failed to update display name: {e:#}");
                return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                    500,
                    "Failed to update profile.",
                ));
            }
        }
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
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                "User not found.",
            ));
        }
        Err(e) => {
            log::error!("Failed to load user: {e:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to load user data.",
            ));
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
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to verify password.",
            ));
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
        Ok(false) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            "User not found.",
        )),
        Err(e) => {
            log::error!("Failed to update password: {e:#}");
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Failed to change password.",
            ))
        }
    }
}
