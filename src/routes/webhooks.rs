//
//  heimdall
//  src/routes/webhooks.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

// Webhook endpoints for GitHub and GitLab push events.
// These are PUBLIC endpoints (no auth middleware) but verify payload signatures.

use actix_web::{HttpRequest, HttpResponse, web};
use log::{error, info, warn};
use serde::Deserialize;
use std::sync::Arc;

use crate::models::ApiResponse;
use crate::pipeline::ScanPipeline;
use crate::state::AppState;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/github", web::post().to(github_webhook))
        .route("/gitlab", web::post().to(gitlab_webhook));
}

// ---------------------------------------------------------------------------
// GitHub webhook
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GitHubRepository {
    full_name: String,
    clone_url: String,
}

#[derive(Debug, Deserialize)]
struct GitHubPushPayload {
    #[serde(rename = "ref")]
    git_ref: String,
    after: String,
    repository: GitHubRepository,
}

async fn github_webhook(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    // 1. Require webhook secret
    let secret = match &state.config.webhook.webhook_secret {
        Some(s) => s.clone(),
        None => {
            warn!("GitHub webhook received but WEBHOOK_SECRET is not configured");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Webhook secret not configured",
            ));
        }
    };

    // 2. Verify HMAC-SHA256 signature
    let signature = req
        .headers()
        .get("X-Hub-Signature-256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_github_signature(&secret, &body, signature) {
        warn!("GitHub webhook signature verification failed");
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            401,
            "Invalid signature",
        ));
    }

    // 3. Check event type
    let event = req
        .headers()
        .get("X-GitHub-Event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if event != "push" {
        info!("Ignoring GitHub event type: {event}");
        return HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "status": "ignored",
            "reason": format!("event type '{event}' is not handled"),
        })));
    }

    // 4. Parse payload
    let payload: GitHubPushPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to parse GitHub push payload: {e}");
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                format!("Invalid payload: {e}"),
            ));
        }
    };

    info!(
        "GitHub push webhook: repo={}, ref={}, commit={}",
        payload.repository.full_name, payload.git_ref, payload.after
    );

    // 5. Find matching repo and trigger scan
    trigger_scan_for_webhook(
        &state,
        &payload.repository.clone_url,
        &payload.repository.full_name,
        &payload.after,
        &payload.git_ref,
        "github",
    )
    .await
}

// ---------------------------------------------------------------------------
// GitLab webhook
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GitLabProject {
    path_with_namespace: String,
    http_url: String,
}

#[derive(Debug, Deserialize)]
struct GitLabPushPayload {
    object_kind: String,
    #[serde(rename = "ref")]
    git_ref: String,
    after: String,
    project: GitLabProject,
}

async fn gitlab_webhook(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    // 1. Require webhook secret
    let secret = match &state.config.webhook.webhook_secret {
        Some(s) => s.clone(),
        None => {
            warn!("GitLab webhook received but WEBHOOK_SECRET is not configured");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                "Webhook secret not configured",
            ));
        }
    };

    // 2. Verify token (GitLab uses simple string comparison)
    let token = req
        .headers()
        .get("X-Gitlab-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if token != secret {
        warn!("GitLab webhook token verification failed");
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            401,
            "Invalid token",
        ));
    }

    // 3. Parse payload
    let payload: GitLabPushPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to parse GitLab push payload: {e}");
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                format!("Invalid payload: {e}"),
            ));
        }
    };

    // 4. Check event type
    if payload.object_kind != "push" {
        info!("Ignoring GitLab event type: {}", payload.object_kind);
        return HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "status": "ignored",
            "reason": format!("event type '{}' is not handled", payload.object_kind),
        })));
    }

    info!(
        "GitLab push webhook: repo={}, ref={}, commit={}",
        payload.project.path_with_namespace, payload.git_ref, payload.after
    );

    // 5. Find matching repo and trigger scan
    trigger_scan_for_webhook(
        &state,
        &payload.project.http_url,
        &payload.project.path_with_namespace,
        &payload.after,
        &payload.git_ref,
        "gitlab",
    )
    .await
}

// ---------------------------------------------------------------------------
// Shared: trigger scan from webhook
// ---------------------------------------------------------------------------

async fn trigger_scan_for_webhook(
    state: &web::Data<AppState>,
    clone_url: &str,
    repo_display_name: &str,
    commit_sha: &str,
    git_ref: &str,
    source: &str,
) -> HttpResponse {
    // Check AI provider is configured
    let ai = match &state.ai {
        Some(ai) => Arc::clone(ai),
        None => {
            return HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                503,
                "No AI provider configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_URL.",
            ));
        }
    };

    // Find repo by remote URL
    let repo = match state.db.get_repo_by_remote_url(clone_url).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            info!(
                "No matching repo found for {source} webhook: {repo_display_name} ({clone_url})"
            );
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                format!("No registered repo matches URL: {clone_url}"),
            ));
        }
        Err(e) => {
            error!("DB error looking up repo by URL: {e:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to look up repo: {e}"),
            ));
        }
    };

    // Create scan (triggered_by = None for webhooks, commit_sha from push)
    let scan = match state
        .db
        .create_scan(repo.id, "full", None, Some(commit_sha), None, None)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create scan from {source} webhook: {e:#}");
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to create scan: {e}"),
            ));
        }
    };

    let _ = state.db.create_scan_job(scan.id).await;

    // Capture values before moving repo into the spawned task
    let repo_id = repo.id;
    let repo_name = repo.name.clone();
    let scan_id = scan.id;

    // Run pipeline in background
    let db = Arc::clone(&state.db);
    let sse = Arc::clone(&state.sse);
    let model = state.config.ai.default_model.clone();

    tokio::spawn(async move {
        let pipeline = ScanPipeline::new(scan_id, db.clone(), ai, model, sse.clone());
        if let Err(e) = pipeline.run(&repo).await {
            error!("Scan pipeline failed for {scan_id}: {e:#}");
            sse.emit_error(scan_id, &format!("{e:#}"));
            let _ = db
                .update_scan_status(scan_id, "failed", Some(&format!("{e:#}")))
                .await;
        }
    });

    info!(
        "Scan {} triggered via {source} webhook for repo {} (ref: {git_ref}, commit: {commit_sha})",
        scan_id, repo_name
    );

    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "status": "scan_triggered",
        "scan_id": scan_id,
        "repo_id": repo_id,
        "commit_sha": commit_sha,
        "ref": git_ref,
    })))
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 verification for GitHub webhooks
// ---------------------------------------------------------------------------

fn verify_github_signature(secret: &str, body: &[u8], signature_header: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let Some(hex_sig) = signature_header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_sig) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}
