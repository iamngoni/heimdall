//
//  heimdall
//  src/routes/pages.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use log::error;
use uuid::Uuid;

use crate::middleware::auth::AuthenticatedUser;
use crate::models::PaginationParams;
use crate::state::AppState;

/// Public pages — no auth required.
pub fn init_public(cfg: &mut web::ServiceConfig) {
    cfg.route("/login", web::get().to(login_page))
        .route("/register", web::get().to(register_page));
}

/// Protected pages — require a valid session (auth middleware wraps these).
pub fn init_protected(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(dashboard_page))
        .route("/repos", web::get().to(repos_page))
        .route("/repos/{id}", web::get().to(repo_detail_page))
        .route("/scans/{id}", web::get().to(scan_detail_page))
        .route("/scans/{id}/findings", web::get().to(scan_findings_page))
        .route("/scans/{id}/threat-model", web::get().to(threat_model_page))
        .route("/findings/{id}", web::get().to(finding_detail_page))
        .route("/settings", web::get().to(settings_page));
}

/// Helper: render a template and return an HTML response.
fn render_html(state: &AppState, template: &str, ctx: minijinja::Value) -> HttpResponse {
    match state.templates.render(template, ctx) {
        Ok(html) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html),
        Err(e) => {
            error!("Template render error for '{}': {e:#}", template);
            server_error_html(state)
        }
    }
}

/// Render a styled 404 Not Found page.
pub fn not_found_html(state: &AppState) -> HttpResponse {
    let ctx = minijinja::context! {
        error_code => 404,
        error_title => "Not Found",
        error_message => "The page you're looking for doesn't exist.",
    };
    match state.templates.render("pages/error.html", ctx) {
        Ok(html) => HttpResponse::NotFound()
            .content_type("text/html; charset=utf-8")
            .body(html),
        Err(_) => HttpResponse::NotFound().body("Not Found"),
    }
}

/// Render a styled 500 Server Error page.
fn server_error_html(state: &AppState) -> HttpResponse {
    let ctx = minijinja::context! {
        error_code => 500,
        error_title => "Server Error",
        error_message => "Something went wrong. Please try again later.",
    };
    match state.templates.render("pages/error.html", ctx) {
        Ok(html) => HttpResponse::InternalServerError()
            .content_type("text/html; charset=utf-8")
            .body(html),
        Err(_) => HttpResponse::InternalServerError().body("Server Error"),
    }
}

/// Extract authenticated user from request extensions (set by auth middleware).
fn get_user(req: &HttpRequest) -> Option<AuthenticatedUser> {
    req.extensions().get::<AuthenticatedUser>().cloned()
}

/// Build the user context for templates (nav, etc.).
fn user_ctx(req: &HttpRequest) -> minijinja::Value {
    match get_user(req) {
        Some(user) => minijinja::Value::from_serialize(&serde_json::json!({
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "role": user.role,
        })),
        None => minijinja::Value::from(()),
    }
}

async fn dashboard_page(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = get_user(&req).expect("auth middleware ensures user exists");

    let repos = state.db.list_repos_by_user(user.id).await.unwrap_or_default();
    let total_repos = repos.len();

    let mut recent_scans = Vec::new();
    for repo in &repos {
        if let Ok(scans) = state.db.list_scans_by_repo(repo.id).await {
            for scan in scans {
                recent_scans.push(minijinja::Value::from_serialize(&serde_json::json!({
                    "id": scan.id,
                    "repo_name": repo.name,
                    "status": scan.status,
                    "finding_count": scan.finding_count,
                    "created_at": scan.created_at.format("%Y-%m-%d %H:%M").to_string(),
                })));
            }
        }
    }
    recent_scans.truncate(10);

    let open_findings: i64 = state.db.count_open_findings_by_user(user.id).await.unwrap_or(0);
    let critical_findings: i64 = state.db.count_critical_findings_by_user(user.id).await.unwrap_or(0);

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        stats => minijinja::Value::from_serialize(&serde_json::json!({
            "total_repos": total_repos,
            "recent_scans": recent_scans.len(),
            "open_findings": open_findings,
            "critical_findings": critical_findings,
        })),
        recent_scans => recent_scans,
    };

    render_html(&state, "pages/dashboard.html", ctx)
}

async fn login_page(state: web::Data<AppState>, _req: HttpRequest) -> HttpResponse {
    let ctx = minijinja::context! {};
    render_html(&state, "pages/login.html", ctx)
}

async fn register_page(state: web::Data<AppState>, _req: HttpRequest) -> HttpResponse {
    let ctx = minijinja::context! {};
    render_html(&state, "pages/register.html", ctx)
}

async fn repos_page(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<PaginationParams>,
) -> HttpResponse {
    let user = get_user(&req).expect("auth middleware ensures user exists");
    let pagination = query.into_inner();

    let total = state.db.count_repos_by_user(user.id).await.unwrap_or(0);
    let repos = state
        .db
        .list_repos_by_user_paginated(user.id, pagination.limit(), pagination.offset())
        .await
        .unwrap_or_default();

    let page = pagination.page();
    let per_page = pagination.per_page();
    let total_pages = if total == 0 {
        1
    } else {
        ((total as f64) / (per_page as f64)).ceil() as u32
    };

    let repo_values: Vec<minijinja::Value> = repos
        .iter()
        .map(|r| {
            minijinja::Value::from_serialize(&serde_json::json!({
                "id": r.id,
                "name": r.name,
                "source_type": r.source_type,
                "remote_url": r.remote_url,
                "default_branch": r.default_branch,
                "created_at": r.created_at.format("%Y-%m-%d %H:%M").to_string(),
            }))
        })
        .collect();

    // Check which OAuth providers are connected
    let oauth_connections = state
        .db
        .list_oauth_connections_by_user(user.id)
        .await
        .unwrap_or_default();
    let has_github = oauth_connections.iter().any(|c| c.provider == "github");
    let has_gitlab = oauth_connections.iter().any(|c| c.provider == "gitlab");

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        repos => repo_values,
        page => page,
        per_page => per_page,
        total => total,
        total_pages => total_pages,
        has_github => has_github,
        has_gitlab => has_gitlab,
    };

    render_html(&state, "pages/repos.html", ctx)
}

async fn repo_detail_page(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    query: web::Query<PaginationParams>,
    req: HttpRequest,
) -> HttpResponse {
    let repo_id = path.into_inner();
    let pagination = query.into_inner();

    let repo = match state.db.get_repo_by_id(repo_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return not_found_html(&state);
        }
        Err(e) => {
            error!("Failed to fetch repo {repo_id}: {e}");
            return server_error_html(&state);
        }
    };

    let total = state.db.count_scans_by_repo(repo_id).await.unwrap_or(0);
    let scans = state
        .db
        .list_scans_by_repo_paginated(repo_id, pagination.limit(), pagination.offset())
        .await
        .unwrap_or_default();

    let page = pagination.page();
    let per_page = pagination.per_page();
    let total_pages = if total == 0 {
        1
    } else {
        ((total as f64) / (per_page as f64)).ceil() as u32
    };

    let scan_values: Vec<minijinja::Value> = scans
        .iter()
        .map(|s| {
            minijinja::Value::from_serialize(&serde_json::json!({
                "id": s.id,
                "scan_type": s.scan_type,
                "status": s.status,
                "finding_count": s.finding_count,
                "created_at": s.created_at.format("%Y-%m-%d %H:%M").to_string(),
            }))
        })
        .collect();

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        repo => minijinja::Value::from_serialize(&serde_json::json!({
            "id": repo.id,
            "name": repo.name,
            "source_type": repo.source_type,
            "remote_url": repo.remote_url,
            "default_branch": repo.default_branch,
        })),
        scans => scan_values,
        page => page,
        per_page => per_page,
        total => total,
        total_pages => total_pages,
    };

    render_html(&state, "pages/repo_detail.html", ctx)
}

async fn scan_detail_page(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    req: HttpRequest,
) -> HttpResponse {
    let scan_id = path.into_inner();

    let scan = match state.db.get_scan_by_id(scan_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found_html(&state);
        }
        Err(e) => {
            error!("Failed to fetch scan {scan_id}: {e}");
            return server_error_html(&state);
        }
    };

    let stages = state.db.list_scan_stages(scan_id).await.unwrap_or_default();

    let stage_values: Vec<minijinja::Value> = stages
        .iter()
        .map(|s| {
            minijinja::Value::from_serialize(&serde_json::json!({
                "stage": s.stage,
                "status": s.status,
            }))
        })
        .collect();

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        scan => minijinja::Value::from_serialize(&serde_json::json!({
            "id": scan.id,
            "repo_id": scan.repo_id,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "finding_count": scan.finding_count,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count,
        })),
        stages => stage_values,
    };

    render_html(&state, "pages/scan.html", ctx)
}

async fn scan_findings_page(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    query: web::Query<FindingsQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let scan_id = path.into_inner();

    let severity = query.severity.as_deref();
    let status = query.status.as_deref();
    let pagination = PaginationParams {
        page: query.page,
        per_page: query.per_page,
    };

    let total = state
        .db
        .count_findings_by_scan(scan_id, severity, status)
        .await
        .unwrap_or(0);

    let findings = state
        .db
        .list_findings_by_scan_paginated(
            scan_id,
            severity,
            status,
            pagination.limit(),
            pagination.offset(),
        )
        .await
        .unwrap_or_default();

    let page = pagination.page();
    let per_page = pagination.per_page();
    let total_pages = if total == 0 {
        1
    } else {
        ((total as f64) / (per_page as f64)).ceil() as u32
    };

    let finding_values: Vec<minijinja::Value> = findings
        .iter()
        .map(|f| {
            minijinja::Value::from_serialize(&serde_json::json!({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "status": f.status,
                "file_path": f.file_path,
                "line_start": f.line_start,
                "cwe_id": f.cwe_id,
                "cve_id": f.cve_id,
            }))
        })
        .collect();

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        scan_id => scan_id.to_string(),
        findings => finding_values,
        page => page,
        per_page => per_page,
        total => total,
        total_pages => total_pages,
    };

    render_html(&state, "pages/findings.html", ctx)
}

async fn finding_detail_page(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    req: HttpRequest,
) -> HttpResponse {
    let finding_id = path.into_inner();

    let finding = match state.db.get_finding_by_id(finding_id).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return not_found_html(&state);
        }
        Err(e) => {
            error!("Failed to fetch finding {finding_id}: {e}");
            return server_error_html(&state);
        }
    };

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        finding => minijinja::Value::from_serialize(&serde_json::json!({
            "id": finding.id,
            "scan_id": finding.scan_id,
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "status": finding.status,
            "description": finding.description,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "code_snippet": finding.code_snippet,
            "suggested_patch": finding.suggested_patch,
            "cwe_id": finding.cwe_id,
            "cve_id": finding.cve_id,
            "poc_exploit_json": finding.poc_exploit_json,
            "poc_validated": finding.poc_validated,
            "agent_reasoning": finding.agent_reasoning,
        })),
    };

    render_html(&state, "pages/finding_detail.html", ctx)
}

async fn threat_model_page(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    req: HttpRequest,
) -> HttpResponse {
    let scan_id = path.into_inner();

    let threat_model = match state.db.get_threat_model_by_scan(scan_id).await {
        Ok(Some(tm)) => tm,
        Ok(None) => {
            return not_found_html(&state);
        }
        Err(e) => {
            error!("Failed to fetch threat model for scan {scan_id}: {e}");
            return server_error_html(&state);
        }
    };

    let boundaries: Vec<serde_json::Value> = threat_model
        .boundaries_json
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();

    let surfaces: Vec<serde_json::Value> = threat_model
        .surfaces_json
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();

    let data_flows: Vec<serde_json::Value> = threat_model
        .data_flows_json
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        scan_id => scan_id.to_string(),
        threat_model => minijinja::Value::from_serialize(&serde_json::json!({
            "summary": threat_model.summary,
        })),
        boundaries => minijinja::Value::from_serialize(&boundaries),
        surfaces => minijinja::Value::from_serialize(&surfaces),
        data_flows => minijinja::Value::from_serialize(&data_flows),
    };

    render_html(&state, "pages/threat_model.html", ctx)
}

async fn settings_page(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = get_user(&req).expect("auth middleware ensures user exists");
    let ai_cfg = &state.config.ai;

    let api_keys = state.db.list_api_keys_by_user(user.id).await.unwrap_or_default();
    let key_values: Vec<minijinja::Value> = api_keys
        .iter()
        .map(|k| {
            minijinja::Value::from_serialize(&serde_json::json!({
                "id": k.id,
                "provider": k.provider,
                "label": k.label,
                "created_at": k.created_at.format("%Y-%m-%d %H:%M").to_string(),
            }))
        })
        .collect();

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        ai_config => minijinja::Value::from_serialize(&serde_json::json!({
            "has_anthropic": ai_cfg.anthropic_api_key.is_some(),
            "has_openai": ai_cfg.openai_api_key.is_some(),
            "has_ollama": ai_cfg.ollama_url.is_some(),
            "default_model": ai_cfg.default_model,
        })),
        api_keys => key_values,
    };

    render_html(&state, "pages/settings.html", ctx)
}

/// Default 404 handler for unmatched routes.
pub async fn default_not_found(state: web::Data<AppState>) -> HttpResponse {
    not_found_html(&state)
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct FindingsQuery {
    severity: Option<String>,
    status: Option<String>,
    page: Option<u32>,
    per_page: Option<u32>,
}
