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
        .route("/repos/new", web::get().to(repo_new_page))
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

fn user_initial(req: &HttpRequest) -> String {
    get_user(req)
        .and_then(|user| {
            user.display_name
                .as_deref()
                .or(Some(user.email.as_str()))
                .and_then(|value| value.chars().next())
        })
        .unwrap_or('H')
        .to_uppercase()
        .collect()
}

fn source_type_label(source_type: &str) -> &'static str {
    match source_type {
        "github" => "GitHub",
        "gitlab" => "GitLab",
        "git_url" => "Git URL",
        "zip" => "ZIP Upload",
        _ => "Source",
    }
}

async fn oauth_connections_ctx(state: &AppState, user_id: Uuid) -> minijinja::Value {
    let oauth_connections = state
        .db
        .list_oauth_connections_by_user(user_id)
        .await
        .unwrap_or_default();

    let github = oauth_connections
        .iter()
        .find(|conn| conn.provider == "github");
    let gitlab = oauth_connections
        .iter()
        .find(|conn| conn.provider == "gitlab");

    minijinja::Value::from_serialize(&serde_json::json!({
        "github": {
            "connected": github.is_some(),
            "scopes": github.and_then(|conn| conn.scopes.clone()),
            "updated_at": github.map(|conn| conn.updated_at.format("%Y-%m-%d %H:%M").to_string()),
        },
        "gitlab": {
            "connected": gitlab.is_some(),
            "scopes": gitlab.and_then(|conn| conn.scopes.clone()),
            "updated_at": gitlab.map(|conn| conn.updated_at.format("%Y-%m-%d %H:%M").to_string()),
        }
    }))
}

#[derive(Debug, serde::Deserialize)]
struct RepoNewQuery {
    source: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct SettingsPageQuery {
    integration_error: Option<String>,
}

async fn dashboard_page(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = get_user(&req).expect("auth middleware ensures user exists");

    let repos = state
        .db
        .list_repos_by_user(user.id)
        .await
        .unwrap_or_default();
    let total_repos = repos.len();

    let mut recent_scan_rows = Vec::new();
    let mut repo_summaries = Vec::new();
    for repo in &repos {
        if let Ok(scans) = state.db.list_scans_by_repo(repo.id).await {
            let latest_scan = scans.first();

            repo_summaries.push(minijinja::Value::from_serialize(&serde_json::json!({
                "id": repo.id,
                "name": repo.name,
                "host": match repo.source_type.as_str() {
                    "github" | "gitlab" | "git_url" => repo
                        .remote_url
                        .as_deref()
                        .and_then(|remote| remote.split('/').nth(2))
                        .unwrap_or("Unknown host"),
                    "zip" => "ZIP Upload",
                    _ => "Local / Upload",
                },
                "source_label": source_type_label(&repo.source_type),
                "last_scan_status": latest_scan.as_ref().map(|scan| scan.status.clone()),
                "last_scan_at": latest_scan
                    .as_ref()
                    .map(|scan| scan.created_at.format("%Y-%m-%d %H:%M").to_string()),
                "finding_count": latest_scan.as_ref().map(|scan| scan.finding_count).unwrap_or(0),
            })));

            for scan in scans {
                recent_scan_rows.push((
                    scan.created_at.timestamp(),
                    minijinja::Value::from_serialize(&serde_json::json!({
                        "id": scan.id,
                        "repo_name": repo.name,
                        "status": scan.status,
                        "scan_type": scan.scan_type,
                        "finding_count": scan.finding_count,
                        "created_at": scan.created_at.format("%Y-%m-%d %H:%M").to_string(),
                    })),
                ));
            }
        }
    }
    recent_scan_rows.sort_by(|left, right| right.0.cmp(&left.0));
    let recent_scans: Vec<minijinja::Value> = recent_scan_rows
        .into_iter()
        .take(8)
        .map(|(_, scan)| scan)
        .collect();

    let open_findings: i64 = state
        .db
        .count_open_findings_by_user(user.id)
        .await
        .unwrap_or(0);
    let critical_findings: i64 = state
        .db
        .count_critical_findings_by_user(user.id)
        .await
        .unwrap_or(0);

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        user_initial => user_initial(&req),
        stats => minijinja::Value::from_serialize(&serde_json::json!({
            "total_repos": total_repos,
            "recent_scans": recent_scans.len(),
            "open_findings": open_findings,
            "critical_findings": critical_findings,
        })),
        recent_scans => recent_scans,
        repo_summaries => repo_summaries.into_iter().take(5).collect::<Vec<_>>(),
        integrations => oauth_connections_ctx(&state, user.id).await,
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

    let mut repo_values = Vec::with_capacity(repos.len());
    for repo in &repos {
        let latest_scan = state
            .db
            .list_scans_by_repo(repo.id)
            .await
            .unwrap_or_default()
            .into_iter()
            .next();

        repo_values.push(minijinja::Value::from_serialize(&serde_json::json!({
            "id": repo.id,
            "name": repo.name,
            "source_type": repo.source_type,
            "source_label": source_type_label(&repo.source_type),
            "remote_url": repo.remote_url,
            "default_branch": repo.default_branch,
            "host": match repo.source_type.as_str() {
                "github" | "gitlab" | "git_url" => repo.remote_url
                    .as_deref()
                    .and_then(|remote| remote.split('/').nth(2))
                    .unwrap_or("Unknown host"),
                "zip" => "ZIP Upload",
                _ => "Local / Upload",
            },
            "last_scan_status": latest_scan.as_ref().map(|scan| scan.status.clone()),
            "last_scan_at": latest_scan.as_ref().map(|scan| scan.created_at.format("%Y-%m-%d %H:%M").to_string()),
            "finding_count": latest_scan.as_ref().map(|scan| scan.finding_count).unwrap_or(0),
            "created_at": repo.created_at.format("%Y-%m-%d %H:%M").to_string(),
        })));
    }

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        user_initial => user_initial(&req),
        repos => repo_values,
        page => page,
        per_page => per_page,
        total => total,
        total_pages => total_pages,
        integrations => oauth_connections_ctx(&state, user.id).await,
    };

    render_html(&state, "pages/repos.html", ctx)
}

async fn repo_new_page(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<RepoNewQuery>,
) -> HttpResponse {
    let user = get_user(&req).expect("auth middleware ensures user exists");
    let integrations = oauth_connections_ctx(&state, user.id).await;

    let requested_source = query.source.as_deref().unwrap_or("github");
    let active_source = match requested_source {
        "github" | "gitlab" | "git_url" | "zip" => requested_source,
        _ => "github",
    };

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        user_initial => user_initial(&req),
        active_source => active_source,
        integrations => integrations,
    };

    render_html(&state, "pages/repo_new.html", ctx)
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
                "short_id": s.id.to_string().chars().take(8).collect::<String>(),
                "scan_type": s.scan_type,
                "status": s.status,
                "finding_count": s.finding_count,
                "created_at": s.created_at.format("%Y-%m-%d %H:%M").to_string(),
            }))
        })
        .collect();

    let latest_scan = scans.first();

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        user_initial => user_initial(&req),
        repo => minijinja::Value::from_serialize(&serde_json::json!({
            "id": repo.id,
            "name": repo.name,
            "source_type": repo.source_type,
            "source_label": source_type_label(&repo.source_type),
            "remote_url": repo.remote_url,
            "default_branch": repo.default_branch,
            "host": match repo.source_type.as_str() {
                "github" | "gitlab" | "git_url" => repo
                    .remote_url
                    .as_deref()
                    .and_then(|remote| remote.split('/').nth(2))
                    .unwrap_or("Unknown host"),
                "zip" => "ZIP Upload",
                _ => "Local / Upload",
            },
        })),
        scans => scan_values,
        latest_scan => minijinja::Value::from_serialize(&serde_json::json!({
            "status": latest_scan.as_ref().map(|scan| scan.status.clone()),
            "created_at": latest_scan
                .as_ref()
                .map(|scan| scan.created_at.format("%Y-%m-%d %H:%M").to_string()),
            "finding_count": latest_scan.as_ref().map(|scan| scan.finding_count).unwrap_or(0),
        })),
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
        user_initial => user_initial(&req),
        scan => minijinja::Value::from_serialize(&serde_json::json!({
            "id": scan.id,
            "short_id": scan.id.to_string().chars().take(8).collect::<String>(),
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
    let scan = match state.db.get_scan_by_id(scan_id).await {
        Ok(Some(scan)) => scan,
        Ok(None) => return not_found_html(&state),
        Err(e) => {
            error!("Failed to fetch scan {scan_id} for findings page: {e}");
            return server_error_html(&state);
        }
    };
    let repo = match state.db.get_repo_by_id(scan.repo_id).await {
        Ok(Some(repo)) => repo,
        Ok(None) => return not_found_html(&state),
        Err(e) => {
            error!(
                "Failed to fetch repo {} for findings page: {e}",
                scan.repo_id
            );
            return server_error_html(&state);
        }
    };

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
                "source": f.source,
                "severity": f.severity,
                "confidence": f.confidence,
                "status": f.status,
                "file_path": f.file_path,
                "line_start": f.line_start,
                "cwe_id": f.cwe_id,
                "cve_id": f.cve_id,
                "updated_at": f.updated_at.format("%Y-%m-%d %H:%M").to_string(),
            }))
        })
        .collect();

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        user_initial => user_initial(&req),
        repo => minijinja::Value::from_serialize(&serde_json::json!({
            "id": repo.id,
            "name": repo.name,
        })),
        scan => minijinja::Value::from_serialize(&serde_json::json!({
            "id": scan.id,
            "status": scan.status,
            "finding_count": scan.finding_count,
        })),
        scan_id => scan_id.to_string(),
        findings => finding_values,
        severity_filter => query.severity.clone().unwrap_or_default(),
        status_filter => query.status.clone().unwrap_or_default(),
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
    let repo = match state.db.get_repo_by_id(finding.repo_id).await {
        Ok(Some(repo)) => repo,
        Ok(None) => return not_found_html(&state),
        Err(e) => {
            error!(
                "Failed to fetch repo {} for finding {finding_id}: {e}",
                finding.repo_id
            );
            return server_error_html(&state);
        }
    };
    let patch = state
        .db
        .get_patch_for_finding(finding_id)
        .await
        .unwrap_or_default();
    let events = state
        .db
        .list_finding_events(finding_id)
        .await
        .unwrap_or_default();
    let event_values: Vec<minijinja::Value> = events
        .iter()
        .rev()
        .take(6)
        .map(|event| {
            minijinja::Value::from_serialize(&serde_json::json!({
                "event_type": event.event_type,
                "old_value": event.old_value,
                "new_value": event.new_value,
                "comment": event.comment,
                "created_at": event.created_at.format("%Y-%m-%d %H:%M").to_string(),
            }))
        })
        .collect();

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        user_initial => user_initial(&req),
        repo => minijinja::Value::from_serialize(&serde_json::json!({
            "id": repo.id,
            "name": repo.name,
        })),
        finding => minijinja::Value::from_serialize(&serde_json::json!({
            "id": finding.id,
            "scan_id": finding.scan_id,
            "repo_id": finding.repo_id,
            "title": finding.title,
            "source": finding.source,
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
        patch => minijinja::Value::from_serialize(&serde_json::json!({
            "id": patch.as_ref().map(|patch| patch.id),
            "applied": patch.as_ref().map(|patch| patch.applied).unwrap_or(false),
            "created_at": patch
                .as_ref()
                .map(|patch| patch.created_at.format("%Y-%m-%d %H:%M").to_string()),
        })),
        events => event_values,
    };

    render_html(&state, "pages/finding_detail.html", ctx)
}

async fn threat_model_page(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    req: HttpRequest,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let scan = match state.db.get_scan_by_id(scan_id).await {
        Ok(Some(scan)) => scan,
        Ok(None) => return not_found_html(&state),
        Err(e) => {
            error!("Failed to fetch scan {scan_id} for threat model page: {e}");
            return server_error_html(&state);
        }
    };
    let repo = match state.db.get_repo_by_id(scan.repo_id).await {
        Ok(Some(repo)) => repo,
        Ok(None) => return not_found_html(&state),
        Err(e) => {
            error!(
                "Failed to fetch repo {} for threat model page: {e}",
                scan.repo_id
            );
            return server_error_html(&state);
        }
    };

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
        user_initial => user_initial(&req),
        repo => minijinja::Value::from_serialize(&serde_json::json!({
            "id": repo.id,
            "name": repo.name,
        })),
        scan => minijinja::Value::from_serialize(&serde_json::json!({
            "id": scan.id,
            "status": scan.status,
            "finding_count": scan.finding_count,
        })),
        scan_id => scan_id.to_string(),
        threat_model => minijinja::Value::from_serialize(&serde_json::json!({
            "id": threat_model.id,
            "summary": threat_model.summary,
            "model_version": threat_model.model_version,
            "updated_at": threat_model.updated_at.format("%Y-%m-%d %H:%M").to_string(),
        })),
        boundaries => minijinja::Value::from_serialize(&boundaries),
        surfaces => minijinja::Value::from_serialize(&surfaces),
        data_flows => minijinja::Value::from_serialize(&data_flows),
    };

    render_html(&state, "pages/threat_model.html", ctx)
}

async fn settings_page(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<SettingsPageQuery>,
) -> HttpResponse {
    let user = get_user(&req).expect("auth middleware ensures user exists");
    let ai_cfg = &state.config.ai;

    let api_keys = state
        .db
        .list_api_keys_by_user(user.id)
        .await
        .unwrap_or_default();
    let has_stored_anthropic = api_keys
        .iter()
        .any(|key| key.provider.as_deref() == Some("anthropic"));
    let has_stored_openai = api_keys
        .iter()
        .any(|key| key.provider.as_deref() == Some("openai"));
    let has_stored_ollama = api_keys
        .iter()
        .any(|key| key.provider.as_deref() == Some("ollama"));
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
        user_initial => user_initial(&req),
        integrations => oauth_connections_ctx(&state, user.id).await,
        ai_config => minijinja::Value::from_serialize(&serde_json::json!({
            "has_anthropic": ai_cfg.anthropic_api_key.is_some() || has_stored_anthropic,
            "has_openai": ai_cfg.openai_api_key.is_some() || has_stored_openai,
            "has_ollama": ai_cfg.ollama_url.is_some() || has_stored_ollama,
            "default_model": ai_cfg.default_model,
        })),
        api_keys => key_values,
        integration_error => query.integration_error.clone(),
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
