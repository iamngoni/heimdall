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

use crate::integrations::issues;
use crate::middleware::auth::AuthenticatedUser;
use crate::models::PaginationParams;
use crate::routes::scans::build_scan_live_snapshot;
use crate::state::AppState;

/// Public pages — no auth required.
pub fn init_public(cfg: &mut web::ServiceConfig) {
    cfg.route("/login", web::get().to(login_page))
        .route("/register", web::get().to(register_page));
}

/// Protected pages — require a valid session (auth middleware wraps these).
pub fn init_protected(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(dashboard_page))
        .route("/dashboard", web::get().to(dashboard_page))
        .route("/dashboard/", web::get().to(dashboard_page))
        .route("/repos", web::get().to(repos_page))
        .route("/repos/new", web::get().to(repo_new_page))
        .route("/repos/{id}", web::get().to(repo_detail_page))
        .route("/scans/{id}", web::get().to(scan_detail_page))
        .route("/scans/{id}/findings", web::get().to(scan_findings_page))
        .route("/scans/{id}/threat-model", web::get().to(threat_model_page))
        .route("/findings/{id}", web::get().to(finding_detail_page))
        .route("/settings", web::get().to(settings_page));
}

/// Helper: render a template using the specified theme and return an HTML response.
///
/// Automatically injects `current_theme` into the template context so every
/// page can render the `data-theme` attribute on `<body>`.
fn render_html(state: &AppState, template: &str, theme: &str, ctx: minijinja::Value) -> HttpResponse {
    let ctx = minijinja::context! {
        current_theme => theme,
        ..ctx
    };
    match state.themes.get(theme).render(template, ctx) {
        Ok(html) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html),
        Err(e) => {
            error!("Template render error for '{}' (theme '{}'): {e:#}", template, theme);
            server_error_html(state, theme)
        }
    }
}

/// Render a styled 404 Not Found page.
pub fn not_found_html(state: &AppState) -> HttpResponse {
    let theme = crate::templates::DEFAULT_THEME;
    let ctx = minijinja::context! {
        error_code => 404,
        error_title => "Not Found",
        error_message => "The page you're looking for doesn't exist.",
    };
    match state.themes.get(theme).render("pages/error.html", ctx) {
        Ok(html) => HttpResponse::NotFound()
            .content_type("text/html; charset=utf-8")
            .body(html),
        Err(_) => HttpResponse::NotFound().body("Not Found"),
    }
}

/// Render a styled 500 Server Error page.
fn server_error_html(state: &AppState, theme: &str) -> HttpResponse {
    let ctx = minijinja::context! {
        error_code => 500,
        error_title => "Server Error",
        error_message => "Something went wrong. Please try again later.",
    };
    match state.themes.get(theme).render("pages/error.html", ctx) {
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

/// Get the user's theme, falling back to the default.
fn user_theme(req: &HttpRequest) -> String {
    get_user(req)
        .map(|u| crate::templates::normalize_theme(&u.theme).to_string())
        .unwrap_or_else(|| crate::templates::DEFAULT_THEME.to_string())
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
        "bitbucket" => "Bitbucket",
        "git_url" => "Git URL",
        "zip" => "ZIP Upload",
        _ => "Source",
    }
}

fn humanize_slug(value: &str) -> String {
    value
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let mut label = first.to_uppercase().collect::<String>();
                    label.push_str(chars.as_str());
                    label
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_terminal_scan_status(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "cancelled")
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
    let bitbucket = oauth_connections
        .iter()
        .find(|conn| conn.provider == "bitbucket");

    minijinja::Value::from_serialize(&serde_json::json!({
        "github": {
            "connected": github.is_some(),
            "token_source": github.map(|conn| conn.token_source.as_str()).unwrap_or("none"),
            "scopes": github.and_then(|conn| conn.scopes.clone()),
            "updated_at": github.map(|conn| conn.updated_at.format("%Y-%m-%d %H:%M").to_string()),
        },
        "gitlab": {
            "connected": gitlab.is_some(),
            "token_source": gitlab.map(|conn| conn.token_source.as_str()).unwrap_or("none"),
            "scopes": gitlab.and_then(|conn| conn.scopes.clone()),
            "updated_at": gitlab.map(|conn| conn.updated_at.format("%Y-%m-%d %H:%M").to_string()),
        },
        "bitbucket": {
            "connected": bitbucket.is_some(),
            "token_source": bitbucket.map(|conn| conn.token_source.as_str()).unwrap_or("none"),
            "scopes": bitbucket.and_then(|conn| conn.scopes.clone()),
            "updated_at": bitbucket.map(|conn| conn.updated_at.format("%Y-%m-%d %H:%M").to_string()),
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
                    "github" | "gitlab" | "bitbucket" | "git_url" => repo
                        .remote_url
                        .as_deref()
                        .and_then(|remote| {
                            let host = remote.split('/').nth(2)?;
                            // Strip user@ prefix (e.g. Bitbucket URLs include username@)
                            Some(host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host))
                        })
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

    render_html(&state, "pages/dashboard.html", &user_theme(&req), ctx)
}

#[derive(Debug, serde::Deserialize)]
struct ThemeQuery {
    theme: Option<String>,
}

/// Resolve theme for pre-auth pages: query param > cookie > default.
fn resolve_public_theme(req: &HttpRequest, query_theme: Option<&str>) -> String {
    if let Some(t) = query_theme {
        if crate::templates::KNOWN_THEMES.contains(&t) {
            return t.to_string();
        }
    }
    if let Some(cookie) = req.cookie("heimdall_theme") {
        let v = cookie.value().to_string();
        if crate::templates::KNOWN_THEMES.contains(&v.as_str()) {
            return v;
        }
    }
    crate::templates::DEFAULT_THEME.to_string()
}

async fn login_page(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<ThemeQuery>,
) -> HttpResponse {
    let theme = resolve_public_theme(&req, query.theme.as_deref());
    let ctx = minijinja::context! {
        current_theme => &theme,
        available_themes => crate::templates::KNOWN_THEMES,
    };
    render_html(&state, "pages/login.html", &theme, ctx)
}

async fn register_page(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<ThemeQuery>,
) -> HttpResponse {
    let theme = resolve_public_theme(&req, query.theme.as_deref());
    let ctx = minijinja::context! {
        current_theme => &theme,
        available_themes => crate::templates::KNOWN_THEMES,
    };
    render_html(&state, "pages/register.html", &theme, ctx)
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

    render_html(&state, "pages/repos.html", &user_theme(&req), ctx)
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
        "github" | "gitlab" | "bitbucket" | "git_url" | "zip" => requested_source,
        _ => "github",
    };

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        user_initial => user_initial(&req),
        active_source => active_source,
        integrations => integrations,
    };

    render_html(&state, "pages/repo_new.html", &user_theme(&req), ctx)
}

async fn repo_detail_page(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    query: web::Query<PaginationParams>,
    req: HttpRequest,
) -> HttpResponse {
    let repo_id = path.into_inner();
    let pagination = query.into_inner();
    let user = get_user(&req).expect("auth middleware ensures user exists");

    let repo = match state.db.get_repo_by_id_for_user(repo_id, user.id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return not_found_html(&state);
        }
        Err(e) => {
            error!("Failed to fetch repo {repo_id}: {e}");
            return server_error_html(&state, &user_theme(&req));
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
    let scan_capability = match state.resolve_ai_for_user(repo.user_id).await {
        Ok(runtime) => serde_json::json!({
            "available": true,
            "provider": runtime.provider_kind.as_str(),
            "model": runtime.model,
            "source": runtime.source,
            "reason": serde_json::Value::Null,
        }),
        Err(error) => serde_json::json!({
            "available": false,
            "provider": serde_json::Value::Null,
            "model": serde_json::Value::Null,
            "source": serde_json::Value::Null,
            "reason": error.to_string(),
        }),
    };
    let issue_provider = issues::issue_provider(&repo);
    let base_supported = issues::supports_issue_creation(&repo);

    // For Bitbucket repos, check whether the issue tracker is actually enabled.
    let mut bb_issue_tracker_disabled = false;
    if base_supported && repo.source_type == "bitbucket" {
        if let Some(conn_id) = repo.oauth_connection_id {
            if let Ok(Some(conn)) = state.db.get_oauth_connection_by_id(conn_id).await {
                if let Ok(token) = crate::crypto::decode_stored_secret(
                    conn.access_token_enc.as_deref().unwrap_or(""),
                    state.encryption_key.as_ref(),
                ) {
                    if let Ok(false) = issues::check_bitbucket_issue_tracker(
                        repo.remote_url.as_deref().unwrap_or(""),
                        &token,
                        &conn,
                    )
                    .await
                    {
                        bb_issue_tracker_disabled = true;
                    }
                }
            }
        }
    }

    let effective_supported = base_supported && !bb_issue_tracker_disabled;
    let issue_support = serde_json::json!({
        "supported": effective_supported,
        "provider": issue_provider,
        "provider_label": issue_provider.map(str::to_uppercase),
        "bb_issue_tracker_disabled": bb_issue_tracker_disabled,
        "message": if bb_issue_tracker_disabled {
            "Bitbucket issue tracker is not enabled for this repository. Enable it in Bitbucket repo settings, then recheck.".to_string()
        } else if effective_supported {
            format!(
                "New findings can create or sync {} issues automatically.",
                issue_provider.unwrap_or("repository").to_uppercase()
            )
        } else if matches!(repo.source_type.as_str(), "github" | "gitlab" | "bitbucket") {
            "Issue creation becomes available once this repository is connected through the provider integration.".to_string()
        } else {
            "Issue creation is currently available for provider-backed GitHub, GitLab, and Bitbucket repositories.".to_string()
        }
    });

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
            "issue_auto_create_enabled": repo.issue_auto_create_enabled,
            "issue_auto_create_min_severity": repo.issue_auto_create_min_severity,
            "host": match repo.source_type.as_str() {
                "github" | "gitlab" | "bitbucket" | "git_url" => repo
                    .remote_url
                    .as_deref()
                    .and_then(|remote| {
                        let host = remote.split('/').nth(2)?;
                        Some(host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host))
                    })
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
        scan_capability => minijinja::Value::from_serialize(&scan_capability),
        issue_support => minijinja::Value::from_serialize(&issue_support),
        page => page,
        per_page => per_page,
        total => total,
        total_pages => total_pages,
    };

    render_html(&state, "pages/repo_detail.html", &user_theme(&req), ctx)
}

async fn scan_detail_page(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    req: HttpRequest,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let user = get_user(&req).expect("auth middleware ensures user exists");

    let scan = match state.db.get_scan_by_id_for_user(scan_id, user.id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found_html(&state);
        }
        Err(e) => {
            error!("Failed to fetch scan {scan_id}: {e}");
            return server_error_html(&state, &user_theme(&req));
        }
    };
    let repo = match state
        .db
        .get_repo_by_id_for_user(scan.repo_id, user.id)
        .await
    {
        Ok(Some(repo)) => repo,
        Ok(None) => return not_found_html(&state),
        Err(e) => {
            error!(
                "Failed to fetch repo {} for scan {scan_id}: {e}",
                scan.repo_id
            );
            return server_error_html(&state, &user_theme(&req));
        }
    };
    let live_snapshot = match build_scan_live_snapshot(state.db.as_ref(), scan_id).await {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return not_found_html(&state),
        Err(e) => {
            error!("Failed to build scan live snapshot for {scan_id}: {e:#}");
            return server_error_html(&state, &user_theme(&req));
        }
    };
    let stage_values = live_snapshot
        .get("stages")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let activity_values = live_snapshot
        .get("activity")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let current_task = live_snapshot
        .get("current_task")
        .cloned()
        .unwrap_or_else(|| {
            serde_json::json!({
                "stage": serde_json::Value::Null,
                "title": "Waiting for activity",
                "detail": "No execution activity has been recorded yet.",
                "progress_pct": serde_json::Value::Null,
                "timestamp": scan.updated_at.to_rfc3339(),
            })
        });
    let agent_calls = live_snapshot
        .get("agent_calls")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        user_initial => user_initial(&req),
        repo => minijinja::Value::from_serialize(&serde_json::json!({
            "id": repo.id,
            "name": repo.name,
            "issue_auto_create_enabled": repo.issue_auto_create_enabled,
            "issue_auto_create_min_severity": repo.issue_auto_create_min_severity,
        })),
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
            "status_label": humanize_slug(&scan.status),
            "is_live": !is_terminal_scan_status(&scan.status),
            "created_at": scan.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            "updated_at": scan.updated_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            "error_message": scan.error_message,
        })),
        stages => minijinja::Value::from_serialize(&stage_values),
        activities => minijinja::Value::from_serialize(&activity_values),
        current_task => minijinja::Value::from_serialize(&current_task),
        agent_calls => minijinja::Value::from_serialize(&agent_calls),
    };

    render_html(&state, "pages/scan.html", &user_theme(&req), ctx)
}

async fn scan_findings_page(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    query: web::Query<FindingsQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let user = get_user(&req).expect("auth middleware ensures user exists");
    let scan = match state.db.get_scan_by_id_for_user(scan_id, user.id).await {
        Ok(Some(scan)) => scan,
        Ok(None) => return not_found_html(&state),
        Err(e) => {
            error!("Failed to fetch scan {scan_id} for findings page: {e}");
            return server_error_html(&state, &user_theme(&req));
        }
    };
    let repo = match state
        .db
        .get_repo_by_id_for_user(scan.repo_id, user.id)
        .await
    {
        Ok(Some(repo)) => repo,
        Ok(None) => return not_found_html(&state),
        Err(e) => {
            error!(
                "Failed to fetch repo {} for findings page: {e}",
                scan.repo_id
            );
            return server_error_html(&state, &user_theme(&req));
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

    let issue_supported = crate::integrations::issues::supports_issue_creation(&repo);
    let issue_provider = crate::integrations::issues::issue_provider(&repo).unwrap_or("unknown");

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
        issue_supported => issue_supported,
        issue_provider => issue_provider,
    };

    render_html(&state, "pages/findings.html", &user_theme(&req), ctx)
}

async fn finding_detail_page(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    req: HttpRequest,
) -> HttpResponse {
    let finding_id = path.into_inner();
    let user = get_user(&req).expect("auth middleware ensures user exists");

    let finding = match state
        .db
        .get_finding_by_id_for_user(finding_id, user.id)
        .await
    {
        Ok(Some(f)) => f,
        Ok(None) => {
            return not_found_html(&state);
        }
        Err(e) => {
            error!("Failed to fetch finding {finding_id}: {e}");
            return server_error_html(&state, &user_theme(&req));
        }
    };
    let repo = match state
        .db
        .get_repo_by_id_for_user(finding.repo_id, user.id)
        .await
    {
        Ok(Some(repo)) => repo,
        Ok(None) => return not_found_html(&state),
        Err(e) => {
            error!(
                "Failed to fetch repo {} for finding {finding_id}: {e}",
                finding.repo_id
            );
            return server_error_html(&state, &user_theme(&req));
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
    let explain_review = latest_finding_review_value(&events, "ai_explanation");
    let verify_review = latest_finding_review_value(&events, "ai_verification");
    let issue_provider = issues::issue_provider(&repo);
    let repo_issue = match issue_provider {
        Some(provider) => state
            .db
            .get_repo_issue_by_fingerprint(repo.id, provider, &finding.fingerprint)
            .await
            .unwrap_or_default(),
        None => None,
    };
    let event_values: Vec<minijinja::Value> = events
        .iter()
        .rev()
        .take(6)
        .map(serialize_finding_event)
        .collect();

    let ctx = minijinja::context! {
        user => user_ctx(&req),
        user_initial => user_initial(&req),
        repo => minijinja::Value::from_serialize(&serde_json::json!({
            "id": repo.id,
            "name": repo.name,
            "remote_url": repo.remote_url,
            "source_type": repo.source_type,
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
        explain_review => explain_review,
        verify_review => verify_review,
        issue => minijinja::Value::from_serialize(&serde_json::json!({
            "supported": issues::supports_issue_creation(&repo),
            "provider": issue_provider,
            "url": repo_issue.as_ref().map(|issue| issue.issue_url.clone()),
            "number": repo_issue.as_ref().and_then(|issue| issue.external_issue_number.clone()),
            "state": repo_issue.as_ref().map(|issue| issue.state.clone()),
            "auto_created": repo_issue.as_ref().map(|issue| issue.auto_created).unwrap_or(false),
        })),
    };

    render_html(&state, "pages/finding_detail.html", &user_theme(&req), ctx)
}

async fn threat_model_page(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    req: HttpRequest,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let user = get_user(&req).expect("auth middleware ensures user exists");
    let scan = match state.db.get_scan_by_id_for_user(scan_id, user.id).await {
        Ok(Some(scan)) => scan,
        Ok(None) => return not_found_html(&state),
        Err(e) => {
            error!("Failed to fetch scan {scan_id} for threat model page: {e}");
            return server_error_html(&state, &user_theme(&req));
        }
    };
    let repo = match state
        .db
        .get_repo_by_id_for_user(scan.repo_id, user.id)
        .await
    {
        Ok(Some(repo)) => repo,
        Ok(None) => return not_found_html(&state),
        Err(e) => {
            error!(
                "Failed to fetch repo {} for threat model page: {e}",
                scan.repo_id
            );
            return server_error_html(&state, &user_theme(&req));
        }
    };

    let threat_model = match state
        .db
        .get_threat_model_by_scan_for_user(scan_id, user.id)
        .await
    {
        Ok(Some(tm)) => tm,
        Ok(None) => {
            return not_found_html(&state);
        }
        Err(e) => {
            error!("Failed to fetch threat model for scan {scan_id}: {e}");
            return server_error_html(&state, &user_theme(&req));
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

    render_html(&state, "pages/threat_model.html", &user_theme(&req), ctx)
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
        current_theme => crate::templates::normalize_theme(&user.theme).to_string(),
        available_themes => crate::templates::KNOWN_THEMES,
    };

    render_html(&state, "pages/settings.html", &user_theme(&req), ctx)
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

fn latest_finding_review_value(
    events: &[crate::models::db_models::FindingEvent],
    event_type: &str,
) -> minijinja::Value {
    events
        .iter()
        .rev()
        .find(|event| event.event_type == event_type)
        .map(|event| {
            minijinja::Value::from_serialize(&serde_json::json!({
                "created_at": event.created_at.format("%Y-%m-%d %H:%M").to_string(),
                "comment": event.comment,
                "metadata": event.metadata,
            }))
        })
        .unwrap_or_else(|| minijinja::Value::from(()))
}

fn serialize_finding_event(event: &crate::models::db_models::FindingEvent) -> minijinja::Value {
    let metadata = event.metadata.clone().unwrap_or(serde_json::Value::Null);
    let (title, detail, tone) = match event.event_type.as_str() {
        "status_change" => (
            "Status updated".to_string(),
            match (event.old_value.as_deref(), event.new_value.as_deref()) {
                (Some(old), Some(new)) => {
                    format!(
                        "Triage moved from {} to {}.",
                        humanize_slug(old),
                        humanize_slug(new)
                    )
                }
                (_, Some(new)) => format!("Triage moved to {}.", humanize_slug(new)),
                _ => event
                    .comment
                    .clone()
                    .unwrap_or_else(|| "The finding status was updated.".to_string()),
            },
            match event.new_value.as_deref() {
                Some("confirmed") | Some("fixed") => "success",
                Some("false_positive") => "warning",
                Some("dismissed") => "neutral",
                _ => "active",
            },
        ),
        "ai_explanation" => (
            "AI explanation generated".to_string(),
            metadata
                .get("summary")
                .and_then(|value| value.as_str())
                .or_else(|| event.comment.as_deref())
                .unwrap_or("Plain-language clarification is now available for this alert.")
                .to_string(),
            "active",
        ),
        "ai_verification" => {
            let verdict = metadata
                .get("verdict")
                .and_then(|value| value.as_str())
                .map(humanize_slug)
                .unwrap_or_else(|| "Needs Review".to_string());
            (
                format!("AI verification: {verdict}"),
                metadata
                    .get("rationale")
                    .and_then(|value| value.as_str())
                    .or_else(|| event.comment.as_deref())
                    .unwrap_or("A second-pass verification review was recorded.")
                    .to_string(),
                match metadata.get("verdict").and_then(|value| value.as_str()) {
                    Some("confirmed") => "success",
                    Some("false_positive_likely") => "warning",
                    _ => "active",
                },
            )
        }
        "issue_linked" => (
            "Repository issue linked".to_string(),
            match (
                metadata.get("provider").and_then(|value| value.as_str()),
                metadata
                    .get("external_issue_number")
                    .and_then(|value| value.as_str()),
                metadata.get("created").and_then(|value| value.as_bool()),
            ) {
                (Some(provider), Some(number), Some(true)) => format!(
                    "{} issue #{} was created for this finding.",
                    provider.to_uppercase(),
                    number
                ),
                (Some(provider), Some(number), _) => format!(
                    "Linked to existing {} issue #{} for this finding.",
                    provider.to_uppercase(),
                    number
                ),
                _ => event
                    .comment
                    .clone()
                    .unwrap_or_else(|| "Repository issue linkage changed.".to_string()),
            },
            "success",
        ),
        "patch_applied" => (
            "Suggested diff marked applied".to_string(),
            event
                .comment
                .clone()
                .unwrap_or_else(|| {
                    "The suggested diff was marked as applied in Heimdall. No repository write-back was recorded.".to_string()
                }),
            "success",
        ),
        "comment" => (
            "Comment added".to_string(),
            event
                .comment
                .clone()
                .unwrap_or_else(|| "A review comment was added.".to_string()),
            "neutral",
        ),
        "severity_change" => (
            "Severity updated".to_string(),
            match (event.old_value.as_deref(), event.new_value.as_deref()) {
                (Some(old), Some(new)) => format!(
                    "Severity changed from {} to {}.",
                    humanize_slug(old),
                    humanize_slug(new)
                ),
                (_, Some(new)) => format!("Severity changed to {}.", humanize_slug(new)),
                _ => "Severity changed.".to_string(),
            },
            "active",
        ),
        _ => (
            humanize_slug(&event.event_type),
            event
                .comment
                .clone()
                .or_else(|| event.new_value.clone())
                .or_else(|| event.old_value.clone())
                .unwrap_or_else(|| "Review activity was recorded.".to_string()),
            "neutral",
        ),
    };

    minijinja::Value::from_serialize(&serde_json::json!({
        "title": title,
        "detail": detail,
        "tone": tone,
        "created_at": event.created_at.format("%Y-%m-%d %H:%M").to_string(),
    }))
}
