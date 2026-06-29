//
//  heimdall
//  src/routes/repos.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_multipart::Multipart;
use actix_web::{Either, HttpMessage, HttpRequest, HttpResponse, web};
use futures_util::StreamExt;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write as IoWrite;
use std::sync::Arc;
use uuid::Uuid;

use crate::middleware::auth::AuthenticatedUser;
use crate::models::ApiResponse;
use crate::pipeline::ScanPipeline;
use crate::state::AppState;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/repos")
            .route("", web::post().to(create_repo))
            .route("/{id}", web::get().to(get_repo))
            .route("/{id}", web::delete().to(delete_repo))
            .route("/{id}/scan", web::post().to(trigger_scan))
            .route(
                "/{id}/issue-automation",
                web::patch().to(update_repo_issue_automation),
            )
            .route("/{id}/branches", web::get().to(list_repo_branches))
            .route("/{id}/branch", web::patch().to(update_repo_branch))
            .route(
                "/{id}/check-issue-tracker",
                web::get().to(check_issue_tracker),
            )
            .route("/upload", web::post().to(upload_zip))
            .route("/github/list", web::get().to(list_github_repos))
            .route("/gitlab/list", web::get().to(list_gitlab_repos))
            .route("/bitbucket/list", web::get().to(list_bitbucket_repos))
            .route("/import", web::post().to(import_repo)),
    );
}

#[derive(Debug, Deserialize)]
pub struct CreateRepoRequest {
    pub name: String,
    pub remote_url: Option<String>,
    pub source_type: Option<String>,
    pub default_branch: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIssueAutomationRequest {
    pub enabled: bool,
    pub min_severity: String,
}

async fn load_owned_repo(
    state: &AppState,
    repo_id: Uuid,
    user_id: Uuid,
) -> Result<crate::models::db_models::Repo, HttpResponse> {
    match state.db.get_repo_by_id_for_user(repo_id, user_id).await {
        Ok(Some(repo)) => Ok(repo),
        Ok(None) => Err(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            format!("Repo '{repo_id}' not found"),
        ))),
        Err(error) => Err(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to fetch repo: {error}"),
            )),
        ),
    }
}

async fn get_repo(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let repo_id = path.into_inner();
    match load_owned_repo(&state, repo_id, extract_user_id(&req)).await {
        Ok(repo) => HttpResponse::Ok().json(ApiResponse::ok(repo)),
        Err(response) => response,
    }
}

async fn delete_repo(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let repo_id = path.into_inner();

    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    let repo = match load_owned_repo(&state, repo_id, user.id).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };

    match state.db.delete_repo(repo_id).await {
        Ok(true) => {
            info!(
                "Repo {} ({}) deleted by user {}",
                repo.name, repo_id, user.id
            );

            if req.headers().contains_key("HX-Request") {
                return HttpResponse::Ok()
                    .insert_header(("HX-Redirect", "/repos"))
                    .finish();
            }

            HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "id": repo_id,
                "deleted": true,
            })))
        }
        Ok(false) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            format!("Repo '{repo_id}' not found"),
        )),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to delete repo: {e}"),
        )),
    }
}

async fn create_repo(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: Either<web::Json<CreateRepoRequest>, web::Form<CreateRepoRequest>>,
) -> HttpResponse {
    let body = match body {
        Either::Left(json) => json.into_inner(),
        Either::Right(form) => form.into_inner(),
    };
    let source_type = body.source_type.as_deref().unwrap_or("git_url");
    let default_branch = body.default_branch.as_deref();

    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");
    let user_id = user.id;

    match state
        .db
        .create_repo(
            user_id,
            &body.name,
            source_type,
            body.remote_url.as_deref(),
            default_branch,
            None,
        )
        .await
    {
        Ok(repo) => repo_created_response(&req, &repo),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to create repo: {e}"),
        )),
    }
}

async fn trigger_scan(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    req: HttpRequest,
) -> HttpResponse {
    let repo_id = path.into_inner();

    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");
    let user_id = user.id;

    let repo = match load_owned_repo(&state, repo_id, user_id).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };

    let runtime = match state.resolve_ai_for_user(repo.user_id).await {
        Ok(runtime) => runtime,
        Err(error) => {
            return HttpResponse::ServiceUnavailable()
                .json(ApiResponse::<()>::error(503, error.to_string()));
        }
    };

    // Create scan and job
    let scan = match state
        .db
        .create_scan(repo_id, "full", Some(user_id), None, None, None)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to create scan: {e}"),
            ));
        }
    };

    if state.worker_enabled {
        if let Err(e) = state.db.create_scan_job(scan.id).await {
            let _ = state
                .db
                .update_scan_status(scan.id, "failed", Some(&format!("{e:#}")))
                .await;
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to enqueue scan: {e}"),
            ));
        }

        info!(
            "Queued scan {} for repo {} using {} ({})",
            scan.id,
            repo.name,
            runtime.provider_kind.as_str(),
            runtime.source
        );
    } else {
        // Local/dev fallback when the background worker is disabled.
        let db = Arc::clone(&state.db);
        let sse = Arc::clone(&state.sse);
        let ai = Arc::clone(&runtime.provider);
        let model = runtime.model;
        let encryption_key = state.encryption_key;
        let data_dir = state.config.app.data_dir.clone();
        let semgrep_config = state.config.semgrep.clone();
        let scan_id = scan.id;
        let repo_name = repo.name.clone();

        let cancel_token = sse.register_cancellation_token(scan_id);
        tokio::spawn(async move {
            let pipeline = ScanPipeline::new(
                scan_id,
                db.clone(),
                ai,
                model,
                sse.clone(),
                encryption_key,
                data_dir,
                semgrep_config,
                cancel_token,
            );
            if let Err(e) = pipeline.run(&repo).await {
                error!("Scan pipeline failed for {scan_id}: {e:#}");
                if !pipeline.cancel_token.is_cancelled() {
                    sse.emit_error(scan_id, &format!("{e:#}"));
                    let _ = db
                        .update_scan_status(scan_id, "failed", Some(&format!("{e:#}")))
                        .await;
                }
                // Cleanup on error
                sse.cleanup_cancellation_token(scan_id);
            }
        });

        info!(
            "Started inline scan {} for repo {} using {} ({})",
            scan.id,
            repo_name,
            runtime.provider_kind.as_str(),
            runtime.source
        );
    }

    let mut response = HttpResponse::Accepted();
    if req.headers().contains_key("HX-Request") {
        response.insert_header(("HX-Redirect", format!("/scans/{}", scan.id)));
    }

    response.json(ApiResponse::ok(scan))
}

async fn update_repo_issue_automation(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: Either<web::Json<UpdateIssueAutomationRequest>, web::Form<UpdateIssueAutomationRequest>>,
) -> HttpResponse {
    let repo_id = path.into_inner();
    let body = match body {
        Either::Left(json) => json.into_inner(),
        Either::Right(form) => form.into_inner(),
    };
    let min_severity = body.min_severity.trim().to_ascii_lowercase();
    if !["critical", "high", "medium", "low"].contains(&min_severity.as_str()) {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            format!("Unsupported severity threshold: {}", body.min_severity),
        ));
    }

    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");
    let _repo = match load_owned_repo(&state, repo_id, user.id).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };

    match state
        .db
        .update_repo_issue_settings(repo_id, body.enabled, &min_severity)
        .await
    {
        Ok(Some(repo)) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "id": repo.id,
            "issue_auto_create_enabled": repo.issue_auto_create_enabled,
            "issue_auto_create_min_severity": repo.issue_auto_create_min_severity,
        }))),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            format!("Repo '{repo_id}' not found"),
        )),
        Err(error) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to update repository issue automation: {error}"),
        )),
    }
}

/// GET /repos/{id}/branches — list remote branches for a repo.
async fn list_repo_branches(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let repo_id = path.into_inner();
    let repo = match load_owned_repo(&state, repo_id, extract_user_id(&req)).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };

    let remote_url = match repo.remote_url.as_deref() {
        Some(url) => url,
        None => {
            return HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "branches": serde_json::Value::Array(vec![]),
                "message": "No remote URL configured.",
            })));
        }
    };

    let conn_id = match repo.oauth_connection_id {
        Some(id) => id,
        None => {
            return HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "branches": serde_json::Value::Array(vec![]),
                "message": "No provider connection found.",
            })));
        }
    };

    let conn = match state.db.get_oauth_connection_by_id(conn_id).await {
        Ok(Some(c)) => c,
        _ => {
            return HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "branches": serde_json::Value::Array(vec![]),
                "message": "Provider connection could not be loaded.",
            })));
        }
    };

    let token = match connection_access_token(&state, &conn) {
        Ok(t) => t,
        Err(msg) => {
            return HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "branches": serde_json::Value::Array(vec![]),
                "message": msg,
            })));
        }
    };

    // Extract owner/repo from remote URL
    let (owner, repo_name) = match extract_owner_repo(remote_url) {
        Some(pair) => pair,
        None => {
            return HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "branches": serde_json::Value::Array(vec![]),
                "message": "Could not determine repository path from remote URL.",
            })));
        }
    };

    let client = reqwest::Client::new();
    let provider = repo.source_type.as_str();

    let branches: Vec<String> = match provider {
        "github" => fetch_github_branches(&client, &token, &owner, &repo_name).await,
        "gitlab" => {
            fetch_gitlab_branches(
                &client,
                &token,
                &state.config.gitlab_oauth.base_url,
                &owner,
                &repo_name,
            )
            .await
        }
        "bitbucket" => fetch_bitbucket_branches(&client, &token, &conn, &owner, &repo_name).await,
        _ => vec![],
    };

    let mut seen = HashSet::new();
    let mut branches: Vec<String> = branches
        .into_iter()
        .filter(|branch| seen.insert(branch.clone()))
        .collect();
    branches.sort_unstable_by_key(|a| a.to_lowercase());

    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "branches": branches,
        "current": repo.default_branch,
    })))
}

const REMOTE_BRANCH_PAGE_SIZE: usize = 100;
const REMOTE_BRANCH_MAX_PAGES: usize = 50;

async fn fetch_github_branches(
    client: &reqwest::Client,
    token: &str,
    owner: &str,
    repo_name: &str,
) -> Vec<String> {
    #[derive(Deserialize)]
    struct GithubBranch {
        name: String,
    }

    let mut branches = Vec::new();

    for page in 1..=REMOTE_BRANCH_MAX_PAGES {
        let resp = client
            .get(format!(
                "https://api.github.com/repos/{owner}/{repo_name}/branches?per_page={REMOTE_BRANCH_PAGE_SIZE}&page={page}"
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("User-Agent", "Heimdall")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await;

        let page_branches = match resp {
            Ok(r) if r.status().is_success() => {
                r.json::<Vec<GithubBranch>>().await.unwrap_or_default()
            }
            _ => break,
        };

        let page_len = page_branches.len();
        if page_len == 0 {
            break;
        }

        branches.extend(page_branches.into_iter().map(|branch| branch.name));
        if page_len < REMOTE_BRANCH_PAGE_SIZE {
            break;
        }
    }

    branches
}

async fn fetch_gitlab_branches(
    client: &reqwest::Client,
    token: &str,
    base_url: &str,
    owner: &str,
    repo_name: &str,
) -> Vec<String> {
    #[derive(Deserialize)]
    struct GitlabBranch {
        name: String,
    }

    let encoded = format!("{owner}%2F{repo_name}");
    let base_url = base_url.trim_end_matches('/');
    let mut branches = Vec::new();

    for page in 1..=REMOTE_BRANCH_MAX_PAGES {
        let resp = client
            .get(format!(
                "{base_url}/api/v4/projects/{encoded}/repository/branches?per_page={REMOTE_BRANCH_PAGE_SIZE}&page={page}"
            ))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await;

        let page_branches = match resp {
            Ok(r) if r.status().is_success() => {
                r.json::<Vec<GitlabBranch>>().await.unwrap_or_default()
            }
            _ => break,
        };

        let page_len = page_branches.len();
        if page_len == 0 {
            break;
        }

        branches.extend(page_branches.into_iter().map(|branch| branch.name));
        if page_len < REMOTE_BRANCH_PAGE_SIZE {
            break;
        }
    }

    branches
}

async fn fetch_bitbucket_branches(
    client: &reqwest::Client,
    token: &str,
    conn: &crate::models::db_models::OauthConnection,
    owner: &str,
    repo_name: &str,
) -> Vec<String> {
    #[derive(Deserialize)]
    struct BitbucketBranchResponse {
        values: Vec<BitbucketBranch>,
        next: Option<String>,
    }

    #[derive(Deserialize)]
    struct BitbucketBranch {
        name: String,
    }

    let mut branches = Vec::new();
    let mut next_url = Some(format!(
        "https://api.bitbucket.org/2.0/repositories/{owner}/{repo_name}/refs/branches?pagelen={REMOTE_BRANCH_PAGE_SIZE}"
    ));

    for _ in 0..REMOTE_BRANCH_MAX_PAGES {
        let Some(url) = next_url.take() else {
            break;
        };

        let mut req = client.get(url);
        if conn.token_source == "pat" {
            req = req.basic_auth(&conn.provider_user_id, Some(token));
        } else {
            req = req.header("Authorization", format!("Bearer {token}"));
        }

        let resp = req.send().await;
        let payload = match resp {
            Ok(r) if r.status().is_success() => r
                .json::<BitbucketBranchResponse>()
                .await
                .unwrap_or(BitbucketBranchResponse {
                    values: Vec::new(),
                    next: None,
                }),
            _ => break,
        };

        let page_len = payload.values.len();
        if page_len == 0 {
            break;
        }

        branches.extend(payload.values.into_iter().map(|branch| branch.name));
        next_url = payload.next;
        if next_url.is_none() || page_len < REMOTE_BRANCH_PAGE_SIZE {
            break;
        }
    }

    branches
}

/// Extract owner/repo from a remote URL like https://github.com/owner/repo.git
fn extract_owner_repo(remote_url: &str) -> Option<(String, String)> {
    let trimmed = remote_url.trim().trim_end_matches(".git");
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    // Strip user@ prefix (e.g. Bitbucket URLs)
    let without_auth = without_scheme
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(without_scheme);
    let mut parts = without_auth.split('/').filter(|s| !s.is_empty());
    let _host = parts.next()?; // github.com, gitlab.com, bitbucket.org
    let owner = parts.next()?.to_string();
    let repo = parts.next()?.to_string();
    Some((owner, repo))
}

#[derive(Debug, Deserialize)]
struct UpdateBranchRequest {
    branch: String,
}

/// PATCH /repos/{id}/branch — update the default branch for a repo.
async fn update_repo_branch(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: Either<web::Json<UpdateBranchRequest>, web::Form<UpdateBranchRequest>>,
) -> HttpResponse {
    let repo_id = path.into_inner();
    let body = match body {
        Either::Left(json) => json.into_inner(),
        Either::Right(form) => form.into_inner(),
    };

    let branch = body.branch.trim();
    if branch.is_empty() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Branch name cannot be empty.",
        ));
    }

    if let Err(response) = load_owned_repo(&state, repo_id, extract_user_id(&req)).await {
        return response;
    }

    match state.db.update_repo_default_branch(repo_id, branch).await {
        Ok(Some(repo)) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "id": repo.id,
            "default_branch": repo.default_branch,
        }))),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            format!("Repo '{repo_id}' not found"),
        )),
        Err(error) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to update branch: {error}"),
        )),
    }
}

/// GET /repos/{id}/check-issue-tracker — check if Bitbucket issue tracker is enabled.
async fn check_issue_tracker(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let repo_id = path.into_inner();
    let repo = match load_owned_repo(&state, repo_id, extract_user_id(&req)).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };

    if repo.source_type != "bitbucket" {
        return HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "issue_tracker_enabled": true,
            "message": "Issue tracker check is only needed for Bitbucket repositories.",
            "issue_support_message": "New findings can create or sync BITBUCKET issues automatically.",
        })));
    }

    let conn_id = match repo.oauth_connection_id {
        Some(id) => id,
        None => {
            return HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "issue_tracker_enabled": false,
                "message": "No provider connection found for this repository.",
                "issue_support_message": "Issue creation becomes available once this repository is connected through the provider integration.",
            })));
        }
    };

    let conn = match state.db.get_oauth_connection_by_id(conn_id).await {
        Ok(Some(c)) => c,
        _ => {
            return HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "issue_tracker_enabled": false,
                "message": "Provider connection could not be loaded.",
                "issue_support_message": "Issue creation becomes available once this repository is connected through the provider integration.",
            })));
        }
    };

    let token = match crate::crypto::decode_stored_secret(
        conn.access_token_enc.as_deref().unwrap_or(""),
        state.encryption_key.as_ref(),
    ) {
        Ok(t) => t,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "issue_tracker_enabled": false,
                "message": "Failed to decode stored credentials.",
                "issue_support_message": "Issue creation becomes available once this repository is connected through the provider integration.",
            })));
        }
    };

    let remote_url = repo.remote_url.as_deref().unwrap_or("");
    match crate::integrations::issues::check_bitbucket_issue_tracker(remote_url, &token, &conn).await {
        Ok(true) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "issue_tracker_enabled": true,
            "message": "Bitbucket issue tracker is enabled.",
            "issue_support_message": "New findings can create or sync BITBUCKET issues automatically.",
        }))),
        Ok(false) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "issue_tracker_enabled": false,
            "message": "Issue tracker is still not enabled. Enable it in Bitbucket repository settings.",
            "issue_support_message": "Bitbucket issue tracker is not enabled for this repository. Enable it in Bitbucket repo settings, then recheck.",
        }))),
        Err(e) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "issue_tracker_enabled": false,
            "message": format!("Failed to check issue tracker: {e}"),
            "issue_support_message": "Bitbucket issue tracker could not be verified right now.",
        }))),
    }
}

/// Handle zip file upload: saves the file and creates a repo record.
async fn upload_zip(
    state: web::Data<AppState>,
    req: HttpRequest,
    mut payload: Multipart,
) -> HttpResponse {
    let user_id = req
        .extensions()
        .get::<crate::middleware::auth::AuthenticatedUser>()
        .map(|u| u.id)
        .unwrap_or_else(Uuid::nil);

    let upload_dir = std::path::PathBuf::from(&state.config.app.data_dir).join("uploads");
    if let Err(e) = std::fs::create_dir_all(&upload_dir) {
        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to create upload directory: {e}"),
        ));
    }

    let mut file_path: Option<std::path::PathBuf> = None;
    let mut repo_name: Option<String> = None;

    while let Some(Ok(mut field)) = payload.next().await {
        let content_disposition = match field.content_disposition() {
            Some(cd) => cd.clone(),
            None => continue,
        };
        let field_name = content_disposition.get_name().unwrap_or("");

        match field_name {
            "file" => {
                let original_name = content_disposition
                    .get_filename()
                    .unwrap_or("upload.zip")
                    .to_string();

                // Validate it's a zip file
                if !original_name.ends_with(".zip") {
                    return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                        400,
                        "Only .zip files are accepted",
                    ));
                }

                let dest = upload_dir.join(format!("{}-{}", Uuid::now_v7(), original_name));

                let mut f = match std::fs::File::create(&dest) {
                    Ok(f) => f,
                    Err(e) => {
                        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                            500,
                            format!("Failed to create upload file: {e}"),
                        ));
                    }
                };

                while let Some(Ok(chunk)) = field.next().await {
                    if let Err(e) = f.write_all(&chunk) {
                        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                            500,
                            format!("Failed to write upload data: {e}"),
                        ));
                    }
                }

                if repo_name.is_none() {
                    repo_name = Some(original_name.trim_end_matches(".zip").to_string());
                }
                file_path = Some(dest);
            }
            "name" => {
                let mut bytes = Vec::new();
                while let Some(Ok(chunk)) = field.next().await {
                    bytes.extend_from_slice(&chunk);
                }
                if let Ok(name) = String::from_utf8(bytes)
                    && !name.trim().is_empty()
                {
                    repo_name = Some(name.trim().to_string());
                }
            }
            _ => {}
        }
    }

    let file_path = match file_path {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                "No file field found in upload",
            ));
        }
    };

    let name = repo_name.unwrap_or_else(|| "uploaded-repo".to_string());

    // Create repo record with source_type="upload" and store the local path
    match state
        .db
        .create_repo(
            user_id,
            &name,
            "zip",
            Some(&file_path.to_string_lossy()),
            None,
            None,
        )
        .await
    {
        Ok(repo) => {
            info!("Zip upload created repo {} from {:?}", repo.id, file_path);
            repo_created_response(&req, &repo)
        }
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to create repo from upload: {e}"),
        )),
    }
}

#[derive(Debug, Deserialize)]
struct ImportRepoRequest {
    provider: String,
    full_name: String,
    clone_url: String,
    name: Option<String>,
    default_branch: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RemoteRepoQuery {
    q: Option<String>,
}

#[derive(Debug, Serialize)]
struct RemoteRepo {
    full_name: String,
    clone_url: String,
    description: Option<String>,
    default_branch: String,
    language: Option<String>,
    private: bool,
}

#[derive(Debug, Deserialize)]
struct GitHubRepo {
    full_name: String,
    clone_url: String,
    description: Option<String>,
    default_branch: Option<String>,
    language: Option<String>,
    private: bool,
}

#[derive(Debug, Deserialize)]
struct GitLabProject {
    path_with_namespace: String,
    http_url_to_repo: String,
    description: Option<String>,
    default_branch: Option<String>,
    language: Option<String>,
    visibility: String,
}

#[derive(Debug, Deserialize)]
struct BitbucketResponse {
    values: Vec<BitbucketRepo>,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BitbucketRepo {
    full_name: String,
    description: Option<String>,
    language: Option<String>,
    is_private: bool,
    mainbranch: Option<BitbucketBranch>,
    links: BitbucketLinks,
}

#[derive(Debug, Deserialize)]
struct BitbucketBranch {
    name: String,
}

#[derive(Debug, Deserialize)]
struct BitbucketLinks {
    clone: Vec<BitbucketCloneLink>,
}

#[derive(Debug, Deserialize)]
struct BitbucketCloneLink {
    name: String,
    href: String,
}

enum RemoteFetchError {
    Auth(String),
    Other(String),
}

// Cap the total pages we'll follow per listing as a safety stop against
// runaway pagination loops or pathological accounts.
const REMOTE_REPO_MAX_PAGES: usize = 50;

fn parse_next_link(link_header: &str) -> Option<String> {
    for part in link_header.split(',') {
        let segs: Vec<&str> = part.split(';').map(str::trim).collect();
        if segs.len() < 2 {
            continue;
        }
        let url_seg = segs[0];
        if !url_seg.starts_with('<') || !url_seg.ends_with('>') {
            continue;
        }
        let url = &url_seg[1..url_seg.len() - 1];
        if segs[1..].contains(&"rel=\"next\"") {
            return Some(url.to_string());
        }
    }
    None
}

fn apply_bitbucket_auth(
    builder: reqwest::RequestBuilder,
    conn: &crate::models::db_models::OauthConnection,
    token: &str,
) -> reqwest::RequestBuilder {
    if conn.token_source == "pat" {
        builder.basic_auth(&conn.provider_user_id, Some(token))
    } else {
        builder.header("Authorization", format!("Bearer {token}"))
    }
}

async fn fetch_bitbucket_repos(
    client: &reqwest::Client,
    conn: &crate::models::db_models::OauthConnection,
    token: &str,
) -> Result<Vec<RemoteRepo>, RemoteFetchError> {
    let mut workspace_slugs: Vec<String> = Vec::new();
    // /2.0/workspaces?role=member and /2.0/user/permissions/workspaces are
    // both sunset under CHANGE-2770/3022 (deprecation triggers post-auth, so
    // unauth probes return 401 misleadingly). /2.0/user/workspaces is the
    // shared base path of the documented replacement
    // /2.0/user/workspaces/{workspace}/permissions/repositories, so it's the
    // live discovery route.
    let mut next_url: Option<String> =
        Some("https://api.bitbucket.org/2.0/user/workspaces?pagelen=100".to_string());
    let mut pages = 0usize;
    while let Some(url) = next_url.take() {
        if pages >= REMOTE_REPO_MAX_PAGES {
            error!(
                "[bitbucket] workspaces pagination exceeded {REMOTE_REPO_MAX_PAGES} pages, stopping"
            );
            break;
        }
        pages += 1;
        info!("[bitbucket] listing workspaces page={pages}");
        let resp = apply_bitbucket_auth(client.get(&url), conn, token)
            .send()
            .await
            .map_err(|e| RemoteFetchError::Other(format!("Failed to reach Bitbucket: {e}")))?;
        let status = resp.status();
        info!("[bitbucket] workspaces API response: {status}");
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            let body = resp.text().await.unwrap_or_default();
            error!("[bitbucket] workspaces auth failed ({status}): {body}");
            return Err(RemoteFetchError::Auth(format!(
                "{} needs to be reconnected before repositories can be loaded.",
                provider_display_name("bitbucket")
            )));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RemoteFetchError::Other(format!(
                "{} workspaces API error ({status}): {body}",
                provider_display_name("bitbucket")
            )));
        }
        // Pull the body as text first so we can log a snippet if the shape
        // surprises us — Bitbucket's user-scoped endpoints have varied between
        // returning workspace objects directly and wrapping them in a
        // `workspace_membership` envelope, and we want diagnostics either way.
        let body = resp
            .text()
            .await
            .map_err(|e| RemoteFetchError::Other(format!("Failed to read workspaces body: {e}")))?;
        let value: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
            error!(
                "[bitbucket] workspaces JSON parse failed: {e}; body[..200]={}",
                body.chars().take(200).collect::<String>()
            );
            RemoteFetchError::Other(format!("Failed to parse workspaces: {e}"))
        })?;
        let values = value.get("values").and_then(|v| v.as_array());
        let Some(values) = values else {
            error!(
                "[bitbucket] workspaces response missing `values` array; body[..200]={}",
                body.chars().take(200).collect::<String>()
            );
            return Err(RemoteFetchError::Other(
                "Bitbucket workspaces response did not contain a values array".to_string(),
            ));
        };
        let mut found_in_page = 0usize;
        for entry in values {
            // Direct workspace object: { "slug": "..." }
            // Wrapped membership: { "workspace": { "slug": "..." } }
            let slug = entry.get("slug").and_then(|s| s.as_str()).or_else(|| {
                entry
                    .get("workspace")
                    .and_then(|w| w.get("slug"))
                    .and_then(|s| s.as_str())
            });
            if let Some(slug) = slug {
                workspace_slugs.push(slug.to_string());
                found_in_page += 1;
            }
        }
        if found_in_page == 0 && !values.is_empty() {
            // Couldn't find slugs in either shape — log so we can adapt.
            let sample = values.first().map(|v| v.to_string()).unwrap_or_default();
            error!(
                "[bitbucket] workspaces: no slug field found in entries (sample[..300]={})",
                sample.chars().take(300).collect::<String>()
            );
        }
        info!(
            "[bitbucket] workspaces page={pages}: parsed {} entries, kept {found_in_page}",
            values.len()
        );
        next_url = value
            .get("next")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());
    }

    let mut all_repos: Vec<RemoteRepo> = Vec::new();
    for slug in &workspace_slugs {
        let mut next_url: Option<String> = Some(format!(
            "https://api.bitbucket.org/2.0/repositories/{slug}?sort=-updated_on&pagelen=100"
        ));
        let mut pages = 0usize;
        while let Some(url) = next_url.take() {
            if pages >= REMOTE_REPO_MAX_PAGES {
                error!(
                    "[bitbucket] workspace {slug} pagination exceeded {REMOTE_REPO_MAX_PAGES} pages, stopping"
                );
                break;
            }
            pages += 1;
            info!("[bitbucket] listing repos for workspace={slug} page={pages}");
            let resp = apply_bitbucket_auth(client.get(&url), conn, token)
                .send()
                .await
                .map_err(|e| {
                    RemoteFetchError::Other(format!(
                        "Failed to reach Bitbucket workspace {slug}: {e}"
                    ))
                })?;
            let status = resp.status();
            info!("[bitbucket] workspace {slug} response: {status}");
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                let body = resp.text().await.unwrap_or_default();
                error!("[bitbucket] workspace {slug} auth failed ({status}): {body}");
                return Err(RemoteFetchError::Auth(format!(
                    "{} needs to be reconnected before repositories can be loaded.",
                    provider_display_name("bitbucket")
                )));
            }
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(RemoteFetchError::Other(format!(
                    "{} repositories API error ({status}) for workspace {slug}: {body}",
                    provider_display_name("bitbucket")
                )));
            }
            let parsed: BitbucketResponse = resp.json().await.map_err(|e| {
                RemoteFetchError::Other(format!(
                    "Failed to parse repositories for workspace {slug}: {e}"
                ))
            })?;
            for repo in parsed.values {
                let clone_url = repo
                    .links
                    .clone
                    .iter()
                    .find(|l| l.name == "https")
                    .map(|l| l.href.clone())
                    .unwrap_or_default();
                all_repos.push(RemoteRepo {
                    full_name: repo.full_name,
                    clone_url,
                    description: repo.description,
                    default_branch: repo
                        .mainbranch
                        .map(|b| b.name)
                        .unwrap_or_else(|| "main".to_string()),
                    language: repo.language,
                    private: repo.is_private,
                });
            }
            next_url = parsed.next;
        }
    }
    Ok(all_repos)
}

async fn fetch_github_repos(
    client: &reqwest::Client,
    token: &str,
) -> Result<Vec<RemoteRepo>, RemoteFetchError> {
    let mut next_url: Option<String> =
        Some("https://api.github.com/user/repos?sort=updated&per_page=100".to_string());
    let mut all = Vec::new();
    let mut pages = 0usize;
    while let Some(url) = next_url.take() {
        if pages >= REMOTE_REPO_MAX_PAGES {
            error!("[github] pagination exceeded {REMOTE_REPO_MAX_PAGES} pages, stopping");
            break;
        }
        pages += 1;
        info!("[github] listing repos page={pages}");
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("User-Agent", "Heimdall")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| RemoteFetchError::Other(format!("Failed to reach GitHub: {e}")))?;
        let status = resp.status();
        info!("[github] repos API response: {status}");
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            let body = resp.text().await.unwrap_or_default();
            error!("[github] auth failed ({status}): {body}");
            return Err(RemoteFetchError::Auth(format!(
                "{} needs to be reconnected before repositories can be loaded.",
                provider_display_name("github")
            )));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RemoteFetchError::Other(format!(
                "{} API error ({status}): {body}",
                provider_display_name("github")
            )));
        }
        let next = resp
            .headers()
            .get(reqwest::header::LINK)
            .and_then(|h| h.to_str().ok())
            .and_then(parse_next_link);
        let parsed: Vec<GitHubRepo> = resp
            .json()
            .await
            .map_err(|e| RemoteFetchError::Other(format!("Failed to parse repositories: {e}")))?;
        for repo in parsed {
            all.push(RemoteRepo {
                full_name: repo.full_name,
                clone_url: repo.clone_url,
                description: repo.description,
                default_branch: repo.default_branch.unwrap_or_else(|| "main".to_string()),
                language: repo.language,
                private: repo.private,
            });
        }
        next_url = next;
    }
    Ok(all)
}

async fn fetch_gitlab_repos(
    client: &reqwest::Client,
    token: &str,
) -> Result<Vec<RemoteRepo>, RemoteFetchError> {
    let mut next_url: Option<String> = Some(
        "https://gitlab.com/api/v4/projects?membership=true&order_by=updated_at&per_page=100"
            .to_string(),
    );
    let mut all = Vec::new();
    let mut pages = 0usize;
    while let Some(url) = next_url.take() {
        if pages >= REMOTE_REPO_MAX_PAGES {
            error!("[gitlab] pagination exceeded {REMOTE_REPO_MAX_PAGES} pages, stopping");
            break;
        }
        pages += 1;
        info!("[gitlab] listing projects page={pages}");
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| RemoteFetchError::Other(format!("Failed to reach GitLab: {e}")))?;
        let status = resp.status();
        info!("[gitlab] projects API response: {status}");
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            let body = resp.text().await.unwrap_or_default();
            error!("[gitlab] auth failed ({status}): {body}");
            return Err(RemoteFetchError::Auth(format!(
                "{} needs to be reconnected before repositories can be loaded.",
                provider_display_name("gitlab")
            )));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RemoteFetchError::Other(format!(
                "{} API error ({status}): {body}",
                provider_display_name("gitlab")
            )));
        }
        let next = resp
            .headers()
            .get(reqwest::header::LINK)
            .and_then(|h| h.to_str().ok())
            .and_then(parse_next_link);
        let parsed: Vec<GitLabProject> = resp
            .json()
            .await
            .map_err(|e| RemoteFetchError::Other(format!("Failed to parse projects: {e}")))?;
        for project in parsed {
            all.push(RemoteRepo {
                full_name: project.path_with_namespace,
                clone_url: project.http_url_to_repo,
                description: project.description,
                default_branch: project.default_branch.unwrap_or_else(|| "main".to_string()),
                language: project.language,
                private: project.visibility != "public",
            });
        }
        next_url = next;
    }
    Ok(all)
}

fn extract_user_id(req: &HttpRequest) -> Uuid {
    req.extensions()
        .get::<crate::middleware::auth::AuthenticatedUser>()
        .map(|u| u.id)
        .unwrap_or_else(Uuid::nil)
}

fn extract_user_theme(req: &HttpRequest) -> String {
    req.extensions()
        .get::<crate::middleware::auth::AuthenticatedUser>()
        .map(|u| u.theme.clone())
        .unwrap_or_else(|| crate::templates::DEFAULT_THEME.to_string())
}

async fn list_github_repos(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<RemoteRepoQuery>,
) -> HttpResponse {
    list_remote_repos(state, req, query, "github").await
}

async fn list_gitlab_repos(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<RemoteRepoQuery>,
) -> HttpResponse {
    list_remote_repos(state, req, query, "gitlab").await
}

async fn list_bitbucket_repos(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<RemoteRepoQuery>,
) -> HttpResponse {
    list_remote_repos(state, req, query, "bitbucket").await
}

async fn list_remote_repos(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<RemoteRepoQuery>,
    provider: &str,
) -> HttpResponse {
    let user_id = extract_user_id(&req);
    let theme = extract_user_theme(&req);
    let connected_urls: HashSet<String> = state
        .db
        .list_repos_by_user(user_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|repo| repo.remote_url)
        .map(|url| normalize_remote_url(&url))
        .collect();

    let conn = match state.db.get_oauth_connection(user_id, provider).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return render_remote_repo_list(
                &state,
                &theme,
                provider,
                &[],
                Some(&connected_urls),
                Some(&format!(
                    "No {} connection found. Connect your account first.",
                    provider_display_name(provider)
                )),
            );
        }
        Err(e) => {
            return render_remote_repo_list(
                &state,
                &theme,
                provider,
                &[],
                Some(&connected_urls),
                Some(&format!("Failed to load integration: {e}")),
            );
        }
    };

    let token = match connection_access_token(&state, &conn) {
        Ok(token) => token,
        Err(message) => {
            return render_remote_repo_list(
                &state,
                &theme,
                provider,
                &[],
                Some(&connected_urls),
                Some(&message),
            );
        }
    };
    let client = reqwest::Client::new();

    info!(
        "[{provider}] list_remote_repos: token_source={}, provider_user_id={}, token_len={}, token_prefix={}...",
        conn.token_source,
        conn.provider_user_id,
        token.len(),
        &token[..token.len().min(4)]
    );

    // Bitbucket App Passwords require Basic auth with the account email.
    // If the stored provider_user_id doesn't look like an email, the user
    // needs to re-save their credentials with the correct email.
    if provider == "bitbucket"
        && conn.token_source == "pat"
        && (conn.provider_user_id == "pat" || !conn.provider_user_id.contains('@'))
    {
        return render_remote_repo_list(
            &state,
            &theme,
            provider,
            &[],
            Some(&connected_urls),
            Some(
                "Bitbucket App Passwords require your account email for authentication. Please re-save your credentials in Settings with your Bitbucket account email.",
            ),
        );
    }

    // Each provider helper handles its own pagination (Link headers for
    // GitHub/GitLab, cursor URL in body for Bitbucket). Bitbucket additionally
    // iterates per workspace because cross-workspace `/2.0/repositories` was
    // sunset (CHANGE-2770).
    let result = match provider {
        "github" => fetch_github_repos(&client, &token).await,
        "gitlab" => fetch_gitlab_repos(&client, &token).await,
        "bitbucket" => fetch_bitbucket_repos(&client, &conn, &token).await,
        _ => unreachable!(),
    };

    match result {
        Ok(repos) => {
            let filtered = filter_remote_repos(repos, query.q.as_deref());
            render_remote_repo_list(
                &state,
                &theme,
                provider,
                &filtered,
                Some(&connected_urls),
                None,
            )
        }
        Err(RemoteFetchError::Auth(message)) | Err(RemoteFetchError::Other(message)) => {
            render_remote_repo_list(
                &state,
                &theme,
                provider,
                &[],
                Some(&connected_urls),
                Some(&message),
            )
        }
    }
}

fn connection_access_token(
    state: &AppState,
    connection: &crate::models::db_models::OauthConnection,
) -> Result<String, String> {
    let encoded = connection
        .access_token_enc
        .as_deref()
        .ok_or_else(|| "OAuth connection is missing an access token".to_string())?;

    crate::crypto::decode_stored_secret(encoded, state.encryption_key.as_ref()).map_err(|e| {
        error!(
            "Failed to decode {} OAuth token for user {}: {e:#}",
            connection.provider, connection.user_id
        );
        "Failed to decode stored OAuth credentials".to_string()
    })
}

fn provider_display_name(provider: &str) -> &'static str {
    match provider {
        "github" => "GitHub",
        "gitlab" => "GitLab",
        "bitbucket" => "Bitbucket",
        _ => "Provider",
    }
}

fn filter_remote_repos(mut repos: Vec<RemoteRepo>, query: Option<&str>) -> Vec<RemoteRepo> {
    if let Some(query) = query {
        let needle = query.trim().to_lowercase();
        if !needle.is_empty() {
            repos.retain(|repo| {
                repo.full_name.to_lowercase().contains(&needle)
                    || repo
                        .description
                        .as_deref()
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains(&needle)
                    || repo
                        .language
                        .as_deref()
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains(&needle)
            });
        }
    }

    repos
}

fn normalize_remote_url(url: &str) -> String {
    let mut normalized = url.trim().to_lowercase();

    if let Some(rest) = normalized.strip_prefix("https://") {
        normalized = rest.to_string();
    } else if let Some(rest) = normalized.strip_prefix("http://") {
        normalized = rest.to_string();
    }

    if let Some((_, rest)) = normalized.rsplit_once('@') {
        normalized = rest.to_string();
    }

    normalized.trim_end_matches(".git").to_string()
}

fn render_remote_repo_list(
    state: &AppState,
    theme: &str,
    provider: &str,
    repos: &[RemoteRepo],
    connected_urls: Option<&HashSet<String>>,
    error_message: Option<&str>,
) -> HttpResponse {
    let repo_values: Vec<minijinja::Value> = repos
        .iter()
        .map(|repo| {
            minijinja::Value::from_serialize(serde_json::json!({
                "full_name": repo.full_name,
                "clone_url": repo.clone_url,
                "description": repo.description,
                "default_branch": repo.default_branch,
                "language": repo.language,
                "private": repo.private,
                "already_connected": connected_urls
                    .map(|urls| urls.contains(&normalize_remote_url(&repo.clone_url)))
                    .unwrap_or(false),
            }))
        })
        .collect();

    let ctx = minijinja::context! {
        provider => provider,
        provider_name => provider_display_name(provider),
        repos => repo_values,
        error_message => error_message,
    };

    match state
        .themes
        .get(theme)
        .render("partials/repo_import_list.html", ctx)
    {
        Ok(html) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html),
        Err(e) => {
            error!("Failed to render repo import list: {e:#}");
            HttpResponse::InternalServerError()
                .content_type("text/plain; charset=utf-8")
                .body("Failed to render repository list")
        }
    }
}

async fn import_repo(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: Either<web::Json<ImportRepoRequest>, web::Form<ImportRepoRequest>>,
) -> HttpResponse {
    let body = match body {
        Either::Left(json) => json.into_inner(),
        Either::Right(form) => form.into_inner(),
    };
    let user_id = extract_user_id(&req);

    let provider = body.provider.as_str();
    if !matches!(provider, "github" | "gitlab" | "bitbucket") {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Provider must be 'github', 'gitlab', or 'bitbucket'.",
        ));
    }

    // Get OAuth connection for token embedding
    let conn = match state.db.get_oauth_connection(user_id, provider).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                format!("No {provider} OAuth connection found"),
            ));
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error(500, format!("{e}")));
        }
    };

    let repo_name = body.name.as_deref().unwrap_or(&body.full_name);

    match state
        .db
        .create_repo(
            user_id,
            repo_name,
            provider,
            Some(&body.clone_url),
            body.default_branch.as_deref(),
            Some(conn.id),
        )
        .await
    {
        Ok(repo) => repo_created_response(&req, &repo),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to import repo: {e}"),
        )),
    }
}

fn repo_created_response(req: &HttpRequest, repo: &crate::models::db_models::Repo) -> HttpResponse {
    let redirect_path = format!("/repos/{}", repo.id);

    if req.headers().contains_key("HX-Request") {
        return HttpResponse::Created()
            .insert_header(("HX-Redirect", redirect_path))
            .finish();
    }

    let accepts_html = req
        .headers()
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.contains("text/html"))
        .unwrap_or(false);

    if accepts_html {
        return HttpResponse::SeeOther()
            .insert_header(("Location", redirect_path))
            .finish();
    }

    HttpResponse::Created().json(ApiResponse::ok(repo))
}

#[cfg(test)]
mod tests {
    use super::parse_next_link;

    #[test]
    fn parses_github_style_link_header() {
        let header = r#"<https://api.github.com/user/repos?page=2>; rel="next", <https://api.github.com/user/repos?page=10>; rel="last""#;
        assert_eq!(
            parse_next_link(header),
            Some("https://api.github.com/user/repos?page=2".to_string())
        );
    }

    #[test]
    fn returns_none_when_no_next_rel() {
        let header = r#"<https://api.github.com/user/repos?page=10>; rel="last""#;
        assert_eq!(parse_next_link(header), None);
    }

    #[test]
    fn handles_extra_params_after_url() {
        let header = r#"<https://gitlab.com/api/v4/projects?page=2>; rel="next"; foo="bar""#;
        assert_eq!(
            parse_next_link(header),
            Some("https://gitlab.com/api/v4/projects?page=2".to_string())
        );
    }

    #[test]
    fn empty_header_yields_none() {
        assert_eq!(parse_next_link(""), None);
    }
}
