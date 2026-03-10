//
//  heimdall
//  src/routes/repos.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_multipart::Multipart;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use futures_util::StreamExt;
use log::{error, info};
use serde::{Deserialize, Serialize};
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
            .route("/new", web::get().to(new_repo_page))
            .route("/{id}", web::get().to(get_repo))
            .route("/{id}/scan", web::post().to(trigger_scan))
            .route("/upload", web::post().to(upload_zip))
            .route("/github/list", web::get().to(list_github_repos))
            .route("/gitlab/list", web::get().to(list_gitlab_repos))
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

async fn new_repo_page() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("<html><body><h1>Heimdall — Add Repository</h1><p>Coming soon.</p></body></html>")
}

async fn get_repo(state: web::Data<AppState>, path: web::Path<Uuid>) -> HttpResponse {
    let repo_id = path.into_inner();
    match state.db.get_repo_by_id(repo_id).await {
        Ok(Some(repo)) => HttpResponse::Ok().json(ApiResponse::ok(repo)),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            format!("Repo '{repo_id}' not found"),
        )),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to fetch repo: {e}"),
        )),
    }
}

async fn create_repo(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CreateRepoRequest>,
) -> HttpResponse {
    let source_type = body.source_type.as_deref().unwrap_or("github");
    let default_branch = body.default_branch.as_deref();

    let user = req.extensions().get::<AuthenticatedUser>().cloned()
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
        Ok(repo) => HttpResponse::Created().json(ApiResponse::ok(repo)),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to create repo: {e}"),
        )),
    }
}

async fn trigger_scan(state: web::Data<AppState>, path: web::Path<Uuid>, req: HttpRequest) -> HttpResponse {
    let repo_id = path.into_inner();

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

    // Fetch the repo
    let repo = match state.db.get_repo_by_id(repo_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                format!("Repo '{repo_id}' not found"),
            ));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to fetch repo: {e}"),
            ));
        }
    };

    let user = req.extensions().get::<AuthenticatedUser>().cloned()
        .expect("auth middleware ensures user exists");
    let user_id = user.id;

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

    let _ = state.db.create_scan_job(scan.id).await;

    // Run pipeline in background
    let db = Arc::clone(&state.db);
    let sse = Arc::clone(&state.sse);
    let model = state.config.ai.default_model.clone();
    let scan_id = scan.id;
    let repo_name = repo.name.clone();

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

    info!("Scan {} triggered for repo {}", scan.id, repo_name);
    HttpResponse::Accepted().json(ApiResponse::ok(scan))
}

/// Handle zip file upload: saves the file and creates a repo record.
async fn upload_zip(
    state: web::Data<AppState>,
    req: HttpRequest,
    mut payload: Multipart,
) -> HttpResponse {
    let user_id = req.extensions()
        .get::<crate::middleware::auth::AuthenticatedUser>()
        .map(|u| u.id)
        .unwrap_or_else(Uuid::nil);

    let upload_dir = std::env::temp_dir().join("heimdall_uploads");
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
                if let Ok(name) = String::from_utf8(bytes) {
                    if !name.trim().is_empty() {
                        repo_name = Some(name.trim().to_string());
                    }
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
            HttpResponse::Created().json(ApiResponse::ok(repo))
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
}

#[derive(Debug, Serialize)]
struct RemoteRepo {
    full_name: String,
    clone_url: String,
    description: Option<String>,
    default_branch: String,
    private: bool,
}

#[derive(Debug, Deserialize)]
struct GitHubRepo {
    full_name: String,
    clone_url: String,
    description: Option<String>,
    default_branch: Option<String>,
    private: bool,
}

#[derive(Debug, Deserialize)]
struct GitLabProject {
    path_with_namespace: String,
    http_url_to_repo: String,
    description: Option<String>,
    default_branch: Option<String>,
    visibility: String,
}

fn extract_user_id(req: &HttpRequest) -> Uuid {
    req.extensions()
        .get::<crate::middleware::auth::AuthenticatedUser>()
        .map(|u| u.id)
        .unwrap_or_else(Uuid::nil)
}

async fn list_github_repos(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user_id = extract_user_id(&req);

    let conn = match state.db.get_oauth_connection(user_id, "github").await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                "No GitHub OAuth connection found. Connect your GitHub account first.",
            ))
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(500, format!("{e}")))
        }
    };

    let token = conn.access_token_enc.unwrap_or_default();
    let client = reqwest::Client::new();

    match client
        .get("https://api.github.com/user/repos?sort=updated&per_page=50")
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "Heimdall")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                // Token is invalid or missing required scopes — tell the client to re-authorize
                return HttpResponse::Ok().json(serde_json::json!({
                    "success": false,
                    "reauthorize": true,
                    "redirect": "/api/auth/github/authorize",
                    "error": "GitHub token expired or missing repo scope. Please reconnect your GitHub account."
                }));
            }
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return HttpResponse::BadGateway().json(ApiResponse::<()>::error(
                    502,
                    format!("GitHub API error ({status}): {body}"),
                ));
            }
            match resp.json::<Vec<GitHubRepo>>().await {
                Ok(repos) => {
                    let remote: Vec<RemoteRepo> = repos
                        .into_iter()
                        .map(|r| RemoteRepo {
                            full_name: r.full_name,
                            clone_url: r.clone_url,
                            description: r.description,
                            default_branch: r.default_branch.unwrap_or_else(|| "main".to_string()),
                            private: r.private,
                        })
                        .collect();
                    HttpResponse::Ok().json(ApiResponse::ok(remote))
                }
                Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                    500,
                    format!("Failed to parse GitHub repos: {e}"),
                )),
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to reach GitHub API: {e}"),
        )),
    }
}

async fn list_gitlab_repos(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user_id = extract_user_id(&req);

    let conn = match state.db.get_oauth_connection(user_id, "gitlab").await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                "No GitLab OAuth connection found. Connect your GitLab account first.",
            ))
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(500, format!("{e}")))
        }
    };

    let token = conn.access_token_enc.unwrap_or_default();
    let client = reqwest::Client::new();

    match client
        .get("https://gitlab.com/api/v4/projects?membership=true&order_by=updated_at&per_page=50")
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                return HttpResponse::Ok().json(serde_json::json!({
                    "success": false,
                    "reauthorize": true,
                    "redirect": "/api/auth/gitlab/authorize",
                    "error": "GitLab token expired or missing repository scope. Please reconnect your GitLab account."
                }));
            }
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return HttpResponse::BadGateway().json(ApiResponse::<()>::error(
                    502,
                    format!("GitLab API error ({status}): {body}"),
                ));
            }
            match resp.json::<Vec<GitLabProject>>().await {
                Ok(projects) => {
                    let remote: Vec<RemoteRepo> = projects
                        .into_iter()
                        .map(|p| RemoteRepo {
                            full_name: p.path_with_namespace,
                            clone_url: p.http_url_to_repo,
                            description: p.description,
                            default_branch: p.default_branch.unwrap_or_else(|| "main".to_string()),
                            private: p.visibility != "public",
                        })
                        .collect();
                    HttpResponse::Ok().json(ApiResponse::ok(remote))
                }
                Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                    500,
                    format!("Failed to parse GitLab projects: {e}"),
                )),
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to reach GitLab API: {e}"),
        )),
    }
}

async fn import_repo(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<ImportRepoRequest>,
) -> HttpResponse {
    let user_id = extract_user_id(&req);

    let provider = body.provider.as_str();
    if provider != "github" && provider != "gitlab" {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "Provider must be 'github' or 'gitlab'",
        ));
    }

    // Get OAuth connection for token embedding
    let conn = match state.db.get_oauth_connection(user_id, provider).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                400,
                format!("No {provider} OAuth connection found"),
            ))
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(500, format!("{e}")))
        }
    };

    // Embed token into clone URL for private repos
    let clone_url = if let Some(ref token) = conn.access_token_enc {
        embed_token_in_url(&body.clone_url, token)
    } else {
        body.clone_url.clone()
    };

    let repo_name = body.name.as_deref().unwrap_or(&body.full_name);

    match state
        .db
        .create_repo(
            user_id,
            repo_name,
            provider,
            Some(&clone_url),
            None,
            Some(conn.id),
        )
        .await
    {
        Ok(repo) => HttpResponse::Created().json(ApiResponse::ok(repo)),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to import repo: {e}"),
        )),
    }
}

/// Embed an OAuth token into a clone URL for authenticated cloning.
fn embed_token_in_url(url: &str, token: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        format!("https://oauth2:{token}@{rest}")
    } else {
        url.to_string()
    }
}
