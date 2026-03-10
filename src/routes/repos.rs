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

    let runtime = match state.resolve_ai_for_user(repo.user_id).await {
        Ok(runtime) => runtime,
        Err(error) => {
            return HttpResponse::ServiceUnavailable()
                .json(ApiResponse::<()>::error(503, error.to_string()));
        }
    };

    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
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
        let scan_id = scan.id;
        let repo_name = repo.name.clone();

        tokio::spawn(async move {
            let pipeline =
                ScanPipeline::new(scan_id, db.clone(), ai, model, sse.clone(), encryption_key);
            if let Err(e) = pipeline.run(&repo).await {
                error!("Scan pipeline failed for {scan_id}: {e:#}");
                sse.emit_error(scan_id, &format!("{e:#}"));
                let _ = db
                    .update_scan_status(scan_id, "failed", Some(&format!("{e:#}")))
                    .await;
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

fn extract_user_id(req: &HttpRequest) -> Uuid {
    req.extensions()
        .get::<crate::middleware::auth::AuthenticatedUser>()
        .map(|u| u.id)
        .unwrap_or_else(Uuid::nil)
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

async fn list_remote_repos(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<RemoteRepoQuery>,
    provider: &str,
) -> HttpResponse {
    let user_id = extract_user_id(&req);
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
                provider,
                &[],
                Some(&connected_urls),
                Some(&message),
            );
        }
    };
    let client = reqwest::Client::new();

    let response = match provider {
        "github" => client
            .get("https://api.github.com/user/repos?sort=updated&per_page=100")
            .header("Authorization", format!("Bearer {token}"))
            .header("User-Agent", "Heimdall")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await,
        "gitlab" => client
            .get("https://gitlab.com/api/v4/projects?membership=true&order_by=updated_at&per_page=100")
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await,
        _ => unreachable!(),
    };

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                return render_remote_repo_list(
                    &state,
                    provider,
                    &[],
                    Some(&connected_urls),
                    Some(&format!(
                        "{} needs to be reconnected before repositories can be loaded.",
                        provider_display_name(provider)
                    )),
                );
            }
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return render_remote_repo_list(
                    &state,
                    provider,
                    &[],
                    Some(&connected_urls),
                    Some(&format!(
                        "{} API error ({status}): {body}",
                        provider_display_name(provider)
                    )),
                );
            }
            let repos = match provider {
                "github" => match resp.json::<Vec<GitHubRepo>>().await {
                    Ok(repos) => repos
                        .into_iter()
                        .map(|repo| RemoteRepo {
                            full_name: repo.full_name,
                            clone_url: repo.clone_url,
                            description: repo.description,
                            default_branch: repo
                                .default_branch
                                .unwrap_or_else(|| "main".to_string()),
                            language: repo.language,
                            private: repo.private,
                        })
                        .collect(),
                    Err(e) => {
                        return render_remote_repo_list(
                            &state,
                            provider,
                            &[],
                            Some(&connected_urls),
                            Some(&format!("Failed to parse repositories: {e}")),
                        );
                    }
                },
                "gitlab" => match resp.json::<Vec<GitLabProject>>().await {
                    Ok(projects) => projects
                        .into_iter()
                        .map(|project| RemoteRepo {
                            full_name: project.path_with_namespace,
                            clone_url: project.http_url_to_repo,
                            description: project.description,
                            default_branch: project
                                .default_branch
                                .unwrap_or_else(|| "main".to_string()),
                            language: project.language,
                            private: project.visibility != "public",
                        })
                        .collect(),
                    Err(e) => {
                        return render_remote_repo_list(
                            &state,
                            provider,
                            &[],
                            Some(&connected_urls),
                            Some(&format!("Failed to parse projects: {e}")),
                        );
                    }
                },
                _ => unreachable!(),
            };

            let filtered = filter_remote_repos(repos, query.q.as_deref());
            render_remote_repo_list(&state, provider, &filtered, Some(&connected_urls), None)
        }
        Err(e) => render_remote_repo_list(
            &state,
            provider,
            &[],
            Some(&connected_urls),
            Some(&format!(
                "Failed to reach {}: {e}",
                provider_display_name(provider)
            )),
        ),
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
    provider: &str,
    repos: &[RemoteRepo],
    connected_urls: Option<&HashSet<String>>,
    error_message: Option<&str>,
) -> HttpResponse {
    let repo_values: Vec<minijinja::Value> = repos
        .iter()
        .map(|repo| {
            minijinja::Value::from_serialize(&serde_json::json!({
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
        .templates
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
            None,
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
