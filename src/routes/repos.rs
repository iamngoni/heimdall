//
//  heimdall
//  src/routes/repos.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::{web, HttpResponse};
use serde::Deserialize;
use uuid::Uuid;

use crate::models::ApiResponse;
use crate::state::AppState;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/repos")
            .route("", web::post().to(create_repo))
            .route("/new", web::get().to(new_repo_page))
            .route("/{id}", web::get().to(get_repo))
            .route("/{id}/scan", web::post().to(trigger_scan)),
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

async fn get_repo(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> HttpResponse {
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
    body: web::Json<CreateRepoRequest>,
) -> HttpResponse {
    let source_type = body.source_type.as_deref().unwrap_or("github");
    let default_branch = body.default_branch.as_deref();

    // TODO: get user_id from session
    let user_id = Uuid::nil();

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

async fn trigger_scan(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let repo_id = path.into_inner();

    // TODO: get user_id from session
    let user_id = Uuid::nil();

    match state
        .db
        .create_scan(repo_id, "full", Some(user_id), None, None, None)
        .await
    {
        Ok(scan) => HttpResponse::Accepted().json(ApiResponse::ok(scan)),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to trigger scan: {e}"),
        )),
    }
}
