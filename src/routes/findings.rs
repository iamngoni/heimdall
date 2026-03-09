//
//  heimdall
//  src/routes/findings.rs
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
        web::scope("/findings")
            .route("/{id}", web::get().to(get_finding))
            .route("/{id}/status", web::patch().to(update_finding_status))
            .route("/{id}/apply-patch", web::post().to(apply_patch))
            .route("/{id}/comment", web::post().to(add_comment))
            .route("/{id}/severity", web::patch().to(update_severity)),
    );
}

#[derive(Debug, Deserialize)]
pub struct UpdateStatusRequest {
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSeverityRequest {
    pub severity: String,
}

#[derive(Debug, Deserialize)]
pub struct AddCommentRequest {
    pub comment: String,
}

async fn get_finding(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let finding_id = path.into_inner();
    match state.db.get_finding_by_id(finding_id).await {
        Ok(Some(finding)) => HttpResponse::Ok().json(ApiResponse::ok(finding)),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            format!("Finding '{finding_id}' not found"),
        )),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to fetch finding: {e}"),
        )),
    }
}

async fn update_finding_status(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateStatusRequest>,
) -> HttpResponse {
    let finding_id = path.into_inner();
    match state.db.update_finding_status(finding_id, &body.status).await {
        Ok(true) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "id": finding_id,
            "status": body.status,
        }))),
        Ok(false) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            format!("Finding '{finding_id}' not found"),
        )),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to update finding status: {e}"),
        )),
    }
}

async fn apply_patch(path: web::Path<Uuid>) -> HttpResponse {
    let finding_id = path.into_inner();
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "finding_id": finding_id,
        "message": "Apply patch — not yet implemented"
    })))
}

async fn add_comment(
    path: web::Path<Uuid>,
    body: web::Json<AddCommentRequest>,
) -> HttpResponse {
    let finding_id = path.into_inner();
    HttpResponse::Created().json(ApiResponse::ok(serde_json::json!({
        "finding_id": finding_id,
        "comment": body.comment,
        "message": "Comment added — not yet implemented"
    })))
}

async fn update_severity(
    path: web::Path<Uuid>,
    body: web::Json<UpdateSeverityRequest>,
) -> HttpResponse {
    let finding_id = path.into_inner();
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "finding_id": finding_id,
        "severity": body.severity,
        "message": "Severity update — not yet implemented"
    })))
}
