//
//  heimdall
//  src/routes/scans.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::{web, HttpResponse};
use uuid::Uuid;

use crate::models::ApiResponse;
use crate::state::AppState;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/scans")
            .route("/{id}", web::get().to(get_scan))
            .route("/{id}/findings", web::get().to(get_scan_findings))
            .route("/{id}/threat-model", web::get().to(get_scan_threat_model))
            .route("/{id}/patches", web::get().to(get_scan_patches))
            .route("/{id}/progress/stream", web::get().to(scan_progress_stream)),
    );
}

async fn get_scan(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    match state.db.get_scan_by_id(scan_id).await {
        Ok(Some(scan)) => HttpResponse::Ok().json(ApiResponse::ok(scan)),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            format!("Scan '{scan_id}' not found"),
        )),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to fetch scan: {e}"),
        )),
    }
}

async fn get_scan_findings(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    match state.db.list_findings_by_scan(scan_id, None, None).await {
        Ok(findings) => HttpResponse::Ok().json(ApiResponse::ok(findings)),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to list findings: {e}"),
        )),
    }
}

async fn get_scan_threat_model(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    match state.db.get_threat_model_by_scan(scan_id).await {
        Ok(Some(model)) => HttpResponse::Ok().json(ApiResponse::ok(model)),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            format!("Threat model for scan '{scan_id}' not found"),
        )),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to fetch threat model: {e}"),
        )),
    }
}

async fn get_scan_patches(path: web::Path<Uuid>) -> HttpResponse {
    let scan_id = path.into_inner();
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "scan_id": scan_id,
        "patches": [],
        "message": "Patches endpoint — not yet implemented"
    })))
}

async fn scan_progress_stream(path: web::Path<Uuid>) -> HttpResponse {
    let scan_id = path.into_inner();
    // SSE placeholder — will be replaced with proper streaming
    HttpResponse::Ok()
        .content_type("text/event-stream")
        .body(format!("data: {{\"scan_id\": \"{scan_id}\", \"status\": \"pending\"}}\n\n"))
}
