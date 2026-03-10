//
//  heimdall
//  src/routes/scans.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::db::DatabaseOperations;
use crate::models::{ApiResponse, PaginatedResponse, PaginationParams};
use crate::sse::{ScanBroadcaster, ScanEvent, ScanEventType};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
struct FindingsQuery {
    severity: Option<String>,
    status: Option<String>,
    page: Option<u32>,
    per_page: Option<u32>,
}

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

async fn get_scan(state: web::Data<AppState>, path: web::Path<Uuid>) -> HttpResponse {
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
    query: web::Query<FindingsQuery>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let pagination = PaginationParams {
        page: query.page,
        per_page: query.per_page,
    };
    let severity = query.severity.as_deref();
    let status = query.status.as_deref();

    let total = match state.db.count_findings_by_scan(scan_id, severity, status).await {
        Ok(t) => t,
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to count findings: {e}"),
            ));
        }
    };

    match state
        .db
        .list_findings_by_scan_paginated(
            scan_id,
            severity,
            status,
            pagination.limit(),
            pagination.offset(),
        )
        .await
    {
        Ok(findings) => {
            let resp = PaginatedResponse::new(findings, total, pagination.page(), pagination.per_page());
            HttpResponse::Ok().json(ApiResponse::ok(resp))
        }
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to list findings: {e}"),
        )),
    }
}

async fn get_scan_threat_model(state: web::Data<AppState>, path: web::Path<Uuid>) -> HttpResponse {
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

async fn get_scan_patches(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    match state.db.list_patches_by_scan(scan_id).await {
        Ok(patches) => HttpResponse::Ok().json(ApiResponse::ok(patches)),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to list patches: {e}"),
        )),
    }
}

/// Format a `ScanEvent` as an SSE text frame.
fn format_sse_event(event: &ScanEvent) -> String {
    format!(
        "event: {}\ndata: {}\n\n",
        event.event_type.as_event_name(),
        serde_json::to_string(&event.data).unwrap_or_default()
    )
}

/// Build the initial SSE payload describing the current scan state (fetched from DB).
async fn build_initial_state(db: &DatabaseOperations, scan_id: Uuid) -> String {
    let mut payload = String::new();

    // Send current scan status
    if let Ok(Some(scan)) = db.get_scan_by_id(scan_id).await {
        let data = serde_json::json!({
            "scan_id": scan_id,
            "status": scan.status,
            "timestamp": scan.updated_at.to_rfc3339(),
        });
        payload.push_str(&format!(
            "event: status_change\ndata: {}\n\n",
            serde_json::to_string(&data).unwrap_or_default()
        ));
    }

    // Send current stage statuses
    if let Ok(stages) = db.list_scan_stages(scan_id).await {
        for stage in stages {
            let mut data = serde_json::json!({
                "scan_id": scan_id,
                "stage": stage.stage,
                "status": stage.status,
                "timestamp": stage.created_at.to_rfc3339(),
            });
            if let Some(err) = &stage.error_message {
                data["error"] = serde_json::Value::String(err.clone());
            }
            payload.push_str(&format!(
                "event: stage_update\ndata: {}\n\n",
                serde_json::to_string(&data).unwrap_or_default()
            ));
        }
    }

    payload
}

async fn scan_progress_stream(state: web::Data<AppState>, path: web::Path<Uuid>) -> HttpResponse {
    let scan_id = path.into_inner();
    let db: Arc<DatabaseOperations> = Arc::clone(&state.db);
    let sse: Arc<ScanBroadcaster> = Arc::clone(&state.sse);

    // Subscribe before fetching initial state to avoid missing events
    let rx = sse.subscribe(scan_id);

    // Build initial state from DB
    let initial = build_initial_state(&db, scan_id).await;

    // Bridge the broadcast receiver into a tokio_stream-compatible stream
    let broadcast_stream = tokio_stream::wrappers::BroadcastStream::new(rx);

    // Build a channel-based stream for actix-web.
    // We use `std::io::Error` as the error type because it implements `Send`
    // (unlike `actix_web::Error`), which is required for `tokio::spawn`.
    let (tx, body_stream) = tokio::sync::mpsc::channel::<Result<web::Bytes, std::io::Error>>(32);

    tokio::spawn(async move {
        // 1) Send initial state snapshot
        if !initial.is_empty() {
            if tx.send(Ok(web::Bytes::from(initial))).await.is_err() {
                return; // Client disconnected
            }
        }

        // 2) Stream live events + keepalive
        let keepalive_interval = std::time::Duration::from_secs(15);

        tokio::pin!(broadcast_stream);

        loop {
            tokio::select! {
                item = broadcast_stream.next() => {
                    match item {
                        Some(Ok(event)) => {
                            let is_terminal = event.event_type == ScanEventType::ScanComplete
                                || event.event_type == ScanEventType::Error;
                            let frame = format_sse_event(&event);
                            if tx.send(Ok(web::Bytes::from(frame))).await.is_err() {
                                return; // Client disconnected
                            }
                            if is_terminal {
                                return; // Scan finished
                            }
                        }
                        Some(Err(_lagged)) => {
                            let msg = ": lagged — some events were skipped\n\n";
                            if tx.send(Ok(web::Bytes::from(msg))).await.is_err() {
                                return;
                            }
                        }
                        None => {
                            // Channel closed — scan broadcaster cleaned up
                            return;
                        }
                    }
                }
                _ = tokio::time::sleep(keepalive_interval) => {
                    if tx.send(Ok(web::Bytes::from(": keepalive\n\n"))).await.is_err() {
                        return; // Client disconnected
                    }
                }
            }
        }
    });

    let receiver_stream = tokio_stream::wrappers::ReceiverStream::new(body_stream);

    HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(receiver_stream)
}
