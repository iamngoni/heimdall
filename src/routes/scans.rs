//
//  heimdall
//  src/routes/scans.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::db::DatabaseOperations;
use crate::models::ScanStage;
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
            .route("/{id}/live", web::get().to(get_scan_live))
            .route("/{id}/cancel", web::post().to(cancel_scan))
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

async fn get_scan_live(state: web::Data<AppState>, path: web::Path<Uuid>) -> HttpResponse {
    let scan_id = path.into_inner();
    match build_scan_live_snapshot(&state.db, scan_id).await {
        Ok(Some(snapshot)) => HttpResponse::Ok().json(ApiResponse::ok(snapshot)),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            format!("Scan '{scan_id}' not found"),
        )),
        Err(error) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to build live scan snapshot: {error}"),
        )),
    }
}

async fn cancel_scan(state: web::Data<AppState>, path: web::Path<Uuid>) -> HttpResponse {
    let scan_id = path.into_inner();

    let scan = match state.db.get_scan_by_id(scan_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                format!("Scan '{scan_id}' not found"),
            ));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to fetch scan: {e}"),
            ));
        }
    };

    // Only allow cancelling scans that are still running
    if matches!(scan.status.as_str(), "completed" | "failed" | "cancelled") {
        return HttpResponse::Conflict().json(ApiResponse::<()>::error(
            409,
            format!("Scan is already {}", scan.status),
        ));
    }

    // Mark as cancelled in DB
    if let Err(e) = state
        .db
        .update_scan_status(scan_id, "cancelled", Some("Cancelled by user"))
        .await
    {
        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to cancel scan: {e}"),
        ));
    }

    // Signal the cancellation token to abort the running pipeline task
    state.sse.cancel_scan(scan_id);

    // Emit SSE events so the UI updates immediately
    state.sse.emit_status_change(scan_id, "cancelled");
    state.sse.emit_error(scan_id, "Scan was cancelled by user");

    // Clean up the SSE channel after a short delay
    let sse = Arc::clone(&state.sse);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        sse.cleanup(scan_id);
    });

    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "id": scan_id,
        "status": "cancelled",
    })))
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

    let total = match state
        .db
        .count_findings_by_scan(scan_id, severity, status)
        .await
    {
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
            let resp =
                PaginatedResponse::new(findings, total, pagination.page(), pagination.per_page());
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

async fn get_scan_patches(state: web::Data<AppState>, path: web::Path<Uuid>) -> HttpResponse {
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
    let mut scan_snapshot = None;

    if let Ok(Some(scan)) = db.get_scan_by_id(scan_id).await {
        let finding_count = db
            .count_findings_by_scan(scan_id, None, None)
            .await
            .unwrap_or(scan.finding_count as i64) as i32;
        let critical = db
            .count_findings_by_scan(scan_id, Some("critical"), None)
            .await
            .unwrap_or(scan.critical_count as i64) as i32;
        let high = db
            .count_findings_by_scan(scan_id, Some("high"), None)
            .await
            .unwrap_or(scan.high_count as i64) as i32;
        let medium = db
            .count_findings_by_scan(scan_id, Some("medium"), None)
            .await
            .unwrap_or(scan.medium_count as i64) as i32;
        let low = db
            .count_findings_by_scan(scan_id, Some("low"), None)
            .await
            .unwrap_or(scan.low_count as i64) as i32;

        scan_snapshot = Some(serde_json::json!({
            "status": scan.status,
            "timestamp": scan.updated_at.to_rfc3339(),
            "finding_count": finding_count,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "error_message": scan.error_message,
        }));
    }

    if let Ok(stages) = db.list_scan_stages(scan_id).await {
        let mut latest_stage_by_name: HashMap<String, ScanStage> = HashMap::new();
        for stage in stages {
            latest_stage_by_name.insert(stage.stage.clone(), stage);
        }

        for stage_name in [
            "ingest",
            "tyr",
            "static_analysis",
            "taint_analysis",
            "config_scan",
            "hunt",
            "vidarr",
            "garmr",
            "report",
        ] {
            let Some(stage) = latest_stage_by_name.get(stage_name) else {
                continue;
            };
            let mut data = serde_json::json!({
                "scan_id": scan_id,
                "stage": stage.stage,
                "status": stage.status,
                "timestamp": stage_event_timestamp(stage),
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

    if let Some(scan) = scan_snapshot {
        let data = serde_json::json!({
            "scan_id": scan_id,
            "status": scan["status"],
            "timestamp": scan["timestamp"],
            "finding_count": scan["finding_count"],
            "critical": scan["critical"],
            "high": scan["high"],
            "medium": scan["medium"],
            "low": scan["low"],
        });
        payload.push_str(&format!(
            "event: status_change\ndata: {}\n\n",
            serde_json::to_string(&data).unwrap_or_default()
        ));

        if scan["status"] == "completed" || scan["status"] == "cancelled" {
            let data = serde_json::json!({
                "scan_id": scan_id,
                "finding_count": scan["finding_count"],
                "critical": scan["critical"],
                "high": scan["high"],
                "medium": scan["medium"],
                "low": scan["low"],
                "timestamp": scan["timestamp"],
            });
            payload.push_str(&format!(
                "event: scan_complete\ndata: {}\n\n",
                serde_json::to_string(&data).unwrap_or_default()
            ));
        } else if scan["status"] == "failed" {
            let data = serde_json::json!({
                "scan_id": scan_id,
                "error": scan["error_message"],
                "timestamp": scan["timestamp"],
            });
            payload.push_str(&format!(
                "event: error\ndata: {}\n\n",
                serde_json::to_string(&data).unwrap_or_default()
            ));
        }
    }

    payload
}

fn stage_event_timestamp(stage: &ScanStage) -> String {
    stage
        .completed_at
        .clone()
        .or(stage.started_at.clone())
        .unwrap_or(stage.created_at)
        .to_rfc3339()
}

pub async fn build_scan_live_snapshot(
    db: &DatabaseOperations,
    scan_id: Uuid,
) -> anyhow::Result<Option<serde_json::Value>> {
    let Some(scan) = db.get_scan_by_id(scan_id).await? else {
        return Ok(None);
    };

    let total = db.count_findings_by_scan(scan_id, None, None).await? as i32;
    let critical = db
        .count_findings_by_scan(scan_id, Some("critical"), None)
        .await? as i32;
    let high = db
        .count_findings_by_scan(scan_id, Some("high"), None)
        .await? as i32;
    let medium = db
        .count_findings_by_scan(scan_id, Some("medium"), None)
        .await? as i32;
    let low = db
        .count_findings_by_scan(scan_id, Some("low"), None)
        .await? as i32;

    let stages = db.list_scan_stages(scan_id).await?;
    let mut latest_stage_by_name: HashMap<String, ScanStage> = HashMap::new();
    for stage in stages {
        latest_stage_by_name.insert(stage.stage.clone(), stage);
    }
    let stage_values = [
        "ingest",
        "tyr",
        "static_analysis",
        "taint_analysis",
        "config_scan",
        "hunt",
        "vidarr",
        "garmr",
        "report",
    ]
    .into_iter()
    .map(|stage_name| {
        let stage = latest_stage_by_name.get(stage_name);
        serde_json::json!({
            "stage": stage_name,
            "label": humanize_slug(stage_name),
            "status": stage.map(|stage| stage.status.as_str()).unwrap_or("pending"),
            "attempt": stage.map(|stage| stage.attempt).unwrap_or(0),
            "error": stage.and_then(|stage| stage.error_message.clone()),
            "timestamp": stage.map(stage_event_timestamp),
        })
    })
    .collect::<Vec<_>>();

    let scan_events = db.list_scan_events(scan_id, 30).await?;
    let activity = scan_events
        .iter()
        .map(|event| {
            serde_json::json!({
                "key": event.id.to_string(),
                "event_type": event.event_type,
                "tone": activity_tone(event.status.as_deref(), &event.event_type),
                "status": event.status,
                "stage": event.stage,
                "task_key": event.task_key,
                "title": event.title,
                "detail": event.detail,
                "progress_pct": event.progress_pct,
                "timestamp": event.created_at.to_rfc3339(),
            })
        })
        .collect::<Vec<_>>();

    let current_task = scan_events
        .iter()
        .find(|event| event.status.as_deref() == Some("running"))
        .map(|event| {
            serde_json::json!({
                "stage": event.stage,
                "title": event.title,
                "detail": event.detail,
                "progress_pct": event.progress_pct,
                "timestamp": event.created_at.to_rfc3339(),
            })
        })
        .or_else(|| {
            scan_events.first().map(|event| {
                serde_json::json!({
                    "stage": event.stage,
                    "title": event.title,
                    "detail": event.detail,
                    "progress_pct": event.progress_pct,
                    "timestamp": event.created_at.to_rfc3339(),
                })
            })
        })
        .unwrap_or_else(|| {
            serde_json::json!({
                "stage": serde_json::Value::Null,
                "title": "Waiting for activity",
                "detail": "No execution activity has been recorded yet.",
                "progress_pct": serde_json::Value::Null,
                "timestamp": scan.updated_at.to_rfc3339(),
            })
        });

    let agent_calls = db
        .list_agent_tool_calls_by_scan(scan_id, 12)
        .await?
        .into_iter()
        .map(|call| {
            serde_json::json!({
                "id": call.id,
                "stage": call.stage,
                "tool_name": call.tool_name,
                "label": humanize_tool_name(&call.tool_name),
                "duration_ms": call.duration_ms,
                "error": call.error,
                "tone": if call.error.is_some() { "error" } else { "active" },
                "created_at": call.created_at.to_rfc3339(),
            })
        })
        .collect::<Vec<_>>();

    Ok(Some(serde_json::json!({
        "scan": {
            "id": scan.id,
            "status": scan.status,
            "status_label": humanize_slug(&scan.status),
            "is_live": !matches!(scan.status.as_str(), "completed" | "failed" | "cancelled"),
            "updated_at": scan.updated_at.to_rfc3339(),
            "error_message": scan.error_message,
        },
        "counts": {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "current_task": current_task,
        "stages": stage_values,
        "activity": activity,
        "agent_calls": agent_calls,
    })))
}

fn humanize_slug(value: &str) -> String {
    // Named stages get proper labels
    match value {
        "ingest" => return "Ingest".to_string(),
        "tyr" => return "Tyr".to_string(),
        "static_analysis" => return "Static Analysis".to_string(),
        "taint_analysis" => return "Taint Analysis".to_string(),
        "config_scan" => return "Config Scan".to_string(),
        "hunt" => return "Hunt".to_string(),
        "vidarr" => return "Víðarr".to_string(),
        "garmr" => return "Garmr".to_string(),
        "report" => return "Report".to_string(),
        _ => {}
    }

    // Fallback: split on _ and capitalize
    value
        .split('_')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(first) => {
                    let mut result = first.to_uppercase().collect::<String>();
                    result.push_str(chars.as_str());
                    result
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn humanize_tool_name(tool_name: &str) -> &'static str {
    match tool_name {
        "llm_completion" => "LLM completion",
        "read_file" => "Read file",
        "search_code" => "Search code",
        "get_callers" => "Trace callers",
        "get_dependencies" => "Trace dependencies",
        _ => "Tool call",
    }
}

fn activity_tone(status: Option<&str>, event_type: &str) -> &'static str {
    match status {
        Some("completed") => "success",
        Some("failed") => "error",
        Some("running") => "active",
        _ => match event_type {
            "issue_automation" => "active",
            "scan_failed" => "error",
            _ => "neutral",
        },
    }
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
