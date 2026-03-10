//
//  heimdall
//  src/routes/findings.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::{Either, HttpMessage, HttpRequest, HttpResponse, web};
use serde::Deserialize;
use uuid::Uuid;

use crate::middleware::auth::AuthenticatedUser;
use crate::models::ApiResponse;
use crate::state::AppState;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/findings")
            .route("/{id}", web::get().to(get_finding))
            .route("/{id}/status", web::patch().to(update_finding_status))
            .route("/{id}/apply-patch", web::post().to(apply_patch))
            .route("/{id}/comment", web::post().to(add_comment))
            .route("/{id}/severity", web::patch().to(update_severity))
            .route("/{id}/events", web::get().to(list_events)),
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

async fn get_finding(state: web::Data<AppState>, path: web::Path<Uuid>) -> HttpResponse {
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
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: Either<web::Json<UpdateStatusRequest>, web::Form<UpdateStatusRequest>>,
) -> HttpResponse {
    let finding_id = path.into_inner();
    let body = match body {
        Either::Left(json) => json.into_inner(),
        Either::Right(form) => form.into_inner(),
    };
    let new_status = body.status.trim().to_lowercase();

    if !["open", "confirmed", "dismissed", "false_positive", "fixed"].contains(&new_status.as_str())
    {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            format!("Unsupported finding status: {}", body.status),
        ));
    }

    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    let mut finding = match state.db.get_finding_by_id(finding_id).await {
        Ok(Some(finding)) => finding,
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                format!("Finding '{finding_id}' not found"),
            ));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to fetch finding: {e}"),
            ));
        }
    };

    let old_status = finding.status.clone();

    match state
        .db
        .update_finding_status(finding_id, &new_status)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                format!("Finding '{finding_id}' not found"),
            ));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to update finding status: {e}"),
            ));
        }
    }

    if let Err(e) = state
        .db
        .create_finding_event(
            finding_id,
            Some(user.id),
            "status_change",
            Some(&old_status),
            Some(&new_status),
            None,
        )
        .await
    {
        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Status updated but failed to record event: {e}"),
        ));
    }

    finding.status = new_status.clone();

    if req.headers().contains_key("HX-Request") {
        let ctx = minijinja::context! {
            finding => minijinja::Value::from_serialize(&serde_json::json!({
                "id": finding.id,
                "status": finding.status,
            })),
        };

        return match state
            .templates
            .render("partials/finding_status_controls.html", ctx)
        {
            Ok(html) => HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(html),
            Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Status updated but failed to render controls: {e}"),
            )),
        };
    }

    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "id": finding_id,
        "old_status": old_status,
        "status": new_status,
    })))
}

async fn apply_patch(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let finding_id = path.into_inner();
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    // Look up the finding
    let finding = match state.db.get_finding_by_id(finding_id).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                format!("Finding '{finding_id}' not found"),
            ));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to fetch finding: {e}"),
            ));
        }
    };

    // Get the latest patch for this finding
    let patch = match state.db.get_patch_for_finding(finding.id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                format!("No patch available for finding '{finding_id}'"),
            ));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to get patch: {e}"),
            ));
        }
    };

    if patch.applied {
        return HttpResponse::Conflict().json(ApiResponse::<()>::error(
            409,
            "Patch has already been applied",
        ));
    }

    // Mark patch as applied
    if let Err(e) = state.db.mark_patch_applied(patch.id, user.id).await {
        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to apply patch: {e}"),
        ));
    }

    // Create a finding event
    let event = state
        .db
        .create_finding_event(
            finding_id,
            Some(user.id),
            "patch_applied",
            None,
            Some(&patch.id.to_string()),
            None,
        )
        .await;

    match event {
        Ok(evt) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "finding_id": finding_id,
            "patch_id": patch.id,
            "applied_by": user.id,
            "event": evt,
        }))),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Patch applied but failed to record event: {e}"),
        )),
    }
}

async fn add_comment(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<AddCommentRequest>,
) -> HttpResponse {
    let finding_id = path.into_inner();
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    // Verify finding exists
    match state.db.get_finding_by_id(finding_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                format!("Finding '{finding_id}' not found"),
            ));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to fetch finding: {e}"),
            ));
        }
    }

    match state
        .db
        .create_finding_event(
            finding_id,
            Some(user.id),
            "comment",
            None,
            None,
            Some(&body.comment),
        )
        .await
    {
        Ok(event) => HttpResponse::Created().json(ApiResponse::ok(event)),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to add comment: {e}"),
        )),
    }
}

async fn update_severity(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<UpdateSeverityRequest>,
) -> HttpResponse {
    let finding_id = path.into_inner();
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");

    // Get current finding to record old severity
    let finding = match state.db.get_finding_by_id(finding_id).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                format!("Finding '{finding_id}' not found"),
            ));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to fetch finding: {e}"),
            ));
        }
    };

    let old_severity = finding.severity.clone();

    // Update the severity
    match state
        .db
        .update_finding_severity(finding_id, &body.severity)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                format!("Finding '{finding_id}' not found"),
            ));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to update severity: {e}"),
            ));
        }
    }

    // Create a finding event recording the change
    match state
        .db
        .create_finding_event(
            finding_id,
            Some(user.id),
            "severity_change",
            Some(&old_severity),
            Some(&body.severity),
            None,
        )
        .await
    {
        Ok(event) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "finding_id": finding_id,
            "old_severity": old_severity,
            "new_severity": body.severity,
            "event": event,
        }))),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Severity updated but failed to record event: {e}"),
        )),
    }
}

async fn list_events(state: web::Data<AppState>, path: web::Path<Uuid>) -> HttpResponse {
    let finding_id = path.into_inner();
    match state.db.list_finding_events(finding_id).await {
        Ok(events) => HttpResponse::Ok().json(ApiResponse::ok(events)),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to list finding events: {e}"),
        )),
    }
}
