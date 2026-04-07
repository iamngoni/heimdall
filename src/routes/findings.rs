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

use crate::ai::types::{CompletionRequest, Message};
use crate::integrations::issues;
use crate::middleware::auth::AuthenticatedUser;
use crate::models::ApiResponse;
use crate::models::db_models::{Finding, Repo};
use crate::state::AppState;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/findings")
            .route("/{id}", web::get().to(get_finding))
            .route("/{id}/status", web::patch().to(update_finding_status))
            .route("/{id}/explain", web::post().to(explain_finding))
            .route("/{id}/verify", web::post().to(verify_finding))
            .route("/{id}/issue", web::post().to(create_issue))
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

fn valid_severity(severity: &str) -> bool {
    matches!(severity, "critical" | "high" | "medium" | "low")
}

async fn load_owned_finding(
    state: &AppState,
    finding_id: Uuid,
    user_id: Uuid,
) -> Result<Finding, HttpResponse> {
    match state
        .db
        .get_finding_by_id_for_user(finding_id, user_id)
        .await
    {
        Ok(Some(finding)) => Ok(finding),
        Ok(None) => Err(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            404,
            format!("Finding '{finding_id}' not found"),
        ))),
        Err(error) => Err(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to fetch finding: {error}"),
            )),
        ),
    }
}

async fn get_finding(
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
    match load_owned_finding(&state, finding_id, user.id).await {
        Ok(finding) => HttpResponse::Ok().json(ApiResponse::ok(finding)),
        Err(response) => response,
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

    let mut finding = match load_owned_finding(&state, finding_id, user.id).await {
        Ok(finding) => finding,
        Err(response) => return response,
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

        let controls_html = match state
            .templates
            .render("partials/finding_status_controls.html", ctx)
        {
            Ok(html) => html,
            Err(e) => {
                return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                    500,
                    format!("Status updated but failed to render controls: {e}"),
                ));
            }
        };
        let activity_html = match render_finding_recent_activity_html(&state, finding.id).await {
            Ok(html) => html,
            Err(response) => return response,
        };

        return HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(format!("{controls_html}\n{activity_html}"));
    }

    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "id": finding_id,
        "old_status": old_status,
        "status": new_status,
    })))
}

async fn explain_finding(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> HttpResponse {
    run_finding_ai_review(state, req, path.into_inner(), "ai_explanation").await
}

async fn verify_finding(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> HttpResponse {
    run_finding_ai_review(state, req, path.into_inner(), "ai_verification").await
}

async fn create_issue(
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
    let (finding, repo) = match load_finding_and_repo(&state, finding_id, user.id).await {
        Ok(data) => data,
        Err(response) => return response,
    };
    if !issues::supports_issue_creation(&repo) {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            "This repository does not currently support issue creation.",
        ));
    }

    let issue_result = issues::create_or_link_issue(
        &state.db,
        state.encryption_key.as_ref(),
        &repo,
        &finding,
        false,
    )
    .await;
    let (repo_issue, created) = match issue_result {
        Ok(result) => result,
        Err(error) => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(400, error.to_string()));
        }
    };

    let metadata = serde_json::json!({
        "provider": repo_issue.provider,
        "issue_url": repo_issue.issue_url,
        "external_issue_number": repo_issue.external_issue_number,
        "auto_created": false,
        "created": created,
    });
    let _ = state
        .db
        .create_finding_event_with_metadata(
            finding.id,
            Some(user.id),
            "issue_linked",
            None,
            repo_issue.external_issue_number.as_deref(),
            Some(if created {
                "Repository issue created from the finding review screen."
            } else {
                "An existing repository issue is already linked to this fingerprint."
            }),
            Some(&metadata),
        )
        .await;

    if req.headers().contains_key("HX-Request") {
        return render_finding_issue_panel(&state, &finding, &repo).await;
    }

    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "created": created,
        "issue": repo_issue,
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

    let finding = match load_owned_finding(&state, finding_id, user.id).await {
        Ok(finding) => finding,
        Err(response) => return response,
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
            "Suggested diff has already been marked as applied in Heimdall",
        ));
    }

    // Mark the stored diff as applied in Heimdall metadata only.
    if let Err(e) = state.db.mark_patch_applied(patch.id, user.id).await {
        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to mark suggested diff as applied in Heimdall: {e}"),
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
            format!(
                "Suggested diff was marked as applied, but Heimdall failed to record the event: {e}"
            ),
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

    if let Err(response) = load_owned_finding(&state, finding_id, user.id).await {
        return response;
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

    let new_severity = body.severity.trim().to_ascii_lowercase();
    if !valid_severity(&new_severity) {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            400,
            format!("Unsupported finding severity: {}", body.severity),
        ));
    }

    // Get current finding to record old severity
    let finding = match load_owned_finding(&state, finding_id, user.id).await {
        Ok(finding) => finding,
        Err(response) => return response,
    };

    let old_severity = finding.severity.clone();

    // Update the severity
    match state
        .db
        .update_finding_severity(finding_id, &new_severity)
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
            Some(&new_severity),
            None,
        )
        .await
    {
        Ok(event) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "finding_id": finding_id,
            "old_severity": old_severity,
            "new_severity": new_severity,
            "event": event,
        }))),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Severity updated but failed to record event: {e}"),
        )),
    }
}

async fn list_events(
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
    if let Err(response) = load_owned_finding(&state, finding_id, user.id).await {
        return response;
    }
    match state.db.list_finding_events(finding_id).await {
        Ok(events) => HttpResponse::Ok().json(ApiResponse::ok(events)),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to list finding events: {e}"),
        )),
    }
}

async fn run_finding_ai_review(
    state: web::Data<AppState>,
    req: HttpRequest,
    finding_id: Uuid,
    event_type: &str,
) -> HttpResponse {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .expect("auth middleware ensures user exists");
    let (finding, repo) = match load_finding_and_repo(&state, finding_id, user.id).await {
        Ok(data) => data,
        Err(response) => return response,
    };

    let runtime = match state.resolve_ai_for_user(repo.user_id).await {
        Ok(runtime) => runtime,
        Err(error) => {
            return HttpResponse::ServiceUnavailable()
                .json(ApiResponse::<()>::error(503, error.to_string()));
        }
    };
    let source_context = load_grounded_source_context(&state, &finding).await;

    let request = CompletionRequest {
        model: runtime.model.clone(),
        messages: if event_type == "ai_verification" {
            vec![
                Message {
                    role: "system".to_string(),
                    content: "You are a security triage reviewer. Evaluate whether a finding is likely correct using the grounded source excerpt when available. Return ONLY JSON with keys: verdict, rationale, true_positive_signals, false_positive_signals, recommended_status. verdict must be one of confirmed, needs_review, false_positive_likely. recommended_status must be one of confirmed, open, false_positive. If the referenced source excerpt does not support the finding, prefer false_positive_likely.".to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: build_verification_prompt(&finding, &source_context),
                },
            ]
        } else {
            vec![
                Message {
                    role: "system".to_string(),
                    content: "You are a security mentor explaining vulnerability findings to an operator. Use the grounded source excerpt when available and say when the evidence is weak or likely mismatched. Return ONLY JSON with keys: summary, why_flagged, what_to_review, remediation_focus.".to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: build_explanation_prompt(&finding, &source_context),
                },
            ]
        },
        tools: None,
        max_tokens: Some(1400),
        temperature: Some(0.2),
    };

    let response = match runtime.provider.complete(request).await {
        Ok(response) => response,
        Err(error) => {
            return HttpResponse::BadGateway().json(ApiResponse::<()>::error(
                502,
                format!("AI review failed: {error:#}"),
            ));
        }
    };

    let metadata = match parse_json_completion(&response.content) {
        Ok(metadata) => metadata,
        Err(error) => {
            return HttpResponse::BadGateway().json(ApiResponse::<()>::error(
                502,
                format!("AI review returned an invalid response: {error}"),
            ));
        }
    };

    let comment = if event_type == "ai_verification" {
        "AI verification review completed."
    } else {
        "AI explanation generated for this finding."
    };
    if let Err(error) = state
        .db
        .create_finding_event_with_metadata(
            finding.id,
            Some(user.id),
            event_type,
            None,
            metadata
                .get("recommended_status")
                .and_then(|value| value.as_str()),
            Some(comment),
            Some(&metadata),
        )
        .await
    {
        return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to store AI review: {error}"),
        ));
    }

    if req.headers().contains_key("HX-Request") {
        return render_finding_ai_review(&state, finding.id).await;
    }

    HttpResponse::Ok().json(ApiResponse::ok(metadata))
}

async fn load_finding_and_repo(
    state: &AppState,
    finding_id: Uuid,
    user_id: Uuid,
) -> Result<(Finding, Repo), HttpResponse> {
    let finding = load_owned_finding(state, finding_id, user_id).await?;

    let repo = match state
        .db
        .get_repo_by_id_for_user(finding.repo_id, user_id)
        .await
    {
        Ok(Some(repo)) => repo,
        Ok(None) => {
            return Err(HttpResponse::NotFound().json(ApiResponse::<()>::error(
                404,
                format!("Repository for finding '{finding_id}' not found"),
            )));
        }
        Err(error) => {
            return Err(
                HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                    500,
                    format!("Failed to fetch repository: {error}"),
                )),
            );
        }
    };

    Ok((finding, repo))
}

async fn load_grounded_source_context(state: &AppState, finding: &Finding) -> String {
    match state
        .db
        .get_file_snapshot_by_scan_and_path(finding.scan_id, &finding.file_path)
        .await
    {
        Ok(Some(snapshot)) => snapshot
            .content_text
            .as_deref()
            .map(|content| extract_grounded_excerpt(content, finding.line_start, finding.line_end))
            .unwrap_or_else(|| {
                finding.code_snippet.clone().unwrap_or_else(|| {
                    "No grounded source excerpt is available for this finding.".to_string()
                })
            }),
        _ => finding.code_snippet.clone().unwrap_or_else(|| {
            "No grounded source excerpt is available for this finding.".to_string()
        }),
    }
}

fn extract_grounded_excerpt(content: &str, line_start: i32, line_end: Option<i32>) -> String {
    let lines = content.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return "No grounded source excerpt is available for this finding.".to_string();
    }

    let start_line = line_start.max(1) as usize;
    let end_line = line_end.unwrap_or(line_start).max(line_start) as usize;
    let excerpt_start = start_line.saturating_sub(5).max(1);
    let excerpt_end = (end_line + 5).min(lines.len());

    (excerpt_start..=excerpt_end)
        .filter_map(|line_number| {
            lines
                .get(line_number - 1)
                .map(|line| format!("{line_number:>5} | {line}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn render_finding_ai_review(state: &AppState, finding_id: Uuid) -> HttpResponse {
    let events = match state.db.list_finding_events(finding_id).await {
        Ok(events) => events,
        Err(error) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to load finding review activity: {error}"),
            ));
        }
    };

    let explain = latest_review_value(&events, "ai_explanation");
    let verify = latest_review_value(&events, "ai_verification");
    let ctx = minijinja::context! {
        finding_id => finding_id,
        explain_review => explain,
        verify_review => verify,
    };

    match state
        .templates
        .render("partials/finding_ai_review.html", ctx)
    {
        Ok(html) => {
            let activity_html = match render_finding_recent_activity_html(state, finding_id).await {
                Ok(activity) => activity,
                Err(response) => return response,
            };
            HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(format!("{html}\n{activity_html}"))
        }
        Err(error) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to render finding AI review: {error}"),
        )),
    }
}

async fn render_finding_issue_panel(
    state: &AppState,
    finding: &Finding,
    repo: &Repo,
) -> HttpResponse {
    let provider = issues::issue_provider(repo);
    let repo_issue = match provider {
        Some(provider) => state
            .db
            .get_repo_issue_by_fingerprint(repo.id, provider, &finding.fingerprint)
            .await
            .unwrap_or_default(),
        None => None,
    };
    let ctx = minijinja::context! {
        finding_id => finding.id,
        issue => minijinja::Value::from_serialize(&serde_json::json!({
            "supported": issues::supports_issue_creation(repo),
            "provider": provider,
            "url": repo_issue.as_ref().map(|issue| issue.issue_url.clone()),
            "number": repo_issue.as_ref().and_then(|issue| issue.external_issue_number.clone()),
            "state": repo_issue.as_ref().map(|issue| issue.state.clone()),
            "auto_created": repo_issue.as_ref().map(|issue| issue.auto_created).unwrap_or(false),
        })),
        repo => minijinja::Value::from_serialize(&serde_json::json!({
            "issue_auto_create_enabled": repo.issue_auto_create_enabled,
            "issue_auto_create_min_severity": repo.issue_auto_create_min_severity,
        })),
    };

    match state
        .templates
        .render("partials/finding_issue_panel.html", ctx)
    {
        Ok(html) => {
            let activity_html = match render_finding_recent_activity_html(state, finding.id).await {
                Ok(activity) => activity,
                Err(response) => return response,
            };
            HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(format!("{html}\n{activity_html}"))
        }
        Err(error) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
            500,
            format!("Failed to render finding issue panel: {error}"),
        )),
    }
}

async fn render_finding_recent_activity_html(
    state: &AppState,
    finding_id: Uuid,
) -> Result<String, HttpResponse> {
    let events = match state.db.list_finding_events(finding_id).await {
        Ok(events) => events,
        Err(error) => {
            return Err(
                HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                    500,
                    format!("Failed to load recent finding activity: {error}"),
                )),
            );
        }
    };

    let event_values: Vec<minijinja::Value> = events
        .iter()
        .rev()
        .take(6)
        .map(serialize_recent_activity_event)
        .collect();
    let ctx = minijinja::context! {
        events => event_values,
    };

    match state
        .templates
        .render("partials/finding_recent_activity.html", ctx)
    {
        Ok(html) => Ok(html.replacen(
            "<section id=\"finding-recent-activity\"",
            "<section id=\"finding-recent-activity\" hx-swap-oob=\"outerHTML\"",
            1,
        )),
        Err(error) => Err(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                500,
                format!("Failed to render recent finding activity: {error}"),
            )),
        ),
    }
}

fn latest_review_value(
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

fn serialize_recent_activity_event(
    event: &crate::models::db_models::FindingEvent,
) -> minijinja::Value {
    let metadata = event.metadata.clone().unwrap_or(serde_json::Value::Null);
    let (title, detail, tone) = match event.event_type.as_str() {
        "status_change" => (
            "Status updated".to_string(),
            match (event.old_value.as_deref(), event.new_value.as_deref()) {
                (Some(old), Some(new)) => format!(
                    "Triage moved from {} to {}.",
                    humanize_event_slug(old),
                    humanize_event_slug(new)
                ),
                (_, Some(new)) => format!("Triage moved to {}.", humanize_event_slug(new)),
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
                .map(humanize_event_slug)
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
        _ => (
            humanize_event_slug(&event.event_type),
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

fn humanize_event_slug(value: &str) -> String {
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

fn parse_json_completion(content: &str) -> Result<serde_json::Value, String> {
    let content = content.trim();
    let json_str = if content.starts_with("```") {
        content
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
    } else {
        content
    };

    serde_json::from_str(json_str).map_err(|error| error.to_string())
}

fn build_explanation_prompt(finding: &Finding, source_context: &str) -> String {
    format!(
        "Explain this security finding in plain language.\n\n\
         Title: {}\n\
         Severity: {}\n\
         Confidence: {}\n\
         CWE: {}\n\
         File: {}:{}{}\n\
         Description: {}\n\
         Agent reasoning: {}\n\
         Stored snippet:\n{}\n\n\
         Grounded source excerpt from the scanned revision:\n{}\n\n\
         Focus on why it was flagged, whether the evidence actually supports the claim, what a reviewer should inspect next, and what remediation focus makes sense.",
        finding.title,
        finding.severity,
        finding.confidence,
        finding.cwe_id.as_deref().unwrap_or("N/A"),
        finding.file_path,
        finding.line_start,
        finding
            .line_end
            .map(|line| format!("-{line}"))
            .unwrap_or_default(),
        finding.description.as_deref().unwrap_or("N/A"),
        finding.agent_reasoning.as_deref().unwrap_or("N/A"),
        finding.code_snippet.as_deref().unwrap_or("N/A"),
        source_context,
    )
}

fn build_verification_prompt(finding: &Finding, source_context: &str) -> String {
    format!(
        "Review whether this security finding is likely correct.\n\n\
         Title: {}\n\
         Severity: {}\n\
         Confidence: {}\n\
         CWE: {}\n\
         File: {}:{}{}\n\
         Description: {}\n\
         Agent reasoning: {}\n\
         Stored snippet:\n{}\n\n\
         Grounded source excerpt from the scanned revision:\n{}\n\n\
         Decide if this is likely a true positive, needs more review, or is likely a false positive. \
         Your answer must be based on whether the grounded source excerpt supports the finding, not just the title. \
         Recommend a Heimdall status based on the evidence.",
        finding.title,
        finding.severity,
        finding.confidence,
        finding.cwe_id.as_deref().unwrap_or("N/A"),
        finding.file_path,
        finding.line_start,
        finding
            .line_end
            .map(|line| format!("-{line}"))
            .unwrap_or_default(),
        finding.description.as_deref().unwrap_or("N/A"),
        finding.agent_reasoning.as_deref().unwrap_or("N/A"),
        finding.code_snippet.as_deref().unwrap_or("N/A"),
        source_context,
    )
}
