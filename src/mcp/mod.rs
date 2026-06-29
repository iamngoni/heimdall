//
//  heimdall
//  src/mcp/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/20.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::{env, sync::Arc};

use log::warn;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::schemars;
use rmcp::schemars::JsonSchema;
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ai;
use crate::ai::types::{CompletionRequest, Message};
use crate::integrations::issues;
use crate::models::db_models::{Finding, Repo, User};
use crate::routes::scans::build_scan_live_snapshot;
use crate::state::AppState;

#[derive(Clone)]
pub struct HeimdallMcp {
    state: Arc<AppState>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListReposRequest {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddRepositoryRequest {
    pub remote_url: String,
    pub name: Option<String>,
    pub source_type: Option<String>,
    pub default_branch: Option<String>,
    pub oauth_connection_id: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetRepoRequest {
    pub repo_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteRepositoryRequest {
    pub repo_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TriggerScanRequest {
    pub repo_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListScansRequest {
    pub repo_id: String,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetScanRequest {
    pub scan_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CancelScanRequest {
    pub scan_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListScanEventsRequest {
    pub scan_id: String,
    pub limit: Option<i64>,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetScanProgressStreamRequest {
    pub scan_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFindingsRequest {
    pub scan_id: String,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetFindingRequest {
    pub finding_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExplainFindingRequest {
    pub finding_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyFindingRequest {
    pub finding_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFindingEventsRequest {
    pub finding_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommentOnFindingRequest {
    pub finding_id: String,
    pub comment: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplyPatchRequest {
    pub finding_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetThreatModelRequest {
    pub scan_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateThreatModelRequest {
    pub threat_model_id: Option<String>,
    pub scan_id: Option<String>,
    pub field: String,
    #[schemars(schema_with = "json_value_input_schema")]
    pub value: serde_json::Value,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetPatchesRequest {
    pub scan_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateFindingStatusRequest {
    pub finding_id: String,
    pub status: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateFindingSeverityRequest {
    pub finding_id: String,
    pub severity: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateIssueRequest {
    pub finding_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateAllIssuesRequest {
    pub scan_id: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListAgentToolCallsRequest {
    pub scan_id: String,
    pub limit: Option<i64>,
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ManageApiKeysRequest {
    pub action: String,
    pub user_id: Option<String>,
    pub provider: Option<String>,
    pub key: Option<String>,
    pub label: Option<String>,
    pub key_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TestConnectionRequest {
    pub provider: String,
    pub key: String,
}

#[derive(Debug, Serialize)]
struct RepoInfo {
    id: String,
    user_id: String,
    name: String,
    source_type: String,
    remote_url: Option<String>,
    default_branch: Option<String>,
    issue_auto_create_enabled: bool,
    issue_auto_create_min_severity: String,
}

#[derive(Debug, Serialize)]
struct ScanInfo {
    id: String,
    repo_id: String,
    status: String,
    scan_type: String,
    finding_count: i32,
    critical_count: i32,
    high_count: i32,
    medium_count: i32,
    low_count: i32,
    error_message: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct FindingInfo {
    id: String,
    repo_id: String,
    scan_id: String,
    source: String,
    status: String,
    severity: String,
    confidence: String,
    title: String,
    description: Option<String>,
    cwe_id: Option<String>,
    cve_id: Option<String>,
    file_path: String,
    line_start: i32,
    line_end: Option<i32>,
    code_snippet: Option<String>,
    suggested_patch: Option<String>,
    agent_reasoning: Option<String>,
    poc_validated: bool,
}

#[derive(Debug, Serialize)]
struct ApiKeyInfo {
    id: String,
    user_id: String,
    provider: Option<String>,
    label: Option<String>,
    last_used_at: Option<String>,
    created_at: String,
}

fn parse_uuid(value: &str) -> Result<Uuid, rmcp::ErrorData> {
    Uuid::parse_str(value)
        .map_err(|error| invalid_params(format!("Invalid UUID '{value}': {error}")))
}

fn json_text<T: Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
}

fn invalid_params(message: String) -> rmcp::ErrorData {
    rmcp::ErrorData::new(ErrorCode::INVALID_PARAMS, message, None)
}

fn internal_err(message: String) -> rmcp::ErrorData {
    rmcp::ErrorData::new(ErrorCode::INTERNAL_ERROR, message, None)
}

fn repo_info(repo: &Repo) -> RepoInfo {
    RepoInfo {
        id: repo.id.to_string(),
        user_id: repo.user_id.to_string(),
        name: repo.name.clone(),
        source_type: repo.source_type.clone(),
        remote_url: repo.remote_url.clone(),
        default_branch: repo.default_branch.clone(),
        issue_auto_create_enabled: repo.issue_auto_create_enabled,
        issue_auto_create_min_severity: repo.issue_auto_create_min_severity.clone(),
    }
}

fn scan_info(scan: &crate::models::db_models::Scan) -> ScanInfo {
    ScanInfo {
        id: scan.id.to_string(),
        repo_id: scan.repo_id.to_string(),
        status: scan.status.clone(),
        scan_type: scan.scan_type.clone(),
        finding_count: scan.finding_count,
        critical_count: scan.critical_count,
        high_count: scan.high_count,
        medium_count: scan.medium_count,
        low_count: scan.low_count,
        error_message: scan.error_message.clone(),
        created_at: scan.created_at.to_rfc3339(),
        updated_at: scan.updated_at.to_rfc3339(),
    }
}

fn finding_info(finding: &Finding) -> FindingInfo {
    FindingInfo {
        id: finding.id.to_string(),
        repo_id: finding.repo_id.to_string(),
        scan_id: finding.scan_id.to_string(),
        source: finding.source.clone(),
        status: finding.status.clone(),
        severity: finding.severity.clone(),
        confidence: finding.confidence.clone(),
        title: finding.title.clone(),
        description: finding.description.clone(),
        cwe_id: finding.cwe_id.clone(),
        cve_id: finding.cve_id.clone(),
        file_path: finding.file_path.clone(),
        line_start: finding.line_start,
        line_end: finding.line_end,
        code_snippet: finding.code_snippet.clone(),
        suggested_patch: finding.suggested_patch.clone(),
        agent_reasoning: finding.agent_reasoning.clone(),
        poc_validated: finding.poc_validated,
    }
}

fn valid_finding_status(status: &str) -> bool {
    matches!(
        status,
        "open" | "confirmed" | "dismissed" | "false_positive" | "fixed"
    )
}

fn valid_severity(severity: &str) -> bool {
    matches!(severity, "critical" | "high" | "medium" | "low")
}

fn valid_provider(provider: &str) -> bool {
    matches!(provider, "anthropic" | "openai" | "ollama")
}

fn infer_source_type(remote_url: &str) -> &'static str {
    let lower = remote_url.to_ascii_lowercase();
    if lower.contains("github.com") {
        "github"
    } else if lower.contains("gitlab.com") {
        "gitlab"
    } else if lower.contains("bitbucket.org") {
        "bitbucket"
    } else {
        "git_url"
    }
}

fn repo_name_from_url(remote_url: &str) -> String {
    let trimmed = remote_url.trim_end_matches('/');
    let last = trimmed
        .split('/')
        .next_back()
        .unwrap_or("repo")
        .trim_end_matches(".git");
    if last.is_empty() {
        "repo".to_string()
    } else {
        last.to_string()
    }
}

fn mask_key(key: &str) -> String {
    let len = key.len();
    if len <= 6 {
        return "***".to_string();
    }
    if len < 12 {
        format!("{}***{}", &key[..3], &key[len - 2..])
    } else {
        format!("{}***{}", &key[..7], &key[len - 3..])
    }
}

fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn encrypt_key(key: &str, encryption_key: Option<&[u8; 32]>) -> String {
    match encryption_key {
        Some(enc_key) => match crate::crypto::encrypt(key.as_bytes(), enc_key) {
            Ok(encrypted) => encrypted,
            Err(_) => hex::encode(key.as_bytes()),
        },
        None => hex::encode(key.as_bytes()),
    }
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

fn normalize_threat_model_field(field: &str) -> Option<&'static str> {
    match field {
        "summary" => Some("summary"),
        "boundaries" | "boundaries_json" => Some("boundaries_json"),
        "surfaces" | "surfaces_json" => Some("surfaces_json"),
        "data_flows" | "data_flows_json" => Some("data_flows_json"),
        _ => None,
    }
}

fn json_value_input_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
    serde_json::from_value(serde_json::json!({
        "description": "JSON value to store in the threat model field. Use a string for summary, and an object or array for boundaries, surfaces, and data_flows.",
        "oneOf": [
            { "type": "string" },
            { "type": "number" },
            { "type": "integer" },
            { "type": "boolean" },
            { "type": "null" },
            { "type": "array" },
            { "type": "object" }
        ]
    }))
    .expect("valid JSON schema")
}

impl HeimdallMcp {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    async fn resolve_user(&self, user_id: Option<&str>) -> Result<User, rmcp::ErrorData> {
        if let Some(user_id) = user_id {
            let user_id = parse_uuid(user_id)?;
            return self
                .state
                .db
                .get_user_by_id(user_id)
                .await
                .map_err(|error| internal_err(format!("Database error: {error}")))?
                .ok_or_else(|| invalid_params(format!("User {user_id} not found")));
        }

        let configured_default = env::var("MCP_DEFAULT_USER_ID")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        if let Some(user_id) = configured_default {
            let user_id = parse_uuid(&user_id)?;
            return self
                .state
                .db
                .get_user_by_id(user_id)
                .await
                .map_err(|error| internal_err(format!("Database error: {error}")))?
                .ok_or_else(|| {
                    invalid_params(format!(
                        "Configured MCP_DEFAULT_USER_ID {user_id} was not found"
                    ))
                });
        }

        Err(invalid_params(
            "Pass an explicit user_id or set MCP_DEFAULT_USER_ID for single-user stdio mode."
                .to_string(),
        ))
    }

    async fn load_repo_for_user(
        &self,
        repo_id: Uuid,
        user_id: Uuid,
    ) -> Result<Repo, rmcp::ErrorData> {
        self.state
            .db
            .get_repo_by_id_for_user(repo_id, user_id)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?
            .ok_or_else(|| invalid_params(format!("Repository {repo_id} not found")))
    }

    async fn resolve_actor_user_id(
        &self,
        explicit_user_id: Option<&str>,
        _fallback_user_id: Option<Uuid>,
    ) -> Result<Uuid, rmcp::ErrorData> {
        Ok(self.resolve_user(explicit_user_id).await?.id)
    }

    async fn load_scan_for_user(
        &self,
        scan_id: Uuid,
        user_id: Uuid,
    ) -> Result<crate::models::db_models::Scan, rmcp::ErrorData> {
        self.state
            .db
            .get_scan_by_id_for_user(scan_id, user_id)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?
            .ok_or_else(|| invalid_params(format!("Scan {scan_id} not found")))
    }

    async fn load_finding_and_repo_for_user(
        &self,
        finding_id: Uuid,
        user_id: Uuid,
    ) -> Result<(Finding, Repo), rmcp::ErrorData> {
        let finding = self
            .state
            .db
            .get_finding_by_id_for_user(finding_id, user_id)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?
            .ok_or_else(|| invalid_params(format!("Finding {finding_id} not found")))?;

        let repo = self.load_repo_for_user(finding.repo_id, user_id).await?;

        Ok((finding, repo))
    }

    async fn load_grounded_source_context(&self, finding: &Finding) -> String {
        match self
            .state
            .db
            .get_file_snapshot_by_scan_and_path(finding.scan_id, &finding.file_path)
            .await
        {
            Ok(Some(snapshot)) => snapshot
                .content_text
                .as_deref()
                .map(|content| {
                    extract_grounded_excerpt(content, finding.line_start, finding.line_end)
                })
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

    async fn run_finding_ai_review(
        &self,
        finding_id: Uuid,
        actor_user_id: Uuid,
        event_type: &str,
    ) -> Result<String, rmcp::ErrorData> {
        let (finding, repo) = self
            .load_finding_and_repo_for_user(finding_id, actor_user_id)
            .await?;
        let runtime = self
            .state
            .resolve_ai_for_user(repo.user_id)
            .await
            .map_err(|error| internal_err(format!("AI runtime unavailable: {error}")))?;
        let source_context = self.load_grounded_source_context(&finding).await;

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

        let response = runtime
            .provider
            .complete(request)
            .await
            .map_err(|error| internal_err(format!("AI review failed: {error:#}")))?;
        let metadata = parse_json_completion(&response.content)
            .map_err(|error| internal_err(format!("AI review returned invalid JSON: {error}")))?;

        let comment = if event_type == "ai_verification" {
            "AI verification review completed."
        } else {
            "AI explanation generated for this finding."
        };
        self.state
            .db
            .create_finding_event_with_metadata(
                finding.id,
                Some(actor_user_id),
                event_type,
                None,
                metadata
                    .get("recommended_status")
                    .and_then(|value| value.as_str()),
                Some(comment),
                Some(&metadata),
            )
            .await
            .map_err(|error| internal_err(format!("Failed to store AI review: {error}")))?;

        Ok(json_text(&serde_json::json!({
            "finding_id": finding.id,
            "event_type": event_type,
            "provider": runtime.provider.provider_name(),
            "model": runtime.model,
            "review": metadata,
            "note": if event_type == "ai_verification" {
                "This is an AI verification review using grounded source context. It does not re-run sandbox PoC validation."
            } else {
                "This is an AI explanation generated from the finding and grounded source context."
            },
        })))
    }

    fn app_base_url(&self) -> String {
        let host = match self.state.config.app.host.as_str() {
            "0.0.0.0" | "::" => "localhost",
            value => value,
        };
        let scheme = if self.state.config.app.tls_enabled {
            "https"
        } else {
            "http"
        };
        format!("{scheme}://{host}:{}", self.state.config.app.port)
    }
}

#[tool_router]
impl HeimdallMcp {
    #[tool(description = "List repositories visible to a Heimdall user.")]
    async fn list_repositories(
        &self,
        Parameters(req): Parameters<ListReposRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let limit = req.limit.unwrap_or(50);
        let offset = req.offset.unwrap_or(0);
        let repos = self
            .state
            .db
            .list_repos_by_user_paginated(user.id, limit, offset)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?;

        Ok(json_text(
            &repos
                .into_iter()
                .map(|repo| repo_info(&repo))
                .collect::<Vec<_>>(),
        ))
    }

    #[tool(
        description = "Import a repository by URL into Heimdall. If the remote URL already exists, the existing repository is returned instead of creating a duplicate."
    )]
    async fn add_repository(
        &self,
        Parameters(req): Parameters<AddRepositoryRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let remote_url = req.remote_url.trim();
        if remote_url.is_empty() {
            return Err(invalid_params("remote_url must not be empty".to_string()));
        }

        let user = self.resolve_user(req.user_id.as_deref()).await?;
        if let Some(existing) = self
            .state
            .db
            .get_repo_by_remote_url_for_user(user.id, remote_url)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?
        {
            return Ok(json_text(&serde_json::json!({
                "created": false,
                "repo": repo_info(&existing),
            })));
        }

        let oauth_connection_id = match req.oauth_connection_id.as_deref() {
            Some(value) => Some(parse_uuid(value)?),
            None => None,
        };
        let name = req
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| repo_name_from_url(remote_url));
        let source_type = req
            .source_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| infer_source_type(remote_url));

        let repo = self
            .state
            .db
            .create_repo(
                user.id,
                &name,
                source_type,
                Some(remote_url),
                req.default_branch.as_deref(),
                oauth_connection_id,
            )
            .await
            .map_err(|error| internal_err(format!("Failed to create repository: {error}")))?;

        Ok(json_text(&serde_json::json!({
            "created": true,
            "repo": repo_info(&repo),
        })))
    }

    #[tool(description = "Get details of a specific repository by its ID")]
    async fn get_repository(
        &self,
        Parameters(req): Parameters<GetRepoRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let repo_id = parse_uuid(&req.repo_id)?;
        let repo = self.load_repo_for_user(repo_id, user.id).await?;

        Ok(json_text(&repo_info(&repo)))
    }

    #[tool(description = "Delete a repository from Heimdall.")]
    async fn delete_repository(
        &self,
        Parameters(req): Parameters<DeleteRepositoryRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let repo_id = parse_uuid(&req.repo_id)?;
        let repo = self.load_repo_for_user(repo_id, user.id).await?;

        self.state
            .db
            .delete_repo(repo.id)
            .await
            .map_err(|error| internal_err(format!("Failed to delete repository: {error}")))?;

        Ok(json_text(&serde_json::json!({
            "deleted": true,
            "repo_id": repo_id,
        })))
    }

    #[tool(
        description = "Trigger a new security scan on a repository. The scan runs asynchronously and a scan job is queued immediately."
    )]
    async fn trigger_scan(
        &self,
        Parameters(req): Parameters<TriggerScanRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let actor_user_id = self
            .resolve_actor_user_id(req.user_id.as_deref(), None)
            .await?;
        let repo_id = parse_uuid(&req.repo_id)?;
        let repo = self.load_repo_for_user(repo_id, actor_user_id).await?;

        self.state
            .resolve_ai_for_user(repo.user_id)
            .await
            .map_err(|error| internal_err(format!("AI runtime unavailable: {error}")))?;

        let scan = self
            .state
            .db
            .create_scan(repo_id, "full", Some(actor_user_id), None, None, None)
            .await
            .map_err(|error| internal_err(format!("Failed to create scan: {error}")))?;

        self.state
            .db
            .create_scan_job(scan.id)
            .await
            .map_err(|error| internal_err(format!("Failed to enqueue scan job: {error}")))?;

        Ok(json_text(&serde_json::json!({
            "queued": true,
            "scan": scan_info(&scan),
        })))
    }

    #[tool(description = "See scan history for a repository.")]
    async fn list_scans(
        &self,
        Parameters(req): Parameters<ListScansRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let repo_id = parse_uuid(&req.repo_id)?;
        let limit = req.limit.unwrap_or(50);
        let offset = req.offset.unwrap_or(0);

        let repo = self.load_repo_for_user(repo_id, user.id).await?;

        let total = self
            .state
            .db
            .count_scans_by_repo(repo.id)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?;
        let scans = self
            .state
            .db
            .list_scans_by_repo_paginated(repo.id, limit, offset)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?;

        Ok(json_text(&serde_json::json!({
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": scans.into_iter().map(|scan| scan_info(&scan)).collect::<Vec<_>>(),
        })))
    }

    #[tool(description = "Get the current status and live finding counts of a scan.")]
    async fn get_scan_status(
        &self,
        Parameters(req): Parameters<GetScanRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let scan_id = parse_uuid(&req.scan_id)?;
        let scan = self.load_scan_for_user(scan_id, user.id).await?;

        let finding_count = self
            .state
            .db
            .count_findings_by_scan(scan_id, None, None)
            .await
            .map_err(|error| internal_err(format!("Failed to count findings: {error}")))?
            as i32;
        let critical_count = self
            .state
            .db
            .count_findings_by_scan(scan_id, Some("critical"), None)
            .await
            .map_err(|error| internal_err(format!("Failed to count critical findings: {error}")))?
            as i32;
        let high_count = self
            .state
            .db
            .count_findings_by_scan(scan_id, Some("high"), None)
            .await
            .map_err(|error| internal_err(format!("Failed to count high findings: {error}")))?
            as i32;
        let medium_count = self
            .state
            .db
            .count_findings_by_scan(scan_id, Some("medium"), None)
            .await
            .map_err(|error| internal_err(format!("Failed to count medium findings: {error}")))?
            as i32;
        let low_count = self
            .state
            .db
            .count_findings_by_scan(scan_id, Some("low"), None)
            .await
            .map_err(|error| internal_err(format!("Failed to count low findings: {error}")))?
            as i32;

        Ok(json_text(&serde_json::json!({
            "id": scan.id,
            "repo_id": scan.repo_id,
            "status": scan.status,
            "scan_type": scan.scan_type,
            "finding_count": finding_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "error_message": scan.error_message,
            "created_at": scan.created_at.to_rfc3339(),
            "updated_at": scan.updated_at.to_rfc3339(),
        })))
    }

    #[tool(description = "Stop a running or queued scan.")]
    async fn cancel_scan(
        &self,
        Parameters(req): Parameters<CancelScanRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let scan_id = parse_uuid(&req.scan_id)?;
        let scan = self.load_scan_for_user(scan_id, user.id).await?;

        if matches!(scan.status.as_str(), "completed" | "failed" | "cancelled") {
            return Err(invalid_params(format!("Scan is already {}", scan.status)));
        }

        self.state
            .db
            .update_scan_status(scan_id, "cancelled", Some("Cancelled via MCP"))
            .await
            .map_err(|error| internal_err(format!("Failed to cancel scan: {error}")))?;

        self.state.sse.cancel_scan(scan_id);
        self.state.sse.emit_status_change(scan_id, "cancelled");
        self.state
            .sse
            .emit_error(scan_id, "Scan was cancelled via MCP");

        Ok(json_text(&serde_json::json!({
            "cancelled": true,
            "scan_id": scan_id,
            "status": "cancelled",
        })))
    }

    #[tool(description = "Full audit trail and progress events for a scan.")]
    async fn list_scan_events(
        &self,
        Parameters(req): Parameters<ListScanEventsRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let scan_id = parse_uuid(&req.scan_id)?;
        let _scan = self.load_scan_for_user(scan_id, user.id).await?;
        let limit = req.limit.unwrap_or(100);
        let events = self
            .state
            .db
            .list_scan_events(scan_id, limit)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?;

        Ok(json_text(&events))
    }

    #[tool(
        description = "Return the live scan snapshot plus the SSE endpoint for a scan. MCP returns a snapshot; the SSE stream itself is available via the web API."
    )]
    async fn get_scan_progress_stream(
        &self,
        Parameters(req): Parameters<GetScanProgressStreamRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let scan_id = parse_uuid(&req.scan_id)?;
        let _scan = self.load_scan_for_user(scan_id, user.id).await?;
        let snapshot = build_scan_live_snapshot(&self.state.db, scan_id)
            .await
            .map_err(|error| internal_err(format!("Failed to build live snapshot: {error}")))?
            .ok_or_else(|| invalid_params(format!("Scan {} not found", req.scan_id)))?;

        Ok(json_text(&serde_json::json!({
            "scan_id": scan_id,
            "snapshot": snapshot,
            "sse": {
                "relative_path": format!("/api/scans/{scan_id}/progress/stream"),
                "url": format!("{}/api/scans/{scan_id}/progress/stream", self.app_base_url()),
                "note": "Use the web API endpoint for live SSE updates. This MCP tool returns the current snapshot only."
            }
        })))
    }

    #[tool(
        description = "List security findings for a scan. Supports filtering by severity and status with pagination."
    )]
    async fn list_findings(
        &self,
        Parameters(req): Parameters<ListFindingsRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let scan_id = parse_uuid(&req.scan_id)?;
        let _scan = self.load_scan_for_user(scan_id, user.id).await?;
        let limit = req.limit.unwrap_or(50);
        let offset = req.offset.unwrap_or(0);
        let findings = self
            .state
            .db
            .list_findings_by_scan_paginated(
                scan_id,
                req.severity.as_deref(),
                req.status.as_deref(),
                limit,
                offset,
            )
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?;

        Ok(json_text(
            &findings
                .into_iter()
                .map(|finding| finding_info(&finding))
                .collect::<Vec<_>>(),
        ))
    }

    #[tool(
        description = "Get full details of a specific finding including code snippet, suggested diff, analyst reasoning, and PoC validation status."
    )]
    async fn get_finding(
        &self,
        Parameters(req): Parameters<GetFindingRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let finding_id = parse_uuid(&req.finding_id)?;
        let (finding, _) = self
            .load_finding_and_repo_for_user(finding_id, user.id)
            .await?;

        Ok(json_text(&finding_info(&finding)))
    }

    #[tool(description = "AI-powered explanation of a finding using grounded source context.")]
    async fn explain_finding(
        &self,
        Parameters(req): Parameters<ExplainFindingRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let finding_id = parse_uuid(&req.finding_id)?;
        let actor_user_id = self
            .resolve_actor_user_id(req.user_id.as_deref(), None)
            .await?;
        self.run_finding_ai_review(finding_id, actor_user_id, "ai_explanation")
            .await
    }

    #[tool(
        description = "Verification review of a finding. This currently performs AI triage verification using grounded source context; it does not re-run sandbox PoC validation."
    )]
    async fn verify_finding(
        &self,
        Parameters(req): Parameters<VerifyFindingRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let finding_id = parse_uuid(&req.finding_id)?;
        let actor_user_id = self
            .resolve_actor_user_id(req.user_id.as_deref(), None)
            .await?;
        self.run_finding_ai_review(finding_id, actor_user_id, "ai_verification")
            .await
    }

    #[tool(description = "Audit trail for a finding.")]
    async fn list_finding_events(
        &self,
        Parameters(req): Parameters<ListFindingEventsRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let finding_id = parse_uuid(&req.finding_id)?;
        let (_finding, _) = self
            .load_finding_and_repo_for_user(finding_id, user.id)
            .await?;
        let events = self
            .state
            .db
            .list_finding_events(finding_id)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?;

        Ok(json_text(&events))
    }

    #[tool(description = "Add a comment or note to a finding.")]
    async fn comment_on_finding(
        &self,
        Parameters(req): Parameters<CommentOnFindingRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        if req.comment.trim().is_empty() {
            return Err(invalid_params("comment must not be empty".to_string()));
        }
        let actor_user_id = self
            .resolve_actor_user_id(req.user_id.as_deref(), None)
            .await?;
        let finding_id = parse_uuid(&req.finding_id)?;
        let (_finding, _) = self
            .load_finding_and_repo_for_user(finding_id, actor_user_id)
            .await?;

        let event = self
            .state
            .db
            .create_finding_event(
                finding_id,
                Some(actor_user_id),
                "comment",
                None,
                None,
                Some(req.comment.trim()),
            )
            .await
            .map_err(|error| internal_err(format!("Failed to add comment: {error}")))?;

        Ok(json_text(&event))
    }

    #[tool(
        description = "Mark the latest suggested diff for a finding as applied in Heimdall metadata. This does not modify the repository checkout directly."
    )]
    async fn apply_patch(
        &self,
        Parameters(req): Parameters<ApplyPatchRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let actor_user_id = self
            .resolve_actor_user_id(req.user_id.as_deref(), None)
            .await?;
        let finding_id = parse_uuid(&req.finding_id)?;
        let (finding, _) = self
            .load_finding_and_repo_for_user(finding_id, actor_user_id)
            .await?;

        let patch = self
            .state
            .db
            .get_patch_for_finding(finding.id)
            .await
            .map_err(|error| internal_err(format!("Failed to fetch patch: {error}")))?
            .ok_or_else(|| {
                invalid_params(format!("No patch available for finding {}", req.finding_id))
            })?;

        if patch.applied {
            return Err(invalid_params(
                "Suggested diff has already been marked as applied in Heimdall.".to_string(),
            ));
        }

        self.state
            .db
            .mark_patch_applied(patch.id, actor_user_id)
            .await
            .map_err(|error| {
                internal_err(format!(
                    "Failed to mark suggested diff as applied in Heimdall: {error}"
                ))
            })?;

        let event = self
            .state
            .db
            .create_finding_event(
                finding.id,
                Some(actor_user_id),
                "patch_applied",
                None,
                Some(&patch.id.to_string()),
                Some("Suggested diff marked as applied in Heimdall via MCP"),
            )
            .await
            .map_err(|error| {
                internal_err(format!(
                    "Suggested diff was marked as applied, but event creation failed: {error}"
                ))
            })?;

        Ok(json_text(&serde_json::json!({
            "finding_id": finding.id,
            "patch_id": patch.id,
            "applied_by": actor_user_id,
            "event": event,
        })))
    }

    #[tool(
        description = "Get the STRIDE-based threat model for a scan, including trust boundaries, attack surfaces, and sensitive data flows."
    )]
    async fn get_threat_model(
        &self,
        Parameters(req): Parameters<GetThreatModelRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let scan_id = parse_uuid(&req.scan_id)?;
        let threat_model = self
            .state
            .db
            .get_threat_model_by_scan_for_user(scan_id, user.id)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?
            .ok_or_else(|| {
                invalid_params(format!("No threat model found for scan {}", req.scan_id))
            })?;

        Ok(json_text(&threat_model))
    }

    #[tool(
        description = "Edit a threat model field. Supported fields are summary, boundaries, surfaces, and data_flows."
    )]
    async fn update_threat_model(
        &self,
        Parameters(req): Parameters<UpdateThreatModelRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let threat_model_id = match req.threat_model_id.as_deref() {
            Some(value) => {
                let threat_model_id = parse_uuid(value)?;
                self.state
                    .db
                    .get_threat_model_by_id_for_user(threat_model_id, user.id)
                    .await
                    .map_err(|error| internal_err(format!("Database error: {error}")))?
                    .ok_or_else(|| {
                        invalid_params(format!("Threat model {threat_model_id} not found"))
                    })?
                    .id
            }
            None => {
                let scan_id = req.scan_id.as_deref().ok_or_else(|| {
                    invalid_params("Either threat_model_id or scan_id is required".to_string())
                })?;
                let scan_id = parse_uuid(scan_id)?;
                self.state
                    .db
                    .get_threat_model_by_scan_for_user(scan_id, user.id)
                    .await
                    .map_err(|error| internal_err(format!("Database error: {error}")))?
                    .ok_or_else(|| {
                        invalid_params(format!("No threat model found for scan {scan_id}"))
                    })?
                    .id
            }
        };
        let field = normalize_threat_model_field(req.field.trim()).ok_or_else(|| {
            invalid_params(
                "field must be one of: summary, boundaries, surfaces, data_flows".to_string(),
            )
        })?;

        self.state
            .db
            .update_threat_model_field(threat_model_id, field, &req.value)
            .await
            .map_err(|error| internal_err(format!("Failed to update threat model: {error}")))?;

        let updated = self
            .state
            .db
            .get_threat_model_by_id_for_user(threat_model_id, user.id)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?
            .ok_or_else(|| invalid_params(format!("Threat model {threat_model_id} not found")))?;

        Ok(json_text(&updated))
    }

    #[tool(description = "Get all suggested diffs for a scan as unified patches.")]
    async fn get_patches(
        &self,
        Parameters(req): Parameters<GetPatchesRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let scan_id = parse_uuid(&req.scan_id)?;
        let _scan = self.load_scan_for_user(scan_id, user.id).await?;
        let patches = self
            .state
            .db
            .list_patches_by_scan(scan_id)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?;

        Ok(json_text(&patches))
    }

    #[tool(description = "Update the status of a finding.")]
    async fn update_finding_status(
        &self,
        Parameters(req): Parameters<UpdateFindingStatusRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let status = req.status.trim().to_lowercase();
        if !valid_finding_status(&status) {
            return Err(invalid_params(format!(
                "Invalid status '{}'. Must be one of: open, confirmed, dismissed, false_positive, fixed",
                req.status
            )));
        }

        let actor_user_id = self
            .resolve_actor_user_id(req.user_id.as_deref(), None)
            .await?;
        let finding_id = parse_uuid(&req.finding_id)?;
        let (finding, _) = self
            .load_finding_and_repo_for_user(finding_id, actor_user_id)
            .await?;

        self.state
            .db
            .update_finding_status(finding_id, &status)
            .await
            .map_err(|error| internal_err(format!("Failed to update status: {error}")))?;

        let event = self
            .state
            .db
            .create_finding_event(
                finding_id,
                Some(actor_user_id),
                "status_change",
                Some(&finding.status),
                Some(&status),
                Some("Updated via MCP"),
            )
            .await
            .map_err(|error| {
                internal_err(format!("Status updated but event creation failed: {error}"))
            })?;

        Ok(json_text(&serde_json::json!({
            "finding_id": finding_id,
            "old_status": finding.status,
            "new_status": status,
            "event": event,
        })))
    }

    #[tool(description = "Adjust a finding severity manually.")]
    async fn update_finding_severity(
        &self,
        Parameters(req): Parameters<UpdateFindingSeverityRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let severity = req.severity.trim().to_lowercase();
        if !valid_severity(&severity) {
            return Err(invalid_params(format!(
                "Invalid severity '{}'. Must be one of: critical, high, medium, low",
                req.severity
            )));
        }

        let actor_user_id = self
            .resolve_actor_user_id(req.user_id.as_deref(), None)
            .await?;
        let finding_id = parse_uuid(&req.finding_id)?;
        let (finding, _) = self
            .load_finding_and_repo_for_user(finding_id, actor_user_id)
            .await?;

        self.state
            .db
            .update_finding_severity(finding_id, &severity)
            .await
            .map_err(|error| internal_err(format!("Failed to update severity: {error}")))?;

        let event = self
            .state
            .db
            .create_finding_event(
                finding_id,
                Some(actor_user_id),
                "severity_change",
                Some(&finding.severity),
                Some(&severity),
                Some("Updated via MCP"),
            )
            .await
            .map_err(|error| {
                internal_err(format!(
                    "Severity updated but event creation failed: {error}"
                ))
            })?;

        Ok(json_text(&serde_json::json!({
            "finding_id": finding_id,
            "old_severity": finding.severity,
            "new_severity": severity,
            "event": event,
        })))
    }

    #[tool(
        description = "Push a finding to the repository issue tracker or link an existing matching issue."
    )]
    async fn create_issue(
        &self,
        Parameters(req): Parameters<CreateIssueRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let actor_user_id = self
            .resolve_actor_user_id(req.user_id.as_deref(), None)
            .await?;
        let finding_id = parse_uuid(&req.finding_id)?;
        let (finding, repo) = self
            .load_finding_and_repo_for_user(finding_id, actor_user_id)
            .await?;

        if !issues::supports_issue_creation(&repo) {
            return Err(invalid_params(
                "This repository does not currently support issue creation.".to_string(),
            ));
        }

        let (repo_issue, created) = issues::create_or_link_issue(
            &self.state.db,
            self.state.encryption_key.as_ref(),
            &repo,
            &finding,
            false,
        )
        .await
        .map_err(|error| internal_err(format!("Issue creation failed: {error}")))?;

        let metadata = serde_json::json!({
            "provider": repo_issue.provider,
            "issue_url": repo_issue.issue_url,
            "external_issue_number": repo_issue.external_issue_number,
            "auto_created": false,
            "created": created,
        });
        let event = self
            .state
            .db
            .create_finding_event_with_metadata(
                finding.id,
                Some(actor_user_id),
                "issue_linked",
                None,
                repo_issue.external_issue_number.as_deref(),
                Some(if created {
                    "Repository issue created via MCP."
                } else {
                    "An existing repository issue was already linked."
                }),
                Some(&metadata),
            )
            .await
            .map_err(|error| {
                internal_err(format!("Issue linked but event creation failed: {error}"))
            })?;

        Ok(json_text(&serde_json::json!({
            "created": created,
            "issue": repo_issue,
            "event": event,
        })))
    }

    #[tool(
        description = "Bulk push open findings in a scan to the repository issue tracker, grouped by finding title."
    )]
    async fn create_all_issues(
        &self,
        Parameters(req): Parameters<CreateAllIssuesRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let actor_user_id = self
            .resolve_actor_user_id(req.user_id.as_deref(), None)
            .await?;
        let scan_id = parse_uuid(&req.scan_id)?;
        let scan = self.load_scan_for_user(scan_id, actor_user_id).await?;
        let repo = self.load_repo_for_user(scan.repo_id, actor_user_id).await?;

        if !issues::supports_issue_creation(&repo) {
            return Err(invalid_params(
                "This repository does not support issue creation.".to_string(),
            ));
        }

        let findings = self
            .state
            .db
            .list_findings_by_scan(scan_id, None, Some("open"))
            .await
            .map_err(|error| internal_err(format!("Failed to list findings: {error}")))?;
        let groups = issues::group_findings_by_rule(&findings);

        let mut created_count = 0u32;
        let mut linked_count = 0u32;
        let mut failed_count = 0u32;
        let mut findings_covered = 0u32;

        for (title, grouped_findings) in &groups {
            match issues::create_or_link_grouped_issue(
                &self.state.db,
                self.state.encryption_key.as_ref(),
                &repo,
                title,
                grouped_findings,
                false,
            )
            .await
            {
                Ok((repo_issue, created, count)) => {
                    if created {
                        created_count += 1;
                    } else {
                        linked_count += 1;
                    }
                    findings_covered += count as u32;

                    let metadata = serde_json::json!({
                        "provider": repo_issue.provider,
                        "issue_url": repo_issue.issue_url,
                        "external_issue_number": repo_issue.external_issue_number,
                        "auto_created": false,
                        "created": created,
                        "bulk": true,
                        "grouped": true,
                        "finding_count": count,
                    });
                    for finding in grouped_findings {
                        let _ = self
                            .state
                            .db
                            .create_finding_event_with_metadata(
                                finding.id,
                                Some(actor_user_id),
                                "issue_linked",
                                None,
                                repo_issue.external_issue_number.as_deref(),
                                Some(if created {
                                    "Issue created via grouped MCP bulk action."
                                } else {
                                    "Linked to an existing grouped issue via MCP bulk action."
                                }),
                                Some(&metadata),
                            )
                            .await;
                    }
                }
                Err(error) => {
                    warn!(
                        "Failed to create grouped issue for '{}' ({} findings): {error}",
                        title,
                        grouped_findings.len()
                    );
                    failed_count += grouped_findings.len() as u32;
                }
            }
        }

        Ok(json_text(&serde_json::json!({
            "created": created_count,
            "linked": linked_count,
            "failed": failed_count,
            "total_findings": findings.len(),
            "total_groups": groups.len(),
            "findings_covered": findings_covered,
            "summary": format!(
                "{created_count} issues created, {linked_count} already linked, {failed_count} failed ({findings_covered} findings across {} groups)",
                groups.len()
            ),
        })))
    }

    #[tool(description = "See what AI agents did during a scan.")]
    async fn list_agent_tool_calls(
        &self,
        Parameters(req): Parameters<ListAgentToolCallsRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let user = self.resolve_user(req.user_id.as_deref()).await?;
        let scan_id = parse_uuid(&req.scan_id)?;
        let _scan = self.load_scan_for_user(scan_id, user.id).await?;
        let limit = req.limit.unwrap_or(50);
        let tool_calls = self
            .state
            .db
            .list_agent_tool_calls_by_scan(scan_id, limit)
            .await
            .map_err(|error| internal_err(format!("Database error: {error}")))?;

        Ok(json_text(&tool_calls))
    }

    #[tool(
        description = "Create, list, or delete stored AI provider API keys. Supported actions are create, list, and delete."
    )]
    async fn manage_api_keys(
        &self,
        Parameters(req): Parameters<ManageApiKeysRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let action = req.action.trim().to_lowercase();
        let user = self.resolve_user(req.user_id.as_deref()).await?;

        match action.as_str() {
            "list" => {
                let keys = self
                    .state
                    .db
                    .list_api_keys_by_user(user.id)
                    .await
                    .map_err(|error| internal_err(format!("Database error: {error}")))?;
                let keys = keys
                    .into_iter()
                    .filter(|key| {
                        req.provider
                            .as_deref()
                            .map(|provider| key.provider.as_deref() == Some(provider))
                            .unwrap_or(true)
                    })
                    .map(|key| ApiKeyInfo {
                        id: key.id.to_string(),
                        user_id: key.user_id.to_string(),
                        provider: key.provider,
                        label: key.label,
                        last_used_at: key.last_used_at.map(|value| value.to_rfc3339()),
                        created_at: key.created_at.to_rfc3339(),
                    })
                    .collect::<Vec<_>>();
                Ok(json_text(&keys))
            }
            "create" => {
                let provider = req
                    .provider
                    .as_deref()
                    .map(str::trim)
                    .ok_or_else(|| {
                        invalid_params("provider is required for action=create".to_string())
                    })?
                    .to_lowercase();
                if !valid_provider(&provider) {
                    return Err(invalid_params(
                        "provider must be one of: anthropic, openai, ollama".to_string(),
                    ));
                }
                let key = req
                    .key
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        invalid_params("key is required for action=create".to_string())
                    })?;

                let created = self
                    .state
                    .db
                    .create_api_key(
                        user.id,
                        "llm_provider",
                        &provider,
                        req.label.as_deref(),
                        &hash_key(key),
                        &encrypt_key(key, self.state.encryption_key.as_ref()),
                    )
                    .await
                    .map_err(|error| internal_err(format!("Failed to create API key: {error}")))?;

                Ok(json_text(&serde_json::json!({
                    "created": true,
                    "key": {
                        "id": created.id,
                        "user_id": created.user_id,
                        "provider": created.provider,
                        "label": created.label,
                        "key_preview": mask_key(key),
                        "created_at": created.created_at.to_rfc3339(),
                    }
                })))
            }
            "delete" => {
                let key_id = req.key_id.as_deref().ok_or_else(|| {
                    invalid_params("key_id is required for action=delete".to_string())
                })?;
                let key_id = parse_uuid(key_id)?;
                self.state
                    .db
                    .delete_api_key(key_id)
                    .await
                    .map_err(|error| internal_err(format!("Failed to delete API key: {error}")))?;
                Ok(json_text(&serde_json::json!({
                    "deleted": true,
                    "key_id": key_id,
                })))
            }
            _ => Err(invalid_params(
                "action must be one of: create, list, delete".to_string(),
            )),
        }
    }

    #[tool(description = "Verify AI provider connectivity with a short completion request.")]
    async fn test_connection(
        &self,
        Parameters(req): Parameters<TestConnectionRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let provider = req.provider.trim().to_lowercase();
        let provider_impl: Box<dyn ai::ModelProvider> = match provider.as_str() {
            "anthropic" => Box::new(ai::claude::ClaudeProvider::new(req.key.clone())),
            "openai" => Box::new(ai::openai::OpenAiProvider::new(req.key.clone())),
            "ollama" => Box::new(ai::ollama::OllamaProvider::new(req.key.clone())),
            _ => {
                return Err(invalid_params(
                    "provider must be one of: anthropic, openai, ollama".to_string(),
                ));
            }
        };

        let model = match provider.as_str() {
            "anthropic" => "claude-sonnet-4-20250514",
            "openai" => "gpt-4o-mini",
            "ollama" => "llama3.2",
            _ => unreachable!(),
        };

        let request = CompletionRequest {
            model: model.to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: "Say hello in one word.".to_string(),
            }],
            tools: None,
            max_tokens: Some(32),
            temperature: Some(0.0),
        };

        match provider_impl.complete(request).await {
            Ok(response) => Ok(json_text(&serde_json::json!({
                "success": true,
                "provider": provider_impl.provider_name(),
                "message": format!(
                    "Connection successful. Response: {}",
                    response.content.chars().take(100).collect::<String>()
                ),
            }))),
            Err(error) => Ok(json_text(&serde_json::json!({
                "success": false,
                "provider": provider_impl.provider_name(),
                "message": format!("Connection failed: {error:#}"),
            }))),
        }
    }
}

#[tool_handler]
impl ServerHandler for HeimdallMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Heimdall is an agentic security scanner for source code repositories. \
             Use these tools to import repositories, queue scans, inspect scan history and audit trails, \
             review findings, manage issue creation, update threat models, and manage stored AI provider keys.",
        )
    }
}
