//
//  heimdall
//  src/mcp/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/20.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::schemars;
use rmcp::schemars::JsonSchema;
use rmcp::{ServerHandler, tool, tool_router};
use serde::{Deserialize, Serialize};

use crate::db::DatabaseOperations;

/// Heimdall MCP Server — exposes security scanning capabilities via the
/// Model Context Protocol for use in AI coding tools (Claude Code, Cursor, etc.).
#[derive(Clone)]
pub struct HeimdallMcp {
    db: Arc<DatabaseOperations>,
    tool_router: ToolRouter<Self>,
}

// --- Request types ---

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListReposRequest {
    /// Maximum number of repositories to return (default: 50)
    pub limit: Option<i64>,
    /// Offset for pagination (default: 0)
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetRepoRequest {
    /// Repository UUID
    pub repo_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TriggerScanRequest {
    /// Repository UUID to scan
    pub repo_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetScanRequest {
    /// Scan UUID
    pub scan_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFindingsRequest {
    /// Scan UUID
    pub scan_id: String,
    /// Filter by severity: critical, high, medium, low
    pub severity: Option<String>,
    /// Filter by status: open, confirmed, dismissed, false_positive, fixed
    pub status: Option<String>,
    /// Maximum number of findings to return (default: 50)
    pub limit: Option<i64>,
    /// Offset for pagination (default: 0)
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetFindingRequest {
    /// Finding UUID
    pub finding_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetThreatModelRequest {
    /// Scan UUID
    pub scan_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetPatchesRequest {
    /// Scan UUID
    pub scan_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateFindingStatusRequest {
    /// Finding UUID
    pub finding_id: String,
    /// New status: open, confirmed, dismissed, false_positive, fixed
    pub status: String,
}

// --- Response types (for JSON serialization) ---

#[derive(Debug, Serialize)]
struct RepoInfo {
    id: String,
    name: String,
    source_type: String,
    remote_url: Option<String>,
    default_branch: Option<String>,
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
}

#[derive(Debug, Serialize)]
struct FindingInfo {
    id: String,
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

fn parse_uuid(s: &str) -> Result<uuid::Uuid, rmcp::ErrorData> {
    uuid::Uuid::parse_str(s).map_err(|e| {
        rmcp::ErrorData::new(
            rmcp::model::ErrorCode::INVALID_PARAMS,
            format!("Invalid UUID '{s}': {e}"),
            None,
        )
    })
}

fn json_text<T: Serialize>(val: &T) -> String {
    serde_json::to_string_pretty(val).unwrap_or_default()
}

fn internal_err(msg: String) -> rmcp::ErrorData {
    rmcp::ErrorData::new(rmcp::model::ErrorCode::INTERNAL_ERROR, msg, None)
}

impl HeimdallMcp {
    pub fn new(db: Arc<DatabaseOperations>) -> Self {
        Self {
            db,
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl HeimdallMcp {
    #[tool(description = "List all repositories connected to Heimdall")]
    async fn list_repositories(
        &self,
        Parameters(req): Parameters<ListReposRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let limit = req.limit.unwrap_or(50);
        let offset = req.offset.unwrap_or(0);
        let repos = self
            .db
            .list_all_repos_paginated(limit, offset)
            .await
            .map_err(|e| internal_err(format!("Database error: {e}")))?;

        let infos: Vec<RepoInfo> = repos
            .into_iter()
            .map(|r| RepoInfo {
                id: r.id.to_string(),
                name: r.name,
                source_type: r.source_type,
                remote_url: r.remote_url,
                default_branch: r.default_branch,
            })
            .collect();

        Ok(json_text(&infos))
    }

    #[tool(description = "Get details of a specific repository by its ID")]
    async fn get_repository(
        &self,
        Parameters(req): Parameters<GetRepoRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let id = parse_uuid(&req.repo_id)?;
        let repo = self
            .db
            .get_repo_by_id(id)
            .await
            .map_err(|e| internal_err(format!("Database error: {e}")))?
            .ok_or_else(|| {
                rmcp::ErrorData::new(
                    rmcp::model::ErrorCode::INVALID_PARAMS,
                    format!("Repository {} not found", req.repo_id),
                    None,
                )
            })?;

        Ok(json_text(&RepoInfo {
            id: repo.id.to_string(),
            name: repo.name,
            source_type: repo.source_type,
            remote_url: repo.remote_url,
            default_branch: repo.default_branch,
        }))
    }

    #[tool(description = "Trigger a new security scan on a repository. The scan runs asynchronously — use get_scan_status to check progress.")]
    async fn trigger_scan(
        &self,
        Parameters(req): Parameters<TriggerScanRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let repo_id = parse_uuid(&req.repo_id)?;

        self.db
            .get_repo_by_id(repo_id)
            .await
            .map_err(|e| internal_err(format!("Database error: {e}")))?
            .ok_or_else(|| {
                rmcp::ErrorData::new(
                    rmcp::model::ErrorCode::INVALID_PARAMS,
                    format!("Repository {} not found", req.repo_id),
                    None,
                )
            })?;

        let scan = self
            .db
            .create_scan(repo_id, "full", None, None, None, None)
            .await
            .map_err(|e| internal_err(format!("Failed to create scan: {e}")))?;

        Ok(format!("Scan queued: {} (status: {})", scan.id, scan.status))
    }

    #[tool(description = "Get the current status and finding counts of a scan")]
    async fn get_scan_status(
        &self,
        Parameters(req): Parameters<GetScanRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let id = parse_uuid(&req.scan_id)?;
        let scan = self
            .db
            .get_scan_by_id(id)
            .await
            .map_err(|e| internal_err(format!("Database error: {e}")))?
            .ok_or_else(|| {
                rmcp::ErrorData::new(
                    rmcp::model::ErrorCode::INVALID_PARAMS,
                    format!("Scan {} not found", req.scan_id),
                    None,
                )
            })?;

        Ok(json_text(&ScanInfo {
            id: scan.id.to_string(),
            repo_id: scan.repo_id.to_string(),
            status: scan.status,
            scan_type: scan.scan_type,
            finding_count: scan.finding_count,
            critical_count: scan.critical_count,
            high_count: scan.high_count,
            medium_count: scan.medium_count,
            low_count: scan.low_count,
        }))
    }

    #[tool(description = "List security findings for a scan. Supports filtering by severity (critical/high/medium/low) and status (open/confirmed/dismissed/false_positive/fixed).")]
    async fn list_findings(
        &self,
        Parameters(req): Parameters<ListFindingsRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let scan_id = parse_uuid(&req.scan_id)?;
        let limit = req.limit.unwrap_or(50);
        let offset = req.offset.unwrap_or(0);
        let findings = self
            .db
            .list_findings_by_scan_paginated(
                scan_id,
                req.severity.as_deref(),
                req.status.as_deref(),
                limit,
                offset,
            )
            .await
            .map_err(|e| internal_err(format!("Database error: {e}")))?;

        let infos: Vec<FindingInfo> = findings
            .into_iter()
            .map(|f| FindingInfo {
                id: f.id.to_string(),
                source: f.source,
                status: f.status,
                severity: f.severity,
                confidence: f.confidence,
                title: f.title,
                description: f.description,
                cwe_id: f.cwe_id,
                cve_id: f.cve_id,
                file_path: f.file_path,
                line_start: f.line_start,
                line_end: f.line_end,
                code_snippet: f.code_snippet,
                suggested_patch: f.suggested_patch,
                agent_reasoning: f.agent_reasoning,
                poc_validated: f.poc_validated,
            })
            .collect();

        Ok(json_text(&infos))
    }

    #[tool(description = "Get full details of a specific finding including code snippet, suggested patch, analyst reasoning, and PoC validation status")]
    async fn get_finding(
        &self,
        Parameters(req): Parameters<GetFindingRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let id = parse_uuid(&req.finding_id)?;
        let f = self
            .db
            .get_finding_by_id(id)
            .await
            .map_err(|e| internal_err(format!("Database error: {e}")))?
            .ok_or_else(|| {
                rmcp::ErrorData::new(
                    rmcp::model::ErrorCode::INVALID_PARAMS,
                    format!("Finding {} not found", req.finding_id),
                    None,
                )
            })?;

        Ok(json_text(&FindingInfo {
            id: f.id.to_string(),
            source: f.source,
            status: f.status,
            severity: f.severity,
            confidence: f.confidence,
            title: f.title,
            description: f.description,
            cwe_id: f.cwe_id,
            cve_id: f.cve_id,
            file_path: f.file_path,
            line_start: f.line_start,
            line_end: f.line_end,
            code_snippet: f.code_snippet,
            suggested_patch: f.suggested_patch,
            agent_reasoning: f.agent_reasoning,
            poc_validated: f.poc_validated,
        }))
    }

    #[tool(description = "Get the STRIDE-based threat model for a scan, including trust boundaries, attack surfaces, and sensitive data flows")]
    async fn get_threat_model(
        &self,
        Parameters(req): Parameters<GetThreatModelRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let scan_id = parse_uuid(&req.scan_id)?;
        let tm = self
            .db
            .get_threat_model_by_scan(scan_id)
            .await
            .map_err(|e| internal_err(format!("Database error: {e}")))?
            .ok_or_else(|| {
                rmcp::ErrorData::new(
                    rmcp::model::ErrorCode::INVALID_PARAMS,
                    format!("No threat model found for scan {}", req.scan_id),
                    None,
                )
            })?;

        #[derive(Serialize)]
        struct TmInfo {
            id: String,
            summary: Option<String>,
            boundaries: Option<serde_json::Value>,
            surfaces: Option<serde_json::Value>,
            data_flows: Option<serde_json::Value>,
        }

        Ok(json_text(&TmInfo {
            id: tm.id.to_string(),
            summary: tm.summary,
            boundaries: tm.boundaries_json,
            surfaces: tm.surfaces_json,
            data_flows: tm.data_flows_json,
        }))
    }

    #[tool(description = "Get all suggested patches for a scan as unified diffs")]
    async fn get_patches(
        &self,
        Parameters(req): Parameters<GetPatchesRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let scan_id = parse_uuid(&req.scan_id)?;
        let patches = self
            .db
            .list_patches_by_scan(scan_id)
            .await
            .map_err(|e| internal_err(format!("Database error: {e}")))?;

        #[derive(Serialize)]
        struct PInfo {
            id: String,
            finding_id: String,
            file_path: String,
            diff_content: String,
            applied: bool,
        }

        let infos: Vec<PInfo> = patches
            .into_iter()
            .map(|p| PInfo {
                id: p.id.to_string(),
                finding_id: p.finding_id.to_string(),
                file_path: p.file_path,
                diff_content: p.diff_content,
                applied: p.applied,
            })
            .collect();

        Ok(json_text(&infos))
    }

    #[tool(description = "Update the status of a finding (open, confirmed, dismissed, false_positive, fixed)")]
    async fn update_finding_status(
        &self,
        Parameters(req): Parameters<UpdateFindingStatusRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let valid = ["open", "confirmed", "dismissed", "false_positive", "fixed"];
        if !valid.contains(&req.status.as_str()) {
            return Err(rmcp::ErrorData::new(
                rmcp::model::ErrorCode::INVALID_PARAMS,
                format!(
                    "Invalid status '{}'. Must be one of: {}",
                    req.status,
                    valid.join(", ")
                ),
                None,
            ));
        }

        let id = parse_uuid(&req.finding_id)?;
        let finding = self
            .db
            .get_finding_by_id(id)
            .await
            .map_err(|e| internal_err(format!("Database error: {e}")))?
            .ok_or_else(|| {
                rmcp::ErrorData::new(
                    rmcp::model::ErrorCode::INVALID_PARAMS,
                    format!("Finding {} not found", req.finding_id),
                    None,
                )
            })?;

        let old_status = finding.status.clone();

        self.db
            .update_finding_status(id, &req.status)
            .await
            .map_err(|e| internal_err(format!("Failed to update status: {e}")))?;

        let _ = self
            .db
            .create_finding_event(
                id,
                None,
                "status_change",
                Some(&old_status),
                Some(&req.status),
                Some("Updated via MCP"),
            )
            .await;

        Ok(format!(
            "Finding {} status updated: {} -> {}",
            req.finding_id, old_status, req.status
        ))
    }
}

impl ServerHandler for HeimdallMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "Heimdall is an agentic security scanner for source code repositories. \
                 Use these tools to list repositories, trigger scans, review findings, \
                 read threat models, and manage finding statuses.",
            )
    }
}
