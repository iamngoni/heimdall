//
//  heimdall
//  src/models/db_models.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum ScanStatus {
    Queued,
    Ingesting,
    Ingested,
    Modeling,
    Modeled,
    StaticAnalysis,
    Hunting,
    Hunted,
    Validating,
    Validated,
    Reporting,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum ScanStageStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Claimed,
    Running,
    Completed,
    Failed,
    Dead,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Confirmed,
    Dismissed,
    FalsePositive,
    Fixed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum SourceType {
    Github,
    Gitlab,
    GitUrl,
    Zip,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum FindingSource {
    Ai,
    Static,
    Dependencies,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum EventType {
    StatusChange,
    SeverityChange,
    Comment,
    PatchApplied,
    PocValidated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum ScanStageKind {
    Ingest,
    Tyr,
    StaticAnalysis,
    Hunt,
    Garmr,
    Report,
}

// ---------------------------------------------------------------------------
// Table Models — all fields match the Postgres migration exactly
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OrgMember {
    pub id: Uuid,
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OauthConnection {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub access_token_enc: Option<String>,
    pub refresh_token_enc: Option<String>,
    pub scopes: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApiKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub org_id: Option<Uuid>,
    pub key_type: String,
    pub provider: Option<String>,
    pub label: Option<String>,
    pub key_hash: String,
    pub encrypted_key: String,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Repo {
    pub id: Uuid,
    pub org_id: Option<Uuid>,
    pub user_id: Uuid,
    pub name: String,
    pub source_type: String,
    pub remote_url: Option<String>,
    pub default_branch: Option<String>,
    pub last_commit_sha: Option<String>,
    pub oauth_connection_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Scan {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub scan_type: String,
    pub status: String,
    pub commit_sha: Option<String>,
    pub base_commit_sha: Option<String>,
    pub parent_scan_id: Option<Uuid>,
    pub triggered_by: Option<Uuid>,
    pub finding_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanStage {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub stage: String,
    pub status: String,
    pub attempt: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub metadata_json: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanJob {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub status: String,
    pub priority: i32,
    pub worker_id: Option<String>,
    pub run_after: Option<DateTime<Utc>>,
    pub attempts: i32,
    pub max_attempts: i32,
    pub last_error: Option<String>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FileSnapshot {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub scan_id: Uuid,
    pub file_path: String,
    pub content_hash: String,
    pub language: Option<String>,
    pub line_count: Option<i32>,
    pub byte_size: Option<i32>,
    pub ast_summary_json: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Finding {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub repo_id: Uuid,
    pub source: String,
    pub status: String,
    pub severity: String,
    pub confidence: String,
    pub title: String,
    pub description: Option<String>,
    pub cwe_id: Option<String>,
    pub cve_id: Option<String>,
    pub file_path: String,
    pub line_start: i32,
    pub line_end: Option<i32>,
    pub code_snippet: Option<String>,
    pub suggested_patch: Option<String>,
    pub poc_exploit_json: Option<serde_json::Value>,
    pub poc_validated: bool,
    pub fingerprint: String,
    pub agent_reasoning: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FindingEvent {
    pub id: Uuid,
    pub finding_id: Uuid,
    pub user_id: Option<Uuid>,
    pub event_type: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub comment: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Patch {
    pub id: Uuid,
    pub finding_id: Uuid,
    pub scan_id: Uuid,
    pub diff_content: String,
    pub description: Option<String>,
    pub applies_cleanly: bool,
    pub applied: bool,
    pub applied_by: Option<Uuid>,
    pub applied_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Flattened patch view that includes the file_path from the associated finding.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PatchWithFilePath {
    pub id: Uuid,
    pub finding_id: Uuid,
    pub file_path: String,
    pub diff_content: String,
    pub applied: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AgentToolCall {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub stage: String,
    pub tool_name: String,
    pub input_json: Option<serde_json::Value>,
    pub output_json: Option<serde_json::Value>,
    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
    pub total_tokens: Option<i32>,
    pub duration_ms: Option<i32>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ThreatModel {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub repo_id: Uuid,
    pub summary: Option<String>,
    pub boundaries_json: Option<serde_json::Value>,
    pub surfaces_json: Option<serde_json::Value>,
    pub data_flows_json: Option<serde_json::Value>,
    pub model_version: i32,
    pub edited_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
