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
    pub theme: String,
    pub preferred_ai_provider: Option<String>,
    pub ai_fallbacks_enabled: bool,
    pub ai_fallback_order: String,
    pub ai_provider_models: String,
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
    pub token_source: String,
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
    pub issue_auto_create_enabled: bool,
    pub issue_auto_create_min_severity: String,
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
    pub content_text: Option<String>,
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
    /// The vulnerable code section — concrete lines from the target file.
    /// Every production finding is expected to carry this evidence. See
    /// [`FindingEvidence`] and [`crate::db::DatabaseOperations::create_finding_full`].
    pub code_snippet: Option<String>,
    /// Suggested fix — unified diff, replacement snippet, or structured patch
    /// text. For dependency findings this is a manifest-format diff bumping
    /// the version. For code findings this is either an autofix (from semgrep
    /// or the hunt agent) or a hand-authored template from the rule.
    pub suggested_patch: Option<String>,
    /// Classification of the fix (code edit vs dependency upgrade vs config
    /// change vs manual review). Drives how the UI renders the fix and what
    /// automation (PR bots, dependabot-style workflows) can do with it.
    #[sqlx(default)]
    pub fix_type: Option<String>,
    /// Plain-English summary of the suggested fix. Always populated when a
    /// concrete remediation exists. Rendered alongside the patch so operators
    /// who skim triage queues can understand intent without reading a diff.
    #[sqlx(default)]
    pub fix_summary: Option<String>,
    /// External references — advisory URLs (GHSA, CVE, OWASP), migration
    /// guides, rule documentation. Stored as `jsonb` array of strings.
    #[sqlx(default)]
    pub references_json: Option<serde_json::Value>,
    /// For dependency findings: ecosystem / package / installed version /
    /// fixed version bundle. Lets the UI render upgrade guidance without
    /// re-parsing the patch. `None` for code findings.
    #[sqlx(default)]
    pub manifest_coordinates_json: Option<serde_json::Value>,
    pub poc_exploit_json: Option<serde_json::Value>,
    pub poc_validated: bool,
    pub fingerprint: String,
    pub agent_reasoning: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Classification of a finding's remediation shape.
///
/// Drives UI rendering (code diff vs version picker vs config editor) and
/// downstream automation (who can apply the fix automatically). Every finding
/// carries one of these values — when there is no automatic remediation,
/// [`FindingFixType::ManualReview`] is the honest choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingFixType {
    /// Edit the vulnerable code in place (e.g., replace `md5(x)` with `sha256(x)`,
    /// swap string interpolation for parameterized query binding).
    CodeChange,
    /// Bump a package version in a manifest file. Produced by the deps audit
    /// stage. Suggested patch is a manifest-format diff; manifest_coordinates
    /// carries ecosystem/name/versions for structured rendering.
    DependencyUpgrade,
    /// Change a configuration file or environment variable (e.g., set
    /// `httponly=true` on cookies, flip `DEBUG=false`, disable ECB mode).
    ConfigChange,
    /// No mechanical fix available — human judgement required. Used for
    /// architectural concerns, TOCTOU races, low-confidence matches, or
    /// findings where the "right" answer depends on business logic.
    ManualReview,
}

impl Default for FindingFixType {
    fn default() -> Self {
        Self::ManualReview
    }
}

impl FindingFixType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingFixType::CodeChange => "code_change",
            FindingFixType::DependencyUpgrade => "dependency_upgrade",
            FindingFixType::ConfigChange => "config_change",
            FindingFixType::ManualReview => "manual_review",
        }
    }
}

/// Bundle of remediation evidence attached to every finding.
///
/// This exists to enforce the invariant that a finding without evidence is
/// meaningless. `code_snippet` shows WHERE the problem is. `suggested_patch`
/// + `fix_summary` show HOW to fix it. `references` point to AUTHORITY for the
/// remediation. `manifest_coordinates` carries structured upgrade data for
/// dependency findings that UI and automation can consume directly.
///
/// Stages should construct this inline when creating findings — the fields
/// are deliberately ergonomic (`Option<String>` / `Vec<String>`) so there is
/// no excuse for leaving them empty when real data exists.
#[derive(Debug, Clone, Default)]
pub struct FindingEvidence {
    /// Vulnerable code lines pulled from the target file with surrounding
    /// context. Expected to always be populated for code / config / dep
    /// findings. `None` is only acceptable for findings that genuinely have
    /// no code locus (and those should be rare).
    pub code_snippet: Option<String>,
    /// The suggested replacement — either a unified diff (preferred) or a
    /// replacement snippet. `None` only when the finding is [`FindingFixType::ManualReview`].
    pub suggested_patch: Option<String>,
    /// Classification of the remediation shape.
    pub fix_type: FindingFixType,
    /// One-liner summary of the fix in plain English. Always populated for
    /// anything other than [`FindingFixType::ManualReview`].
    pub fix_summary: Option<String>,
    /// Authoritative URLs — advisories, CVE records, migration guides, OWASP
    /// entries. Stored as `jsonb` array on the finding row.
    pub references: Vec<String>,
    /// For dependency findings: structured upgrade bundle. See the
    /// [`ManifestCoordinates`] builder.
    pub manifest_coordinates: Option<serde_json::Value>,
}

impl FindingEvidence {
    /// Convenience constructor for code-change findings (static rules, taint,
    /// hunt agent).
    pub fn code_change(
        code_snippet: impl Into<String>,
        suggested_patch: impl Into<String>,
        fix_summary: impl Into<String>,
    ) -> Self {
        Self {
            code_snippet: Some(code_snippet.into()),
            suggested_patch: Some(suggested_patch.into()),
            fix_type: FindingFixType::CodeChange,
            fix_summary: Some(fix_summary.into()),
            references: Vec::new(),
            manifest_coordinates: None,
        }
    }

    /// Convenience constructor for config / IaC fixes.
    pub fn config_change(
        code_snippet: impl Into<String>,
        suggested_patch: impl Into<String>,
        fix_summary: impl Into<String>,
    ) -> Self {
        Self {
            code_snippet: Some(code_snippet.into()),
            suggested_patch: Some(suggested_patch.into()),
            fix_type: FindingFixType::ConfigChange,
            fix_summary: Some(fix_summary.into()),
            references: Vec::new(),
            manifest_coordinates: None,
        }
    }

    /// Convenience constructor for dependency upgrade findings.
    pub fn dependency_upgrade(
        code_snippet: impl Into<String>,
        suggested_patch: impl Into<String>,
        fix_summary: impl Into<String>,
        manifest_coordinates: serde_json::Value,
    ) -> Self {
        Self {
            code_snippet: Some(code_snippet.into()),
            suggested_patch: Some(suggested_patch.into()),
            fix_type: FindingFixType::DependencyUpgrade,
            fix_summary: Some(fix_summary.into()),
            references: Vec::new(),
            manifest_coordinates: Some(manifest_coordinates),
        }
    }

    /// Convenience constructor for manual-review findings where no mechanical
    /// fix exists — still carries the snippet so the UI can show evidence.
    pub fn manual_review(code_snippet: Option<String>, fix_summary: impl Into<String>) -> Self {
        Self {
            code_snippet,
            suggested_patch: None,
            fix_type: FindingFixType::ManualReview,
            fix_summary: Some(fix_summary.into()),
            references: Vec::new(),
            manifest_coordinates: None,
        }
    }

    /// Attach references (advisory URLs, migration guides) to an evidence
    /// bundle. Chainable.
    pub fn with_references<I, S>(mut self, refs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.references.extend(refs.into_iter().map(Into::into));
        self
    }
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
    pub provider: Option<String>,
    pub model: Option<String>,
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
pub struct ScanEventRecord {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub stage: Option<String>,
    pub task_key: Option<String>,
    pub event_type: String,
    pub status: Option<String>,
    pub title: String,
    pub detail: Option<String>,
    pub progress_pct: Option<i32>,
    pub metadata_json: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RepoIssue {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub finding_id: Option<Uuid>,
    pub provider: String,
    pub external_issue_id: String,
    pub external_issue_number: Option<String>,
    pub issue_url: String,
    pub title: String,
    pub fingerprint: String,
    pub severity: String,
    pub state: String,
    pub auto_created: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
