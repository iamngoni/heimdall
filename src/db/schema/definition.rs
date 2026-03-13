//
//  heimdall
//  src/db/schema/definition.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::db::schema::builder::Schema;
use crate::db::schema::types::*;

/// The single source of truth for Heimdall's database schema.
/// All 16 tables, all indexes, all constraints.
/// Generate driver-specific SQL from this definition.
pub fn heimdall_schema() -> SchemaDef {
    Schema::new()
        .extension("pgcrypto")
        // ---------------------------------------------------------------
        // 1. users
        // ---------------------------------------------------------------
        .table("users", |t| {
            t.uuid_pk("id");
            t.text("email").unique().not_null();
            t.text("password_hash").not_null();
            t.text("display_name");
            t.text("avatar_url");
            t.text("role").not_null().default_str("'user'");
            t.timestamps();
            t.soft_delete();
        })
        // ---------------------------------------------------------------
        // 2. organizations
        // ---------------------------------------------------------------
        .table("organizations", |t| {
            t.uuid_pk("id");
            t.text("name").not_null();
            t.text("slug").unique().not_null();
            t.text("plan").not_null().default_str("'free'");
            t.timestamps();
            t.soft_delete();
        })
        // ---------------------------------------------------------------
        // 3. org_members
        // ---------------------------------------------------------------
        .table("org_members", |t| {
            t.uuid_pk("id");
            t.uuid("org_id")
                .not_null()
                .references("organizations", "id")
                .on_delete(OnDelete::Cascade);
            t.uuid("user_id")
                .not_null()
                .references("users", "id")
                .on_delete(OnDelete::Cascade);
            t.text("role").not_null().default_str("'member'");
            t.timestamp("created_at")
                .not_null()
                .default(DefaultValue::Now);
            t.unique_together(&["org_id", "user_id"]);
        })
        // ---------------------------------------------------------------
        // 4. sessions
        // ---------------------------------------------------------------
        .table("sessions", |t| {
            t.uuid_pk("id");
            t.uuid("user_id")
                .not_null()
                .references("users", "id")
                .on_delete(OnDelete::Cascade);
            t.text("token_hash").not_null();
            t.text("ip_address");
            t.text("user_agent");
            t.timestamp("expires_at").not_null();
            t.timestamp("created_at")
                .not_null()
                .default(DefaultValue::Now);
        })
        // ---------------------------------------------------------------
        // 5. oauth_connections
        // ---------------------------------------------------------------
        .table("oauth_connections", |t| {
            t.uuid_pk("id");
            t.uuid("user_id")
                .not_null()
                .references("users", "id")
                .on_delete(OnDelete::Cascade);
            t.text("provider").not_null();
            t.text("provider_user_id").not_null();
            t.text("access_token_enc");
            t.text("refresh_token_enc");
            t.text("scopes");
            t.text("token_source")
                .not_null()
                .default_str("'oauth'");
            t.timestamp("expires_at");
            t.timestamps();
            t.unique_together(&["user_id", "provider"]);
        })
        // ---------------------------------------------------------------
        // 6. api_keys
        // ---------------------------------------------------------------
        .table("api_keys", |t| {
            t.uuid_pk("id");
            t.uuid("user_id")
                .not_null()
                .references("users", "id")
                .on_delete(OnDelete::Cascade);
            t.uuid("org_id")
                .references("organizations", "id")
                .on_delete(OnDelete::SetNull);
            t.text("key_type").not_null();
            t.text("provider");
            t.text("label");
            t.text("key_hash").not_null();
            t.text("encrypted_key").not_null();
            t.timestamp("last_used_at");
            t.timestamp("created_at")
                .not_null()
                .default(DefaultValue::Now);
            t.soft_delete();
        })
        // ---------------------------------------------------------------
        // 7. repos
        // ---------------------------------------------------------------
        .table("repos", |t| {
            t.uuid_pk("id");
            t.uuid("org_id")
                .references("organizations", "id")
                .on_delete(OnDelete::SetNull);
            t.uuid("user_id")
                .not_null()
                .references("users", "id")
                .on_delete(OnDelete::Cascade);
            t.text("name").not_null();
            t.text("source_type").not_null();
            t.text("remote_url");
            t.text("default_branch");
            t.text("last_commit_sha");
            t.uuid("oauth_connection_id")
                .references("oauth_connections", "id")
                .on_delete(OnDelete::SetNull);
            t.boolean("issue_auto_create_enabled")
                .not_null()
                .default_bool(true);
            t.text("issue_auto_create_min_severity")
                .not_null()
                .default_str("'high'");
            t.timestamps();
            t.soft_delete();
        })
        // ---------------------------------------------------------------
        // 8. scans
        // ---------------------------------------------------------------
        .table("scans", |t| {
            t.uuid_pk("id");
            t.uuid("repo_id")
                .not_null()
                .references("repos", "id")
                .on_delete(OnDelete::Cascade);
            t.text("scan_type").not_null().default_str("'full'");
            t.text("status").not_null().default_str("'queued'");
            t.text("commit_sha");
            t.text("base_commit_sha");
            t.uuid("parent_scan_id")
                .references("scans", "id")
                .on_delete(OnDelete::SetNull);
            t.uuid("triggered_by")
                .references("users", "id")
                .on_delete(OnDelete::SetNull);
            t.int("finding_count").not_null().default_int(0);
            t.int("critical_count").not_null().default_int(0);
            t.int("high_count").not_null().default_int(0);
            t.int("medium_count").not_null().default_int(0);
            t.int("low_count").not_null().default_int(0);
            t.timestamp("started_at");
            t.timestamp("completed_at");
            t.text("error_message");
            t.timestamps();
        })
        // ---------------------------------------------------------------
        // 9. scan_stages
        // ---------------------------------------------------------------
        .table("scan_stages", |t| {
            t.uuid_pk("id");
            t.uuid("scan_id")
                .not_null()
                .references("scans", "id")
                .on_delete(OnDelete::Cascade);
            t.text("stage").not_null();
            t.text("status").not_null().default_str("'pending'");
            t.int("attempt").not_null().default_int(1);
            t.timestamp("started_at");
            t.timestamp("completed_at");
            t.text("error_message");
            t.jsonb("metadata_json");
            t.timestamp("created_at")
                .not_null()
                .default(DefaultValue::Now);
        })
        // ---------------------------------------------------------------
        // 10. scan_jobs
        // ---------------------------------------------------------------
        .table("scan_jobs", |t| {
            t.uuid_pk("id");
            t.uuid("scan_id")
                .not_null()
                .unique()
                .references("scans", "id")
                .on_delete(OnDelete::Cascade);
            t.text("status").not_null().default_str("'pending'");
            t.int("priority").not_null().default_int(0);
            t.text("worker_id");
            t.timestamp("run_after");
            t.int("attempts").not_null().default_int(0);
            t.int("max_attempts").not_null().default_int(3);
            t.text("last_error");
            t.timestamp("claimed_at");
            t.timestamp("started_at");
            t.timestamp("completed_at");
            t.timestamps();
        })
        // ---------------------------------------------------------------
        // 11. file_snapshots
        // ---------------------------------------------------------------
        .table("file_snapshots", |t| {
            t.uuid_pk("id");
            t.uuid("repo_id")
                .not_null()
                .references("repos", "id")
                .on_delete(OnDelete::Cascade);
            t.uuid("scan_id")
                .not_null()
                .references("scans", "id")
                .on_delete(OnDelete::Cascade);
            t.text("file_path").not_null();
            t.text("content_hash").not_null();
            t.text("content_text");
            t.text("language");
            t.int("line_count");
            t.int("byte_size");
            t.jsonb("ast_summary_json");
            t.timestamp("created_at")
                .not_null()
                .default(DefaultValue::Now);
        })
        // ---------------------------------------------------------------
        // 12. findings
        // ---------------------------------------------------------------
        .table("findings", |t| {
            t.uuid_pk("id");
            t.uuid("scan_id")
                .not_null()
                .references("scans", "id")
                .on_delete(OnDelete::Cascade);
            t.uuid("repo_id")
                .not_null()
                .references("repos", "id")
                .on_delete(OnDelete::Cascade);
            t.text("source").not_null().default_str("'ai'");
            t.text("status").not_null().default_str("'open'");
            t.text("severity").not_null();
            t.text("confidence").not_null().default_str("'medium'");
            t.text("title").not_null();
            t.text("description");
            t.text("cwe_id");
            t.text("cve_id");
            t.text("file_path").not_null();
            t.int("line_start").not_null();
            t.int("line_end");
            t.text("code_snippet");
            t.text("suggested_patch");
            t.jsonb("poc_exploit_json");
            t.boolean("poc_validated").not_null().default_bool(false);
            t.text("fingerprint").not_null();
            t.text("agent_reasoning");
            t.timestamps();
        })
        // ---------------------------------------------------------------
        // 13. finding_events
        // ---------------------------------------------------------------
        .table("finding_events", |t| {
            t.uuid_pk("id");
            t.uuid("finding_id")
                .not_null()
                .references("findings", "id")
                .on_delete(OnDelete::Cascade);
            t.uuid("user_id")
                .references("users", "id")
                .on_delete(OnDelete::SetNull);
            t.text("event_type").not_null();
            t.text("old_value");
            t.text("new_value");
            t.text("comment");
            t.timestamp("created_at")
                .not_null()
                .default(DefaultValue::Now);
        })
        // ---------------------------------------------------------------
        // 14. patches
        // ---------------------------------------------------------------
        .table("patches", |t| {
            t.uuid_pk("id");
            t.uuid("finding_id")
                .not_null()
                .references("findings", "id")
                .on_delete(OnDelete::Cascade);
            t.uuid("scan_id")
                .not_null()
                .references("scans", "id")
                .on_delete(OnDelete::Cascade);
            t.text("diff_content").not_null();
            t.text("description");
            t.boolean("applies_cleanly").not_null().default_bool(true);
            t.boolean("applied").not_null().default_bool(false);
            t.uuid("applied_by")
                .references("users", "id")
                .on_delete(OnDelete::SetNull);
            t.timestamp("applied_at");
            t.timestamp("created_at")
                .not_null()
                .default(DefaultValue::Now);
        })
        // ---------------------------------------------------------------
        // 15. agent_tool_calls
        // ---------------------------------------------------------------
        .table("agent_tool_calls", |t| {
            t.uuid_pk("id");
            t.uuid("scan_id")
                .not_null()
                .references("scans", "id")
                .on_delete(OnDelete::Cascade);
            t.text("stage").not_null();
            t.text("tool_name").not_null();
            t.text("provider");
            t.text("model");
            t.jsonb("input_json");
            t.jsonb("output_json");
            t.int("prompt_tokens");
            t.int("completion_tokens");
            t.int("total_tokens");
            t.int("duration_ms");
            t.text("error");
            t.timestamp("created_at")
                .not_null()
                .default(DefaultValue::Now);
        })
        // ---------------------------------------------------------------
        // 16. scan_events
        // ---------------------------------------------------------------
        .table("scan_events", |t| {
            t.uuid_pk("id");
            t.uuid("scan_id")
                .not_null()
                .references("scans", "id")
                .on_delete(OnDelete::Cascade);
            t.text("stage");
            t.text("task_key");
            t.text("event_type").not_null();
            t.text("status");
            t.text("title").not_null();
            t.text("detail");
            t.int("progress_pct");
            t.jsonb("metadata_json");
            t.timestamp("created_at")
                .not_null()
                .default(DefaultValue::Now);
        })
        // ---------------------------------------------------------------
        // 17. repo_issues
        // ---------------------------------------------------------------
        .table("repo_issues", |t| {
            t.uuid_pk("id");
            t.uuid("repo_id")
                .not_null()
                .references("repos", "id")
                .on_delete(OnDelete::Cascade);
            t.uuid("finding_id")
                .references("findings", "id")
                .on_delete(OnDelete::SetNull);
            t.text("provider").not_null();
            t.text("external_issue_id").not_null();
            t.text("external_issue_number");
            t.text("issue_url").not_null();
            t.text("title").not_null();
            t.text("fingerprint").not_null();
            t.text("severity").not_null();
            t.text("state").not_null().default_str("'open'");
            t.boolean("auto_created").not_null().default_bool(false);
            t.timestamps();
        })
        // ---------------------------------------------------------------
        // 18. threat_models
        // ---------------------------------------------------------------
        .table("threat_models", |t| {
            t.uuid_pk("id");
            t.uuid("scan_id")
                .not_null()
                .unique()
                .references("scans", "id")
                .on_delete(OnDelete::Cascade);
            t.uuid("repo_id")
                .not_null()
                .references("repos", "id")
                .on_delete(OnDelete::Cascade);
            t.text("summary");
            t.jsonb("boundaries_json");
            t.jsonb("surfaces_json");
            t.jsonb("data_flows_json");
            t.int("model_version").not_null().default_int(1);
            t.uuid("edited_by")
                .references("users", "id")
                .on_delete(OnDelete::SetNull);
            t.timestamps();
        })
        // ---------------------------------------------------------------
        // Spec indexes
        // ---------------------------------------------------------------
        .index(
            "idx_file_snapshots_dedup",
            "file_snapshots",
            &["repo_id", "file_path", "content_hash"],
        )
        .index("idx_findings_fingerprint", "findings", &["fingerprint"])
        .index(
            "idx_findings_scan_severity",
            "findings",
            &["scan_id", "severity"],
        )
        .index(
            "idx_scan_jobs_polling",
            "scan_jobs",
            &["status", "run_after", "priority"],
        )
        .index(
            "idx_scan_events_scan_created",
            "scan_events",
            &["scan_id", "created_at"],
        )
        .index(
            "idx_repo_issues_repo_state",
            "repo_issues",
            &["repo_id", "state"],
        )
        .index("idx_repo_issues_finding", "repo_issues", &["finding_id"])
        .index("idx_scans_repo_commit", "scans", &["repo_id", "commit_sha"])
        // ---------------------------------------------------------------
        // Practical indexes
        // ---------------------------------------------------------------
        .index("idx_users_email", "users", &["email"])
        .index("idx_repos_user", "repos", &["user_id"])
        .index("idx_scans_repo", "scans", &["repo_id"])
        .index("idx_findings_scan", "findings", &["scan_id"])
        .index("idx_sessions_user", "sessions", &["user_id"])
        .index("idx_sessions_token", "sessions", &["token_hash"])
        .build()
}
