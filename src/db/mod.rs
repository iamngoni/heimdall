//
//  heimdall
//  src/db/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod schema;

use anyhow::Context;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::HeimdallResult;
use crate::models::db_models::*;

pub struct DatabaseOperations {
    pool: PgPool,
}

impl DatabaseOperations {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // -----------------------------------------------------------------------
    // Health
    // -----------------------------------------------------------------------

    pub async fn health_check(&self) -> HeimdallResult<bool> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("Health check query failed")?;
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Users
    // -----------------------------------------------------------------------

    pub async fn create_user(
        &self,
        email: &str,
        password_hash: &str,
        display_name: Option<&str>,
    ) -> HeimdallResult<User> {
        sqlx::query_as::<_, User>(
            "INSERT INTO users (email, password_hash, display_name) \
             VALUES ($1, $2, $3) \
             RETURNING *",
        )
        .bind(email)
        .bind(password_hash)
        .bind(display_name)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create user")
    }

    pub async fn get_user_by_id(&self, id: Uuid) -> HeimdallResult<Option<User>> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch user by id")
    }

    pub async fn get_user_by_email(&self, email: &str) -> HeimdallResult<Option<User>> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch user by email")
    }

    // -----------------------------------------------------------------------
    // OAuth connections
    // -----------------------------------------------------------------------

    pub async fn get_user_by_oauth_provider(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> HeimdallResult<Option<User>> {
        sqlx::query_as::<_, User>(
            "SELECT u.* FROM users u \
             JOIN oauth_connections oc ON oc.user_id = u.id \
             WHERE oc.provider = $1 AND oc.provider_user_id = $2 \
             AND u.deleted_at IS NULL",
        )
        .bind(provider)
        .bind(provider_user_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch user by OAuth provider")
    }

    pub async fn upsert_oauth_connection(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_user_id: &str,
        access_token_enc: Option<&str>,
        refresh_token_enc: Option<&str>,
        scopes: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> HeimdallResult<OauthConnection> {
        sqlx::query_as::<_, OauthConnection>(
            "INSERT INTO oauth_connections \
             (user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, scopes, token_source, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'oauth', $7) \
             ON CONFLICT (user_id, provider) DO UPDATE SET \
                 provider_user_id = EXCLUDED.provider_user_id, \
                 access_token_enc = EXCLUDED.access_token_enc, \
                 refresh_token_enc = EXCLUDED.refresh_token_enc, \
                 scopes = EXCLUDED.scopes, \
                 token_source = EXCLUDED.token_source, \
                 expires_at = EXCLUDED.expires_at \
             RETURNING *",
        )
        .bind(user_id)
        .bind(provider)
        .bind(provider_user_id)
        .bind(access_token_enc)
        .bind(refresh_token_enc)
        .bind(scopes)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .context("Failed to upsert OAuth connection")
    }

    pub async fn upsert_pat_connection(
        &self,
        user_id: Uuid,
        provider: &str,
        access_token_enc: &str,
        provider_user_id: &str,
    ) -> HeimdallResult<OauthConnection> {
        sqlx::query_as::<_, OauthConnection>(
            "INSERT INTO oauth_connections \
             (user_id, provider, provider_user_id, access_token_enc, token_source) \
             VALUES ($1, $2, $4, $3, 'pat') \
             ON CONFLICT (user_id, provider) DO UPDATE SET \
                 access_token_enc = EXCLUDED.access_token_enc, \
                 token_source = EXCLUDED.token_source, \
                 provider_user_id = EXCLUDED.provider_user_id \
             RETURNING *",
        )
        .bind(user_id)
        .bind(provider)
        .bind(access_token_enc)
        .bind(provider_user_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to upsert PAT connection")
    }

    pub async fn create_user_with_avatar(
        &self,
        email: &str,
        password_hash: &str,
        display_name: Option<&str>,
        avatar_url: Option<&str>,
    ) -> HeimdallResult<User> {
        sqlx::query_as::<_, User>(
            "INSERT INTO users (email, password_hash, display_name, avatar_url) \
             VALUES ($1, $2, $3, $4) \
             RETURNING *",
        )
        .bind(email)
        .bind(password_hash)
        .bind(display_name)
        .bind(avatar_url)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create user with avatar")
    }

    pub async fn update_user_avatar(
        &self,
        user_id: Uuid,
        avatar_url: &str,
    ) -> HeimdallResult<bool> {
        let result =
            sqlx::query("UPDATE users SET avatar_url = $1 WHERE id = $2 AND deleted_at IS NULL")
                .bind(avatar_url)
                .bind(user_id)
                .execute(&self.pool)
                .await
                .context("Failed to update user avatar")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_user_display_name(
        &self,
        user_id: Uuid,
        display_name: &str,
    ) -> HeimdallResult<bool> {
        let result = sqlx::query(
            "UPDATE users SET display_name = $1, updated_at = now() WHERE id = $2 AND deleted_at IS NULL",
        )
        .bind(display_name)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .context("Failed to update user display name")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> HeimdallResult<bool> {
        let result = sqlx::query(
            "UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2 AND deleted_at IS NULL",
        )
        .bind(password_hash)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .context("Failed to update user password")?;
        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Repos
    // -----------------------------------------------------------------------

    pub async fn create_repo(
        &self,
        user_id: Uuid,
        name: &str,
        source_type: &str,
        remote_url: Option<&str>,
        default_branch: Option<&str>,
        oauth_connection_id: Option<Uuid>,
    ) -> HeimdallResult<Repo> {
        sqlx::query_as::<_, Repo>(
            "INSERT INTO repos (user_id, name, source_type, remote_url, default_branch, oauth_connection_id) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING *",
        )
        .bind(user_id)
        .bind(name)
        .bind(source_type)
        .bind(remote_url)
        .bind(default_branch)
        .bind(oauth_connection_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create repo")
    }

    pub async fn get_repo_by_id(&self, id: Uuid) -> HeimdallResult<Option<Repo>> {
        sqlx::query_as::<_, Repo>("SELECT * FROM repos WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch repo by id")
    }

    pub async fn list_repos_by_user(&self, user_id: Uuid) -> HeimdallResult<Vec<Repo>> {
        sqlx::query_as::<_, Repo>(
            "SELECT * FROM repos WHERE user_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list repos by user")
    }

    pub async fn list_repos_by_user_paginated(
        &self,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> HeimdallResult<Vec<Repo>> {
        sqlx::query_as::<_, Repo>(
            "SELECT * FROM repos WHERE user_id = $1 AND deleted_at IS NULL \
             ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list repos by user (paginated)")
    }

    pub async fn update_repo_issue_settings(
        &self,
        repo_id: Uuid,
        enabled: bool,
        min_severity: &str,
    ) -> HeimdallResult<Option<Repo>> {
        sqlx::query_as::<_, Repo>(
            "UPDATE repos SET issue_auto_create_enabled = $1, issue_auto_create_min_severity = $2, updated_at = now() \
             WHERE id = $3 AND deleted_at IS NULL RETURNING *",
        )
        .bind(enabled)
        .bind(min_severity)
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to update repo issue settings")
    }

    pub async fn update_repo_default_branch(
        &self,
        repo_id: Uuid,
        branch: &str,
    ) -> HeimdallResult<Option<Repo>> {
        sqlx::query_as::<_, Repo>(
            "UPDATE repos SET default_branch = $1, updated_at = now() \
             WHERE id = $2 AND deleted_at IS NULL RETURNING *",
        )
        .bind(branch)
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to update repo default branch")
    }

    pub async fn count_repos_by_user(&self, user_id: Uuid) -> HeimdallResult<i64> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM repos WHERE user_id = $1 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count repos by user")
    }

    /// Find a repo by its remote URL. Tries exact match first, then fuzzy
    /// match with/without trailing `.git` suffix to handle GitHub/GitLab URL
    /// variants (e.g. `https://github.com/user/repo` vs `https://github.com/user/repo.git`).
    pub async fn get_repo_by_remote_url(&self, url: &str) -> HeimdallResult<Option<Repo>> {
        let normalized = url.trim_end_matches(".git");
        let with_git = format!("{normalized}.git");

        sqlx::query_as::<_, Repo>(
            "SELECT * FROM repos \
             WHERE deleted_at IS NULL \
               AND (remote_url = $1 OR remote_url = $2 OR remote_url = $3) \
             LIMIT 1",
        )
        .bind(url)
        .bind(normalized)
        .bind(&with_git)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch repo by remote URL")
    }

    pub async fn delete_repo(&self, id: Uuid) -> HeimdallResult<bool> {
        let result = sqlx::query("DELETE FROM repos WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete repo")?;
        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Scans
    // -----------------------------------------------------------------------

    pub async fn create_scan(
        &self,
        repo_id: Uuid,
        scan_type: &str,
        triggered_by: Option<Uuid>,
        commit_sha: Option<&str>,
        base_commit_sha: Option<&str>,
        parent_scan_id: Option<Uuid>,
    ) -> HeimdallResult<Scan> {
        sqlx::query_as::<_, Scan>(
            "INSERT INTO scans (repo_id, scan_type, triggered_by, commit_sha, base_commit_sha, parent_scan_id) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING *",
        )
        .bind(repo_id)
        .bind(scan_type)
        .bind(triggered_by)
        .bind(commit_sha)
        .bind(base_commit_sha)
        .bind(parent_scan_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create scan")
    }

    pub async fn get_scan_by_id(&self, id: Uuid) -> HeimdallResult<Option<Scan>> {
        sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch scan by id")
    }

    pub async fn list_scans_by_repo(&self, repo_id: Uuid) -> HeimdallResult<Vec<Scan>> {
        sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE repo_id = $1 ORDER BY created_at DESC")
            .bind(repo_id)
            .fetch_all(&self.pool)
            .await
            .context("Failed to list scans by repo")
    }

    pub async fn list_scans_by_repo_paginated(
        &self,
        repo_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> HeimdallResult<Vec<Scan>> {
        sqlx::query_as::<_, Scan>(
            "SELECT * FROM scans WHERE repo_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(repo_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list scans by repo (paginated)")
    }

    pub async fn count_scans_by_repo(&self, repo_id: Uuid) -> HeimdallResult<i64> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scans WHERE repo_id = $1")
            .bind(repo_id)
            .fetch_one(&self.pool)
            .await
            .context("Failed to count scans by repo")
    }

    pub async fn update_scan_status(
        &self,
        id: Uuid,
        status: &str,
        error_message: Option<&str>,
    ) -> HeimdallResult<bool> {
        let result = sqlx::query("UPDATE scans SET status = $1, error_message = $2 WHERE id = $3")
            .bind(status)
            .bind(error_message)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update scan status")?;
        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Scan Jobs
    // -----------------------------------------------------------------------

    pub async fn create_scan_job(&self, scan_id: Uuid) -> HeimdallResult<ScanJob> {
        sqlx::query_as::<_, ScanJob>("INSERT INTO scan_jobs (scan_id) VALUES ($1) RETURNING *")
            .bind(scan_id)
            .fetch_one(&self.pool)
            .await
            .context("Failed to create scan job")
    }

    // -----------------------------------------------------------------------
    // Findings
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Dashboard stats
    // -----------------------------------------------------------------------

    pub async fn count_open_findings_by_user(&self, user_id: Uuid) -> HeimdallResult<i64> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM findings f JOIN repos r ON f.repo_id = r.id \
             WHERE r.user_id = $1 AND f.status = 'open' AND r.deleted_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count open findings by user")
    }

    pub async fn count_critical_findings_by_user(&self, user_id: Uuid) -> HeimdallResult<i64> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM findings f JOIN repos r ON f.repo_id = r.id \
             WHERE r.user_id = $1 AND f.status = 'open' AND f.severity = 'critical' AND r.deleted_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count critical findings by user")
    }

    // -----------------------------------------------------------------------
    // Findings
    // -----------------------------------------------------------------------

    pub async fn create_finding(
        &self,
        scan_id: Uuid,
        repo_id: Uuid,
        source: &str,
        severity: &str,
        confidence: &str,
        title: &str,
        description: Option<&str>,
        file_path: &str,
        line_start: i32,
        line_end: Option<i32>,
        fingerprint: &str,
    ) -> HeimdallResult<Finding> {
        sqlx::query_as::<_, Finding>(
            "INSERT INTO findings \
             (scan_id, repo_id, source, severity, confidence, title, description, file_path, line_start, line_end, fingerprint) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             RETURNING *",
        )
        .bind(scan_id)
        .bind(repo_id)
        .bind(source)
        .bind(severity)
        .bind(confidence)
        .bind(title)
        .bind(description)
        .bind(file_path)
        .bind(line_start)
        .bind(line_end)
        .bind(fingerprint)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create finding")
    }

    pub async fn get_finding_by_id(&self, id: Uuid) -> HeimdallResult<Option<Finding>> {
        sqlx::query_as::<_, Finding>("SELECT * FROM findings WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch finding by id")
    }

    pub async fn list_findings_by_scan(
        &self,
        scan_id: Uuid,
        severity: Option<&str>,
        status: Option<&str>,
    ) -> HeimdallResult<Vec<Finding>> {
        let mut query = String::from("SELECT * FROM findings WHERE scan_id = $1");
        let mut param_idx = 2;

        if severity.is_some() {
            query.push_str(&format!(" AND severity = ${param_idx}"));
            param_idx += 1;
        }
        if status.is_some() {
            query.push_str(&format!(" AND status = ${param_idx}"));
        }
        query.push_str(
            " ORDER BY CASE severity \
            WHEN 'critical' THEN 0 \
            WHEN 'high' THEN 1 \
            WHEN 'medium' THEN 2 \
            WHEN 'low' THEN 3 \
            ELSE 4 END, created_at DESC",
        );

        let mut q = sqlx::query_as::<_, Finding>(&query).bind(scan_id);
        if let Some(sev) = severity {
            q = q.bind(sev);
        }
        if let Some(st) = status {
            q = q.bind(st);
        }

        q.fetch_all(&self.pool)
            .await
            .context("Failed to list findings by scan")
    }

    pub async fn list_findings_by_scan_paginated(
        &self,
        scan_id: Uuid,
        severity: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> HeimdallResult<Vec<Finding>> {
        let mut query = String::from("SELECT * FROM findings WHERE scan_id = $1");
        let mut param_idx = 2;

        if severity.is_some() {
            query.push_str(&format!(" AND severity = ${param_idx}"));
            param_idx += 1;
        }
        if status.is_some() {
            query.push_str(&format!(" AND status = ${param_idx}"));
            param_idx += 1;
        }
        query.push_str(
            " ORDER BY CASE severity \
            WHEN 'critical' THEN 0 \
            WHEN 'high' THEN 1 \
            WHEN 'medium' THEN 2 \
            WHEN 'low' THEN 3 \
            ELSE 4 END, created_at DESC",
        );
        query.push_str(&format!(" LIMIT ${param_idx} OFFSET ${}", param_idx + 1));

        let mut q = sqlx::query_as::<_, Finding>(&query).bind(scan_id);
        if let Some(sev) = severity {
            q = q.bind(sev);
        }
        if let Some(st) = status {
            q = q.bind(st);
        }
        q = q.bind(limit).bind(offset);

        q.fetch_all(&self.pool)
            .await
            .context("Failed to list findings by scan (paginated)")
    }

    pub async fn count_findings_by_scan(
        &self,
        scan_id: Uuid,
        severity: Option<&str>,
        status: Option<&str>,
    ) -> HeimdallResult<i64> {
        let mut query = String::from("SELECT COUNT(*) FROM findings WHERE scan_id = $1");
        let mut param_idx = 2;

        if severity.is_some() {
            query.push_str(&format!(" AND severity = ${param_idx}"));
            param_idx += 1;
        }
        if status.is_some() {
            query.push_str(&format!(" AND status = ${param_idx}"));
        }
        let _ = param_idx;

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(scan_id);
        if let Some(sev) = severity {
            q = q.bind(sev);
        }
        if let Some(st) = status {
            q = q.bind(st);
        }

        q.fetch_one(&self.pool)
            .await
            .context("Failed to count findings by scan")
    }

    pub async fn update_finding_status(&self, id: Uuid, status: &str) -> HeimdallResult<bool> {
        let result = sqlx::query("UPDATE findings SET status = $1 WHERE id = $2")
            .bind(status)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update finding status")?;
        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Threat Models
    // -----------------------------------------------------------------------

    pub async fn create_threat_model(
        &self,
        scan_id: Uuid,
        repo_id: Uuid,
        summary: Option<&str>,
        boundaries_json: Option<&serde_json::Value>,
        surfaces_json: Option<&serde_json::Value>,
        data_flows_json: Option<&serde_json::Value>,
    ) -> HeimdallResult<ThreatModel> {
        sqlx::query_as::<_, ThreatModel>(
            "INSERT INTO threat_models \
             (scan_id, repo_id, summary, boundaries_json, surfaces_json, data_flows_json) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (scan_id) DO UPDATE SET \
             summary = EXCLUDED.summary, \
             boundaries_json = EXCLUDED.boundaries_json, \
             surfaces_json = EXCLUDED.surfaces_json, \
             data_flows_json = EXCLUDED.data_flows_json, \
             updated_at = NOW() \
             RETURNING *",
        )
        .bind(scan_id)
        .bind(repo_id)
        .bind(summary)
        .bind(boundaries_json)
        .bind(surfaces_json)
        .bind(data_flows_json)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create threat model")
    }

    pub async fn get_threat_model_by_scan(
        &self,
        scan_id: Uuid,
    ) -> HeimdallResult<Option<ThreatModel>> {
        sqlx::query_as::<_, ThreatModel>("SELECT * FROM threat_models WHERE scan_id = $1")
            .bind(scan_id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch threat model by scan")
    }

    // -----------------------------------------------------------------------
    // Sessions
    // -----------------------------------------------------------------------

    pub async fn create_session(
        &self,
        user_id: Uuid,
        token_hash: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> HeimdallResult<Session> {
        sqlx::query_as::<_, Session>(
            "INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, expires_at) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING *",
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(ip_address)
        .bind(user_agent)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create session")
    }

    pub async fn get_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> HeimdallResult<Option<Session>> {
        sqlx::query_as::<_, Session>(
            "SELECT * FROM sessions WHERE token_hash = $1 AND expires_at > now()",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch session by token hash")
    }

    pub async fn delete_expired_sessions(&self) -> HeimdallResult<u64> {
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= now()")
            .execute(&self.pool)
            .await
            .context("Failed to delete expired sessions")?;
        Ok(result.rows_affected())
    }

    pub async fn delete_session(&self, id: Uuid) -> HeimdallResult<bool> {
        let result = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete session")?;
        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Scan stages
    // -----------------------------------------------------------------------

    pub async fn create_scan_stage(&self, scan_id: Uuid, stage: &str) -> HeimdallResult<ScanStage> {
        sqlx::query_as::<_, ScanStage>(
            "INSERT INTO scan_stages (scan_id, stage) VALUES ($1, $2) RETURNING *",
        )
        .bind(scan_id)
        .bind(stage)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create scan stage")
    }

    pub async fn update_scan_stage_status(
        &self,
        id: Uuid,
        status: &str,
        error_message: Option<&str>,
    ) -> HeimdallResult<bool> {
        let now = Utc::now();
        let result = match status {
            "running" => {
                sqlx::query(
                    "UPDATE scan_stages SET status = $1, started_at = $2 WHERE id = $3",
                )
                .bind(status)
                .bind(now)
                .bind(id)
                .execute(&self.pool)
                .await
            }
            "completed" | "failed" => {
                sqlx::query(
                    "UPDATE scan_stages SET status = $1, completed_at = $2, error_message = $3 WHERE id = $4",
                )
                .bind(status)
                .bind(now)
                .bind(error_message)
                .bind(id)
                .execute(&self.pool)
                .await
            }
            _ => {
                sqlx::query("UPDATE scan_stages SET status = $1 WHERE id = $2")
                    .bind(status)
                    .bind(id)
                    .execute(&self.pool)
                    .await
            }
        }
        .context("Failed to update scan stage status")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_scan_stages(&self, scan_id: Uuid) -> HeimdallResult<Vec<ScanStage>> {
        sqlx::query_as::<_, ScanStage>(
            "SELECT * FROM scan_stages WHERE scan_id = $1 ORDER BY created_at ASC",
        )
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list scan stages")
    }

    // -----------------------------------------------------------------------
    // Extended scan operations
    // -----------------------------------------------------------------------

    pub async fn update_scan_commit_sha(&self, id: Uuid, commit_sha: &str) -> HeimdallResult<bool> {
        let result = sqlx::query("UPDATE scans SET commit_sha = $1 WHERE id = $2")
            .bind(commit_sha)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update scan commit SHA")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_scan_timestamps(
        &self,
        id: Uuid,
        started: bool,
        completed: bool,
    ) -> HeimdallResult<bool> {
        let now = Utc::now();
        let result = if started && completed {
            sqlx::query("UPDATE scans SET started_at = COALESCE(started_at, $1), completed_at = $2 WHERE id = $3")
                .bind(now)
                .bind(now)
                .bind(id)
                .execute(&self.pool)
                .await
        } else if started {
            sqlx::query("UPDATE scans SET started_at = $1 WHERE id = $2")
                .bind(now)
                .bind(id)
                .execute(&self.pool)
                .await
        } else {
            sqlx::query("UPDATE scans SET completed_at = $1 WHERE id = $2")
                .bind(now)
                .bind(id)
                .execute(&self.pool)
                .await
        }
        .context("Failed to update scan timestamps")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_scan_counts(&self, id: Uuid) -> HeimdallResult<bool> {
        let result = sqlx::query(
            "UPDATE scans SET \
             finding_count = (SELECT COUNT(*) FROM findings WHERE scan_id = $1), \
             critical_count = (SELECT COUNT(*) FROM findings WHERE scan_id = $1 AND severity = 'critical'), \
             high_count = (SELECT COUNT(*) FROM findings WHERE scan_id = $1 AND severity = 'high'), \
             medium_count = (SELECT COUNT(*) FROM findings WHERE scan_id = $1 AND severity = 'medium'), \
             low_count = (SELECT COUNT(*) FROM findings WHERE scan_id = $1 AND severity = 'low') \
             WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to update scan counts")?;
        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // File snapshots
    // -----------------------------------------------------------------------

    pub async fn create_file_snapshot(
        &self,
        repo_id: Uuid,
        scan_id: Uuid,
        file_path: &str,
        content_hash: &str,
        content_text: &str,
        language: Option<&str>,
        line_count: i32,
        byte_size: i32,
    ) -> HeimdallResult<FileSnapshot> {
        sqlx::query_as::<_, FileSnapshot>(
            "INSERT INTO file_snapshots \
             (repo_id, scan_id, file_path, content_hash, content_text, language, line_count, byte_size) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             RETURNING *",
        )
        .bind(repo_id)
        .bind(scan_id)
        .bind(file_path)
        .bind(content_hash)
        .bind(content_text)
        .bind(language)
        .bind(line_count)
        .bind(byte_size)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create file snapshot")
    }

    pub async fn get_file_snapshot_by_scan_and_path(
        &self,
        scan_id: Uuid,
        file_path: &str,
    ) -> HeimdallResult<Option<FileSnapshot>> {
        sqlx::query_as::<_, FileSnapshot>(
            "SELECT * FROM file_snapshots WHERE scan_id = $1 AND file_path = $2 LIMIT 1",
        )
        .bind(scan_id)
        .bind(file_path)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch file snapshot by scan and path")
    }

    // -----------------------------------------------------------------------
    // Agent tool calls
    // -----------------------------------------------------------------------

    pub async fn create_agent_tool_call(
        &self,
        scan_id: Uuid,
        stage: &str,
        tool_name: &str,
        provider: Option<&str>,
        model: Option<&str>,
        input_json: Option<&serde_json::Value>,
        output_json: Option<&serde_json::Value>,
        prompt_tokens: Option<i32>,
        completion_tokens: Option<i32>,
        total_tokens: Option<i32>,
        duration_ms: Option<i32>,
        error: Option<&str>,
    ) -> HeimdallResult<AgentToolCall> {
        sqlx::query_as::<_, AgentToolCall>(
            "INSERT INTO agent_tool_calls \
             (scan_id, stage, tool_name, provider, model, input_json, output_json, prompt_tokens, completion_tokens, total_tokens, duration_ms, error) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             RETURNING *",
        )
        .bind(scan_id)
        .bind(stage)
        .bind(tool_name)
        .bind(provider)
        .bind(model)
        .bind(input_json)
        .bind(output_json)
        .bind(prompt_tokens)
        .bind(completion_tokens)
        .bind(total_tokens)
        .bind(duration_ms)
        .bind(error)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create agent tool call")
    }

    pub async fn list_agent_tool_calls_by_scan(
        &self,
        scan_id: Uuid,
        limit: i64,
    ) -> HeimdallResult<Vec<AgentToolCall>> {
        sqlx::query_as::<_, AgentToolCall>(
            "SELECT * FROM agent_tool_calls WHERE scan_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(scan_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list agent tool calls by scan")
    }

    pub async fn create_scan_event(
        &self,
        scan_id: Uuid,
        stage: Option<&str>,
        task_key: Option<&str>,
        event_type: &str,
        status: Option<&str>,
        title: &str,
        detail: Option<&str>,
        progress_pct: Option<i32>,
        metadata_json: Option<&serde_json::Value>,
    ) -> HeimdallResult<ScanEventRecord> {
        sqlx::query_as::<_, ScanEventRecord>(
            "INSERT INTO scan_events \
             (scan_id, stage, task_key, event_type, status, title, detail, progress_pct, metadata_json) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             RETURNING *",
        )
        .bind(scan_id)
        .bind(stage)
        .bind(task_key)
        .bind(event_type)
        .bind(status)
        .bind(title)
        .bind(detail)
        .bind(progress_pct)
        .bind(metadata_json)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create scan event")
    }

    pub async fn list_scan_events(
        &self,
        scan_id: Uuid,
        limit: i64,
    ) -> HeimdallResult<Vec<ScanEventRecord>> {
        sqlx::query_as::<_, ScanEventRecord>(
            "SELECT * FROM scan_events WHERE scan_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(scan_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list scan events")
    }

    // -----------------------------------------------------------------------
    // Extended findings
    // -----------------------------------------------------------------------

    pub async fn create_finding_full(
        &self,
        scan_id: Uuid,
        repo_id: Uuid,
        source: &str,
        severity: &str,
        confidence: &str,
        title: &str,
        description: Option<&str>,
        cwe_id: Option<&str>,
        file_path: &str,
        line_start: i32,
        line_end: Option<i32>,
        code_snippet: Option<&str>,
        fingerprint: &str,
        agent_reasoning: Option<&str>,
    ) -> HeimdallResult<Finding> {
        sqlx::query_as::<_, Finding>(
            "INSERT INTO findings \
             (scan_id, repo_id, source, severity, confidence, title, description, cwe_id, \
              file_path, line_start, line_end, code_snippet, fingerprint, agent_reasoning) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
             RETURNING *",
        )
        .bind(scan_id)
        .bind(repo_id)
        .bind(source)
        .bind(severity)
        .bind(confidence)
        .bind(title)
        .bind(description)
        .bind(cwe_id)
        .bind(file_path)
        .bind(line_start)
        .bind(line_end)
        .bind(code_snippet)
        .bind(fingerprint)
        .bind(agent_reasoning)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create finding")
    }

    pub async fn update_finding_poc(
        &self,
        id: Uuid,
        poc_validated: bool,
        poc_exploit_json: &serde_json::Value,
    ) -> HeimdallResult<bool> {
        let result = sqlx::query(
            "UPDATE findings SET poc_validated = $1, poc_exploit_json = $2 WHERE id = $3",
        )
        .bind(poc_validated)
        .bind(poc_exploit_json)
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to update finding PoC")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_finding_patch(
        &self,
        id: Uuid,
        suggested_patch: &str,
    ) -> HeimdallResult<bool> {
        let result = sqlx::query("UPDATE findings SET suggested_patch = $1 WHERE id = $2")
            .bind(suggested_patch)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update finding patch")?;
        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Finding Events
    // -----------------------------------------------------------------------

    pub async fn create_finding_event(
        &self,
        finding_id: Uuid,
        user_id: Option<Uuid>,
        event_type: &str,
        old_value: Option<&str>,
        new_value: Option<&str>,
        comment: Option<&str>,
    ) -> HeimdallResult<FindingEvent> {
        self.create_finding_event_with_metadata(
            finding_id, user_id, event_type, old_value, new_value, comment, None,
        )
        .await
    }

    pub async fn create_finding_event_with_metadata(
        &self,
        finding_id: Uuid,
        user_id: Option<Uuid>,
        event_type: &str,
        old_value: Option<&str>,
        new_value: Option<&str>,
        comment: Option<&str>,
        metadata: Option<&serde_json::Value>,
    ) -> HeimdallResult<FindingEvent> {
        sqlx::query_as::<_, FindingEvent>(
            "INSERT INTO finding_events \
             (finding_id, user_id, event_type, old_value, new_value, comment, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING *",
        )
        .bind(finding_id)
        .bind(user_id)
        .bind(event_type)
        .bind(old_value)
        .bind(new_value)
        .bind(comment)
        .bind(metadata)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create finding event")
    }

    pub async fn list_finding_events(&self, finding_id: Uuid) -> HeimdallResult<Vec<FindingEvent>> {
        sqlx::query_as::<_, FindingEvent>(
            "SELECT * FROM finding_events WHERE finding_id = $1 ORDER BY created_at ASC",
        )
        .bind(finding_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list finding events")
    }

    pub async fn update_finding_severity(&self, id: Uuid, severity: &str) -> HeimdallResult<bool> {
        let result = sqlx::query("UPDATE findings SET severity = $1 WHERE id = $2")
            .bind(severity)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update finding severity")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_finding_confidence(
        &self,
        id: Uuid,
        confidence: &str,
    ) -> HeimdallResult<bool> {
        let result = sqlx::query("UPDATE findings SET confidence = $1 WHERE id = $2")
            .bind(confidence)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update finding confidence")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn append_finding_vidarr_reasoning(
        &self,
        id: Uuid,
        skeptic_reasoning: &str,
    ) -> HeimdallResult<bool> {
        let result = sqlx::query(
            "UPDATE findings SET agent_reasoning = \
             CASE WHEN agent_reasoning IS NULL THEN $1 \
             ELSE agent_reasoning || E'\\n\\n--- Víðarr Review ---\\n' || $1 END \
             WHERE id = $2",
        )
        .bind(skeptic_reasoning)
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to append skeptic reasoning")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_patches_by_scan(
        &self,
        scan_id: Uuid,
    ) -> HeimdallResult<Vec<PatchWithFilePath>> {
        sqlx::query_as::<_, PatchWithFilePath>(
            "SELECT p.id, p.finding_id, f.file_path, p.diff_content, p.applied, p.created_at \
             FROM patches p \
             JOIN findings f ON f.id = p.finding_id \
             WHERE f.scan_id = $1 \
             ORDER BY p.created_at DESC",
        )
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list patches by scan")
    }

    pub async fn get_patch_for_finding(&self, finding_id: Uuid) -> HeimdallResult<Option<Patch>> {
        sqlx::query_as::<_, Patch>(
            "SELECT * FROM patches WHERE finding_id = $1 \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(finding_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to get patch for finding")
    }

    pub async fn mark_patch_applied(
        &self,
        patch_id: Uuid,
        applied_by: Uuid,
    ) -> HeimdallResult<bool> {
        let result = sqlx::query(
            "UPDATE patches SET applied = TRUE, applied_by = $1, applied_at = now() \
             WHERE id = $2 AND applied = FALSE",
        )
        .bind(applied_by)
        .bind(patch_id)
        .execute(&self.pool)
        .await
        .context("Failed to mark patch as applied")?;
        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Patches
    // -----------------------------------------------------------------------

    pub async fn create_patch(
        &self,
        finding_id: Uuid,
        scan_id: Uuid,
        diff_content: &str,
        description: Option<&str>,
        applies_cleanly: bool,
    ) -> HeimdallResult<Patch> {
        sqlx::query_as::<_, Patch>(
            "INSERT INTO patches \
             (finding_id, scan_id, diff_content, description, applies_cleanly) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING *",
        )
        .bind(finding_id)
        .bind(scan_id)
        .bind(diff_content)
        .bind(description)
        .bind(applies_cleanly)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create patch")
    }

    pub async fn get_repo_issue_by_fingerprint(
        &self,
        repo_id: Uuid,
        provider: &str,
        fingerprint: &str,
    ) -> HeimdallResult<Option<RepoIssue>> {
        sqlx::query_as::<_, RepoIssue>(
            "SELECT * FROM repo_issues WHERE repo_id = $1 AND provider = $2 AND fingerprint = $3 LIMIT 1",
        )
        .bind(repo_id)
        .bind(provider)
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch repo issue by fingerprint")
    }

    pub async fn upsert_repo_issue(
        &self,
        repo_id: Uuid,
        finding_id: Option<Uuid>,
        provider: &str,
        external_issue_id: &str,
        external_issue_number: Option<&str>,
        issue_url: &str,
        title: &str,
        fingerprint: &str,
        severity: &str,
        state: &str,
        auto_created: bool,
    ) -> HeimdallResult<RepoIssue> {
        sqlx::query_as::<_, RepoIssue>(
            "INSERT INTO repo_issues \
             (repo_id, finding_id, provider, external_issue_id, external_issue_number, issue_url, title, fingerprint, severity, state, auto_created) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (repo_id, provider, fingerprint) DO UPDATE SET \
                 finding_id = COALESCE(EXCLUDED.finding_id, repo_issues.finding_id), \
                 external_issue_id = EXCLUDED.external_issue_id, \
                 external_issue_number = EXCLUDED.external_issue_number, \
                 issue_url = EXCLUDED.issue_url, \
                 title = EXCLUDED.title, \
                 severity = EXCLUDED.severity, \
                 state = EXCLUDED.state, \
                 auto_created = EXCLUDED.auto_created, \
                 updated_at = now() \
             RETURNING *",
        )
        .bind(repo_id)
        .bind(finding_id)
        .bind(provider)
        .bind(external_issue_id)
        .bind(external_issue_number)
        .bind(issue_url)
        .bind(title)
        .bind(fingerprint)
        .bind(severity)
        .bind(state)
        .bind(auto_created)
        .fetch_one(&self.pool)
        .await
        .context("Failed to upsert repo issue")
    }

    // -----------------------------------------------------------------------
    // Scan jobs (extended)
    // -----------------------------------------------------------------------

    pub async fn claim_next_scan_job(&self, worker_id: &str) -> HeimdallResult<Option<ScanJob>> {
        sqlx::query_as::<_, ScanJob>(
            "UPDATE scan_jobs \
             SET status = 'claimed', worker_id = $1, claimed_at = now() \
             WHERE id = ( \
               SELECT id FROM scan_jobs \
               WHERE status = 'pending' \
                 AND (run_after IS NULL OR run_after <= now()) \
                 AND attempts < max_attempts \
               ORDER BY priority DESC, created_at ASC \
               LIMIT 1 \
               FOR UPDATE SKIP LOCKED \
             ) \
             RETURNING *",
        )
        .bind(worker_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to claim scan job")
    }

    /// Update a scan job's status and optionally set an error message.
    pub async fn update_scan_job_status(
        &self,
        id: Uuid,
        status: &str,
        last_error: Option<&str>,
    ) -> HeimdallResult<bool> {
        let now = Utc::now();
        let started = if status == "running" { Some(now) } else { None };
        let completed = if status == "completed" || status == "failed" || status == "dead" {
            Some(now)
        } else {
            None
        };

        let result = sqlx::query(
            "UPDATE scan_jobs SET \
                status = $1, \
                last_error = $2, \
                started_at = COALESCE($3, started_at), \
                completed_at = COALESCE($4, completed_at), \
                updated_at = now() \
             WHERE id = $5",
        )
        .bind(status)
        .bind(last_error)
        .bind(started)
        .bind(completed)
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to update scan job status")?;
        Ok(result.rows_affected() > 0)
    }

    /// Increment the attempt counter on a scan job.
    pub async fn increment_scan_job_attempts(&self, id: Uuid) -> HeimdallResult<bool> {
        let result = sqlx::query(
            "UPDATE scan_jobs SET attempts = attempts + 1, updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to increment scan job attempts")?;
        Ok(result.rows_affected() > 0)
    }

    /// Reset stale jobs back to pending. Mark those that exceeded max_attempts as dead.
    pub async fn reset_stale_jobs(&self, stale_minutes: i32) -> HeimdallResult<u64> {
        sqlx::query(
            "UPDATE scan_jobs SET \
                status = 'dead', updated_at = now(), completed_at = now() \
             WHERE status IN ('claimed', 'running') \
               AND claimed_at < now() - make_interval(mins => $1) \
               AND attempts >= max_attempts",
        )
        .bind(stale_minutes)
        .execute(&self.pool)
        .await
        .context("Failed to mark dead scan jobs")?;

        let result = sqlx::query(
            "UPDATE scan_jobs SET \
                status = 'pending', worker_id = NULL, claimed_at = NULL, \
                started_at = NULL, updated_at = now() \
             WHERE status IN ('claimed', 'running') \
               AND claimed_at < now() - make_interval(mins => $1) \
               AND attempts < max_attempts",
        )
        .bind(stale_minutes)
        .execute(&self.pool)
        .await
        .context("Failed to reset stale scan jobs")?;
        Ok(result.rows_affected())
    }

    // -----------------------------------------------------------------------
    // API Keys
    // -----------------------------------------------------------------------

    pub async fn create_api_key(
        &self,
        user_id: Uuid,
        key_type: &str,
        provider: &str,
        label: Option<&str>,
        key_hash: &str,
        encrypted_key: &str,
    ) -> HeimdallResult<ApiKey> {
        sqlx::query_as::<_, ApiKey>(
            "INSERT INTO api_keys (user_id, key_type, provider, label, key_hash, encrypted_key) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING *",
        )
        .bind(user_id)
        .bind(key_type)
        .bind(provider)
        .bind(label)
        .bind(key_hash)
        .bind(encrypted_key)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create API key")
    }

    pub async fn list_api_keys_by_user(&self, user_id: Uuid) -> HeimdallResult<Vec<ApiKey>> {
        sqlx::query_as::<_, ApiKey>(
            "SELECT id, user_id, org_id, key_type, provider, label, key_hash, \
             '' AS encrypted_key, last_used_at, created_at, deleted_at \
             FROM api_keys WHERE user_id = $1 AND deleted_at IS NULL \
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list API keys by user")
    }

    pub async fn list_runtime_api_keys_by_user(
        &self,
        user_id: Uuid,
    ) -> HeimdallResult<Vec<ApiKey>> {
        sqlx::query_as::<_, ApiKey>(
            "SELECT * FROM api_keys \
             WHERE user_id = $1 AND deleted_at IS NULL \
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list runtime API keys by user")
    }

    pub async fn delete_api_key(&self, id: Uuid) -> HeimdallResult<bool> {
        let result = sqlx::query(
            "UPDATE api_keys SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to soft-delete API key")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_api_key_by_hash(&self, key_hash: &str) -> HeimdallResult<Option<ApiKey>> {
        sqlx::query_as::<_, ApiKey>(
            "SELECT * FROM api_keys WHERE key_hash = $1 AND deleted_at IS NULL",
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch API key by hash")
    }

    pub async fn count_api_keys_by_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> HeimdallResult<i64> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM api_keys \
             WHERE user_id = $1 AND provider = $2 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .bind(provider)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count API keys by provider")
    }

    // -----------------------------------------------------------------------
    // Threat Models
    // -----------------------------------------------------------------------

    /// Fetch a threat model by its primary key.
    pub async fn get_threat_model_by_id(&self, id: Uuid) -> HeimdallResult<Option<ThreatModel>> {
        sqlx::query_as::<_, ThreatModel>("SELECT * FROM threat_models WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch threat model by id")
    }

    /// Update a single field on a threat model.
    pub async fn update_threat_model_field(
        &self,
        id: Uuid,
        field: &str,
        value: &serde_json::Value,
    ) -> HeimdallResult<bool> {
        // Build query dynamically based on field name
        // Only allow known fields to prevent SQL injection
        let query = match field {
            "summary" => "UPDATE threat_models SET summary = $1, updated_at = now() WHERE id = $2",
            "boundaries_json" => {
                "UPDATE threat_models SET boundaries_json = $1, updated_at = now() WHERE id = $2"
            }
            "surfaces_json" => {
                "UPDATE threat_models SET surfaces_json = $1, updated_at = now() WHERE id = $2"
            }
            "data_flows_json" => {
                "UPDATE threat_models SET data_flows_json = $1, updated_at = now() WHERE id = $2"
            }
            _ => anyhow::bail!("Unknown threat model field: {field}"),
        };

        let result = if field == "summary" {
            let summary_str = value.as_str().unwrap_or("");
            sqlx::query(query)
                .bind(summary_str)
                .bind(id)
                .execute(&self.pool)
                .await
                .context("Failed to update threat model field")?
        } else {
            sqlx::query(query)
                .bind(value)
                .bind(id)
                .execute(&self.pool)
                .await
                .context("Failed to update threat model field")?
        };

        Ok(result.rows_affected() > 0)
    }

    /// Fetch a single OAuth connection for a user and provider.
    pub async fn get_oauth_connection(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> HeimdallResult<Option<OauthConnection>> {
        sqlx::query_as::<_, OauthConnection>(
            "SELECT * FROM oauth_connections WHERE user_id = $1 AND provider = $2 LIMIT 1",
        )
        .bind(user_id)
        .bind(provider)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch OAuth connection")
    }

    /// Fetch a single OAuth connection by id.
    pub async fn get_oauth_connection_by_id(
        &self,
        id: Uuid,
    ) -> HeimdallResult<Option<OauthConnection>> {
        sqlx::query_as::<_, OauthConnection>(
            "SELECT * FROM oauth_connections WHERE id = $1 LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch OAuth connection by id")
    }

    /// List all OAuth connections for a user.
    pub async fn list_oauth_connections_by_user(
        &self,
        user_id: Uuid,
    ) -> HeimdallResult<Vec<OauthConnection>> {
        sqlx::query_as::<_, OauthConnection>(
            "SELECT * FROM oauth_connections WHERE user_id = $1 ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list OAuth connections")
    }

    /// Remove a user's OAuth connection for a provider.
    pub async fn delete_oauth_connection(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> HeimdallResult<u64> {
        let result =
            sqlx::query("DELETE FROM oauth_connections WHERE user_id = $1 AND provider = $2")
                .bind(user_id)
                .bind(provider)
                .execute(&self.pool)
                .await
                .context("Failed to delete OAuth connection")?;

        Ok(result.rows_affected())
    }

    /// Clear the OAuth connection link from repos that used it.
    pub async fn clear_repo_oauth_connection(
        &self,
        oauth_connection_id: Uuid,
    ) -> HeimdallResult<u64> {
        let result = sqlx::query(
            "UPDATE repos SET oauth_connection_id = NULL WHERE oauth_connection_id = $1",
        )
        .bind(oauth_connection_id)
        .execute(&self.pool)
        .await
        .context("Failed to clear repo OAuth connection")?;

        Ok(result.rows_affected())
    }
}
