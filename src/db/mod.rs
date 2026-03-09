//
//  heimdall
//  src/db/mod.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod schema;

use anyhow::Context;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::db_models::*;
use crate::models::HeimdallResult;

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
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch user by id")
    }

    pub async fn get_user_by_email(&self, email: &str) -> HeimdallResult<Option<User>> {
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch user by email")
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
        sqlx::query_as::<_, Repo>(
            "SELECT * FROM repos WHERE id = $1 AND deleted_at IS NULL",
        )
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

    pub async fn soft_delete_repo(&self, id: Uuid) -> HeimdallResult<bool> {
        let result = sqlx::query(
            "UPDATE repos SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to soft-delete repo")?;
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
        sqlx::query_as::<_, Scan>(
            "SELECT * FROM scans WHERE repo_id = $1 ORDER BY created_at DESC",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list scans by repo")
    }

    pub async fn update_scan_status(
        &self,
        id: Uuid,
        status: &str,
        error_message: Option<&str>,
    ) -> HeimdallResult<bool> {
        let result = sqlx::query(
            "UPDATE scans SET status = $1, error_message = $2 WHERE id = $3",
        )
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
        sqlx::query_as::<_, ScanJob>(
            "INSERT INTO scan_jobs (scan_id) VALUES ($1) RETURNING *",
        )
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create scan job")
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
        let mut query = String::from(
            "SELECT * FROM findings WHERE scan_id = $1",
        );
        let mut param_idx = 2;

        if severity.is_some() {
            query.push_str(&format!(" AND severity = ${param_idx}"));
            param_idx += 1;
        }
        if status.is_some() {
            query.push_str(&format!(" AND status = ${param_idx}"));
        }
        query.push_str(" ORDER BY CASE severity \
            WHEN 'critical' THEN 0 \
            WHEN 'high' THEN 1 \
            WHEN 'medium' THEN 2 \
            WHEN 'low' THEN 3 \
            ELSE 4 END, created_at DESC");

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

    pub async fn update_finding_status(
        &self,
        id: Uuid,
        status: &str,
    ) -> HeimdallResult<bool> {
        let result = sqlx::query(
            "UPDATE findings SET status = $1 WHERE id = $2",
        )
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
        sqlx::query_as::<_, ThreatModel>(
            "SELECT * FROM threat_models WHERE scan_id = $1",
        )
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

    pub async fn delete_session(&self, id: Uuid) -> HeimdallResult<bool> {
        let result = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete session")?;
        Ok(result.rows_affected() > 0)
    }
}
