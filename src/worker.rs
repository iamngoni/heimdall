//
//  heimdall
//  src/worker.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;
use std::time::Duration;

use log::{error, info, warn};
use tokio::time::Instant;
use uuid::Uuid;

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, CompletionResponse};
use crate::db::DatabaseOperations;
use crate::models::HeimdallResult;
use crate::pipeline::ScanPipeline;
use crate::state::AppState;

struct ScanAiProvider {
    inner: Arc<dyn ModelProvider>,
    db: Arc<DatabaseOperations>,
    scan_id: Uuid,
}

impl ScanAiProvider {
    fn new(inner: Arc<dyn ModelProvider>, db: Arc<DatabaseOperations>, scan_id: Uuid) -> Self {
        Self { inner, db, scan_id }
    }

    async fn record_fallback(&self, response: &CompletionResponse) {
        let Some(metadata) = response.routing_metadata() else {
            return;
        };
        let Some(detail) = response.fallback_summary() else {
            return;
        };

        if let Err(error) = self
            .db
            .create_scan_event(
                self.scan_id,
                None,
                Some("provider-fallback"),
                "provider_fallback",
                Some("warning"),
                "AI provider fallback used",
                Some(&detail),
                None,
                Some(&metadata),
            )
            .await
        {
            warn!(
                "[{}] Failed to record AI provider fallback: {error:#}",
                self.scan_id
            );
        }
    }
}

#[async_trait::async_trait]
impl ModelProvider for ScanAiProvider {
    async fn complete(&self, request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
        let response = self.inner.complete(request).await?;
        self.record_fallback(&response).await;
        Ok(response)
    }

    fn provider_name(&self) -> &str {
        self.inner.provider_name()
    }
}

/// Background worker that polls `scan_jobs` and executes scan pipelines.
pub struct ScanWorker {
    worker_id: String,
    state: Arc<AppState>,
    poll_interval: Duration,
    stale_check_interval: Duration,
    stale_timeout_minutes: i32,
    max_active_jobs_per_user: i64,
}

impl ScanWorker {
    pub fn new(state: Arc<AppState>, poll_interval: Duration, stale_timeout_minutes: i32) -> Self {
        let worker_id = format!("worker-{}", Uuid::now_v7());
        let max_active_jobs_per_user = std::env::var("SCAN_MAX_ACTIVE_JOBS_PER_USER")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(2);
        Self {
            worker_id,
            state,
            poll_interval,
            stale_check_interval: Duration::from_secs(60),
            stale_timeout_minutes,
            max_active_jobs_per_user,
        }
    }

    /// Main worker loop. Runs indefinitely, polling for scan jobs.
    pub async fn run(self: Arc<Self>) {
        info!(
            "Scan worker '{}' started (poll={:?}, stale_timeout={}min, max_active_per_user={})",
            self.worker_id,
            self.poll_interval,
            self.stale_timeout_minutes,
            self.max_active_jobs_per_user
        );

        let mut last_stale_check = Instant::now();

        loop {
            // Periodically reset stale jobs
            if last_stale_check.elapsed() >= self.stale_check_interval {
                self.reset_stale_jobs().await;
                last_stale_check = Instant::now();
            }

            // Try to claim a job. Each claimed job is processed in its own task;
            // concurrency is controlled by the per-user claim gate in the database.
            match self
                .state
                .db
                .claim_next_scan_job(&self.worker_id, self.max_active_jobs_per_user)
                .await
            {
                Ok(Some(job)) => {
                    info!(
                        "[{}] Claimed job {} for scan {}",
                        self.worker_id, job.id, job.scan_id
                    );
                    let worker = Arc::clone(&self);
                    tokio::spawn(async move {
                        worker
                            .process_job(job.id, job.scan_id, job.attempts, job.max_attempts)
                            .await;
                    });
                }
                Ok(None) => {
                    tokio::time::sleep(self.poll_interval).await;
                }
                Err(e) => {
                    error!("[{}] Failed to claim job: {:#}", self.worker_id, e);
                    tokio::time::sleep(self.poll_interval).await;
                }
            }
        }
    }

    /// Process a single scan job.
    async fn process_job(
        &self,
        job_id: Uuid,
        scan_id: Uuid,
        current_attempts: i32,
        max_attempts: i32,
    ) {
        // Mark as running
        if let Err(e) = self
            .state
            .db
            .update_scan_job_status(job_id, "running", None)
            .await
        {
            error!(
                "[{}] Failed to set job {} to running: {:#}",
                self.worker_id, job_id, e
            );
            return;
        }

        // Increment attempt counter
        let _ = self.state.db.increment_scan_job_attempts(job_id).await;

        // Load the scan to get repo_id
        let scan = match self.state.db.get_scan_by_id(scan_id).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                error!("[{}] Scan {} not found", self.worker_id, scan_id);
                let _ = self
                    .state
                    .db
                    .update_scan_job_status(job_id, "failed", Some("Scan not found"))
                    .await;
                return;
            }
            Err(e) => {
                error!(
                    "[{}] Failed to load scan {}: {:#}",
                    self.worker_id, scan_id, e
                );
                let _ = self
                    .state
                    .db
                    .update_scan_job_status(job_id, "failed", Some(&format!("{e:#}")))
                    .await;
                return;
            }
        };

        // Load the repo
        let repo = match self.state.db.get_repo_by_id(scan.repo_id).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                error!(
                    "[{}] Repo {} not found for scan {}",
                    self.worker_id, scan.repo_id, scan_id
                );
                let _ = self
                    .state
                    .db
                    .update_scan_job_status(job_id, "failed", Some("Repo not found"))
                    .await;
                return;
            }
            Err(e) => {
                error!(
                    "[{}] Failed to load repo {} for scan {}: {:#}",
                    self.worker_id, scan.repo_id, scan_id, e
                );
                let _ = self
                    .state
                    .db
                    .update_scan_job_status(job_id, "failed", Some(&format!("{e:#}")))
                    .await;
                return;
            }
        };

        let runtime = match self.state.resolve_ai_for_user(repo.user_id).await {
            Ok(runtime) => runtime,
            Err(e) => {
                let error_msg = format!("{e:#}");
                error!(
                    "[{}] No AI runtime available for repo {} / scan {}: {}",
                    self.worker_id, repo.id, scan_id, error_msg
                );
                let _ = self
                    .state
                    .db
                    .update_scan_job_status(job_id, "failed", Some(&error_msg))
                    .await;
                let _ = self
                    .state
                    .db
                    .update_scan_status(scan_id, "failed", Some(&error_msg))
                    .await;
                self.state.sse.emit_error(scan_id, &error_msg);
                return;
            }
        };

        // Run the pipeline
        let cancel_token = self.state.sse.register_cancellation_token(scan_id);
        let scan_ai: Arc<dyn ModelProvider> = Arc::new(ScanAiProvider::new(
            Arc::clone(&runtime.provider),
            Arc::clone(&self.state.db),
            scan_id,
        ));
        let pipeline = ScanPipeline::new(
            scan_id,
            Arc::clone(&self.state.db),
            scan_ai,
            runtime.model,
            Arc::clone(&self.state.sse),
            self.state.encryption_key,
            self.state.config.app.data_dir.clone(),
            self.state.config.semgrep.clone(),
            cancel_token,
        );

        match pipeline.run(&repo).await {
            Ok(()) => {
                info!(
                    "[{}] Job {} (scan {}) completed successfully",
                    self.worker_id, job_id, scan_id
                );
                let _ = self
                    .state
                    .db
                    .update_scan_job_status(job_id, "completed", None)
                    .await;
            }
            Err(e) => {
                let error_msg = format!("{e:#}");
                let next_attempt = current_attempts + 1;

                if next_attempt < max_attempts {
                    warn!(
                        "[{}] Job {} (scan {}) failed (attempt {}/{}), will retry: {}",
                        self.worker_id, job_id, scan_id, next_attempt, max_attempts, error_msg
                    );
                    let _ = self
                        .state
                        .db
                        .update_scan_job_status(job_id, "pending", Some(&error_msg))
                        .await;
                } else {
                    error!(
                        "[{}] Job {} (scan {}) failed permanently after {} attempts: {}",
                        self.worker_id, job_id, scan_id, next_attempt, error_msg
                    );
                    let _ = self
                        .state
                        .db
                        .update_scan_job_status(job_id, "failed", Some(&error_msg))
                        .await;
                    let _ = self
                        .state
                        .db
                        .update_scan_status(scan_id, "failed", Some(&error_msg))
                        .await;
                    self.state.sse.emit_error(scan_id, &error_msg);
                }
            }
        }
    }

    /// Reset stale jobs that appear stuck.
    async fn reset_stale_jobs(&self) {
        match self
            .state
            .db
            .reset_stale_jobs(self.stale_timeout_minutes)
            .await
        {
            Ok(count) => {
                if count > 0 {
                    warn!(
                        "[{}] Reset {} stale job(s) back to pending",
                        self.worker_id, count
                    );
                }
            }
            Err(e) => {
                error!("[{}] Failed to reset stale jobs: {:#}", self.worker_id, e);
            }
        }
    }
}
