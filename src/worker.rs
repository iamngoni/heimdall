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
use crate::db::DatabaseOperations;
use crate::pipeline::ScanPipeline;
use crate::sse::ScanBroadcaster;

/// Background worker that polls `scan_jobs` and executes scan pipelines.
pub struct ScanWorker {
    worker_id: String,
    db: Arc<DatabaseOperations>,
    ai: Arc<dyn ModelProvider>,
    default_model: String,
    sse: Arc<ScanBroadcaster>,
    poll_interval: Duration,
    stale_check_interval: Duration,
    stale_timeout_minutes: i32,
}

impl ScanWorker {
    pub fn new(
        db: Arc<DatabaseOperations>,
        ai: Arc<dyn ModelProvider>,
        default_model: String,
        sse: Arc<ScanBroadcaster>,
        poll_interval: Duration,
        stale_timeout_minutes: i32,
    ) -> Self {
        let worker_id = format!("worker-{}", Uuid::now_v7());
        Self {
            worker_id,
            db,
            ai,
            default_model,
            sse,
            poll_interval,
            stale_check_interval: Duration::from_secs(60),
            stale_timeout_minutes,
        }
    }

    /// Main worker loop. Runs indefinitely, polling for scan jobs.
    pub async fn run(self: Arc<Self>) {
        info!(
            "Scan worker '{}' started (poll={:?}, stale_timeout={}min)",
            self.worker_id, self.poll_interval, self.stale_timeout_minutes
        );

        let mut last_stale_check = Instant::now();

        loop {
            // Periodically reset stale jobs
            if last_stale_check.elapsed() >= self.stale_check_interval {
                self.reset_stale_jobs().await;
                last_stale_check = Instant::now();
            }

            // Try to claim a job
            match self.db.claim_next_scan_job(&self.worker_id).await {
                Ok(Some(job)) => {
                    info!(
                        "[{}] Claimed job {} for scan {}",
                        self.worker_id, job.id, job.scan_id
                    );
                    self.process_job(job.id, job.scan_id, job.attempts, job.max_attempts)
                        .await;
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
        let _ = self.db.increment_scan_job_attempts(job_id).await;

        // Load the scan to get repo_id
        let scan = match self.db.get_scan_by_id(scan_id).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                error!("[{}] Scan {} not found", self.worker_id, scan_id);
                let _ = self
                    .db
                    .update_scan_job_status(job_id, "failed", Some("Scan not found"))
                    .await;
                return;
            }
            Err(e) => {
                error!("[{}] Failed to load scan {}: {:#}", self.worker_id, scan_id, e);
                let _ = self
                    .db
                    .update_scan_job_status(job_id, "failed", Some(&format!("{e:#}")))
                    .await;
                return;
            }
        };

        // Load the repo
        let repo = match self.db.get_repo_by_id(scan.repo_id).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                error!("[{}] Repo {} not found for scan {}", self.worker_id, scan.repo_id, scan_id);
                let _ = self
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
                    .db
                    .update_scan_job_status(job_id, "failed", Some(&format!("{e:#}")))
                    .await;
                return;
            }
        };

        // Run the pipeline
        let pipeline = ScanPipeline::new(
            scan_id,
            Arc::clone(&self.db),
            Arc::clone(&self.ai),
            self.default_model.clone(),
            Arc::clone(&self.sse),
        );

        match pipeline.run(&repo).await {
            Ok(()) => {
                info!(
                    "[{}] Job {} (scan {}) completed successfully",
                    self.worker_id, job_id, scan_id
                );
                let _ = self
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
                        .db
                        .update_scan_job_status(job_id, "pending", Some(&error_msg))
                        .await;
                } else {
                    error!(
                        "[{}] Job {} (scan {}) failed permanently after {} attempts: {}",
                        self.worker_id, job_id, scan_id, next_attempt, error_msg
                    );
                    let _ = self
                        .db
                        .update_scan_job_status(job_id, "failed", Some(&error_msg))
                        .await;
                    let _ = self
                        .db
                        .update_scan_status(scan_id, "failed", Some(&error_msg))
                        .await;
                    self.sse.emit_error(scan_id, &error_msg);
                }
            }
        }
    }

    /// Reset stale jobs that appear stuck.
    async fn reset_stale_jobs(&self) {
        match self.db.reset_stale_jobs(self.stale_timeout_minutes).await {
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
