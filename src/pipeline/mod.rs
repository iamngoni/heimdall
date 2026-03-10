//
//  heimdall
//  src/pipeline/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod deps_audit;
pub mod garmr;
pub mod hunt;
pub mod ingest;
pub mod report;
pub mod static_analysis;
pub mod taint;
pub mod tyr;

use std::sync::Arc;

use log::{error, info};

use crate::ai::ModelProvider;
use crate::db::DatabaseOperations;
use crate::models::HeimdallResult;
use crate::models::db_models::Repo;
use crate::sse::ScanBroadcaster;

/// Orchestrates the full scan pipeline:
/// Ingest -> Tyr (threat model) -> Static Analysis -> Hunt (agentic) -> Garmr (sandbox) -> Report
pub struct ScanPipeline {
    pub scan_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
    pub ai: Arc<dyn ModelProvider>,
    pub default_model: String,
    pub sse: Arc<ScanBroadcaster>,
}

impl ScanPipeline {
    pub fn new(
        scan_id: uuid::Uuid,
        db: Arc<DatabaseOperations>,
        ai: Arc<dyn ModelProvider>,
        default_model: String,
        sse: Arc<ScanBroadcaster>,
    ) -> Self {
        Self {
            scan_id,
            db,
            ai,
            default_model,
            sse,
        }
    }

    pub async fn run(&self, repo: &Repo) -> HeimdallResult<()> {
        info!("Starting scan pipeline for scan_id={}", self.scan_id);

        self.db
            .update_scan_timestamps(self.scan_id, true, false)
            .await?;

        // Stage 1: Ingest
        let ingest_output = self.run_stage("ingest", "ingesting", "ingested", async {
            let stage = ingest::IngestStage::new(self.scan_id, Arc::clone(&self.db));
            stage.run(repo).await
        }).await?;

        let code_index = Arc::new(ingest_output.code_index);

        // Stage 2: Tyr (Threat Model)
        let threat_model = self.run_stage("tyr", "modeling", "modeled", async {
            let stage = tyr::TyrStage::new(
                self.scan_id,
                repo.id,
                Arc::clone(&self.db),
                Arc::clone(&self.ai),
            );
            stage.run(&code_index).await
        }).await?;

        // Stage 3: Static Analysis
        let static_ctx = self.run_stage("static_analysis", "static_analysis", "static_analysis", async {
            let stage = static_analysis::StaticAnalysisStage::new(
                self.scan_id,
                repo.id,
                Arc::clone(&self.db),
            );
            stage.run(&code_index).await
        }).await?;

        // Stage 4: Hunt (Agentic Discovery)
        let _hunt_findings = self.run_stage("hunt", "hunting", "hunted", async {
            let stage = hunt::HuntStage::new(
                self.scan_id,
                repo.id,
                Arc::clone(&self.db),
                Arc::clone(&self.ai),
                self.default_model.clone(),
            );
            stage.run(Arc::clone(&code_index), &threat_model, &static_ctx.summary).await
        }).await?;

        // Emit finding_added events for findings created during the hunt stage
        if let Ok(findings) = self.db.list_findings_by_scan(self.scan_id, None, None).await {
            for finding in &findings {
                self.sse.emit_finding_added(
                    self.scan_id,
                    finding.id,
                    &finding.title,
                    &finding.severity,
                );
            }
        }

        // Fetch all findings for Garmr and Report stages
        let findings = self
            .db
            .list_findings_by_scan(self.scan_id, None, None)
            .await?;

        // Stage 5: Garmr (Sandbox Validation)
        let _validated = self.run_stage("garmr", "validating", "validated", async {
            let stage = garmr::GarmrStage::new(
                self.scan_id,
                Arc::clone(&self.db),
                Arc::clone(&self.ai),
                self.default_model.clone(),
            );
            stage.run(&findings, &ingest_output.work_dir).await
        }).await?;

        // Stage 6: Report
        self.run_stage("report", "reporting", "completed", async {
            let stage = report::ReportStage::new(
                self.scan_id,
                Arc::clone(&self.db),
                Arc::clone(&self.ai),
                self.default_model.clone(),
            );
            stage.run(&findings, &code_index).await
        }).await?;

        // Mark scan as completed
        self.db
            .update_scan_timestamps(self.scan_id, false, true)
            .await?;

        // Update finding counts and emit scan_complete
        let _ = self.db.update_scan_counts(self.scan_id).await;
        if let Ok(Some(scan)) = self.db.get_scan_by_id(self.scan_id).await {
            self.sse.emit_scan_complete(
                self.scan_id,
                scan.finding_count,
                scan.critical_count,
                scan.high_count,
                scan.medium_count,
                scan.low_count,
            );
        }

        // Cleanup work directory
        if ingest_output.work_dir.exists() {
            let _ = std::fs::remove_dir_all(&ingest_output.work_dir);
        }

        // Cleanup SSE channel after a short delay to let clients receive final events
        let sse = Arc::clone(&self.sse);
        let scan_id = self.scan_id;
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            sse.cleanup(scan_id);
        });

        info!("Scan pipeline completed for scan_id={}", self.scan_id);
        Ok(())
    }

    /// Run a pipeline stage with proper status tracking, error handling, and SSE events.
    async fn run_stage<T, F>(
        &self,
        stage_name: &str,
        status_running: &str,
        status_done: &str,
        future: F,
    ) -> HeimdallResult<T>
    where
        F: std::future::Future<Output = HeimdallResult<T>>,
    {
        info!("[{}] Starting stage: {stage_name}", self.scan_id);

        // Create scan_stage record
        let scan_stage = self.db.create_scan_stage(self.scan_id, stage_name).await?;
        self.db
            .update_scan_stage_status(scan_stage.id, "running", None)
            .await?;

        // Update scan status
        self.db
            .update_scan_status(self.scan_id, status_running, None)
            .await?;

        // Emit SSE events: stage starting + status change
        self.sse.emit_stage_update(self.scan_id, stage_name, "running", None);
        self.sse.emit_status_change(self.scan_id, status_running);

        match future.await {
            Ok(result) => {
                self.db
                    .update_scan_stage_status(scan_stage.id, "completed", None)
                    .await?;
                self.db
                    .update_scan_status(self.scan_id, status_done, None)
                    .await?;

                // Emit SSE events: stage completed + status change
                self.sse.emit_stage_update(self.scan_id, stage_name, "completed", None);
                self.sse.emit_status_change(self.scan_id, status_done);

                info!("[{}] Stage {stage_name} completed", self.scan_id);
                Ok(result)
            }
            Err(e) => {
                let err_msg = format!("{e:#}");
                error!("[{}] Stage {stage_name} failed: {err_msg}", self.scan_id);
                self.db
                    .update_scan_stage_status(scan_stage.id, "failed", Some(&err_msg))
                    .await?;
                self.db
                    .update_scan_status(self.scan_id, "failed", Some(&err_msg))
                    .await?;

                // Emit SSE events: stage failed + error
                self.sse.emit_stage_update(self.scan_id, stage_name, "failed", Some(&err_msg));
                self.sse.emit_error(self.scan_id, &err_msg);

                Err(e)
            }
        }
    }
}
