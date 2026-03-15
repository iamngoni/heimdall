//
//  heimdall
//  src/pipeline/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod config_scan;
pub mod deps_audit;
pub mod garmr;
pub mod hunt;
pub mod ingest;
pub mod report;
pub mod static_analysis;
pub mod taint;
pub mod tyr;
pub mod vidarr;

use std::sync::Arc;

use log::{error, info, warn};
use tokio_util::sync::CancellationToken;

use crate::ai::ModelProvider;
use crate::db::DatabaseOperations;
use crate::integrations::issues;
use crate::models::HeimdallResult;
use crate::models::db_models::{Finding, Repo};
use crate::sse::ScanBroadcaster;

/// Orchestrates the full scan pipeline:
/// Ingest -> Tyr (threat model) -> Static Analysis -> Taint Analysis -> Config Scan -> Hunt (agentic) -> Víðarr (adversarial verification) -> Garmr (sandbox) -> Report
pub struct ScanPipeline {
    pub scan_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
    pub ai: Arc<dyn ModelProvider>,
    pub default_model: String,
    pub sse: Arc<ScanBroadcaster>,
    pub encryption_key: Option<[u8; 32]>,
    pub data_dir: String,
    pub cancel_token: CancellationToken,
}

impl ScanPipeline {
    pub fn new(
        scan_id: uuid::Uuid,
        db: Arc<DatabaseOperations>,
        ai: Arc<dyn ModelProvider>,
        default_model: String,
        sse: Arc<ScanBroadcaster>,
        encryption_key: Option<[u8; 32]>,
        data_dir: String,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            scan_id,
            db,
            ai,
            default_model,
            sse,
            encryption_key,
            data_dir,
            cancel_token,
        }
    }

    pub async fn run(&self, repo: &Repo) -> HeimdallResult<()> {
        info!("Starting scan pipeline for scan_id={}", self.scan_id);
        self.record_scan_event(
            None,
            Some("scan-start"),
            "system",
            Some("running"),
            "Scan execution started",
            Some("Pipeline booted and is preparing the working copy."),
            None,
            None,
        )
        .await;

        self.db
            .update_scan_timestamps(self.scan_id, true, false)
            .await?;

        // Stage 1: Ingest
        let ingest_output = self
            .run_stage("ingest", "ingesting", "ingested", async {
                let stage = ingest::IngestStage::new(
                    self.scan_id,
                    Arc::clone(&self.db),
                    self.encryption_key,
                    self.data_dir.clone(),
                );
                stage.run(repo).await
            })
            .await?;

        let code_index = Arc::new(ingest_output.code_index);

        // Stage 2: Tyr (Threat Model)
        let threat_model = self
            .run_stage("tyr", "modeling", "modeled", async {
                let stage = tyr::TyrStage::new(
                    self.scan_id,
                    repo.id,
                    Arc::clone(&self.db),
                    Arc::clone(&self.ai),
                    self.default_model.clone(),
                );
                stage.run(&code_index).await
            })
            .await?;

        // Stage 3: Static Analysis
        let static_ctx = self
            .run_stage(
                "static_analysis",
                "static_analysis",
                "static_analysis",
                async {
                    let stage = static_analysis::StaticAnalysisStage::new(
                        self.scan_id,
                        repo.id,
                        Arc::clone(&self.db),
                    )
                    .with_work_dir(ingest_output.work_dir.clone());
                    stage.run(&code_index).await
                },
            )
            .await?;

        // Stage 3b: Taint Analysis
        let _taint_flows = self
            .run_stage(
                "taint_analysis",
                "taint_analyzing",
                "taint_analyzed",
                async {
                    let stage =
                        taint::TaintAnalysisStage::new(self.scan_id, repo.id, Arc::clone(&self.db));
                    stage.run(&code_index).await
                },
            )
            .await?;

        // Stage 3c: Config/IaC Scan
        let _config_ctx = self
            .run_stage("config_scan", "config_scanning", "config_scanned", async {
                let stage =
                    config_scan::ConfigScanStage::new(self.scan_id, repo.id, Arc::clone(&self.db));
                stage.run(&code_index).await
            })
            .await?;

        // Stage 4: Hunt (Agentic Discovery)
        let _hunt_findings = self
            .run_stage("hunt", "hunting", "hunted", async {
                let stage = hunt::HuntStage::new(
                    self.scan_id,
                    repo.id,
                    Arc::clone(&self.db),
                    Arc::clone(&self.ai),
                    self.default_model.clone(),
                );
                stage
                    .run(Arc::clone(&code_index), &threat_model, &static_ctx.summary)
                    .await
            })
            .await?;

        // Emit finding_added events for findings created during the hunt stage
        if let Ok(findings) = self
            .db
            .list_findings_by_scan(self.scan_id, None, None)
            .await
        {
            for finding in &findings {
                self.sse.emit_finding_added(
                    self.scan_id,
                    finding.id,
                    &finding.title,
                    &finding.severity,
                );
            }
        }

        // Fetch all findings for Skeptic, Garmr, and Report stages
        let findings = self
            .db
            .list_findings_by_scan(self.scan_id, None, None)
            .await?;

        // Stage 4b: Víðarr (Adversarial Verification)
        let _vidarr_ctx = self
            .run_stage("vidarr", "verifying", "verified", async {
                let stage = vidarr::VidarrStage::new(
                    self.scan_id,
                    Arc::clone(&self.db),
                    Arc::clone(&self.ai),
                    self.default_model.clone(),
                );
                stage.run(&findings, &code_index).await
            })
            .await?;

        // Re-fetch findings after Víðarr — some may have been marked false_positive
        let findings: Vec<Finding> = self
            .db
            .list_findings_by_scan(self.scan_id, None, None)
            .await?
            .into_iter()
            .filter(|f| f.status != "false_positive")
            .collect();

        // Stage 5: Garmr (Sandbox Validation)
        let _validated = self
            .run_stage("garmr", "validating", "validated", async {
                let stage = garmr::GarmrStage::new(
                    self.scan_id,
                    Arc::clone(&self.db),
                    Arc::clone(&self.ai),
                    self.default_model.clone(),
                );
                stage.run(&findings, &ingest_output.work_dir).await
            })
            .await?;

        // Stage 6: Report
        self.run_stage("report", "reporting", "completed", async {
            let stage = report::ReportStage::new(
                self.scan_id,
                Arc::clone(&self.db),
                Arc::clone(&self.ai),
                self.default_model.clone(),
            );
            stage.run(&findings, &code_index).await
        })
        .await?;

        // Mark scan as completed
        self.db
            .update_scan_timestamps(self.scan_id, false, true)
            .await?;

        // Update finding counts and emit scan_complete
        let _ = self.db.update_scan_counts(self.scan_id).await;
        self.auto_create_repo_issues(repo).await;
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

        self.record_scan_event(
            None,
            Some("scan-finished"),
            "system",
            Some("completed"),
            "Scan execution finished",
            Some("All configured analysis stages completed and final outputs were stored."),
            Some(100),
            None,
        )
        .await;

        // Cleanup SSE channel and cancellation token after a short delay
        let sse = Arc::clone(&self.sse);
        let scan_id = self.scan_id;
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            sse.cleanup(scan_id);
            sse.cleanup_cancellation_token(scan_id);
        });

        info!("Scan pipeline completed for scan_id={}", self.scan_id);
        Ok(())
    }

    /// Run a pipeline stage with proper status tracking, error handling, and SSE events.
    /// The stage future races against the cancellation token — if the user cancels,
    /// the in-progress work is dropped immediately.
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
        // Check for cancellation before starting a new stage
        if self.cancel_token.is_cancelled() {
            info!(
                "[{}] Scan cancelled — skipping stage {stage_name}",
                self.scan_id
            );
            return Err(anyhow::anyhow!("Scan was cancelled"));
        }

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
        self.sse
            .emit_stage_update(self.scan_id, stage_name, "running", None);
        self.sse.emit_status_change(self.scan_id, status_running);
        self.record_scan_event(
            Some(stage_name),
            Some(stage_name),
            "stage",
            Some("running"),
            format!("{} started", humanize_stage_name(stage_name)).as_str(),
            Some("Stage entered active execution."),
            None,
            None,
        )
        .await;

        // Race the stage work against the cancellation token
        let result = tokio::select! {
            biased;
            _ = self.cancel_token.cancelled() => {
                Err(anyhow::anyhow!("Scan was cancelled"))
            }
            result = future => result,
        };

        match result {
            Ok(result) => {
                self.db
                    .update_scan_stage_status(scan_stage.id, "completed", None)
                    .await?;
                self.db
                    .update_scan_status(self.scan_id, status_done, None)
                    .await?;

                // Emit SSE events: stage completed + status change
                self.sse
                    .emit_stage_update(self.scan_id, stage_name, "completed", None);
                self.sse.emit_status_change(self.scan_id, status_done);
                self.record_scan_event(
                    Some(stage_name),
                    Some(stage_name),
                    "stage",
                    Some("completed"),
                    format!("{} completed", humanize_stage_name(stage_name)).as_str(),
                    Some("Stage work finished successfully."),
                    Some(100),
                    None,
                )
                .await;

                info!("[{}] Stage {stage_name} completed", self.scan_id);
                Ok(result)
            }
            Err(e) => {
                let err_msg = format!("{e:#}");

                // If cancelled, mark stage as cancelled rather than failed
                let stage_status = if self.cancel_token.is_cancelled() {
                    "cancelled"
                } else {
                    "failed"
                };

                error!(
                    "[{}] Stage {stage_name} {stage_status}: {err_msg}",
                    self.scan_id
                );
                self.db
                    .update_scan_stage_status(scan_stage.id, stage_status, Some(&err_msg))
                    .await?;

                if !self.cancel_token.is_cancelled() {
                    self.db
                        .update_scan_status(self.scan_id, "failed", Some(&err_msg))
                        .await?;
                }

                // Emit SSE events: stage failed + error
                self.sse
                    .emit_stage_update(self.scan_id, stage_name, stage_status, Some(&err_msg));
                self.sse.emit_error(self.scan_id, &err_msg);
                self.record_scan_event(
                    Some(stage_name),
                    Some(stage_name),
                    "stage",
                    Some(stage_status),
                    format!("{} {stage_status}", humanize_stage_name(stage_name)).as_str(),
                    Some(&err_msg),
                    None,
                    None,
                )
                .await;

                Err(e)
            }
        }
    }

    pub(crate) async fn record_scan_event(
        &self,
        stage: Option<&str>,
        task_key: Option<&str>,
        event_type: &str,
        status: Option<&str>,
        title: &str,
        detail: Option<&str>,
        progress_pct: Option<i32>,
        metadata_json: Option<&serde_json::Value>,
    ) {
        if let Err(error) = self
            .db
            .create_scan_event(
                self.scan_id,
                stage,
                task_key,
                event_type,
                status,
                title,
                detail,
                progress_pct,
                metadata_json,
            )
            .await
        {
            warn!(
                "[{}] Failed to record scan event `{title}`: {error:#}",
                self.scan_id
            );
        }
    }

    async fn auto_create_repo_issues(&self, repo: &Repo) {
        if !repo.issue_auto_create_enabled {
            self.record_scan_event(
                Some("report"),
                Some("issue-automation"),
                "issue",
                Some("skipped"),
                "Issue automation skipped",
                Some("Automatic issue creation is disabled for this repository."),
                None,
                None,
            )
            .await;
            return;
        }

        if !issues::supports_issue_creation(repo) {
            self.record_scan_event(
                Some("report"),
                Some("issue-automation"),
                "issue",
                Some("skipped"),
                "Issue automation unavailable",
                Some("This repository does not currently support provider-backed issue creation."),
                None,
                None,
            )
            .await;
            return;
        }

        let Ok(findings) = self
            .db
            .list_findings_by_scan(self.scan_id, None, None)
            .await
        else {
            return;
        };

        let qualifying_findings = findings
            .iter()
            .filter(|finding| {
                issues::finding_qualifies_for_auto_issue(
                    finding,
                    &repo.issue_auto_create_min_severity,
                )
            })
            .cloned()
            .collect::<Vec<Finding>>();

        if qualifying_findings.is_empty() {
            self.record_scan_event(
                Some("report"),
                Some("issue-automation"),
                "issue",
                Some("completed"),
                "Issue automation completed",
                Some("No findings met the configured severity and confidence requirements for issue creation."),
                None,
                None,
            )
            .await;
            return;
        }

        self.record_scan_event(
            Some("report"),
            Some("issue-automation"),
            "issue",
            Some("running"),
            "Creating repository issues",
            Some("Qualifying findings are being synchronized to the connected repository."),
            None,
            Some(&serde_json::json!({
                "threshold": repo.issue_auto_create_min_severity,
                "requires_high_confidence_or_validation": true,
                "count": qualifying_findings.len(),
            })),
        )
        .await;

        let mut created = 0usize;
        let mut linked = 0usize;
        let mut failures = 0usize;

        for finding in qualifying_findings {
            match issues::create_or_link_issue(
                &self.db,
                self.encryption_key.as_ref(),
                repo,
                &finding,
                true,
            )
            .await
            {
                Ok((repo_issue, was_created)) => {
                    if was_created {
                        created += 1;
                    } else {
                        linked += 1;
                    }

                    let metadata = serde_json::json!({
                        "provider": repo_issue.provider,
                        "issue_url": repo_issue.issue_url,
                        "external_issue_number": repo_issue.external_issue_number,
                        "auto_created": true,
                    });
                    let _ = self
                        .db
                        .create_finding_event_with_metadata(
                            finding.id,
                            None,
                            "issue_linked",
                            None,
                            repo_issue.external_issue_number.as_deref(),
                            Some(if was_created {
                                "Repository issue created automatically from this finding."
                            } else {
                                "Existing repository issue matched this finding fingerprint."
                            }),
                            Some(&metadata),
                        )
                        .await;
                }
                Err(error) => {
                    failures += 1;
                    self.record_scan_event(
                        Some("report"),
                        Some("issue-automation"),
                        "issue",
                        Some("failed"),
                        format!("Issue creation failed for {}", finding.title).as_str(),
                        Some(&error.to_string()),
                        None,
                        Some(&serde_json::json!({
                            "finding_id": finding.id,
                            "severity": finding.severity,
                        })),
                    )
                    .await;
                }
            }
        }

        let status = if failures > 0 {
            "completed_with_errors"
        } else {
            "completed"
        };
        self.record_scan_event(
            Some("report"),
            Some("issue-automation"),
            "issue",
            Some(status),
            "Repository issue sync finished",
            Some(&format!(
                "{created} created, {linked} linked, {failures} failed."
            )),
            Some(100),
            Some(&serde_json::json!({
                "created": created,
                "linked": linked,
                "failed": failures,
            })),
        )
        .await;
    }
}

fn humanize_stage_name(stage_name: &str) -> &'static str {
    match stage_name {
        "ingest" => "Ingest",
        "tyr" => "Tyr",
        "static_analysis" => "Static analysis",
        "taint_analysis" => "Taint analysis",
        "config_scan" => "Config scan",
        "hunt" => "Hunt",
        "vidarr" => "Víðarr",
        "garmr" => "Garmr",
        "report" => "Report",
        _ => "Stage",
    }
}
