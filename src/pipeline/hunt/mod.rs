//
//  heimdall
//  src/pipeline/hunt/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod agent;
pub mod tools;

use std::sync::Arc;

use log::info;

use crate::ai::ModelProvider;
use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::HeimdallResult;
use crate::pipeline::tyr::ThreatModelOutput;

/// Hunt: The agentic vulnerability discovery stage.
/// Deploys AI agents to iteratively investigate potential vulnerabilities.
pub struct HuntStage {
    pub scan_id: uuid::Uuid,
    pub repo_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
    pub ai: Arc<dyn ModelProvider>,
    pub default_model: String,
}

impl HuntStage {
    pub fn new(
        scan_id: uuid::Uuid,
        repo_id: uuid::Uuid,
        db: Arc<DatabaseOperations>,
        ai: Arc<dyn ModelProvider>,
        default_model: String,
    ) -> Self {
        Self {
            scan_id,
            repo_id,
            db,
            ai,
            default_model,
        }
    }

    /// Run hunt agents for each attack surface from the threat model.
    /// Runs investigations concurrently via tokio::spawn.
    pub async fn run(
        &self,
        index: Arc<CodeIndex>,
        threat_model: &ThreatModelOutput,
        static_context: &str,
    ) -> HeimdallResult<usize> {
        info!(
            "[{}] Starting Hunt stage: {} attack surfaces to investigate",
            self.scan_id,
            threat_model.surfaces.len()
        );

        let mut handles = Vec::new();

        for surface in &threat_model.surfaces {
            let scan_id = self.scan_id;
            let repo_id = self.repo_id;
            let db = Arc::clone(&self.db);
            let ai = Arc::clone(&self.ai);
            let model = self.default_model.clone();
            let index = Arc::clone(&index);
            let surface = surface.clone();
            let ctx = static_context.to_string();

            let handle = tokio::spawn(async move {
                let mut agent = agent::HuntAgent::new(scan_id, repo_id, db, ai, model);
                agent.investigate(&surface, &index, &ctx).await
            });
            handles.push(handle);
        }

        let mut total_findings = 0usize;
        for handle in handles {
            match handle.await {
                Ok(Ok(findings)) => {
                    total_findings += findings.len();
                }
                Ok(Err(e)) => {
                    log::warn!("[{}] Hunt agent error: {e}", self.scan_id);
                }
                Err(e) => {
                    log::warn!("[{}] Hunt agent task panicked: {e}", self.scan_id);
                }
            }
        }

        info!(
            "[{}] Hunt stage complete: {total_findings} findings from {} surfaces",
            self.scan_id,
            threat_model.surfaces.len()
        );

        Ok(total_findings)
    }
}
