//
//  heimdall
//  src/pipeline/report/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use log::info;

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, Message};
use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::HeimdallResult;
use crate::models::db_models::Finding;

/// Final report generation stage. Generates patches and enriches findings.
pub struct ReportStage {
    pub scan_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
    pub ai: Arc<dyn ModelProvider>,
    pub default_model: String,
}

impl ReportStage {
    pub fn new(
        scan_id: uuid::Uuid,
        db: Arc<DatabaseOperations>,
        ai: Arc<dyn ModelProvider>,
        default_model: String,
    ) -> Self {
        Self {
            scan_id,
            db,
            ai,
            default_model,
        }
    }

    /// Generate patches and enrich all findings for a scan.
    pub async fn run(&self, findings: &[Finding], index: &CodeIndex) -> HeimdallResult<()> {
        info!(
            "[{}] Starting Report stage: {} findings to enrich",
            self.scan_id,
            findings.len()
        );

        for finding in findings {
            // Generate a suggested patch
            if let Err(e) = self.generate_patch(finding, index).await {
                log::warn!(
                    "[{}] Failed to generate patch for finding {}: {e}",
                    self.scan_id,
                    finding.id
                );
            }
        }

        // Update scan counts
        self.db.update_scan_counts(self.scan_id).await?;

        info!("[{}] Report stage complete", self.scan_id);
        Ok(())
    }

    /// Generate a suggested patch for a finding.
    async fn generate_patch(&self, finding: &Finding, index: &CodeIndex) -> HeimdallResult<()> {
        // Get the file content for context
        let file_content = index
            .read_file(&finding.file_path)
            .unwrap_or("(file not available)");

        // Truncate for LLM context
        let context = if file_content.len() > 10000 {
            &file_content[..10000]
        } else {
            file_content
        };

        let request = CompletionRequest {
            model: self.default_model.clone(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: "You are a security engineer generating patches for vulnerabilities. \
                              Generate a unified diff that fixes the vulnerability. \
                              The diff should be minimal, focused, and correct. \
                              Output ONLY the unified diff — no explanation, no markdown fences."
                        .to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: format!(
                        "Generate a patch for this vulnerability:\n\n\
                         **Title:** {}\n\
                         **Severity:** {}\n\
                         **File:** {}\n\
                         **Line:** {}\n\
                         **Description:** {}\n\n\
                         **File content:**\n```\n{context}\n```",
                        finding.title,
                        finding.severity,
                        finding.file_path,
                        finding.line_start,
                        finding.description.as_deref().unwrap_or("N/A"),
                    ),
                },
            ],
            tools: None,
            max_tokens: Some(2048),
            temperature: Some(0.1),
        };

        let response = self.ai.complete(request).await?;
        let patch = response.content.trim().to_string();

        if !patch.is_empty() {
            // Store the patch on the finding
            self.db.update_finding_patch(finding.id, &patch).await?;

            // Also create a patches row
            self.db
                .create_patch(
                    finding.id,
                    self.scan_id,
                    &patch,
                    Some(&format!("Auto-generated patch for: {}", finding.title)),
                    true, // assume applies cleanly for now
                )
                .await?;
        }

        Ok(())
    }
}
