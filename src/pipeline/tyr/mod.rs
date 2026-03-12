//
//  heimdall
//  src/pipeline/tyr/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use log::info;
use serde::{Deserialize, Serialize};

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, Message};
use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::HeimdallResult;

/// Tyr: The threat model engine. Analyses the codebase to identify
/// attack surfaces, trust boundaries, data flows, and risk ratings.
pub struct TyrStage {
    pub scan_id: uuid::Uuid,
    pub repo_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
    pub ai: Arc<dyn ModelProvider>,
    pub default_model: String,
}

/// The structured threat model produced by Tyr.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModelOutput {
    pub summary: String,
    pub boundaries: Vec<TrustBoundary>,
    pub surfaces: Vec<AttackSurface>,
    pub data_flows: Vec<DataFlow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBoundary {
    pub name: String,
    pub description: String,
    pub from_zone: String,
    pub to_zone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurface {
    pub name: String,
    pub description: String,
    pub endpoint: Option<String>,
    pub file: Option<String>,
    pub line: Option<usize>,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlow {
    pub name: String,
    pub description: String,
    pub source: String,
    pub sink: String,
    pub sensitive_data: String,
}

impl TyrStage {
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

    pub async fn run(&self, index: &CodeIndex) -> HeimdallResult<ThreatModelOutput> {
        info!("[{}] Starting Tyr threat model generation", self.scan_id);
        self.record_event(
            Some("repo-summary"),
            "running",
            "Summarizing repository structure",
            Some("Collecting enough codebase context to identify trust boundaries and attack surfaces."),
            None,
            None,
        )
        .await;

        let code_summary = index.summary_for_llm(12000);
        self.record_event(
            Some("repo-summary"),
            "completed",
            "Repository summary ready",
            Some("Codebase context prepared for the threat-model request."),
            Some(25),
            Some(&serde_json::json!({
                "summary_bytes": code_summary.len(),
            })),
        )
        .await;

        let system_prompt = TYR_SYSTEM_PROMPT;
        let user_prompt = format!(
            "Analyze the following codebase and generate a threat model.\n\n\
             {code_summary}\n\n\
             Respond with a JSON object matching this schema:\n\
             {{\n\
               \"summary\": \"string — what this application does and its security posture\",\n\
               \"boundaries\": [{{\"name\": \"string\", \"description\": \"string\", \"from_zone\": \"string\", \"to_zone\": \"string\"}}],\n\
               \"surfaces\": [{{\"name\": \"string\", \"description\": \"string\", \"endpoint\": \"optional string\", \"file\": \"optional string\", \"line\": null, \"risk_level\": \"critical|high|medium|low\"}}],\n\
               \"data_flows\": [{{\"name\": \"string\", \"description\": \"string\", \"source\": \"string\", \"sink\": \"string\", \"sensitive_data\": \"string\"}}]\n\
             }}\n\n\
             Return ONLY the JSON object, no markdown fences."
        );

        let request = CompletionRequest {
            model: self.default_model.clone(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: user_prompt,
                },
            ],
            tools: None,
            max_tokens: Some(4096),
            temperature: Some(0.2),
        };

        self.record_event(
            Some("threat-model-request"),
            "running",
            "Generating threat model",
            Some("Tyr is reasoning about trust boundaries, attack surfaces, and sensitive data flows."),
            None,
            Some(&serde_json::json!({
                "model": self.default_model,
            })),
        )
        .await;
        let start = std::time::Instant::now();
        let response = self.ai.complete(request).await?;
        let duration = start.elapsed();

        // Log the LLM call
        let _ = self
            .db
            .create_agent_tool_call(
                self.scan_id,
                "tyr",
                "llm_completion",
                Some(&response.provider),
                Some(&response.model),
                None,
                None,
                Some(response.usage.prompt_tokens as i32),
                Some(response.usage.completion_tokens as i32),
                Some(response.usage.total_tokens as i32),
                Some(duration.as_millis() as i32),
                None,
            )
            .await;

        // Parse the structured response
        let content = response.content.trim();
        // Strip markdown fences if present
        let json_str = if content.starts_with("```") {
            content
                .trim_start_matches("```json")
                .trim_start_matches("```")
                .trim_end_matches("```")
                .trim()
        } else {
            content
        };

        let threat_model: ThreatModelOutput = serde_json::from_str(json_str).map_err(|e| {
            anyhow::anyhow!("Failed to parse Tyr threat model response: {e}\nRaw: {json_str}")
        })?;
        self.record_event(
            Some("threat-model-request"),
            "completed",
            "Threat model generated",
            Some("Tyr returned a structured threat model ready to store."),
            Some(80),
            Some(&serde_json::json!({
                "surfaces": threat_model.surfaces.len(),
                "boundaries": threat_model.boundaries.len(),
                "data_flows": threat_model.data_flows.len(),
                "duration_ms": duration.as_millis() as i32,
            })),
        )
        .await;

        // Store in DB
        let boundaries_json = serde_json::to_value(&threat_model.boundaries)?;
        let surfaces_json = serde_json::to_value(&threat_model.surfaces)?;
        let data_flows_json = serde_json::to_value(&threat_model.data_flows)?;

        self.record_event(
            Some("threat-model-store"),
            "running",
            "Persisting threat model",
            Some("Writing structured threat-model artifacts to the database."),
            None,
            None,
        )
        .await;

        self.db
            .create_threat_model(
                self.scan_id,
                self.repo_id,
                Some(&threat_model.summary),
                Some(&boundaries_json),
                Some(&surfaces_json),
                Some(&data_flows_json),
            )
            .await?;
        self.record_event(
            Some("threat-model-store"),
            "completed",
            "Threat model stored",
            Some("Threat-model artifacts are available for downstream stages and review."),
            Some(100),
            None,
        )
        .await;

        info!(
            "[{}] Tyr complete: {} boundaries, {} surfaces, {} data flows",
            self.scan_id,
            threat_model.boundaries.len(),
            threat_model.surfaces.len(),
            threat_model.data_flows.len(),
        );

        Ok(threat_model)
    }

    async fn record_event(
        &self,
        task_key: Option<&str>,
        status: &str,
        title: &str,
        detail: Option<&str>,
        progress_pct: Option<i32>,
        metadata_json: Option<&serde_json::Value>,
    ) {
        let _ = self
            .db
            .create_scan_event(
                self.scan_id,
                Some("tyr"),
                task_key,
                "task",
                Some(status),
                title,
                detail,
                progress_pct,
                metadata_json,
            )
            .await;
    }
}

const TYR_SYSTEM_PROMPT: &str = "\
You are Tyr, the threat model engine of Heimdall security scanner. \
Your role is to analyze a codebase's structure and produce a structured threat model.

You must identify:
1. **Trust boundaries** — where data crosses from one trust zone to another \
   (e.g., public internet → API server, API server → database)
2. **Attack surfaces** — endpoints, file upload handlers, auth mechanisms, \
   deserialization points, and any code reachable by untrusted input
3. **Data flows** — how sensitive data (credentials, PII, tokens, secrets) \
   moves through the system

Focus on actionable, concrete threats rather than theoretical concerns. \
Prioritize surfaces that handle user input, authentication, authorization, \
file I/O, and external service communication.

Risk levels should be: critical, high, medium, or low.";
