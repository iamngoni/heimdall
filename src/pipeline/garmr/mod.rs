//
//  heimdall
//  src/pipeline/garmr/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bollard::Docker;
use bollard::container::{
    Config as ContainerConfig, CreateContainerOptions, RemoveContainerOptions,
    StartContainerOptions, WaitContainerOptions,
};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, Message};
use crate::db::DatabaseOperations;
use crate::models::HeimdallResult;
use crate::models::db_models::Finding;

/// Default sandbox configuration for Garmr containers.
pub struct SandboxConfig {
    pub network_enabled: bool,
    pub cpu_limit: u32,
    pub memory_limit_bytes: u64,
    pub timeout_seconds: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            network_enabled: false,
            cpu_limit: 1,
            memory_limit_bytes: 512 * 1024 * 1024, // 512 MB
            timeout_seconds: 30,
        }
    }
}

/// PoC execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocResult {
    pub script: String,
    pub language: String,
    pub exit_code: i64,
    pub stdout: String,
    pub stderr: String,
    pub verdict: String,
    pub llm_analysis: String,
}

/// Garmr: The sandbox validation stage.
/// Runs exploit PoCs in isolated Docker containers to confirm findings.
pub struct GarmrStage {
    pub scan_id: uuid::Uuid,
    pub config: SandboxConfig,
    pub db: Arc<DatabaseOperations>,
    pub ai: Arc<dyn ModelProvider>,
    pub default_model: String,
}

impl GarmrStage {
    pub fn new(
        scan_id: uuid::Uuid,
        db: Arc<DatabaseOperations>,
        ai: Arc<dyn ModelProvider>,
        default_model: String,
    ) -> Self {
        Self {
            scan_id,
            config: SandboxConfig::default(),
            db,
            ai,
            default_model,
        }
    }

    /// Validate all findings for a scan.
    pub async fn run(&self, findings: &[Finding], repo_work_dir: &Path) -> HeimdallResult<usize> {
        info!(
            "[{}] Starting Garmr validation: {} findings to validate",
            self.scan_id,
            findings.len()
        );

        let docker = match Docker::connect_with_local_defaults() {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "[{}] Docker not available, skipping Garmr validation: {e}",
                    self.scan_id
                );
                return Ok(0);
            }
        };

        let mut validated_count = 0usize;

        for finding in findings {
            match self.validate_finding(&docker, finding, repo_work_dir).await {
                Ok(true) => validated_count += 1,
                Ok(false) => {}
                Err(e) => {
                    warn!(
                        "[{}] Garmr validation error for finding {}: {e}",
                        self.scan_id, finding.id
                    );
                }
            }
        }

        info!(
            "[{}] Garmr complete: {validated_count}/{} findings validated",
            self.scan_id,
            findings.len()
        );

        Ok(validated_count)
    }

    /// Validate a single finding by generating and executing a PoC.
    async fn validate_finding(
        &self,
        docker: &Docker,
        finding: &Finding,
        repo_work_dir: &Path,
    ) -> HeimdallResult<bool> {
        // Step 1: Generate PoC script via LLM
        let poc_script = self.generate_poc(finding).await?;

        // Step 2: Execute in sandbox
        let exec_result = self
            .execute_in_sandbox(docker, &poc_script, repo_work_dir)
            .await?;

        // Step 3: Analyze results via LLM
        let analysis = self
            .analyze_results(finding, &poc_script, &exec_result)
            .await?;

        let poc_result = PocResult {
            script: poc_script.script,
            language: poc_script.language,
            exit_code: exec_result.exit_code,
            stdout: exec_result.stdout,
            stderr: exec_result.stderr,
            verdict: analysis.verdict.clone(),
            llm_analysis: analysis.analysis,
        };

        let poc_json = serde_json::to_value(&poc_result)?;
        let confirmed = analysis.verdict == "confirmed";

        self.db
            .update_finding_poc(finding.id, confirmed, &poc_json)
            .await?;

        if confirmed {
            info!(
                "[{}] Finding {} CONFIRMED by Garmr",
                self.scan_id, finding.id
            );
        }

        Ok(confirmed)
    }

    /// Ask LLM to generate a PoC exploit script.
    async fn generate_poc(&self, finding: &Finding) -> HeimdallResult<PocScript> {
        let request = CompletionRequest {
            model: self.default_model.clone(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: "You are a security researcher generating proof-of-concept exploit scripts. \
                              Generate minimal, safe PoC scripts that demonstrate vulnerabilities. \
                              The script will run in a sandboxed Docker container with the repo mounted read-only at /repo. \
                              Output ONLY a JSON object: {\"language\": \"python|bash|node\", \"script\": \"...\"}. \
                              No markdown fences."
                        .to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: format!(
                        "Generate a PoC script for this vulnerability:\n\
                         Title: {}\n\
                         Severity: {}\n\
                         File: {}:{}\n\
                         Description: {}\n\
                         Code snippet:\n{}\n\
                         \n\
                         The repo is mounted at /repo. Generate a script that demonstrates \
                         the vulnerability exists. Use exit code 0 for success (vulnerability confirmed) \
                         and non-zero for failure.",
                        finding.title,
                        finding.severity,
                        finding.file_path,
                        finding.line_start,
                        finding.description.as_deref().unwrap_or("N/A"),
                        finding.code_snippet.as_deref().unwrap_or("N/A"),
                    ),
                },
            ],
            tools: None,
            max_tokens: Some(2048),
            temperature: Some(0.2),
        };

        let response = self.ai.complete(request).await?;

        let content = response.content.trim();
        let json_str = if content.starts_with("```") {
            content
                .trim_start_matches("```json")
                .trim_start_matches("```")
                .trim_end_matches("```")
                .trim()
        } else {
            content
        };

        let poc: PocScript = serde_json::from_str(json_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse PoC script: {e}\nRaw: {json_str}"))?;

        Ok(poc)
    }

    /// Execute a PoC script in a Docker sandbox.
    async fn execute_in_sandbox(
        &self,
        docker: &Docker,
        poc: &PocScript,
        repo_work_dir: &Path,
    ) -> HeimdallResult<ExecResult> {
        let container_name = format!("heimdall-garmr-{}", uuid::Uuid::now_v7());

        let (image, cmd) = match poc.language.as_str() {
            "python" => ("python:3.12-slim", vec!["python", "-c", &poc.script]),
            "node" => ("node:22-slim", vec!["node", "-e", &poc.script]),
            _ => ("alpine:3.19", vec!["sh", "-c", &poc.script]),
        };

        let repo_path = repo_work_dir.to_string_lossy().to_string();
        let binds = vec![format!("{repo_path}:/repo:ro")];

        let host_config = bollard::models::HostConfig {
            binds: Some(binds),
            network_mode: if self.config.network_enabled {
                None
            } else {
                Some("none".to_string())
            },
            nano_cpus: Some((self.config.cpu_limit as i64) * 1_000_000_000),
            memory: Some(self.config.memory_limit_bytes as i64),
            ..Default::default()
        };

        let config = ContainerConfig {
            image: Some(image.to_string()),
            cmd: Some(cmd.iter().map(|s| s.to_string()).collect()),
            host_config: Some(host_config),
            working_dir: Some("/repo".to_string()),
            user: Some("nobody".to_string()),
            ..Default::default()
        };

        let create_opts = CreateContainerOptions {
            name: &container_name,
            platform: None,
        };

        docker.create_container(Some(create_opts), config).await?;

        docker
            .start_container(&container_name, None::<StartContainerOptions<String>>)
            .await?;

        // Wait for completion with timeout
        let wait_result =
            tokio::time::timeout(Duration::from_secs(self.config.timeout_seconds), async {
                let mut stream =
                    docker.wait_container(&container_name, None::<WaitContainerOptions<String>>);
                stream.next().await
            })
            .await;

        let exit_code = match wait_result {
            Ok(Some(Ok(response))) => response.status_code,
            Ok(Some(Err(e))) => {
                warn!("Container wait error: {e}");
                -1
            }
            Ok(None) => -1,
            Err(_) => {
                // Timeout — kill the container
                let _ = docker.kill_container::<String>(&container_name, None).await;
                -1
            }
        };

        // Capture logs
        let log_opts = bollard::container::LogsOptions::<String> {
            stdout: true,
            stderr: true,
            ..Default::default()
        };
        let mut log_stream = docker.logs(&container_name, Some(log_opts));
        let mut stdout = String::new();
        let mut stderr = String::new();

        while let Some(Ok(output)) = log_stream.next().await {
            match output {
                bollard::container::LogOutput::StdOut { message } => {
                    stdout.push_str(&String::from_utf8_lossy(&message));
                }
                bollard::container::LogOutput::StdErr { message } => {
                    stderr.push_str(&String::from_utf8_lossy(&message));
                }
                _ => {}
            }
        }

        // Cleanup
        let _ = docker
            .remove_container(
                &container_name,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;

        // Truncate output for sanity
        stdout.truncate(10000);
        stderr.truncate(10000);

        Ok(ExecResult {
            exit_code,
            stdout,
            stderr,
        })
    }

    /// Ask LLM to analyze execution results.
    async fn analyze_results(
        &self,
        finding: &Finding,
        poc: &PocScript,
        exec: &ExecResult,
    ) -> HeimdallResult<AnalysisResult> {
        let request = CompletionRequest {
            model: self.default_model.clone(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: "You are analyzing proof-of-concept exploit execution results. \
                              Determine if the PoC successfully demonstrated the vulnerability. \
                              Output ONLY a JSON object: {\"verdict\": \"confirmed|unconfirmed|inconclusive\", \"analysis\": \"string\"}. \
                              No markdown fences."
                        .to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: format!(
                        "Vulnerability: {}\nSeverity: {}\n\n\
                         PoC Script ({}):\n{}\n\n\
                         Execution Results:\n\
                         Exit code: {}\n\
                         Stdout:\n{}\n\
                         Stderr:\n{}\n\n\
                         Did the PoC successfully demonstrate the vulnerability?",
                        finding.title,
                        finding.severity,
                        poc.language,
                        poc.script,
                        exec.exit_code,
                        exec.stdout,
                        exec.stderr,
                    ),
                },
            ],
            tools: None,
            max_tokens: Some(1024),
            temperature: Some(0.1),
        };

        let response = self.ai.complete(request).await?;
        let content = response.content.trim();
        let json_str = if content.starts_with("```") {
            content
                .trim_start_matches("```json")
                .trim_start_matches("```")
                .trim_end_matches("```")
                .trim()
        } else {
            content
        };

        let result: AnalysisResult = serde_json::from_str(json_str).unwrap_or(AnalysisResult {
            verdict: "inconclusive".to_string(),
            analysis: format!("Failed to parse LLM analysis. Raw: {content}"),
        });

        Ok(result)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PocScript {
    language: String,
    script: String,
}

#[derive(Debug)]
struct ExecResult {
    exit_code: i64,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AnalysisResult {
    verdict: String,
    analysis: String,
}
