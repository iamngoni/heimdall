//
//  heimdall
//  src/pipeline/config_scan/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/12.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

mod rules;

use std::sync::Arc;

use log::info;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::HeimdallResult;

use rules::CONFIG_RULES;

/// Context returned from config/IaC scanning.
pub struct ConfigScanContext {
    pub findings_count: usize,
    pub summary: String,
}

/// Config/IaC scanning stage — detects misconfigurations in Dockerfiles,
/// Kubernetes manifests, Terraform files, CI/CD configs, and environment files.
pub struct ConfigScanStage {
    pub scan_id: uuid::Uuid,
    pub repo_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
}

impl ConfigScanStage {
    pub fn new(scan_id: uuid::Uuid, repo_id: uuid::Uuid, db: Arc<DatabaseOperations>) -> Self {
        Self {
            scan_id,
            repo_id,
            db,
        }
    }

    pub async fn run(&self, index: &CodeIndex) -> HeimdallResult<ConfigScanContext> {
        info!("[{}] Starting config/IaC scan", self.scan_id);

        let mut total_findings = 0usize;

        self.record_event(
            Some("config-scan"),
            "running",
            "Scanning configuration and infrastructure files",
            Some("Checking Dockerfiles, Kubernetes manifests, Terraform, CI/CD configs, and environment files for misconfigurations."),
            None,
            None,
        )
        .await;

        for (file_path, indexed_file) in &index.files {
            let file_name = std::path::Path::new(file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            for rule in CONFIG_RULES {
                if !file_matches_patterns(file_path, file_name, rule.file_patterns) {
                    continue;
                }

                let re = match Regex::new(rule.pattern) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                // For whole-file checks (negative patterns), check once
                if rule.whole_file {
                    if !re.is_match(&indexed_file.content) {
                        let fingerprint =
                            make_fingerprint(rule.name, file_path, 1);
                        let _ = self
                            .db
                            .create_finding_full(
                                self.scan_id,
                                self.repo_id,
                                "config",
                                rule.severity,
                                "high",
                                &format!("[{}] {}", rule.cwe, rule.description),
                                Some(rule.description),
                                Some(rule.cwe),
                                file_path,
                                1,
                                None,
                                None,
                                &fingerprint,
                                None,
                            )
                            .await;
                        total_findings += 1;
                    }
                    continue;
                }

                // Line-by-line matching
                for (line_idx, line) in indexed_file.content.lines().enumerate() {
                    if re.is_match(line) {
                        let line_num = (line_idx + 1) as i32;
                        let snippet = extract_snippet(&indexed_file.content, line_idx, 2);
                        let fingerprint = make_fingerprint(rule.name, file_path, line_num);

                        let _ = self
                            .db
                            .create_finding_full(
                                self.scan_id,
                                self.repo_id,
                                "config",
                                rule.severity,
                                "high",
                                &format!("[{}] {}", rule.cwe, rule.description),
                                Some(rule.description),
                                Some(rule.cwe),
                                file_path,
                                line_num,
                                Some(line_num),
                                Some(&snippet),
                                &fingerprint,
                                None,
                            )
                            .await;

                        total_findings += 1;
                    }
                }
            }
        }

        self.record_event(
            Some("config-scan"),
            "completed",
            "Config/IaC scan finished",
            Some(&format!(
                "{total_findings} configuration findings recorded."
            )),
            Some(100),
            Some(&serde_json::json!({
                "findings": total_findings,
            })),
        )
        .await;

        let summary = if total_findings > 0 {
            format!("{total_findings} config/IaC findings")
        } else {
            "No config/IaC findings.".to_string()
        };

        info!(
            "[{}] Config/IaC scan complete: {total_findings} findings",
            self.scan_id
        );

        Ok(ConfigScanContext {
            findings_count: total_findings,
            summary,
        })
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
                Some("config_scan"),
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

/// Check if a file path matches any of the given patterns.
fn file_matches_patterns(file_path: &str, file_name: &str, patterns: &[&str]) -> bool {
    for pattern in patterns {
        if pattern.starts_with("*.") {
            // Extension match
            let ext = &pattern[1..]; // e.g. ".yml"
            if file_path.ends_with(ext) || file_name.ends_with(ext) {
                return true;
            }
        } else if pattern.contains('/') {
            // Path component match
            if file_path.contains(pattern) {
                return true;
            }
        } else {
            // Exact filename match
            if file_name == *pattern {
                return true;
            }
        }
    }
    false
}

fn extract_snippet(content: &str, center_line: usize, context: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = center_line.saturating_sub(context);
    let end = std::cmp::min(center_line + context + 1, lines.len());
    lines[start..end].join("\n")
}

fn make_fingerprint(rule: &str, file: &str, line: i32) -> String {
    let input = format!("config:{rule}:{file}:{line}");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_matches_extension() {
        assert!(file_matches_patterns("deploy/app.yml", "app.yml", &["*.yml", "*.yaml"]));
        assert!(file_matches_patterns("k8s/deployment.yaml", "deployment.yaml", &["*.yml", "*.yaml"]));
        assert!(!file_matches_patterns("src/main.rs", "main.rs", &["*.yml", "*.yaml"]));
    }

    #[test]
    fn test_file_matches_exact_name() {
        assert!(file_matches_patterns("app/Dockerfile", "Dockerfile", &["Dockerfile"]));
        assert!(!file_matches_patterns("app/main.py", "main.py", &["Dockerfile"]));
    }

    #[test]
    fn test_file_matches_path_component() {
        assert!(file_matches_patterns(".github/workflows/ci.yml", "ci.yml", &[".github/workflows/"]));
        assert!(!file_matches_patterns("src/workflows.rs", "workflows.rs", &[".github/workflows/"]));
    }

    #[test]
    fn test_make_fingerprint_deterministic() {
        let fp1 = make_fingerprint("rule", "file", 1);
        let fp2 = make_fingerprint("rule", "file", 1);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_config_rules_all_compile() {
        for rule in CONFIG_RULES {
            let result = Regex::new(rule.pattern);
            assert!(
                result.is_ok(),
                "Config rule '{}' has invalid regex: {}",
                rule.name,
                rule.pattern,
            );
        }
    }
}
