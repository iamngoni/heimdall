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
use crate::models::{FindingEvidence, HeimdallResult};
use crate::util::sat_i32_usize;

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
                        let fingerprint = make_fingerprint(rule.name, file_path, 1);
                        let (snippet, line_end) = leading_excerpt(&indexed_file.content, 12);
                        let evidence = build_config_evidence(rule, file_path, snippet);
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
                                line_end,
                                &fingerprint,
                                None,
                                &evidence,
                            )
                            .await;
                        total_findings += 1;
                    }
                    continue;
                }

                // Line-by-line matching
                for (line_idx, line) in indexed_file.content.lines().enumerate() {
                    if re.is_match(line) {
                        let line_num = sat_i32_usize(line_idx + 1);
                        let snippet = extract_snippet(&indexed_file.content, line_idx, 2);
                        let fingerprint = make_fingerprint(rule.name, file_path, line_num);
                        let evidence = build_config_evidence(rule, file_path, snippet);

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
                                &fingerprint,
                                None,
                                &evidence,
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

fn leading_excerpt(content: &str, max_lines: usize) -> (String, Option<i32>) {
    let lines = content.lines().take(max_lines).collect::<Vec<_>>();
    if lines.is_empty() {
        return (String::new(), None);
    }

    (
        lines.join("\n"),
        Some(lines.len() as i32),
    )
}

fn build_config_evidence(
    rule: &rules::ConfigRule,
    file_path: &str,
    snippet: String,
) -> FindingEvidence {
    FindingEvidence::config_change(
        snippet,
        config_fix_guidance(rule, file_path),
        config_fix_summary(rule),
    )
    .with_references([cwe_reference(rule.cwe)])
}

fn config_fix_summary(rule: &rules::ConfigRule) -> String {
    match rule.name {
        name if name.contains("secret") || name.contains("credentials") => {
            "Move the secret out of configuration, rotate it, and load it from a secret store."
                .to_string()
        }
        name if name.contains("latest") || name.contains("unpinned") => {
            "Pin the mutable dependency reference to a specific version or immutable digest."
                .to_string()
        }
        name if name.contains("root") || name.contains("privileged") => {
            "Drop privileges and run the workload with the minimum permissions it actually needs."
                .to_string()
        }
        name if name.contains("wildcard")
            || name.contains("wide-open")
            || name.contains("permissions-write-all")
            || name.contains("host-network")
            || name.contains("host-pid") =>
        {
            "Tighten the exposed security boundary to the minimum allow-list required."
                .to_string()
        }
        name if name.contains("debug") => {
            "Disable debug / development behavior in production configuration.".to_string()
        }
        name if name.contains("no-tls") => {
            "Re-enable TLS verification and trust only expected certificates.".to_string()
        }
        name if name.contains("healthcheck") => {
            "Add a health check so orchestration can detect unhealthy instances.".to_string()
        }
        name if name.contains("resource-limits") => {
            "Define CPU and memory requests/limits for the workload.".to_string()
        }
        _ => format!("Update this configuration to address: {}.", rule.description),
    }
}

fn config_fix_guidance(rule: &rules::ConfigRule, file_path: &str) -> String {
    match rule.name {
        name if name.contains("secret") || name.contains("credentials") => format!(
            "// {}\n// 1. Remove the hardcoded credential from `{}`.\n// 2. Rotate the exposed value.\n// 3. Load it from a secret manager or runtime environment variable.\n// 4. Keep only the variable NAME in config templates, never the secret VALUE.",
            rule.description, file_path
        ),
        name if name.contains("latest") => format!(
            "// {}\n// Replace the mutable `:latest` tag with an explicit version or digest.\n// Example: `image: my-service:1.24.3` or `image: my-service@sha256:<digest>`.",
            rule.description
        ),
        name if name.contains("unpinned-action") => format!(
            "// {}\n// Replace tag-based GitHub Action references with a full commit SHA.\n// Example:\n//   uses: actions/checkout@v4\n// becomes\n//   uses: actions/checkout@<40-char commit SHA>",
            rule.description
        ),
        name if name.contains("root") || name.contains("privileged") => format!(
            "// {}\n// Add an explicit non-root runtime user or securityContext.\n// Examples:\n//   Dockerfile: `USER 10001`\n//   Kubernetes: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`",
            rule.description
        ),
        name if name.contains("wildcard")
            || name.contains("wide-open")
            || name.contains("permissions-write-all")
            || name.contains("host-network")
            || name.contains("host-pid") =>
        {
            format!(
                "// {}\n// Replace the broad setting with an explicit allow-list or disable the host-level escape hatch.\n// Keep only the minimum privileges / CIDRs / origins / permissions required for the workload.",
                rule.description
            )
        }
        name if name.contains("debug") => format!(
            "// {}\n// Set the production-safe value instead.\n// Examples:\n//   DEBUG=false\n//   FLASK_DEBUG=0\n//   NODE_ENV=production",
            rule.description
        ),
        name if name.contains("no-tls") => format!(
            "// {}\n// Re-enable certificate validation.\n// Examples:\n//   SSL_VERIFY=true\n//   TLS_VERIFY=true\n//   VERIFY_SSL=true",
            rule.description
        ),
        name if name.contains("healthcheck") => format!(
            "// {}\n// Add a liveness / readiness probe or Docker HEALTHCHECK that exercises a cheap application endpoint.",
            rule.description
        ),
        name if name.contains("npm-install") => format!(
            "// {}\n// In CI, prefer `npm ci` so installs are reproducible and locked to package-lock.json.",
            rule.description
        ),
        name if name.contains("resource-limits") => format!(
            "// {}\n// Add CPU/memory requests and limits.\n// Example:\n// resources:\n//   requests:\n//     cpu: 100m\n//     memory: 128Mi\n//   limits:\n//     cpu: 500m\n//     memory: 512Mi",
            rule.description
        ),
        _ => format!(
            "// {}\n// Update the configuration in `{}` so the insecure setting is removed or the missing hardening control is added.",
            rule.description, file_path
        ),
    }
}

fn cwe_reference(cwe_id: &str) -> String {
    let numeric = cwe_id.trim_start_matches("CWE-");
    format!("https://cwe.mitre.org/data/definitions/{numeric}.html")
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
        assert!(file_matches_patterns(
            "deploy/app.yml",
            "app.yml",
            &["*.yml", "*.yaml"]
        ));
        assert!(file_matches_patterns(
            "k8s/deployment.yaml",
            "deployment.yaml",
            &["*.yml", "*.yaml"]
        ));
        assert!(!file_matches_patterns(
            "src/main.rs",
            "main.rs",
            &["*.yml", "*.yaml"]
        ));
    }

    #[test]
    fn test_file_matches_exact_name() {
        assert!(file_matches_patterns(
            "app/Dockerfile",
            "Dockerfile",
            &["Dockerfile"]
        ));
        assert!(!file_matches_patterns(
            "app/main.py",
            "main.py",
            &["Dockerfile"]
        ));
    }

    #[test]
    fn test_file_matches_path_component() {
        assert!(file_matches_patterns(
            ".github/workflows/ci.yml",
            "ci.yml",
            &[".github/workflows/"]
        ));
        assert!(!file_matches_patterns(
            "src/workflows.rs",
            "workflows.rs",
            &[".github/workflows/"]
        ));
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
