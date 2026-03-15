//
//  heimdall
//  src/pipeline/static_analysis/semgrep.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/12.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use log::{info, warn};
use sha2::{Digest, Sha256};

use crate::db::DatabaseOperations;
use crate::models::HeimdallResult;
use crate::util::sat_i32;

/// Semgrep integration for enhanced static analysis.
/// Runs semgrep as a subprocess and parses JSON output into findings.
/// Falls back gracefully if semgrep is not installed.
pub struct SemgrepStage {
    pub scan_id: uuid::Uuid,
    pub repo_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
}

impl SemgrepStage {
    pub fn new(scan_id: uuid::Uuid, repo_id: uuid::Uuid, db: Arc<DatabaseOperations>) -> Self {
        Self {
            scan_id,
            repo_id,
            db,
        }
    }

    /// Run semgrep on the given work directory. Returns count of findings created.
    pub async fn run(
        &self,
        work_dir: &Path,
        existing_fingerprints: &HashSet<String>,
    ) -> HeimdallResult<usize> {
        // Check if semgrep is available
        if !self.semgrep_available().await {
            info!(
                "[{}] Semgrep not installed — skipping enhanced analysis",
                self.scan_id
            );
            return Ok(0);
        }

        info!("[{}] Running semgrep scan", self.scan_id);

        let output = tokio::process::Command::new("semgrep")
            .args([
                "scan",
                "--json",
                "--config",
                "auto",
                "--quiet",
                "--timeout",
                "120",
            ])
            .arg(work_dir)
            .output()
            .await;

        let output = match output {
            Ok(o) => o,
            Err(e) => {
                warn!("[{}] Failed to execute semgrep: {e}", self.scan_id);
                return Ok(0);
            }
        };

        // Semgrep may exit with non-zero even on partial success
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.is_empty() {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(
                    "[{}] Semgrep exited with {}: {}",
                    self.scan_id,
                    output.status,
                    stderr.chars().take(500).collect::<String>()
                );
            }
            return Ok(0);
        }

        let parsed: SemgrepOutput = match serde_json::from_str(&stdout) {
            Ok(p) => p,
            Err(e) => {
                warn!("[{}] Failed to parse semgrep output: {e}", self.scan_id);
                return Ok(0);
            }
        };

        let mut count = 0usize;
        let work_dir_str = work_dir.to_string_lossy();

        for result in &parsed.results {
            // Normalize path relative to work_dir
            let rel_path = result
                .path
                .strip_prefix(work_dir_str.as_ref())
                .unwrap_or(&result.path)
                .trim_start_matches('/');

            let line = sat_i32(result.start.line as u64);
            let fingerprint = make_semgrep_fingerprint(&result.check_id, rel_path, line);

            // Deduplicate against existing findings
            if existing_fingerprints.contains(&fingerprint) {
                continue;
            }

            let severity = map_semgrep_severity(&result.extra.severity);
            let confidence = map_semgrep_confidence(
                result
                    .extra
                    .metadata
                    .as_ref()
                    .and_then(|m| m.confidence.as_deref()),
            );

            let cwe = result
                .extra
                .metadata
                .as_ref()
                .and_then(|m| m.cwe.as_ref())
                .and_then(|cwes| cwes.first())
                .map(|s| s.as_str());

            let title = format!(
                "[semgrep:{}] {}",
                result.check_id,
                result.extra.message.chars().take(200).collect::<String>()
            );

            let _ = self
                .db
                .create_finding_full(
                    self.scan_id,
                    self.repo_id,
                    "static",
                    &severity,
                    &confidence,
                    &title,
                    Some(&result.extra.message),
                    cwe,
                    rel_path,
                    line,
                    Some(sat_i32(result.end.line as u64)),
                    None,
                    &fingerprint,
                    None,
                )
                .await;

            count += 1;
        }

        info!(
            "[{}] Semgrep found {} new findings ({} total results, {} deduplicated)",
            self.scan_id,
            count,
            parsed.results.len(),
            parsed.results.len() - count,
        );

        Ok(count)
    }

    async fn semgrep_available(&self) -> bool {
        tokio::process::Command::new("which")
            .arg("semgrep")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

fn map_semgrep_severity(severity: &str) -> String {
    match severity.to_uppercase().as_str() {
        "ERROR" => "high".to_string(),
        "WARNING" => "medium".to_string(),
        "INFO" => "low".to_string(),
        _ => "medium".to_string(),
    }
}

fn map_semgrep_confidence(confidence: Option<&str>) -> String {
    match confidence {
        Some(c) if c.eq_ignore_ascii_case("HIGH") => "high".to_string(),
        Some(c) if c.eq_ignore_ascii_case("MEDIUM") => "medium".to_string(),
        Some(c) if c.eq_ignore_ascii_case("LOW") => "low".to_string(),
        _ => "medium".to_string(),
    }
}

fn make_semgrep_fingerprint(check_id: &str, file: &str, line: i32) -> String {
    let input = format!("semgrep:{check_id}:{file}:{line}");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Semgrep JSON output types
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct SemgrepOutput {
    #[serde(default)]
    results: Vec<SemgrepResult>,
}

#[derive(serde::Deserialize)]
struct SemgrepResult {
    check_id: String,
    path: String,
    start: SemgrepPosition,
    end: SemgrepPosition,
    extra: SemgrepExtra,
}

#[derive(serde::Deserialize)]
struct SemgrepPosition {
    line: u32,
    #[allow(dead_code)]
    col: u32,
}

#[derive(serde::Deserialize)]
struct SemgrepExtra {
    message: String,
    severity: String,
    #[serde(default)]
    metadata: Option<SemgrepMetadata>,
}

#[derive(serde::Deserialize)]
struct SemgrepMetadata {
    #[serde(default)]
    cwe: Option<Vec<String>>,
    #[serde(default)]
    confidence: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_severity() {
        assert_eq!(map_semgrep_severity("ERROR"), "high");
        assert_eq!(map_semgrep_severity("WARNING"), "medium");
        assert_eq!(map_semgrep_severity("INFO"), "low");
        assert_eq!(map_semgrep_severity("unknown"), "medium");
    }

    #[test]
    fn test_map_confidence() {
        assert_eq!(map_semgrep_confidence(Some("HIGH")), "high");
        assert_eq!(map_semgrep_confidence(Some("MEDIUM")), "medium");
        assert_eq!(map_semgrep_confidence(Some("LOW")), "low");
        assert_eq!(map_semgrep_confidence(None), "medium");
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let fp1 = make_semgrep_fingerprint("rule-id", "file.py", 10);
        let fp2 = make_semgrep_fingerprint("rule-id", "file.py", 10);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_parse_semgrep_output() {
        let json = r#"{
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval-detected",
                    "path": "/tmp/scan/app.py",
                    "start": {"line": 10, "col": 5},
                    "end": {"line": 10, "col": 30},
                    "extra": {
                        "message": "Detected use of eval(). This is dangerous.",
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": ["CWE-95"],
                            "confidence": "HIGH"
                        }
                    }
                }
            ]
        }"#;

        let parsed: SemgrepOutput = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.results.len(), 1);
        assert_eq!(
            parsed.results[0].check_id,
            "python.lang.security.audit.eval-detected"
        );
        assert_eq!(parsed.results[0].extra.severity, "ERROR");
    }
}
