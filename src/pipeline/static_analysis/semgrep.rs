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

use anyhow::{Context, anyhow};
use log::info;
use sha2::{Digest, Sha256};

use crate::config::SemgrepConfig;
use crate::db::DatabaseOperations;
use crate::models::{FindingEvidence, FindingFixType, HeimdallResult};
use crate::util::sat_i32;

/// Semgrep integration for enhanced static analysis.
///
/// Semgrep is a required runtime dependency — [`SemgrepConfig::from_env`]
/// verifies the binary at startup. This stage never silently degrades; if the
/// scan fails mid-flight the error is surfaced to the pipeline which records a
/// `failed` scan event so operators can see degraded coverage.
pub struct SemgrepStage {
    pub scan_id: uuid::Uuid,
    pub repo_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
    pub config: SemgrepConfig,
}

impl SemgrepStage {
    pub fn new(
        scan_id: uuid::Uuid,
        repo_id: uuid::Uuid,
        db: Arc<DatabaseOperations>,
        config: SemgrepConfig,
    ) -> Self {
        Self {
            scan_id,
            repo_id,
            db,
            config,
        }
    }

    /// Run semgrep on the given work directory. Returns count of findings created.
    pub async fn run(
        &self,
        work_dir: &Path,
        existing_fingerprints: &HashSet<String>,
    ) -> HeimdallResult<usize> {
        info!(
            "[{}] Running semgrep scan (config={}, timeout={}s)",
            self.scan_id, self.config.config, self.config.timeout_seconds
        );

        let timeout_str = self.config.timeout_seconds.to_string();
        let output = tokio::process::Command::new(&self.config.binary_path)
            .args([
                "scan",
                "--json",
                "--config",
                &self.config.config,
                "--quiet",
                "--timeout",
                &timeout_str,
            ])
            .arg(work_dir)
            .output()
            .await
            .with_context(|| {
                format!(
                    "Failed to invoke semgrep at `{}` — binary was available at startup but is \
                     no longer executable. Check container /tmp cleanup or PATH changes.",
                    self.config.binary_path
                )
            })?;

        // Semgrep exits non-zero on findings or partial failures; the JSON body
        // is still the authoritative result. Only treat empty stdout + non-zero
        // as a hard failure (it means semgrep crashed before producing output).
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.is_empty() {
            if output.status.success() {
                info!("[{}] Semgrep produced no output", self.scan_id);
                return Ok(0);
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "Semgrep exited with {} and no output. stderr: {}",
                output.status,
                stderr.chars().take(500).collect::<String>()
            ));
        }

        let parsed: SemgrepOutput = serde_json::from_str(&stdout)
            .context("Failed to parse semgrep JSON output — semgrep version may be incompatible")?;

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

            let metadata = result.extra.metadata.as_ref();
            let cwe = metadata
                .and_then(|m| m.cwe.as_ref())
                .and_then(|cwes| cwes.first())
                .map(|s| s.as_str());

            let title = format!(
                "[semgrep:{}] {}",
                result.check_id,
                result.extra.message.chars().take(200).collect::<String>()
            );

            // Prefer semgrep's autofix (`fix` or `fix_regex`) when present; fall
            // back to a plain-text suggestion derived from the rule message.
            let suggested_patch = result
                .extra
                .fix
                .clone()
                .or_else(|| result.extra.fix_regex.as_ref().map(|fr| fr.replacement.clone()));

            let fix_summary = suggested_patch
                .as_ref()
                .map(|_| format!("Apply the semgrep-suggested fix for rule `{}`.", result.check_id))
                .unwrap_or_else(|| {
                    format!(
                        "Review the code against the `{}` rule and apply the guidance in the finding description.",
                        result.check_id
                    )
                });

            let references = metadata
                .and_then(|m| m.references.clone())
                .unwrap_or_default();

            let evidence = FindingEvidence {
                code_snippet: Some(result.extra.lines.clone().unwrap_or_default()),
                suggested_patch,
                fix_type: FindingFixType::CodeChange,
                fix_summary: Some(fix_summary),
                references,
                manifest_coordinates: None,
            };

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
                    &fingerprint,
                    None,
                    &evidence,
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
    /// The matched source lines from the target file. Semgrep includes this in
    /// every result — we use it as the vulnerable code snippet so every finding
    /// has concrete evidence attached.
    #[serde(default)]
    lines: Option<String>,
    /// Autofix replacement text — when the rule author supplied a `fix:` block.
    #[serde(default)]
    fix: Option<String>,
    /// Autofix via regex — some rules use `fix-regex:` instead of `fix:`.
    #[serde(default)]
    fix_regex: Option<SemgrepFixRegex>,
    #[serde(default)]
    metadata: Option<SemgrepMetadata>,
}

#[derive(serde::Deserialize)]
struct SemgrepFixRegex {
    /// Replacement string (after regex substitution).
    #[serde(alias = "regex")]
    replacement: String,
}

#[derive(serde::Deserialize)]
struct SemgrepMetadata {
    #[serde(default)]
    cwe: Option<Vec<String>>,
    #[serde(default)]
    confidence: Option<String>,
    /// External references (OWASP links, CVE records, blog posts) bundled with
    /// semgrep rules. Surfaced on findings so operators can read background.
    #[serde(default)]
    references: Option<Vec<String>>,
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
