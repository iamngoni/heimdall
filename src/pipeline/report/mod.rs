//
//  heimdall
//  src/pipeline/report/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::{Arc, LazyLock};

use log::{info, warn};
use regex::Regex;

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
        self.record_event(
            Some("patch-generation"),
            "running",
            "Generating remediation patches",
            Some("Producing suggested patches and remediation artifacts for recorded findings."),
            None,
            Some(&serde_json::json!({
                "findings": findings.len(),
            })),
        )
        .await;

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
        self.record_event(
            Some("patch-generation"),
            "completed",
            "Remediation artifacts ready",
            Some("Patch generation and finding enrichment completed."),
            Some(100),
            None,
        )
        .await;

        info!("[{}] Report stage complete", self.scan_id);
        Ok(())
    }

    /// Generate a suggested patch for a finding.
    async fn generate_patch(&self, finding: &Finding, index: &CodeIndex) -> HeimdallResult<()> {
        let task_key = format!("patch-{}", finding.id);
        let start_title = format!("Generating patch for {}", finding.title);
        self.record_event(
            Some(&task_key),
            "running",
            &start_title,
            Some("Asking the model for a minimal remediation diff."),
            None,
            Some(&serde_json::json!({
                "finding_id": finding.id,
                "severity": finding.severity,
            })),
        )
        .await;
        // Get the file content for context
        let file_content = index
            .read_file(&finding.file_path)
            .unwrap_or("(file not available)");

        let context =
            extract_finding_context(file_content, finding.line_start, finding.line_end, 8, 12);

        let request = CompletionRequest {
            model: self.default_model.clone(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: "You are a security engineer generating patches for vulnerabilities. \
                              Generate a unified diff that fixes the vulnerability. \
                              The diff should be minimal, focused, and correct. \
                              Every removed or context line in the diff must already exist verbatim in the provided file. \
                              If you cannot produce a grounded diff from the provided file, return an empty string. \
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
                         **Description:** {}\n\
                         **Matched snippet:** {}\n\n\
                         **Grounded source excerpt:**\n```\n{context}\n```\n\n\
                         Only generate a diff that changes the referenced finding location or its immediate neighbors. \
                         If the grounded excerpt does not contain enough evidence for a correct fix, return an empty string.",
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
            temperature: Some(0.1),
        };

        let response = self.ai.complete(request).await?;
        let raw_patch = response.content.trim().to_string();
        let patch = if raw_patch.is_empty() {
            None
        } else if validate_patch_against_finding(&raw_patch, finding, file_content) {
            Some(raw_patch.clone())
        } else {
            warn!(
                "[{}] Discarding ungrounded patch for finding {} in {}:{}",
                self.scan_id, finding.id, finding.file_path, finding.line_start
            );
            None
        };

        if let Some(patch) = patch.as_deref() {
            // Store the patch on the finding
            self.db.update_finding_patch(finding.id, patch).await?;

            // Also create a patches row
            self.db
                .create_patch(
                    finding.id,
                    self.scan_id,
                    patch,
                    Some(&format!("Auto-generated patch for: {}", finding.title)),
                    true, // assume applies cleanly for now
                )
                .await?;
        }

        let detail = if raw_patch.is_empty() {
            "Model did not return a patch for this finding.".to_string()
        } else if patch.is_none() {
            "Model returned a diff that did not match the scanned file, so the patch was discarded."
                .to_string()
        } else {
            "Suggested remediation diff stored for review.".to_string()
        };
        let finish_title = format!("Patch generation finished for {}", finding.title);
        self.record_event(
            Some(&task_key),
            "completed",
            &finish_title,
            Some(&detail),
            None,
            Some(&serde_json::json!({
                "finding_id": finding.id,
                "has_patch": patch.is_some(),
                "patch_rejected": !raw_patch.is_empty() && patch.is_none(),
            })),
        )
        .await;

        Ok(())
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
                Some("report"),
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

fn extract_finding_context(
    file_content: &str,
    line_start: i32,
    line_end: Option<i32>,
    before: usize,
    after: usize,
) -> String {
    if file_content == "(file not available)" {
        return file_content.to_string();
    }

    let lines = file_content.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return "(file not available)".to_string();
    }

    let start = line_start.max(1) as usize;
    let end = line_end.unwrap_or(line_start).max(line_start) as usize;
    let excerpt_start = start.saturating_sub(before).max(1);
    let excerpt_end = (end + after).min(lines.len());

    (excerpt_start..=excerpt_end)
        .filter_map(|line_number| {
            lines
                .get(line_number - 1)
                .map(|line| format!("{line_number:>5} | {line}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn validate_patch_against_finding(patch: &str, finding: &Finding, file_content: &str) -> bool {
    let patch = patch.trim();
    if patch.is_empty() || file_content == "(file not available)" {
        return false;
    }

    patch_targets_file(patch, &finding.file_path)
        && patch_hunks_match_file(patch, file_content)
        && patch_touches_finding_lines(patch, finding, file_content)
}

fn patch_targets_file(patch: &str, file_path: &str) -> bool {
    let normalized_path = normalize_patch_path(file_path);
    let mut matched_old = false;
    let mut matched_new = false;

    for line in patch.lines() {
        if let Some(path) = line.strip_prefix("--- ") {
            matched_old = normalize_patch_path(path) == normalized_path;
        } else if let Some(path) = line.strip_prefix("+++ ") {
            matched_new = normalize_patch_path(path) == normalized_path;
        }
    }

    matched_old || matched_new
}

fn normalize_patch_path(path: &str) -> &str {
    path.trim()
        .trim_start_matches("a/")
        .trim_start_matches("b/")
}

fn patch_hunks_match_file(patch: &str, file_content: &str) -> bool {
    let normalized_content = file_content.replace("\r\n", "\n");
    let file_lines = normalized_content.lines().collect::<Vec<_>>();
    let hunks = extract_patch_hunks(patch);

    !hunks.is_empty()
        && hunks
            .iter()
            .all(|hunk| hunk_matches_file(&file_lines, hunk))
}

fn patch_touches_finding_lines(patch: &str, finding: &Finding, file_content: &str) -> bool {
    let normalized_content = file_content.replace("\r\n", "\n");
    let file_lines = normalized_content.lines().collect::<Vec<_>>();
    let target_start = finding.line_start.max(1) as usize;
    let target_end = finding
        .line_end
        .unwrap_or(finding.line_start)
        .max(finding.line_start) as usize;

    if target_start == 0 || target_start > file_lines.len() {
        return false;
    }

    let relevant_lines = file_lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            let line_number = idx + 1;
            (line_number >= target_start && line_number <= target_end).then_some(*line)
        })
        .collect::<Vec<_>>();

    if relevant_lines.is_empty() {
        return false;
    }

    extract_patch_hunks(patch).iter().any(|hunk| {
        let hunk_end = if hunk.old_count == 0 {
            hunk.old_start
        } else {
            hunk.old_start + hunk.old_count.saturating_sub(1)
        };
        let overlaps_target = hunk.old_start <= target_end && hunk_end >= target_start;

        overlaps_target
            && hunk
                .lines
                .iter()
                .any(|line| relevant_lines.iter().any(|target| *target == line))
    })
}

#[derive(Debug, Clone)]
struct PatchHunk {
    old_start: usize,
    old_count: usize,
    lines: Vec<String>,
}

fn extract_patch_hunks(patch: &str) -> Vec<PatchHunk> {
    let mut hunks = Vec::new();
    let mut current_hunk: Option<PatchHunk> = None;

    for line in patch.lines() {
        if line.starts_with("@@") {
            if let Some(existing) = current_hunk.take()
                && !existing.lines.is_empty()
            {
                hunks.push(existing);
            }
            let Some((old_start, old_count)) = parse_hunk_header(line) else {
                current_hunk = None;
                continue;
            };
            current_hunk = Some(PatchHunk {
                old_start,
                old_count,
                lines: Vec::new(),
            });
            continue;
        }

        let Some(hunk) = current_hunk.as_mut() else {
            continue;
        };

        if let Some(content) = line.strip_prefix(' ') {
            hunk.lines.push(content.to_string());
        } else if let Some(content) = line.strip_prefix('-') {
            hunk.lines.push(content.to_string());
        } else if line.starts_with('+') || line.starts_with('\\') {
            continue;
        }
    }

    if let Some(existing) = current_hunk
        && !existing.lines.is_empty()
    {
        hunks.push(existing);
    }

    hunks
}

fn parse_hunk_header(line: &str) -> Option<(usize, usize)> {
    static HUNK_HEADER_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@").unwrap());

    let captures = HUNK_HEADER_RE.captures(line)?;
    let old_start = captures.get(1)?.as_str().parse::<usize>().ok()?;
    let old_count = captures
        .get(2)
        .and_then(|value| value.as_str().parse::<usize>().ok())
        .unwrap_or(1);
    Some((old_start, old_count))
}

fn hunk_matches_file(file_lines: &[&str], hunk: &PatchHunk) -> bool {
    if hunk.lines.is_empty() || hunk.lines.len() > file_lines.len() {
        return false;
    }

    file_lines.windows(hunk.lines.len()).any(|window| {
        window
            .iter()
            .zip(&hunk.lines)
            .all(|(line, expected)| *line == expected)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_test_finding(file_path: &str, line_start: i32, code_snippet: &str) -> Finding {
        Finding {
            id: uuid::Uuid::nil(),
            scan_id: uuid::Uuid::nil(),
            repo_id: uuid::Uuid::nil(),
            source: "static".to_string(),
            status: "open".to_string(),
            severity: "high".to_string(),
            confidence: "medium".to_string(),
            title: "Example finding".to_string(),
            description: None,
            cwe_id: None,
            cve_id: None,
            file_path: file_path.to_string(),
            line_start,
            line_end: Some(line_start),
            code_snippet: Some(code_snippet.to_string()),
            suggested_patch: None,
            fix_type: Some("manual_review".to_string()),
            fix_summary: None,
            references_json: None,
            manifest_coordinates_json: None,
            poc_exploit_json: None,
            poc_validated: false,
            fingerprint: "fp".to_string(),
            agent_reasoning: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_validate_patch_accepts_grounded_diff() {
        let file = "const foo = 1;\nconst bar = 2;\n";
        let patch = "\
--- a/example.js\n\
+++ b/example.js\n\
@@ -1,2 +1,2 @@\n\
-const foo = 1;\n\
+const foo = process.env.FOO;\n\
 const bar = 2;\n";
        let finding = make_test_finding("example.js", 1, "const foo = 1;");

        assert!(validate_patch_against_finding(patch, &finding, file));
    }

    #[test]
    fn test_validate_patch_rejects_hallucinated_hunk() {
        let file = "app.get(\"/api/applications/failed-authorization\", async (req, res) => {\n  return res.json({ ok: true });\n});\n";
        let patch = "\
--- a/server.js\n\
+++ b/server.js\n\
@@ -1,3 +1,3 @@\n\
-const ENCRYPTION_KEY = \"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6\";\n\
+const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;\n\
 app.get(\"/api/applications/failed-authorization\", async (req, res) => {\n";
        let finding = make_test_finding(
            "server.js",
            1,
            "app.get(\"/api/applications/failed-authorization\", async (req, res) => {",
        );

        assert!(!validate_patch_against_finding(patch, &finding, file));
    }

    #[test]
    fn test_validate_patch_rejects_nearby_but_unrelated_change() {
        let file = "\
const addCondition = () => {\n\
  const newCondition = {\n\
    id: `vc_${Date.now()}`,\n\
    table: \"\",\n\
  };\n\
};\n\
const response = await fetch(\"/api/automations/available-tables\");\n";
        let patch = "\
--- a/src/components/VisibilityConditionBuilder.tsx\n\
+++ b/src/components/VisibilityConditionBuilder.tsx\n\
@@ -1,6 +1,6 @@\n\
 const addCondition = () => {\n\
   const newCondition = {\n\
-    id: `vc_${Date.now()}`,\n\
+    id: `vc_${crypto.randomUUID()}`,\n\
     table: \"\",\n\
   };\n\
 };\n";
        let finding = make_test_finding(
            "src/components/VisibilityConditionBuilder.tsx",
            7,
            "const response = await fetch(\"/api/automations/available-tables\");",
        );

        assert!(!validate_patch_against_finding(patch, &finding, file));
    }
}
