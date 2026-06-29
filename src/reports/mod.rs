//
//  heimdall
//  src/reports/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/05/04.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

//! Per-scan PDF report.
//!
//! The flow:
//!   1. Load scan + repo + threat_model + findings + patches.
//!   2. Compute the score, OWASP categorization, and snippet windows.
//!   3. Build a serde_json::Value context and render the print-ready HTML
//!      template (`pages/scan_report.html`) via the default theme engine.
//!
//! The HTML is theme-independent — it's print-only output, so we always
//! render through the default theme's TemplateEngine regardless of the
//! viewer's preference. The browser handles PDF generation via
//! `window.print()` (no Chromium dep on the server today).

pub mod owasp;
pub mod score;
pub mod snippet;

use std::sync::Arc;

use anyhow::Context;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::db::DatabaseOperations;
use crate::models::HeimdallResult;
use crate::models::db_models::{Finding, PatchWithFilePath, Repo, Scan, ThreatModel};

/// Order severities render in: critical first, then high, medium, low.
const SEVERITY_ORDER: [&str; 4] = ["critical", "high", "medium", "low"];

/// Build the full minijinja context for a scan report, fetching all related
/// rows from the DB and shaping them into a renderable structure.
///
/// Returns `Ok(None)` when the scan is missing or doesn't belong to the user.
pub async fn build_context(
    db: &Arc<DatabaseOperations>,
    scan_id: Uuid,
    user_id: Uuid,
) -> HeimdallResult<Option<Value>> {
    let scan = match db.get_scan_by_id_for_user(scan_id, user_id).await? {
        Some(s) => s,
        None => return Ok(None),
    };
    let repo = match db.get_repo_by_id_for_user(scan.repo_id, user_id).await? {
        Some(r) => r,
        None => return Ok(None),
    };
    let threat_model = db
        .get_threat_model_by_scan_for_user(scan_id, user_id)
        .await?;

    let findings = db
        .list_findings_by_scan(scan_id, None, None)
        .await
        .context("loading findings for report")?;

    let patches = db
        .list_patches_by_scan(scan_id)
        .await
        .context("loading patches for report")?;

    Ok(Some(assemble(
        &scan,
        &repo,
        threat_model.as_ref(),
        &findings,
        &patches,
    )))
}

fn assemble(
    scan: &Scan,
    repo: &Repo,
    threat_model: Option<&ThreatModel>,
    findings: &[Finding],
    patches: &[PatchWithFilePath],
) -> Value {
    let breakdown = score::compute(findings);

    // Severity counts for the cover & findings header. We recompute from the
    // findings slice rather than trusting the scan row's denormalized counts —
    // findings can be reclassified (severity bumped, dismissed) after the
    // initial scan and the report should reflect current state.
    let (mut c, mut h, mut m, mut l) = (0u32, 0u32, 0u32, 0u32);
    for f in findings {
        if matches!(f.status.as_str(), "dismissed" | "false_positive") {
            continue;
        }
        match f.severity.as_str() {
            "critical" => c += 1,
            "high" => h += 1,
            "medium" => m += 1,
            "low" => l += 1,
            _ => {}
        }
    }
    let total = c + h + m + l;

    fn pct(part: u32, total: u32) -> f64 {
        if total == 0 {
            0.0
        } else {
            (part as f64 / total as f64) * 100.0
        }
    }

    let severity_summary = json!({
        "total": total,
        "critical": c,
        "high": h,
        "medium": m,
        "low": l,
        "critical_pct": pct(c, total),
        "high_pct":     pct(h, total),
        "medium_pct":   pct(m, total),
        "low_pct":      pct(l, total),
    });

    // Group findings by severity, render each into a stable shape used by the
    // template (so the template doesn't need to know about CWE→OWASP, snippet
    // windowing, or patch lookup).
    let mut buckets: Vec<Value> = Vec::with_capacity(SEVERITY_ORDER.len());
    let mut display_index = 1usize;
    for sev in SEVERITY_ORDER {
        let in_bucket: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.severity == sev)
            .filter(|f| !matches!(f.status.as_str(), "dismissed" | "false_positive"))
            .collect();
        if in_bucket.is_empty() {
            continue;
        }
        let mut rendered = Vec::with_capacity(in_bucket.len());
        for f in in_bucket {
            rendered.push(render_finding(f, patches, display_index));
            display_index += 1;
        }
        buckets.push(json!({
            "severity": sev,
            "label": severity_label(sev),
            "count": rendered.len(),
            "findings": rendered,
        }));
    }

    let executive_summary = synthesize_summary(repo, &breakdown, c, h, m, l);

    json!({
        "repo": {
            "id": repo.id.to_string(),
            "name": repo.name.clone(),
            "default_branch": repo.default_branch.clone().unwrap_or_else(|| "main".to_string()),
            "remote_url": repo.remote_url.clone(),
        },
        "scan": {
            "id": scan.id.to_string(),
            "short_id": scan.id.to_string().chars().take(8).collect::<String>(),
            "scan_type": scan.scan_type.clone(),
            "status": scan.status.clone(),
            "commit_sha": scan.commit_sha.clone(),
            "commit_short": scan.commit_sha.as_deref().map(short_sha),
            "started_at": scan.started_at.map(format_dt),
            "completed_at": scan.completed_at.map(format_dt),
            "created_at": format_dt(scan.created_at),
            "updated_at": format_dt(scan.updated_at),
        },
        "generated_at": format_dt(chrono::Utc::now()),
        "score": {
            "value": breakdown.score,
            "dasharray": dasharray_for(breakdown.score),
            "critical_loss": format!("{:.1}", breakdown.critical_loss),
            "high_loss":     format!("{:.1}", breakdown.high_loss),
            "medium_loss":   format!("{:.1}", breakdown.medium_loss),
            "low_loss":      format!("{:.1}", breakdown.low_loss),
        },
        "severity_summary": severity_summary,
        "executive_summary": executive_summary,
        "threat_model": threat_model.map(render_threat_model),
        "finding_buckets": buckets,
    })
}

fn render_finding(f: &Finding, patches: &[PatchWithFilePath], display_index: usize) -> Value {
    let cwe = f
        .cwe_id
        .as_deref()
        .or_else(|| extract_cwe_from_title(&f.title));
    let owasp = cwe.and_then(owasp::lookup);

    let snippet = f
        .code_snippet
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| {
            let w = snippet::window(s, f.line_start);
            json!({
                "lines": w.lines.iter().map(|l| json!({
                    "number": l.number,
                    "text": l.text,
                    "line_truncated": l.line_truncated,
                })).collect::<Vec<_>>(),
                "truncated": w.truncated,
                "original_line_count": w.original_line_count,
            })
        });

    let suggested_patch = f.suggested_patch.as_deref().filter(|s| !s.is_empty());
    let patch_is_prose = suggested_patch.map(looks_like_prose).unwrap_or(false);

    let unified_diff = patches
        .iter()
        .find(|p| p.finding_id == f.id)
        .map(|p| p.diff_content.clone());

    let references: Vec<String> = f
        .references_json
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    json!({
        "id": f.id.to_string(),
        "display_index": display_index,
        "title": clean_title(&f.title),
        "severity": f.severity.clone(),
        "confidence": f.confidence.clone(),
        "confidence_pct": confidence_pct(&f.confidence),
        "source": f.source.clone(),
        "fix_type": f.fix_type.clone(),
        "fix_summary": f.fix_summary.clone(),
        "file_path": f.file_path.clone(),
        "line_start": f.line_start,
        "line_end": f.line_end,
        "description": f.description.clone(),
        "agent_reasoning": f.agent_reasoning.clone(),
        "cwe_id": cwe.map(|s| s.to_string()),
        "cve_id": f.cve_id.clone(),
        "owasp_code": owasp.map(|c| c.code.to_string()),
        "owasp_title": owasp.map(|c| c.title.to_string()),
        "poc_validated": f.poc_validated,
        "code_snippet": snippet,
        "suggested_patch": suggested_patch,
        "suggested_patch_is_prose": patch_is_prose,
        "unified_diff": unified_diff,
        "references": references,
    })
}

fn render_threat_model(tm: &ThreatModel) -> Value {
    json!({
        "summary": tm.summary.clone(),
        "boundaries": tm.boundaries_json.clone().unwrap_or(Value::Array(Vec::new())),
        "surfaces":   tm.surfaces_json.clone().unwrap_or(Value::Array(Vec::new())),
        "data_flows": tm.data_flows_json.clone().unwrap_or(Value::Array(Vec::new())),
        "model_version": tm.model_version,
    })
}

fn severity_label(s: &str) -> &'static str {
    match s {
        "critical" => "Critical",
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Other",
    }
}

fn confidence_pct(c: &str) -> u8 {
    match c {
        "high" => 95,
        "medium" => 75,
        "low" => 55,
        _ => 75,
    }
}

fn short_sha(s: &str) -> String {
    s.chars().take(12).collect()
}

fn format_dt<Tz: chrono::TimeZone>(dt: chrono::DateTime<Tz>) -> String
where
    Tz::Offset: std::fmt::Display,
{
    dt.with_timezone(&chrono::Utc)
        .format("%b %d, %Y %H:%M:%S UTC")
        .to_string()
}

/// Compute the SVG `stroke-dasharray` (filled, gap) for a 48-radius circle,
/// where filled = score% of the 301.59 circumference.
fn dasharray_for(score: u8) -> String {
    let circumference = 2.0 * std::f64::consts::PI * 48.0;
    let filled = (score as f64 / 100.0) * circumference;
    let gap = circumference - filled;
    format!("{filled:.1} {gap:.1}")
}

/// Heimdall sometimes prefixes finding titles with `[CWE-XX] `. Strip that to
/// avoid double-rendering when the CWE is also shown in the metadata strip.
fn clean_title(title: &str) -> String {
    if let Some(rest) = title.strip_prefix('[')
        && let Some(close_idx) = rest.find(']')
    {
        let bracket = &rest[..close_idx];
        if bracket.starts_with("CWE-") {
            return rest[close_idx + 1..].trim_start().to_string();
        }
    }
    title.to_string()
}

/// Pull a `CWE-NN` token out of a title that includes `[CWE-NN] …` when the
/// finding's `cwe_id` column is empty.
fn extract_cwe_from_title(title: &str) -> Option<&str> {
    let rest = title.strip_prefix('[')?;
    let close = rest.find(']')?;
    let bracket = &rest[..close];
    if bracket.starts_with("CWE-") {
        Some(bracket)
    } else {
        None
    }
}

/// Heuristic: is the suggested patch prose ("1. Remove the literal. 2. Read
/// from env at runtime.") rather than code? AI-generated remediations often
/// arrive as a numbered prose checklist, while static-analyzer patches are
/// always code blocks.
fn looks_like_prose(patch: &str) -> bool {
    let first = patch
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    if first.is_empty() {
        return false;
    }
    // "1. ", "1) ", "- ", "* "
    let starts_like_list = first.starts_with("1.")
        || first.starts_with("1)")
        || first.starts_with("- ")
        || first.starts_with("* ");
    let has_no_braces_or_semicolons =
        !patch.contains('{') && !patch.contains(';') && !patch.contains("=>");
    starts_like_list && has_no_braces_or_semicolons
}

fn synthesize_summary(
    repo: &Repo,
    breakdown: &score::ScoreBreakdown,
    c: u32,
    h: u32,
    m: u32,
    l: u32,
) -> String {
    let total = c + h + m + l;
    if total == 0 {
        return format!(
            "Heimdall scanned the {} repository and identified no open security findings. The codebase is clean as of this scan.",
            repo.name
        );
    }
    let lead = format!(
        "Heimdall scanned the {} repository and identified {} open security finding{}.",
        repo.name,
        total,
        if total == 1 { "" } else { "s" }
    );
    let critical_clause = if c > 0 {
        format!(
            " {} critical vulnerabilit{} require immediate remediation to reduce the risk of exploitation.",
            c,
            if c == 1 { "y" } else { "ies" }
        )
    } else {
        String::new()
    };
    let priority_clause = if c > 0 || h > 0 {
        " Addressing the critical and high severity findings should be prioritized.".to_string()
    } else if m > 0 {
        " Medium severity findings should be reviewed and triaged.".to_string()
    } else {
        " Remaining findings are informational; address them as part of routine hygiene."
            .to_string()
    };
    let score_clause = format!(
        " Security score: {} / 100 (critical −{:.0}, high −{:.0}, medium −{:.0}, low −{:.0}).",
        breakdown.score,
        breakdown.critical_loss,
        breakdown.high_loss,
        breakdown.medium_loss,
        breakdown.low_loss
    );
    format!("{lead}{critical_clause}{priority_clause}{score_clause}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dasharray_at_zero_is_zero_filled() {
        let d = dasharray_for(0);
        assert!(d.starts_with("0.0 "));
    }

    #[test]
    fn dasharray_at_hundred_is_full_filled() {
        let d = dasharray_for(100);
        assert!(d.contains("0.0") && !d.starts_with("0.0 "));
    }

    #[test]
    fn clean_title_strips_cwe_prefix() {
        assert_eq!(
            clean_title("[CWE-89] Potential SQL injection"),
            "Potential SQL injection"
        );
    }

    #[test]
    fn clean_title_passes_through_unprefixed() {
        assert_eq!(clean_title("Hardcoded secret"), "Hardcoded secret");
    }

    #[test]
    fn extract_cwe_pulls_token_from_bracket() {
        assert_eq!(extract_cwe_from_title("[CWE-89] X"), Some("CWE-89"));
        assert_eq!(extract_cwe_from_title("X"), None);
        assert_eq!(extract_cwe_from_title("[REGEX-foo] X"), None);
    }

    #[test]
    fn looks_like_prose_detects_numbered_lists() {
        assert!(looks_like_prose("1. Remove the literal\n2. Use env vars"));
        assert!(looks_like_prose("- step one\n- step two"));
        assert!(!looks_like_prose("function foo() { return 1; }"));
        assert!(!looks_like_prose("const x = 5;"));
    }
}
