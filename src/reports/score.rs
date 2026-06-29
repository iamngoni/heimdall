//
//  heimdall
//  src/reports/score.rs
//
//  Created by Ngonidzashe Mangudya on 2026/05/04.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

//! Security-score computation for the per-scan PDF report.
//!
//! The score is the headline number on the cover page. We start at 100 and
//! deduct a per-severity penalty on a diminishing-returns curve so that the
//! first finding in a bucket hurts the most and large counts saturate near a
//! cap. Confidence and PoC validation modulate per-finding weight.

use crate::models::db_models::Finding;

/// Per-bucket parameters: maximum penalty (cap) and the count at which we've
/// dealt half of that cap. Tuned against real Heimdall scans (see DB sample
/// of 14 scans / 583 findings) so a typical noisy scan lands around 30 and a
/// clean scan lands at 100.
struct BucketParams {
    max_loss: f64,
    half_at: f64,
}

const CRITICAL: BucketParams = BucketParams {
    max_loss: 35.0,
    half_at: 2.0,
};
const HIGH: BucketParams = BucketParams {
    max_loss: 30.0,
    half_at: 5.0,
};
const MEDIUM: BucketParams = BucketParams {
    max_loss: 18.0,
    half_at: 8.0,
};
const LOW: BucketParams = BucketParams {
    max_loss: 8.0,
    half_at: 20.0,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct ScoreBreakdown {
    pub score: u8,
    pub critical_loss: f64,
    pub high_loss: f64,
    pub medium_loss: f64,
    pub low_loss: f64,
    pub critical_weight: f64,
    pub high_weight: f64,
    pub medium_weight: f64,
    pub low_weight: f64,
}

/// Compute the score from a slice of findings.
///
/// Findings with status `dismissed`, `false_positive`, or `fixed` are excluded
/// — the scoring measures *open* risk in the codebase right now.
pub fn compute(findings: &[Finding]) -> ScoreBreakdown {
    let (mut c, mut h, mut m, mut l) = (0.0, 0.0, 0.0, 0.0);

    for f in findings {
        if matches!(f.status.as_str(), "dismissed" | "false_positive" | "fixed") {
            continue;
        }
        let weight = confidence_weight(&f.confidence) * poc_weight(f.poc_validated);
        match f.severity.as_str() {
            "critical" => c += weight,
            "high" => h += weight,
            "medium" => m += weight,
            "low" => l += weight,
            _ => {}
        }
    }

    let critical_loss = bucket_loss(c, &CRITICAL);
    let high_loss = bucket_loss(h, &HIGH);
    let medium_loss = bucket_loss(m, &MEDIUM);
    let low_loss = bucket_loss(l, &LOW);

    let raw = 100.0 - (critical_loss + high_loss + medium_loss + low_loss);
    let score = raw.round().clamp(0.0, 100.0) as u8;

    ScoreBreakdown {
        score,
        critical_loss,
        high_loss,
        medium_loss,
        low_loss,
        critical_weight: c,
        high_weight: h,
        medium_weight: m,
        low_weight: l,
    }
}

fn confidence_weight(conf: &str) -> f64 {
    match conf {
        "high" => 1.0,
        "medium" => 0.7,
        "low" => 0.4,
        _ => 0.7, // unknown → treat as medium
    }
}

fn poc_weight(validated: bool) -> f64 {
    if validated { 1.3 } else { 1.0 }
}

fn bucket_loss(weighted_count: f64, p: &BucketParams) -> f64 {
    if weighted_count <= 0.0 {
        return 0.0;
    }
    p.max_loss * weighted_count / (weighted_count + p.half_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn fixture(severity: &str, confidence: &str, status: &str, poc_validated: bool) -> Finding {
        Finding {
            id: Uuid::nil(),
            scan_id: Uuid::nil(),
            repo_id: Uuid::nil(),
            source: "static".to_string(),
            status: status.to_string(),
            severity: severity.to_string(),
            confidence: confidence.to_string(),
            title: String::new(),
            description: None,
            cwe_id: None,
            cve_id: None,
            file_path: String::new(),
            line_start: 1,
            line_end: None,
            code_snippet: None,
            suggested_patch: None,
            poc_exploit_json: None,
            poc_validated,
            fingerprint: String::new(),
            agent_reasoning: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            fix_type: Some("manual_review".to_string()),
            fix_summary: None,
            references_json: None,
            manifest_coordinates_json: None,
        }
    }

    #[test]
    fn empty_findings_yields_perfect_score() {
        let b = compute(&[]);
        assert_eq!(b.score, 100);
    }

    #[test]
    fn single_high_confidence_critical_costs_about_twelve() {
        let b = compute(&[fixture("critical", "high", "open", false)]);
        // 35 * 1 / (1 + 2) ≈ 11.67  →  100 − 12 = 88
        assert_eq!(b.score, 88);
    }

    #[test]
    fn dismissed_findings_dont_hurt_score() {
        let mut findings = vec![fixture("critical", "high", "dismissed", true); 5];
        findings.extend(vec![fixture("high", "high", "false_positive", false); 10]);
        let b = compute(&findings);
        assert_eq!(b.score, 100);
    }

    #[test]
    fn validated_poc_costs_more_than_unvalidated() {
        let unvalidated = compute(&[fixture("high", "high", "open", false)]);
        let validated = compute(&[fixture("high", "high", "open", true)]);
        assert!(validated.score < unvalidated.score);
    }

    #[test]
    fn low_confidence_finding_costs_less_than_high_confidence() {
        let high = compute(&[fixture("high", "high", "open", false)]);
        let low = compute(&[fixture("high", "low", "open", false)]);
        assert!(low.score > high.score);
    }

    #[test]
    fn realistic_noisy_scan_lands_in_low_thirties() {
        // The 98-finding scan from the live DB: 15c, 48h, 19m, 16l, all open.
        let mut findings = Vec::new();
        for _ in 0..15 {
            findings.push(fixture("critical", "high", "open", false));
        }
        for _ in 0..48 {
            findings.push(fixture("high", "high", "open", false));
        }
        for _ in 0..19 {
            findings.push(fixture("medium", "high", "open", false));
        }
        for _ in 0..16 {
            findings.push(fixture("low", "high", "open", false));
        }
        let b = compute(&findings);
        assert!(
            (20..=40).contains(&b.score),
            "expected a noisy scan to land around 25-35; got {}",
            b.score
        );
    }

    #[test]
    fn losses_per_bucket_cap_at_max_loss() {
        // 1000 of each → total loss should converge near the configured caps.
        let mut findings = Vec::new();
        for _ in 0..1000 {
            findings.push(fixture("critical", "high", "open", true));
        }
        for _ in 0..1000 {
            findings.push(fixture("high", "high", "open", true));
        }
        for _ in 0..1000 {
            findings.push(fixture("medium", "high", "open", true));
        }
        for _ in 0..1000 {
            findings.push(fixture("low", "high", "open", true));
        }
        let b = compute(&findings);
        assert!(b.critical_loss <= 35.0 && b.critical_loss > 34.0);
        assert!(b.high_loss <= 30.0 && b.high_loss > 29.0);
        assert!(b.medium_loss <= 18.0 && b.medium_loss > 17.0);
        assert!(b.low_loss <= 8.0 && b.low_loss > 7.0);
    }
}
