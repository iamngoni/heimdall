//
//  heimdall
//  src/pipeline/deps_audit/osv.rs
//

use log::warn;
use serde::{Deserialize, Serialize};

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

#[derive(Debug, Serialize)]
pub struct OsvQuery {
    pub package: OsvPackage,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvPackage {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Debug, Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvBatchResult>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResult {
    vulns: Option<Vec<OsvVulnerability>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    pub summary: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub severity: Option<Vec<OsvSeverity>>,
    #[serde(default)]
    pub affected: Option<Vec<OsvAffectedPackage>>,
    #[serde(default)]
    pub references: Option<Vec<OsvReference>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub score_type: String,
    pub score: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvAffectedPackage {
    #[serde(default)]
    pub package: Option<OsvPackage>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvRange {
    #[serde(default)]
    pub events: Vec<OsvRangeEvent>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvRangeEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvReference {
    pub url: String,
}

/// Query OSV API in batches (max 1000 per request).
pub async fn query_osv_batch(queries: &[OsvQuery]) -> Vec<Vec<OsvVulnerability>> {
    let client = reqwest::Client::new();
    let mut all_results = Vec::with_capacity(queries.len());

    for chunk in queries.chunks(1000) {
        let batch = OsvBatchRequest {
            queries: chunk
                .iter()
                .map(|q| OsvQuery {
                    package: OsvPackage {
                        name: q.package.name.clone(),
                        ecosystem: q.package.ecosystem.clone(),
                    },
                    version: q.version.clone(),
                })
                .collect(),
        };

        match client.post(OSV_BATCH_URL).json(&batch).send().await {
            Ok(resp) => {
                if let Ok(body) = resp.json::<OsvBatchResponse>().await {
                    for result in body.results {
                        all_results.push(result.vulns.unwrap_or_default());
                    }
                } else {
                    warn!("Failed to parse OSV batch response");
                    for _ in chunk {
                        all_results.push(vec![]);
                    }
                }
            }
            Err(e) => {
                warn!("OSV batch query failed: {e}");
                for _ in chunk {
                    all_results.push(vec![]);
                }
            }
        }
    }

    all_results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osv_vulnerability_deserialize() {
        let json = r#"{
            "id": "GHSA-abcd-1234-efgh",
            "summary": "Test vulnerability",
            "aliases": ["CVE-2023-12345"],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "references": [{"url": "https://github.com/advisories/GHSA-abcd-1234-efgh"}],
            "affected": [{
                "package": {"name": "example", "ecosystem": "npm"},
                "ranges": [{
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "1.2.3"}
                    ]
                }]
            }]
        }"#;
        let vuln: OsvVulnerability = serde_json::from_str(json).unwrap();
        assert_eq!(vuln.id, "GHSA-abcd-1234-efgh");
        assert!(
            vuln.aliases
                .unwrap()
                .contains(&"CVE-2023-12345".to_string())
        );
        assert_eq!(
            vuln.references.unwrap()[0].url,
            "https://github.com/advisories/GHSA-abcd-1234-efgh"
        );
        assert_eq!(
            vuln.affected.unwrap()[0].ranges[0].events[1]
                .fixed
                .as_deref(),
            Some("1.2.3")
        );
    }
}
