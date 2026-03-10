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

#[derive(Debug, Serialize)]
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub score_type: String,
    pub score: String,
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
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        }"#;
        let vuln: OsvVulnerability = serde_json::from_str(json).unwrap();
        assert_eq!(vuln.id, "GHSA-abcd-1234-efgh");
        assert!(
            vuln.aliases
                .unwrap()
                .contains(&"CVE-2023-12345".to_string())
        );
    }
}
