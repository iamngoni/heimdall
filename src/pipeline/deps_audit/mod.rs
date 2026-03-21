//
//  heimdall
//  src/pipeline/deps_audit/mod.rs
//

pub mod osv;
pub mod parsers;

use log::info;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::HeimdallResult;

/// A dependency extracted from a manifest file.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
}

/// A vulnerability finding from deps audit.
#[derive(Debug, Clone)]
pub struct DepsVulnerability {
    pub dep: Dependency,
    pub vuln_id: String,
    pub summary: String,
    pub severity: String,
    pub aliases: Vec<String>,
    pub manifest_path: String,
}

/// Stage that audits dependencies for known vulnerabilities via OSV.
pub struct DepsAuditStage {
    pub scan_id: Uuid,
    pub repo_id: Uuid,
    pub db: Arc<DatabaseOperations>,
}

impl DepsAuditStage {
    pub fn new(scan_id: Uuid, repo_id: Uuid, db: Arc<DatabaseOperations>) -> Self {
        Self {
            scan_id,
            repo_id,
            db,
        }
    }

    /// Run the dependency audit against all manifest files in the code index.
    pub async fn run(&self, code_index: &CodeIndex) -> HeimdallResult<Vec<DepsVulnerability>> {
        info!("[{}] Starting dependency audit", self.scan_id);

        // Find all manifest files
        let manifests = self.find_manifests(code_index);
        if manifests.is_empty() {
            info!(
                "[{}] No manifest files found, skipping deps audit",
                self.scan_id
            );
            return Ok(vec![]);
        }

        info!(
            "[{}] Found {} manifest file(s)",
            self.scan_id,
            manifests.len()
        );

        // Parse all dependencies, preferring lock files over manifests
        // for the same ecosystem (lock files have exact resolved versions).
        let mut all_deps: Vec<(Dependency, String)> = Vec::new(); // (dep, manifest_path)
        let mut ecosystems_with_lockfile: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // First pass: identify which ecosystems have lock files
        for (path, _) in &manifests {
            if is_lock_file(path) {
                if let Some(eco) = detect_ecosystem(path) {
                    ecosystems_with_lockfile.insert(eco);
                }
            }
        }

        // Second pass: parse lock files first, skip manifests when lock exists
        for (path, content) in &manifests {
            let ecosystem = detect_ecosystem(path);
            if let Some(ref eco) = ecosystem {
                let is_lock = is_lock_file(path);
                // Skip manifest if we have a lock file for this ecosystem
                if !is_lock && ecosystems_with_lockfile.contains(eco.as_str()) {
                    info!(
                        "[{}] Skipping {} (lock file available for {})",
                        self.scan_id, path, eco
                    );
                    continue;
                }

                let filename = std::path::Path::new(path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let deps = parsers::parse_manifest(eco, &filename, content);
                for dep in deps {
                    all_deps.push((dep, path.clone()));
                }
            }
        }

        info!(
            "[{}] Parsed {} dependencies from manifests",
            self.scan_id,
            all_deps.len()
        );

        if all_deps.is_empty() {
            return Ok(vec![]);
        }

        // Query OSV in batches
        let queries: Vec<osv::OsvQuery> = all_deps
            .iter()
            .map(|(dep, _)| osv::OsvQuery {
                package: osv::OsvPackage {
                    name: dep.name.clone(),
                    ecosystem: dep.ecosystem.clone(),
                },
                version: dep.version.clone(),
            })
            .collect();

        let results = osv::query_osv_batch(&queries).await;

        // Map results to vulnerabilities
        let mut vulns = Vec::new();
        for (i, vulns_for_dep) in results.iter().enumerate() {
            let (ref dep, ref manifest_path) = all_deps[i];
            for vuln in vulns_for_dep {
                let severity = classify_severity(vuln);
                vulns.push(DepsVulnerability {
                    dep: dep.clone(),
                    vuln_id: vuln.id.clone(),
                    summary: vuln.summary.clone().unwrap_or_default(),
                    severity,
                    aliases: vuln.aliases.clone().unwrap_or_default(),
                    manifest_path: manifest_path.clone(),
                });
            }
        }

        info!(
            "[{}] Found {} vulnerabilities across {} dependencies",
            self.scan_id,
            vulns.len(),
            all_deps.len()
        );

        // Persist findings
        for v in &vulns {
            let title = format!("{} in {} {}", v.vuln_id, v.dep.name, v.dep.version);
            let description = format!(
                "Vulnerable dependency: {} {} ({})\n\n{}",
                v.dep.name, v.dep.version, v.dep.ecosystem, v.summary
            );

            let _ = self
                .db
                .create_finding(
                    self.scan_id,
                    self.repo_id,
                    "dependencies",
                    &v.severity,
                    "high",
                    &title,
                    Some(&description),
                    &v.manifest_path,
                    1,
                    None,
                    &format!("deps-{}-{}-{}", v.dep.ecosystem, v.dep.name, v.vuln_id),
                )
                .await;
        }

        Ok(vulns)
    }

    /// Find manifest files from the code index.
    fn find_manifests(&self, code_index: &CodeIndex) -> Vec<(String, String)> {
        let manifest_names = [
            "Cargo.toml",
            "Cargo.lock",
            "package.json",
            "package-lock.json",
            "requirements.txt",
            "Pipfile",
            "pyproject.toml",
            "go.mod",
            "go.sum",
            "pom.xml",
            "build.gradle",
            "Gemfile",
            "Gemfile.lock",
            "composer.json",
            "composer.lock",
        ];

        code_index
            .files
            .iter()
            .filter_map(|(_key, f)| {
                let filename = std::path::Path::new(&f.relative_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())?;
                if manifest_names.contains(&filename.as_str()) {
                    Some((f.relative_path.clone(), f.content.clone()))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Detect ecosystem from manifest file path.
fn detect_ecosystem(path: &str) -> Option<String> {
    let filename = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())?;
    match filename.as_str() {
        "Cargo.toml" | "Cargo.lock" => Some("crates.io".to_string()),
        "package.json" | "package-lock.json" => Some("npm".to_string()),
        "requirements.txt" | "Pipfile" | "pyproject.toml" => Some("PyPI".to_string()),
        "go.mod" | "go.sum" => Some("Go".to_string()),
        "pom.xml" | "build.gradle" => Some("Maven".to_string()),
        "Gemfile" | "Gemfile.lock" => Some("RubyGems".to_string()),
        "composer.json" | "composer.lock" => Some("Packagist".to_string()),
        _ => None,
    }
}

/// Check if a manifest path is a lock file (has exact resolved versions).
fn is_lock_file(path: &str) -> bool {
    let filename = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    matches!(
        filename.as_str(),
        "Cargo.lock" | "package-lock.json" | "Gemfile.lock" | "composer.lock" | "go.sum"
    )
}

/// Classify severity from OSV vulnerability data.
fn classify_severity(vuln: &osv::OsvVulnerability) -> String {
    // Check database_specific or severity field for CVSS
    if let Some(ref severity_list) = vuln.severity {
        for s in severity_list {
            if s.score_type == "CVSS_V3" {
                // Parse CVSS score from vector string (last number after /)
                if let Some(score) = extract_cvss_score(&s.score) {
                    return if score >= 9.0 {
                        "critical".to_string()
                    } else if score >= 7.0 {
                        "high".to_string()
                    } else if score >= 4.0 {
                        "medium".to_string()
                    } else {
                        "low".to_string()
                    };
                }
            }
        }
    }
    // Default to high for unknown
    "high".to_string()
}

fn extract_cvss_score(vector: &str) -> Option<f64> {
    // CVSS vectors sometimes end with a numeric score, or we can do a simple lookup
    // For now, try parsing trailing number
    vector.rsplit('/').next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ecosystem_cargo() {
        assert_eq!(
            detect_ecosystem("Cargo.toml"),
            Some("crates.io".to_string())
        );
        assert_eq!(
            detect_ecosystem("src/Cargo.toml"),
            Some("crates.io".to_string())
        );
    }

    #[test]
    fn test_detect_ecosystem_npm() {
        assert_eq!(detect_ecosystem("package.json"), Some("npm".to_string()));
    }

    #[test]
    fn test_detect_ecosystem_python() {
        assert_eq!(
            detect_ecosystem("requirements.txt"),
            Some("PyPI".to_string())
        );
    }

    #[test]
    fn test_detect_ecosystem_go() {
        assert_eq!(detect_ecosystem("go.mod"), Some("Go".to_string()));
    }

    #[test]
    fn test_detect_ecosystem_unknown() {
        assert_eq!(detect_ecosystem("README.md"), None);
    }

    #[test]
    fn test_classify_severity_critical() {
        let vuln = osv::OsvVulnerability {
            id: "GHSA-1234".to_string(),
            summary: None,
            aliases: None,
            severity: Some(vec![osv::OsvSeverity {
                score_type: "CVSS_V3".to_string(),
                score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8".to_string(),
            }]),
        };
        assert_eq!(classify_severity(&vuln), "critical");
    }

    #[test]
    fn test_classify_severity_default() {
        let vuln = osv::OsvVulnerability {
            id: "GHSA-5678".to_string(),
            summary: None,
            aliases: None,
            severity: None,
        };
        assert_eq!(classify_severity(&vuln), "high");
    }
}
