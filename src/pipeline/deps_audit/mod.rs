//
//  heimdall
//  src/pipeline/deps_audit/mod.rs
//

pub mod osv;
pub mod parsers;

use log::info;
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::{FindingEvidence, FindingFixType, HeimdallResult};

/// A dependency extracted from a manifest file.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub declared_version: String,
    pub ecosystem: String,
    pub line_start: i32,
    pub line_end: Option<i32>,
    pub code_snippet: String,
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
    pub line_start: i32,
    pub line_end: Option<i32>,
    pub evidence: FindingEvidence,
}

#[derive(Debug, Clone)]
struct ParsedDependencyOccurrence {
    dep: Dependency,
    manifest_path: String,
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

        let mut all_occurrences = Vec::new();
        let manifest_paths_with_supported_lock = manifests
            .iter()
            .filter_map(|(path, _)| {
                if supports_lockfile_query(path) {
                    companion_manifest_path(path)
                } else {
                    None
                }
            })
            .collect::<HashSet<_>>();

        for (path, content) in &manifests {
            let Some(eco) = detect_ecosystem(path) else {
                continue;
            };

            let filename = std::path::Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let deps = parsers::parse_manifest(&eco, &filename, content);
            for dep in deps {
                all_occurrences.push(ParsedDependencyOccurrence {
                    dep,
                    manifest_path: path.clone(),
                });
            }
        }

        let query_occurrences = all_occurrences
            .iter()
            .filter(|occurrence| {
                if supports_lockfile_query(&occurrence.manifest_path) {
                    return true;
                }
                if is_lock_file(&occurrence.manifest_path) {
                    return false;
                }
                !manifest_paths_with_supported_lock.contains(&occurrence.manifest_path)
            })
            .cloned()
            .collect::<Vec<_>>();

        info!(
            "[{}] Parsed {} dependencies from manifests",
            self.scan_id,
            all_occurrences.len()
        );

        if query_occurrences.is_empty() {
            return Ok(vec![]);
        }

        // Query OSV in batches
        let queries: Vec<osv::OsvQuery> = query_occurrences
            .iter()
            .map(|occurrence| osv::OsvQuery {
                package: osv::OsvPackage {
                    name: occurrence.dep.name.clone(),
                    ecosystem: occurrence.dep.ecosystem.clone(),
                },
                version: occurrence.dep.version.clone(),
            })
            .collect();

        let results = osv::query_osv_batch(&queries).await;

        // Map results to vulnerabilities
        let mut vulns = Vec::new();
        for (i, vulns_for_dep) in results.iter().enumerate() {
            let query_occurrence = &query_occurrences[i];
            let report_occurrence = resolve_report_occurrence(&all_occurrences, query_occurrence);
            for vuln in vulns_for_dep {
                let severity = classify_severity(vuln);
                let fixed_versions = fixed_versions_for(vuln, &query_occurrence.dep);
                let recommended_version = fixed_versions.first().cloned();
                let references = reference_urls_for(vuln);
                let fix_summary = dependency_fix_summary(
                    &report_occurrence.dep,
                    recommended_version.as_deref(),
                    &fixed_versions,
                );
                let suggested_patch = dependency_fix_guidance(
                    &report_occurrence.dep,
                    &report_occurrence.manifest_path,
                    recommended_version.as_deref(),
                );
                let manifest_coordinates = serde_json::json!({
                    "ecosystem": report_occurrence.dep.ecosystem,
                    "name": report_occurrence.dep.name,
                    "installed_version": query_occurrence.dep.version,
                    "declared_version": report_occurrence.dep.declared_version,
                    "recommended_version": recommended_version,
                    "fixed_versions": fixed_versions,
                    "advisory_id": vuln.id,
                    "aliases": vuln.aliases.clone().unwrap_or_default(),
                });
                let mut evidence = if recommended_version.is_some() {
                    FindingEvidence::dependency_upgrade(
                        report_occurrence.dep.code_snippet.clone(),
                        suggested_patch,
                        fix_summary,
                        manifest_coordinates,
                    )
                } else {
                    FindingEvidence {
                        code_snippet: Some(report_occurrence.dep.code_snippet.clone()),
                        suggested_patch: Some(suggested_patch),
                        fix_type: FindingFixType::ManualReview,
                        fix_summary: Some(fix_summary),
                        references: Vec::new(),
                        manifest_coordinates: Some(manifest_coordinates),
                    }
                };
                evidence.references = references;
                vulns.push(DepsVulnerability {
                    dep: query_occurrence.dep.clone(),
                    vuln_id: vuln.id.clone(),
                    summary: vuln.summary.clone().unwrap_or_default(),
                    severity,
                    aliases: vuln.aliases.clone().unwrap_or_default(),
                    manifest_path: report_occurrence.manifest_path.clone(),
                    line_start: report_occurrence.dep.line_start,
                    line_end: report_occurrence.dep.line_end,
                    evidence,
                });
            }
        }

        info!(
            "[{}] Found {} vulnerabilities across {} dependencies",
            self.scan_id,
            vulns.len(),
            query_occurrences.len()
        );

        // Persist findings
        for v in &vulns {
            let title = format!("{} in {} {}", v.vuln_id, v.dep.name, v.dep.version);
            let fixed_versions = v
                .evidence
                .manifest_coordinates
                .as_ref()
                .and_then(|value| value.get("fixed_versions"))
                .and_then(|value| value.as_array())
                .map(|versions| {
                    versions
                        .iter()
                        .filter_map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|value| !value.is_empty());
            let description = format!(
                "Vulnerable dependency: {} {} ({}) in {}\n\n{}\n\nAliases: {}\n{}",
                v.dep.name,
                v.dep.version,
                v.dep.ecosystem,
                v.manifest_path,
                v.summary,
                if v.aliases.is_empty() {
                    "None".to_string()
                } else {
                    v.aliases.join(", ")
                },
                fixed_versions
                    .map(|versions| format!("Known fixed versions: {versions}"))
                    .unwrap_or_else(|| {
                        "No fixed version was published in the OSV response for this advisory."
                            .to_string()
                    })
            );

            let _ = self
                .db
                .create_finding_full(
                    self.scan_id,
                    self.repo_id,
                    "dependencies",
                    &v.severity,
                    "high",
                    &title,
                    Some(&description),
                    Some("CWE-1104"),
                    &v.manifest_path,
                    v.line_start,
                    v.line_end,
                    &format!(
                        "deps-{}-{}-{}-{}",
                        v.dep.ecosystem, v.dep.name, v.vuln_id, v.manifest_path
                    ),
                    None,
                    &v.evidence,
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

fn resolve_report_occurrence<'a>(
    occurrences: &'a [ParsedDependencyOccurrence],
    query: &'a ParsedDependencyOccurrence,
) -> &'a ParsedDependencyOccurrence {
    if supports_lockfile_query(&query.manifest_path) {
        if let Some(companion_path) = companion_manifest_path(&query.manifest_path) {
            if let Some(manifest_occurrence) = occurrences.iter().find(|occurrence| {
                occurrence.manifest_path == companion_path
                    && occurrence.dep.name == query.dep.name
                    && occurrence.dep.ecosystem == query.dep.ecosystem
            }) {
                return manifest_occurrence;
            }
        }
    }

    query
}

fn supports_lockfile_query(path: &str) -> bool {
    matches!(
        std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str()),
        Some("Cargo.lock" | "package-lock.json")
    )
}

fn companion_manifest_path(lock_path: &str) -> Option<String> {
    let path = std::path::Path::new(lock_path);
    let file_name = path.file_name()?.to_str()?;
    let manifest_name = match file_name {
        "Cargo.lock" => "Cargo.toml",
        "package-lock.json" => "package.json",
        _ => return None,
    };

    Some(
        path.parent()
            .map(|parent| parent.join(manifest_name))
            .unwrap_or_else(|| std::path::PathBuf::from(manifest_name))
            .to_string_lossy()
            .to_string(),
    )
}

fn fixed_versions_for(vuln: &osv::OsvVulnerability, dep: &Dependency) -> Vec<String> {
    let mut fixed_versions = Vec::new();

    if let Some(affected) = &vuln.affected {
        for package in affected {
            let package_matches = package
                .package
                .as_ref()
                .map(|pkg| pkg.name == dep.name && pkg.ecosystem == dep.ecosystem)
                .unwrap_or(true);

            if !package_matches {
                continue;
            }

            for range in &package.ranges {
                for event in &range.events {
                    if let Some(fixed) = &event.fixed {
                        if !fixed_versions.contains(fixed) {
                            fixed_versions.push(fixed.clone());
                        }
                    }
                }
            }
        }
    }

    fixed_versions
}

fn reference_urls_for(vuln: &osv::OsvVulnerability) -> Vec<String> {
    let mut urls = vuln
        .references
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|reference| reference.url)
        .collect::<Vec<_>>();

    for alias in vuln.aliases.clone().unwrap_or_default() {
        let alias_url = if alias.starts_with("GHSA-") {
            Some(format!("https://github.com/advisories/{alias}"))
        } else if alias.starts_with("CVE-") {
            Some(format!("https://nvd.nist.gov/vuln/detail/{alias}"))
        } else {
            None
        };

        if let Some(url) = alias_url {
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
    }

    urls
}

fn dependency_fix_summary(
    dep: &Dependency,
    recommended_version: Option<&str>,
    fixed_versions: &[String],
) -> String {
    if let Some(version) = recommended_version {
        if fixed_versions.len() > 1 {
            format!(
                "Upgrade `{}` from `{}` to a fixed release. Suggested target: `{}`. Other known fixed versions: {}.",
                dep.name,
                dep.version,
                version,
                fixed_versions.join(", ")
            )
        } else {
            format!(
                "Upgrade `{}` from `{}` to `{}`.",
                dep.name, dep.version, version
            )
        }
    } else {
        format!(
            "No fixed version was published for `{}` `{}` in the OSV response. Review the advisory and consider removing, replacing, or isolating the package until a fix ships.",
            dep.name, dep.version
        )
    }
}

fn dependency_fix_guidance(
    dep: &Dependency,
    manifest_path: &str,
    recommended_version: Option<&str>,
) -> String {
    match recommended_version {
        Some(version) => {
            let replacement = rendered_dependency_replacement(dep, version);
            format!(
                "// Upgrade `{}` in `{}`.\n// Current declaration:\n{}\n\n// Replace with:\n{}",
                dep.name, manifest_path, dep.code_snippet, replacement
            )
        }
        None => format!(
            "// `{}` `{}` is vulnerable in `{}`.\n// No fixed version was published in the OSV response.\n// Next steps:\n// 1. Review the advisory and linked references.\n// 2. Remove or replace the dependency if possible.\n// 3. Constrain exposure until an upstream fixed version is released.",
            dep.name, dep.version, manifest_path
        ),
    }
}

fn rendered_dependency_replacement(dep: &Dependency, target_version: &str) -> String {
    let replacement_spec = apply_version_style(&dep.declared_version, target_version);
    if dep.declared_version.is_empty() {
        return format!(
            "Set `{}` to `{replacement_spec}` in the manifest entry.",
            dep.name
        );
    }

    dep.code_snippet
        .replacen(&dep.declared_version, &replacement_spec, 1)
}

fn apply_version_style(current_spec: &str, target_version: &str) -> String {
    let prefix = current_spec
        .chars()
        .take_while(|ch| !ch.is_ascii_digit())
        .collect::<String>();

    if prefix.is_empty() {
        target_version.to_string()
    } else {
        format!("{prefix}{target_version}")
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
            affected: None,
            references: None,
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
            affected: None,
            references: None,
        };
        assert_eq!(classify_severity(&vuln), "high");
    }
}
