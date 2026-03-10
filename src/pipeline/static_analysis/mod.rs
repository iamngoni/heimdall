//
//  heimdall
//  src/pipeline/static_analysis/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use log::info;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::HeimdallResult;

/// Static analysis stage using pattern matching for deterministic vulnerability detection.
/// Catches low-hanging fruit before the AI Hunt agent.
pub struct StaticAnalysisStage {
    pub scan_id: uuid::Uuid,
    pub repo_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
}

/// Context passed to the Hunt agent about what static analysis found.
pub struct StaticAnalysisContext {
    pub findings_count: usize,
    pub summary: String,
}

/// A pattern rule for static analysis.
struct Rule {
    name: &'static str,
    pattern: &'static str,
    severity: &'static str,
    cwe: &'static str,
    description: &'static str,
    languages: &'static [&'static str],
}

const RULES: &[Rule] = &[
    // SQL injection
    Rule {
        name: "sql-injection-string-concat",
        pattern: r#"(?i)(?:execute|query|raw)\s*\(.*(?:format!|%s|\+\s*\w+|\$\{)"#,
        severity: "high",
        cwe: "CWE-89",
        description: "Potential SQL injection via string concatenation/interpolation",
        languages: &["rust", "python", "javascript", "typescript", "go", "java"],
    },
    Rule {
        name: "sql-injection-fstring",
        pattern: r#"(?i)(?:execute|query|cursor\.)\s*\(\s*f["'].*(?:SELECT|INSERT|UPDATE|DELETE)"#,
        severity: "high",
        cwe: "CWE-89",
        description: "SQL query built with f-string interpolation",
        languages: &["python"],
    },
    // Command injection
    Rule {
        name: "command-injection",
        pattern: r#"(?i)(?:system|exec|popen|subprocess\.(?:call|run|Popen)|child_process\.exec)\s*\(.*(?:format!|\+\s*\w+|\$\{|%s)"#,
        severity: "critical",
        cwe: "CWE-78",
        description: "Potential command injection via string interpolation in shell command",
        languages: &["rust", "python", "javascript", "typescript", "go", "java"],
    },
    // Hardcoded secrets
    Rule {
        name: "hardcoded-api-key",
        pattern: r#"(?i)(?:api_?key|secret_?key|password|token)\s*[:=]\s*["'][A-Za-z0-9+/=_-]{16,}["']"#,
        severity: "high",
        cwe: "CWE-798",
        description: "Potential hardcoded secret or API key",
        languages: &[],
    },
    Rule {
        name: "aws-access-key",
        pattern: r#"AKIA[0-9A-Z]{16}"#,
        severity: "critical",
        cwe: "CWE-798",
        description: "AWS access key ID detected",
        languages: &[],
    },
    Rule {
        name: "private-key",
        pattern: r#"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"#,
        severity: "critical",
        cwe: "CWE-321",
        description: "Private key embedded in source code",
        languages: &[],
    },
    // Path traversal
    Rule {
        name: "path-traversal",
        pattern: r#"(?i)(?:open|read_file|fs\.read|Path\.new)\s*\(.*(?:params|request|req\.|query|input)"#,
        severity: "high",
        cwe: "CWE-22",
        description: "Potential path traversal — file operation with user-controlled input",
        languages: &[],
    },
    // XSS
    Rule {
        name: "xss-innerhtml",
        pattern: r#"\.innerHTML\s*="#,
        severity: "medium",
        cwe: "CWE-79",
        description: "Potential XSS via innerHTML assignment",
        languages: &["javascript", "typescript"],
    },
    Rule {
        name: "xss-dangerously-set",
        pattern: r#"dangerouslySetInnerHTML"#,
        severity: "medium",
        cwe: "CWE-79",
        description: "React dangerouslySetInnerHTML usage — ensure input is sanitized",
        languages: &["javascript", "typescript"],
    },
    // Deserialization
    Rule {
        name: "unsafe-deserialization-python",
        pattern: r#"(?:pickle\.loads?|yaml\.(?:load|unsafe_load))\s*\("#,
        severity: "high",
        cwe: "CWE-502",
        description: "Unsafe deserialization detected",
        languages: &["python"],
    },
    Rule {
        name: "unsafe-deserialization-java",
        pattern: r#"ObjectInputStream\s*\("#,
        severity: "high",
        cwe: "CWE-502",
        description: "Java deserialization of untrusted data",
        languages: &["java"],
    },
    // Weak crypto
    Rule {
        name: "weak-hash-md5",
        pattern: r#"(?i)(?:md5|MD5)\s*[\(.]"#,
        severity: "medium",
        cwe: "CWE-328",
        description: "Use of weak MD5 hash — consider SHA-256 or better",
        languages: &[],
    },
    Rule {
        name: "weak-hash-sha1",
        pattern: r#"(?i)(?:sha1|SHA1)\s*[\(.]"#,
        severity: "low",
        cwe: "CWE-328",
        description: "Use of SHA-1 hash — consider SHA-256 for security-sensitive contexts",
        languages: &[],
    },
    // CSRF
    Rule {
        name: "missing-csrf-check",
        pattern: r#"(?i)@(?:app\.route|post)\s*\([^)]*methods\s*=\s*\[.*POST"#,
        severity: "medium",
        cwe: "CWE-352",
        description: "POST endpoint without apparent CSRF protection",
        languages: &["python"],
    },
    // Open redirect
    Rule {
        name: "open-redirect",
        pattern: r#"(?i)(?:redirect|location\.href|window\.location)\s*=?\s*(?:params|request|req\.|query)"#,
        severity: "medium",
        cwe: "CWE-601",
        description: "Potential open redirect using user-controlled URL",
        languages: &[],
    },
];

impl StaticAnalysisStage {
    pub fn new(scan_id: uuid::Uuid, repo_id: uuid::Uuid, db: Arc<DatabaseOperations>) -> Self {
        Self {
            scan_id,
            repo_id,
            db,
        }
    }

    pub async fn run(&self, index: &CodeIndex) -> HeimdallResult<StaticAnalysisContext> {
        info!("[{}] Starting static analysis", self.scan_id);

        let mut total_findings = 0usize;
        let mut summary_parts = Vec::new();

        for rule in RULES {
            let re = match Regex::new(rule.pattern) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for (file_path, indexed_file) in &index.files {
                // Check language filter
                if !rule.languages.is_empty() {
                    if let Some(ref lang) = indexed_file.language {
                        if !rule.languages.contains(&lang.as_str()) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                for (line_idx, line) in indexed_file.content.lines().enumerate() {
                    if re.is_match(line) {
                        let line_num = (line_idx + 1) as i32;
                        let snippet = extract_snippet(&indexed_file.content, line_idx, 2);
                        let fingerprint = make_fingerprint(rule.name, file_path, line_num);

                        let _ = self
                            .db
                            .create_finding_full(
                                self.scan_id,
                                self.repo_id,
                                "static",
                                rule.severity,
                                "high", // static rules are deterministic = high confidence
                                &format!("[{}] {}", rule.cwe, rule.description),
                                Some(rule.description),
                                Some(rule.cwe),
                                file_path,
                                line_num,
                                Some(line_num),
                                Some(&snippet),
                                &fingerprint,
                                None,
                            )
                            .await;

                        total_findings += 1;
                    }
                }
            }
        }

        // Secret detection via entropy analysis
        let secret_count = self.detect_secrets(index).await?;
        total_findings += secret_count;

        if total_findings > 0 {
            summary_parts.push(format!("{total_findings} static analysis findings"));
        }

        let summary = if summary_parts.is_empty() {
            "No static analysis findings.".to_string()
        } else {
            summary_parts.join("; ")
        };

        info!(
            "[{}] Static analysis complete: {total_findings} findings",
            self.scan_id
        );

        Ok(StaticAnalysisContext {
            findings_count: total_findings,
            summary,
        })
    }

    /// Detect high-entropy strings that might be secrets.
    async fn detect_secrets(&self, index: &CodeIndex) -> HeimdallResult<usize> {
        static HIGH_ENTROPY_RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r#"["'][A-Za-z0-9+/=_-]{32,}["']"#).unwrap());
        static SECRET_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"(?i)(?:secret|key|token|password|auth|credential|api)").unwrap()
        });

        let mut count = 0usize;

        for (file_path, file) in &index.files {
            // Skip non-code files for entropy analysis
            if file.language.is_none() {
                continue;
            }

            for (line_idx, line) in file.content.lines().enumerate() {
                if HIGH_ENTROPY_RE.is_match(line) && SECRET_CONTEXT.is_match(line) {
                    let line_num = (line_idx + 1) as i32;
                    let fingerprint = make_fingerprint("high-entropy-secret", file_path, line_num);

                    let _ = self
                        .db
                        .create_finding_full(
                            self.scan_id,
                            self.repo_id,
                            "static",
                            "high",
                            "medium",
                            "[CWE-798] Potential secret or credential in source code",
                            Some("High-entropy string found near secret-related keywords"),
                            Some("CWE-798"),
                            file_path,
                            line_num,
                            Some(line_num),
                            Some(line.trim()),
                            &fingerprint,
                            None,
                        )
                        .await;

                    count += 1;
                }
            }
        }

        Ok(count)
    }
}

fn extract_snippet(content: &str, center_line: usize, context: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = center_line.saturating_sub(context);
    let end = std::cmp::min(center_line + context + 1, lines.len());
    lines[start..end].join("\n")
}

fn make_fingerprint(rule: &str, file: &str, line: i32) -> String {
    let input = format!("{rule}:{file}:{line}");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: compile a rule's pattern and check if it matches the given code line.
    fn rule_matches(rule_name: &str, line: &str) -> bool {
        let rule = RULES.iter().find(|r| r.name == rule_name).unwrap();
        let re = Regex::new(rule.pattern).unwrap();
        re.is_match(line)
    }

    // -----------------------------------------------------------------------
    // SQL injection rules
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_sql_injection_format() {
        assert!(rule_matches(
            "sql-injection-string-concat",
            r#"let q = query(format!("SELECT * FROM users WHERE id = {}", user_input));"#,
        ));
    }

    #[test]
    fn test_sql_injection_no_false_positive_parameterized() {
        // Parameterized queries should not match
        assert!(!rule_matches(
            "sql-injection-string-concat",
            r#"sqlx::query("SELECT * FROM users WHERE id = $1").bind(id)"#,
        ));
    }

    #[test]
    fn test_detect_sql_injection_fstring() {
        assert!(rule_matches(
            "sql-injection-fstring",
            r#"cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")"#,
        ));
    }

    // -----------------------------------------------------------------------
    // Command injection
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_command_injection() {
        // The command-injection rule looks for: system/exec/popen/subprocess.call etc.
        // followed by format!/+\s*\w+/${}/%s
        assert!(rule_matches(
            "command-injection",
            r#"subprocess.call("ls " + user_input, shell=True)"#,
        ));
    }

    // -----------------------------------------------------------------------
    // Hardcoded secrets
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_hardcoded_api_key() {
        assert!(rule_matches(
            "hardcoded-api-key",
            r#"api_key = "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx""#,
        ));
    }

    #[test]
    fn test_detect_aws_access_key() {
        assert!(rule_matches(
            "aws-access-key",
            r#"AWS_KEY = "AKIAIOSFODNN7EXAMPLE""#,
        ));
    }

    #[test]
    fn test_detect_private_key() {
        assert!(rule_matches(
            "private-key",
            r#"-----BEGIN RSA PRIVATE KEY-----"#,
        ));
        assert!(rule_matches(
            "private-key",
            r#"-----BEGIN PRIVATE KEY-----"#,
        ));
    }

    // -----------------------------------------------------------------------
    // XSS
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_xss_innerhtml() {
        assert!(rule_matches(
            "xss-innerhtml",
            r#"element.innerHTML = userInput;"#,
        ));
    }

    #[test]
    fn test_detect_dangerously_set_inner_html() {
        assert!(rule_matches(
            "xss-dangerously-set",
            r#"<div dangerouslySetInnerHTML={{__html: data}} />"#,
        ));
    }

    // -----------------------------------------------------------------------
    // Unsafe deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_python_pickle() {
        assert!(rule_matches(
            "unsafe-deserialization-python",
            r#"data = pickle.loads(raw_bytes)"#,
        ));
    }

    #[test]
    fn test_detect_python_yaml_unsafe() {
        assert!(rule_matches(
            "unsafe-deserialization-python",
            r#"config = yaml.load(open("config.yml"))"#,
        ));
    }

    #[test]
    fn test_detect_java_deserialization() {
        assert!(rule_matches(
            "unsafe-deserialization-java",
            r#"ObjectInputStream ois = new ObjectInputStream(inputStream);"#,
        ));
    }

    // -----------------------------------------------------------------------
    // Weak hashing
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_md5_usage() {
        assert!(rule_matches("weak-hash-md5", r#"let hash = md5(data);"#));
    }

    #[test]
    fn test_detect_sha1_usage() {
        assert!(rule_matches("weak-hash-sha1", r#"let hash = sha1(data);"#));
    }

    // -----------------------------------------------------------------------
    // Helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_snippet_center() {
        let content = "line0\nline1\nline2\nline3\nline4";
        let snippet = extract_snippet(content, 2, 1);
        assert_eq!(snippet, "line1\nline2\nline3");
    }

    #[test]
    fn test_extract_snippet_at_start() {
        let content = "line0\nline1\nline2";
        let snippet = extract_snippet(content, 0, 2);
        // Start clamped to 0, end is min(0+2+1, 3) = 3
        assert_eq!(snippet, "line0\nline1\nline2");
    }

    #[test]
    fn test_extract_snippet_at_end() {
        let content = "line0\nline1\nline2";
        let snippet = extract_snippet(content, 2, 2);
        // Start = 2-2 = 0, end = min(2+2+1, 3) = 3
        assert_eq!(snippet, "line0\nline1\nline2");
    }

    #[test]
    fn test_make_fingerprint_deterministic() {
        let fp1 = make_fingerprint("rule-name", "file.rs", 10);
        let fp2 = make_fingerprint("rule-name", "file.rs", 10);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_make_fingerprint_differs_for_different_inputs() {
        let fp1 = make_fingerprint("rule-a", "file.rs", 10);
        let fp2 = make_fingerprint("rule-b", "file.rs", 10);
        assert_ne!(fp1, fp2);

        let fp3 = make_fingerprint("rule-a", "file.rs", 11);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn test_fingerprint_is_hex_sha256() {
        let fp = make_fingerprint("test", "file.rs", 1);
        assert_eq!(fp.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // Rule structure validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_rule_patterns_compile() {
        for rule in RULES {
            let result = Regex::new(rule.pattern);
            assert!(
                result.is_ok(),
                "Rule '{}' has invalid regex pattern: {}",
                rule.name,
                rule.pattern,
            );
        }
    }

    #[test]
    fn test_all_rules_have_cwe() {
        for rule in RULES {
            assert!(
                rule.cwe.starts_with("CWE-"),
                "Rule '{}' has invalid CWE: {}",
                rule.name,
                rule.cwe
            );
        }
    }

    #[test]
    fn test_all_rules_have_valid_severity() {
        let valid_severities = ["critical", "high", "medium", "low"];
        for rule in RULES {
            assert!(
                valid_severities.contains(&rule.severity),
                "Rule '{}' has invalid severity: {}",
                rule.name,
                rule.severity
            );
        }
    }
}
