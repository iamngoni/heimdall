//
//  heimdall
//  src/pipeline/static_analysis/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::collections::HashSet;
use std::sync::Arc;

use log::info;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::HeimdallResult;
use crate::pipeline::deps_audit::DepsAuditStage;

pub mod semgrep;

/// Static analysis stage using pattern matching for deterministic vulnerability detection.
/// Catches low-hanging fruit before the AI Hunt agent.
pub struct StaticAnalysisStage {
    pub scan_id: uuid::Uuid,
    pub repo_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
    pub work_dir: Option<std::path::PathBuf>,
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
    // -----------------------------------------------------------------------
    // Injection (extended)
    // -----------------------------------------------------------------------
    Rule {
        name: "ldap-injection",
        pattern: r#"(?i)(?:ldap_search|ldap_bind|ldap\.search|search_s)\s*\(.*(?:format!|\+\s*\w+|\$\{|%s|f["'])"#,
        severity: "high",
        cwe: "CWE-90",
        description: "Potential LDAP injection via string interpolation in LDAP query",
        languages: &["python", "javascript", "typescript", "java"],
    },
    Rule {
        name: "xxe-xml-parsing",
        pattern: r#"(?i)(?:XMLParser|etree\.parse|parseString|DocumentBuilder|SAXParser|XMLReader)\s*\("#,
        severity: "high",
        cwe: "CWE-611",
        description: "XML parsing without explicit XXE protection — disable external entities",
        languages: &["python", "java", "javascript", "typescript"],
    },
    Rule {
        name: "xpath-injection",
        pattern: r#"(?i)(?:xpath|evaluate)\s*\(.*(?:format!|\+\s*\w+|\$\{|%s|f["'])"#,
        severity: "high",
        cwe: "CWE-643",
        description: "Potential XPath injection via string interpolation",
        languages: &[],
    },
    Rule {
        name: "ssti-template-injection",
        pattern: r#"(?i)(?:render_template_string|Template\(|Jinja2|Environment\(\s*loader)\s*\(.*(?:request|params|input|\+\s*\w+)"#,
        severity: "critical",
        cwe: "CWE-1336",
        description: "Potential server-side template injection (SSTI)",
        languages: &["python", "javascript", "typescript"],
    },
    Rule {
        name: "nosql-injection",
        pattern: r#"(?i)(?:\.find|\.findOne|\.aggregate|\.update|\.delete)\s*\(\s*\{[^}]*(?:\$where|\$regex|\$ne|\$gt|\$lt)"#,
        severity: "high",
        cwe: "CWE-943",
        description: "Potential NoSQL injection via MongoDB operator in query",
        languages: &["javascript", "typescript", "python"],
    },
    Rule {
        name: "header-injection-crlf",
        pattern: r#"(?i)(?:set_header|setHeader|add_header|header)\s*\(.*(?:request|params|req\.|query|input)"#,
        severity: "medium",
        cwe: "CWE-113",
        description: "HTTP header set with user-controlled value — potential CRLF injection",
        languages: &[],
    },
    Rule {
        name: "log-injection",
        pattern: r#"(?i)(?:log\.(?:info|warn|error|debug)|logger\.(?:info|warn|error|debug)|console\.log)\s*\(.*(?:request|req\.|params|query|input)"#,
        severity: "low",
        cwe: "CWE-117",
        description: "User-controlled data in log output — potential log injection/forging",
        languages: &[],
    },
    // -----------------------------------------------------------------------
    // Auth & Session
    // -----------------------------------------------------------------------
    Rule {
        name: "hardcoded-jwt-secret",
        pattern: r#"(?i)(?:jwt\.sign|jwt\.encode|jwt\.decode|JWTManager|SECRET_KEY)\s*[:=\(].*["'][A-Za-z0-9+/=_-]{8,}["']"#,
        severity: "critical",
        cwe: "CWE-798",
        description: "Hardcoded JWT secret — use environment variables for secrets",
        languages: &[],
    },
    Rule {
        name: "permissive-cors",
        pattern: r#"(?i)(?:Access-Control-Allow-Origin|cors\(|CORS\(|allow_origin).*['"]\*['"]"#,
        severity: "medium",
        cwe: "CWE-942",
        description: "Permissive CORS policy allowing all origins",
        languages: &[],
    },
    Rule {
        name: "insecure-cookie",
        pattern: r#"(?i)(?:set_cookie|Set-Cookie|cookie\s*=).*(?:secure\s*[:=]\s*(?:false|False)|httponly\s*[:=]\s*(?:false|False))"#,
        severity: "medium",
        cwe: "CWE-614",
        description: "Cookie set without Secure or HttpOnly flag",
        languages: &[],
    },
    Rule {
        name: "session-fixation",
        pattern: r#"(?i)session\s*\[\s*['"]session_id['"]\s*\]\s*=\s*(?:request|params|req\.|query)"#,
        severity: "high",
        cwe: "CWE-384",
        description: "Session ID set from user-controlled input — potential session fixation",
        languages: &["python", "javascript", "typescript"],
    },
    Rule {
        name: "missing-auth-decorator",
        pattern: r#"@app\.route\([^)]*\)\s*\n\s*def\s+\w+\("#,
        severity: "low",
        cwe: "CWE-862",
        description: "Flask route without apparent authentication decorator",
        languages: &["python"],
    },
    // -----------------------------------------------------------------------
    // Crypto
    // -----------------------------------------------------------------------
    Rule {
        name: "weak-random",
        pattern: r#"(?i)(?:Math\.random\(\)|rand\(\)|random\.random\(\)|random\.randint|random\.choice)"#,
        severity: "medium",
        cwe: "CWE-338",
        description: "Weak random number generator — use cryptographically secure alternatives for security contexts",
        languages: &[],
    },
    Rule {
        name: "ecb-mode",
        pattern: r#"(?i)(?:ECB|MODE_ECB|AES\.new\([^)]*ECB|Cipher\.getInstance\(\s*["']AES["']\s*\))"#,
        severity: "high",
        cwe: "CWE-327",
        description: "ECB mode detected — use CBC, CTR, or GCM mode instead",
        languages: &[],
    },
    Rule {
        name: "hardcoded-iv-nonce",
        pattern: r#"(?i)(?:iv|nonce|initialization_vector)\s*[:=]\s*(?:b["']|["'])[A-Za-z0-9+/=]{8,}["']"#,
        severity: "medium",
        cwe: "CWE-329",
        description: "Hardcoded IV/nonce — use a random value for each encryption",
        languages: &[],
    },
    // -----------------------------------------------------------------------
    // Data Exposure
    // -----------------------------------------------------------------------
    Rule {
        name: "stack-trace-exposure",
        pattern: r#"(?i)(?:traceback\.print_exc|e\.printStackTrace|\.backtrace\(\)|print_stacktrace)"#,
        severity: "medium",
        cwe: "CWE-209",
        description: "Stack trace printed — may leak sensitive information to users",
        languages: &[],
    },
    Rule {
        name: "debug-mode-production",
        pattern: r#"(?i)(?:DEBUG\s*=\s*True|app\.debug\s*=\s*True|debug:\s*true|FLASK_DEBUG\s*=\s*1)"#,
        severity: "medium",
        cwe: "CWE-489",
        description: "Debug mode enabled — disable in production deployments",
        languages: &[],
    },
    Rule {
        name: "verbose-error-response",
        pattern: r#"(?i)(?:res\.send|res\.json|response\.write|render)\s*\(.*(?:err\.message|error\.stack|e\.getMessage)"#,
        severity: "medium",
        cwe: "CWE-209",
        description: "Error details sent in response — may expose sensitive internal information",
        languages: &["javascript", "typescript", "java"],
    },
    Rule {
        name: "todo-with-secret",
        pattern: r#"(?i)(?://|#)\s*(?:TODO|FIXME|HACK|XXX).*(?:password|secret|key|token|credential)"#,
        severity: "low",
        cwe: "CWE-615",
        description: "Comment references secrets — ensure no credentials in source comments",
        languages: &[],
    },
    // -----------------------------------------------------------------------
    // Memory & Resource Safety
    // -----------------------------------------------------------------------
    Rule {
        name: "buffer-overflow-c",
        pattern: r#"(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\("#,
        severity: "critical",
        cwe: "CWE-120",
        description: "Use of unsafe C function prone to buffer overflow — use bounded alternatives",
        languages: &["c", "cpp"],
    },
    Rule {
        name: "use-after-free",
        pattern: r#"(?:free|delete|kfree)\s*\(\s*\w+\s*\)"#,
        severity: "critical",
        cwe: "CWE-416",
        description: "Memory deallocation detected — verify no use-after-free of freed pointer",
        languages: &["c", "cpp"],
    },
    Rule {
        name: "integer-overflow",
        pattern: r#"(?i)(?:as\s+(?:u8|u16|i8|i16|u32|i32)|\(\s*(?:int|short|byte)\s*\)\s*\w+)"#,
        severity: "medium",
        cwe: "CWE-190",
        description: "Potential integer overflow from narrowing cast",
        languages: &["rust", "java", "c", "cpp"],
    },
    // -----------------------------------------------------------------------
    // Misc
    // -----------------------------------------------------------------------
    Rule {
        name: "regex-dos",
        pattern: r#"(?:Regex::new|re\.compile|new RegExp)\s*\(.*(?:\.\*\.\*|\(.+\|\.\+\)\*|\(\.\+\)\+)"#,
        severity: "medium",
        cwe: "CWE-1333",
        description: "Potentially catastrophic regex — may cause ReDoS with crafted input",
        languages: &[],
    },
    Rule {
        name: "ssrf",
        pattern: r#"(?i)(?:requests\.get|fetch|http\.get|urllib\.request|HttpClient|curl_exec)\s*\(.*(?:request|params|req\.|query|input|user)"#,
        severity: "high",
        cwe: "CWE-918",
        description: "HTTP request with user-controlled URL — potential SSRF",
        languages: &[],
    },
    Rule {
        name: "toctou-race",
        pattern: r#"(?i)(?:os\.path\.exists|File\.exists|access)\s*\([^)]+\).*\n.*(?:open|read|write|unlink|remove)\s*\("#,
        severity: "medium",
        cwe: "CWE-367",
        description: "Time-of-check to time-of-use (TOCTOU) race condition on file operation",
        languages: &["python", "java", "c", "cpp"],
    },
    Rule {
        name: "prototype-pollution",
        pattern: r#"(?:__proto__|constructor\s*\.\s*prototype|Object\.assign\s*\(\s*\{\s*\})"#,
        severity: "high",
        cwe: "CWE-1321",
        description: "Potential prototype pollution via __proto__ or constructor.prototype",
        languages: &["javascript", "typescript"],
    },
    // -----------------------------------------------------------------------
    // Additional Secrets
    // -----------------------------------------------------------------------
    Rule {
        name: "github-token",
        pattern: r#"(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})"#,
        severity: "critical",
        cwe: "CWE-798",
        description: "GitHub personal access token or OAuth token detected",
        languages: &[],
    },
    Rule {
        name: "slack-token",
        pattern: r#"xox[bporas]-[0-9]{10,13}-[A-Za-z0-9-]{20,}"#,
        severity: "critical",
        cwe: "CWE-798",
        description: "Slack API token detected",
        languages: &[],
    },
    Rule {
        name: "google-api-key",
        pattern: r#"AIza[0-9A-Za-z_-]{35}"#,
        severity: "high",
        cwe: "CWE-798",
        description: "Google API key detected",
        languages: &[],
    },
    Rule {
        name: "connection-string-password",
        pattern: r#"(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^:]+:[^@\s]+@"#,
        severity: "high",
        cwe: "CWE-798",
        description: "Connection string with embedded password detected",
        languages: &[],
    },
];

impl StaticAnalysisStage {
    pub fn new(scan_id: uuid::Uuid, repo_id: uuid::Uuid, db: Arc<DatabaseOperations>) -> Self {
        Self {
            scan_id,
            repo_id,
            db,
            work_dir: None,
        }
    }

    pub fn with_work_dir(mut self, work_dir: std::path::PathBuf) -> Self {
        self.work_dir = Some(work_dir);
        self
    }

    pub async fn run(&self, index: &CodeIndex) -> HeimdallResult<StaticAnalysisContext> {
        info!("[{}] Starting static analysis", self.scan_id);

        let mut total_findings = 0usize;
        let mut summary_parts = Vec::new();
        let mut pattern_findings = 0usize;

        self.record_event(
            Some("pattern-scan"),
            "running",
            "Running deterministic code pattern checks",
            Some("Inspecting the codebase for known vulnerable patterns and dangerous APIs."),
            None,
            None,
        )
        .await;
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
                        pattern_findings += 1;
                    }
                }
            }
        }
        self.record_event(
            Some("pattern-scan"),
            "completed",
            "Deterministic pattern checks finished",
            Some(&format!(
                "{pattern_findings} findings recorded from regex and rule-based checks."
            )),
            Some(45),
            Some(&serde_json::json!({
                "findings": pattern_findings,
            })),
        )
        .await;

        // Secret detection via entropy analysis
        self.record_event(
            Some("secret-scan"),
            "running",
            "Scanning for embedded secrets",
            Some("Checking source files for high-entropy tokens and secret-like literals."),
            None,
            None,
        )
        .await;
        let secret_count = self.detect_secrets(index).await?;
        total_findings += secret_count;
        self.record_event(
            Some("secret-scan"),
            "completed",
            "Secret scan finished",
            Some(&format!(
                "{secret_count} potential secret findings recorded."
            )),
            Some(70),
            Some(&serde_json::json!({
                "findings": secret_count,
            })),
        )
        .await;

        self.record_event(
            Some("dependency-audit"),
            "running",
            "Auditing dependencies",
            Some("Reviewing manifest files against OSV for known vulnerable packages."),
            None,
            None,
        )
        .await;
        let deps_count = match DepsAuditStage::new(self.scan_id, self.repo_id, Arc::clone(&self.db))
            .run(index)
            .await
        {
            Ok(vulns) => {
                let count = vulns.len();
                self.record_event(
                    Some("dependency-audit"),
                    "completed",
                    "Dependency audit finished",
                    Some(&format!("{count} vulnerable dependency findings recorded.")),
                    Some(100),
                    Some(&serde_json::json!({
                        "findings": count,
                    })),
                )
                .await;
                count
            }
            Err(error) => {
                self.record_event(
                    Some("dependency-audit"),
                    "failed",
                    "Dependency audit failed",
                    Some(&error.to_string()),
                    None,
                    None,
                )
                .await;
                0
            }
        };
        total_findings += deps_count;

        // Semgrep integration (optional — runs if semgrep is installed)
        if let Some(ref work_dir) = self.work_dir {
            self.record_event(
                Some("semgrep-scan"),
                "running",
                "Running Semgrep analysis",
                Some("Executing Semgrep with auto-config rules for enhanced vulnerability detection."),
                None,
                None,
            )
            .await;

            // Collect existing fingerprints for deduplication
            let existing_fingerprints: HashSet<String> = if let Ok(findings) = self
                .db
                .list_findings_by_scan(self.scan_id, None, None)
                .await
            {
                findings.iter().map(|f| f.fingerprint.clone()).collect()
            } else {
                HashSet::new()
            };

            let semgrep_stage =
                semgrep::SemgrepStage::new(self.scan_id, self.repo_id, Arc::clone(&self.db));
            match semgrep_stage.run(work_dir, &existing_fingerprints).await {
                Ok(semgrep_count) => {
                    total_findings += semgrep_count;
                    self.record_event(
                        Some("semgrep-scan"),
                        "completed",
                        "Semgrep analysis finished",
                        Some(&format!(
                            "{semgrep_count} additional findings from Semgrep."
                        )),
                        Some(100),
                        Some(&serde_json::json!({
                            "findings": semgrep_count,
                        })),
                    )
                    .await;
                }
                Err(error) => {
                    self.record_event(
                        Some("semgrep-scan"),
                        "failed",
                        "Semgrep analysis failed",
                        Some(&error.to_string()),
                        None,
                        None,
                    )
                    .await;
                }
            }
        }

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
                Some("static_analysis"),
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

    /// Detect high-entropy strings that might be secrets.
    async fn detect_secrets(&self, index: &CodeIndex) -> HeimdallResult<usize> {
        let mut count = 0usize;

        for (file_path, file) in &index.files {
            // Skip non-code files for entropy analysis
            if file.language.is_none() {
                continue;
            }

            for (line_idx, line) in file.content.lines().enumerate() {
                if let Some(secret_literal) = find_secret_candidate(line) {
                    let line_num = (line_idx + 1) as i32;
                    let fingerprint = make_fingerprint("high-entropy-secret", file_path, line_num);
                    let detail = format!(
                        "Potential hardcoded secret-like literal detected: `{secret_literal}`"
                    );
                    let snippet = extract_snippet(&file.content, line_idx, 2);

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
                            Some(&snippet),
                            &fingerprint,
                            Some(&detail),
                        )
                        .await;

                    count += 1;
                }
            }
        }

        Ok(count)
    }
}

fn find_secret_candidate(line: &str) -> Option<String> {
    static QUOTED_LITERAL_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"["']([^"'\\\n]{20,})["']"#).unwrap());
    static SECRET_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?ix)
                (?:api(?:_|-)?key|secret|secret(?:_|-)?key|token|access(?:_|-)?token|
                   refresh(?:_|-)?token|password|passwd|private(?:_|-)?key|
                   access(?:_|-)?key|client(?:_|-)?secret|encryption(?:_|-)?(?:key|iv)|
                   credential|bearer|session(?:_|-)?secret)
                \s*[:=]
            "#,
        )
        .unwrap()
    });

    if !SECRET_CONTEXT.is_match(line) {
        return None;
    }

    QUOTED_LITERAL_RE
        .captures_iter(line)
        .filter_map(|captures| captures.get(1).map(|matched| matched.as_str()))
        .find(|literal| looks_like_secret_literal(literal))
        .map(ToString::to_string)
}

fn looks_like_secret_literal(literal: &str) -> bool {
    if literal.len() < 24 || looks_like_structured_path(literal) || looks_like_uuid(literal) {
        return false;
    }

    let classes = char_classes(literal);
    let entropy = shannon_entropy(literal);

    (classes >= 3 || (is_hex_like(literal) && literal.len() >= 32)) && entropy >= 3.5
}

fn looks_like_structured_path(literal: &str) -> bool {
    let slash_count = literal.matches('/').count();

    literal.starts_with('/')
        || literal.starts_with("./")
        || literal.starts_with("../")
        || literal.contains("://")
        || literal.contains('?')
        || literal.contains('&')
        || literal.contains('\\')
        || literal.contains(' ')
        || literal.contains('\t')
        || slash_count >= 2
}

fn looks_like_uuid(literal: &str) -> bool {
    static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            .unwrap()
    });

    UUID_RE.is_match(literal)
}

fn is_hex_like(literal: &str) -> bool {
    literal
        .chars()
        .all(|character| character.is_ascii_hexdigit())
}

fn char_classes(literal: &str) -> usize {
    let mut classes = HashSet::new();

    for character in literal.chars() {
        if character.is_ascii_lowercase() {
            classes.insert("lower");
        } else if character.is_ascii_uppercase() {
            classes.insert("upper");
        } else if character.is_ascii_digit() {
            classes.insert("digit");
        } else if matches!(character, '+' | '/' | '=' | '_' | '-') {
            classes.insert("symbol");
        }
    }

    classes.len()
}

fn shannon_entropy(literal: &str) -> f64 {
    let mut frequencies = std::collections::HashMap::new();
    let total = literal.chars().count() as f64;

    for character in literal.chars() {
        *frequencies.entry(character).or_insert(0usize) += 1;
    }

    frequencies
        .values()
        .map(|count| {
            let probability = *count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
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

    #[test]
    fn test_find_secret_candidate_detects_encryption_key_literal() {
        let line =
            r#"private static readonly ENCRYPTION_KEY = "6uRGxB8V6kshhuXI2BedlQqkW8WGCcgg";"#;
        assert_eq!(
            find_secret_candidate(line).as_deref(),
            Some("6uRGxB8V6kshhuXI2BedlQqkW8WGCcgg")
        );
    }

    #[test]
    fn test_find_secret_candidate_ignores_api_route_string() {
        let line = r#"app.get("/api/applications/failed-authorization", async (req, res) => {"#;
        assert!(find_secret_candidate(line).is_none());
    }

    #[test]
    fn test_find_secret_candidate_ignores_fetch_endpoint() {
        let line = r#"const response = await fetch("/api/automations/available-tables");"#;
        assert!(find_secret_candidate(line).is_none());
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
