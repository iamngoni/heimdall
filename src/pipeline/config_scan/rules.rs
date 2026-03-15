//
//  heimdall
//  src/pipeline/config_scan/rules.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/12.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

/// A configuration/IaC scanning rule.
pub struct ConfigRule {
    pub name: &'static str,
    pub pattern: &'static str,
    pub severity: &'static str,
    pub cwe: &'static str,
    pub description: &'static str,
    pub file_patterns: &'static [&'static str],
    /// If true, the rule is a "whole file" negative check — finding is created
    /// when the pattern does NOT match anywhere in the file.
    pub whole_file: bool,
}

pub const CONFIG_RULES: &[ConfigRule] = &[
    // -----------------------------------------------------------------------
    // Dockerfile
    // -----------------------------------------------------------------------
    ConfigRule {
        name: "docker-run-as-root",
        pattern: r#"(?m)^\s*USER\s+\S+"#,
        severity: "medium",
        cwe: "CWE-250",
        description: "Dockerfile has no USER directive — container runs as root by default",
        file_patterns: &["Dockerfile", "*.dockerfile"],
        whole_file: true, // Finding if pattern NOT found
    },
    ConfigRule {
        name: "docker-latest-tag",
        pattern: r#"(?i)^\s*FROM\s+\S+:latest\b"#,
        severity: "low",
        cwe: "CWE-1104",
        description: "Dockerfile uses :latest tag — pin to a specific version for reproducibility",
        file_patterns: &["Dockerfile", "*.dockerfile"],
        whole_file: false,
    },
    ConfigRule {
        name: "docker-copy-all",
        pattern: r#"^\s*COPY\s+\.\s+\."#,
        severity: "medium",
        cwe: "CWE-200",
        description: "Dockerfile uses COPY . . — may include secrets or unnecessary files",
        file_patterns: &["Dockerfile", "*.dockerfile"],
        whole_file: false,
    },
    ConfigRule {
        name: "docker-add-remote",
        pattern: r#"^\s*ADD\s+https?://"#,
        severity: "medium",
        cwe: "CWE-829",
        description: "Dockerfile uses ADD with remote URL — use COPY + curl for better control",
        file_patterns: &["Dockerfile", "*.dockerfile"],
        whole_file: false,
    },
    ConfigRule {
        name: "docker-secret-in-env",
        pattern: r#"(?i)^\s*(?:ENV|ARG)\s+(?:\w*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)\w*)\s*="#,
        severity: "high",
        cwe: "CWE-798",
        description: "Dockerfile exposes secret via ENV/ARG — use build secrets or runtime env instead",
        file_patterns: &["Dockerfile", "*.dockerfile"],
        whole_file: false,
    },
    ConfigRule {
        name: "docker-no-healthcheck",
        pattern: r#"(?m)^\s*HEALTHCHECK\s+"#,
        severity: "low",
        cwe: "CWE-693",
        description: "Dockerfile has no HEALTHCHECK — add one for container orchestration",
        file_patterns: &["Dockerfile", "*.dockerfile"],
        whole_file: true,
    },
    ConfigRule {
        name: "docker-expose-sensitive-port",
        pattern: r#"^\s*EXPOSE\s+(?:22|23|3389|5900)\b"#,
        severity: "medium",
        cwe: "CWE-284",
        description: "Dockerfile exposes sensitive port (SSH/Telnet/RDP/VNC)",
        file_patterns: &["Dockerfile", "*.dockerfile"],
        whole_file: false,
    },
    ConfigRule {
        name: "docker-apt-no-recommends",
        pattern: r#"apt-get\s+install\s+-y\s+(?:\w)"#,
        severity: "low",
        cwe: "CWE-1104",
        description: "apt-get install detected — consider using --no-install-recommends to reduce attack surface",
        file_patterns: &["Dockerfile", "*.dockerfile"],
        whole_file: false,
    },
    // -----------------------------------------------------------------------
    // Kubernetes
    // -----------------------------------------------------------------------
    ConfigRule {
        name: "k8s-privileged-container",
        pattern: r#"(?i)privileged:\s*true"#,
        severity: "critical",
        cwe: "CWE-250",
        description: "Kubernetes container running in privileged mode — full host access",
        file_patterns: &["*.yml", "*.yaml"],
        whole_file: false,
    },
    ConfigRule {
        name: "k8s-host-network",
        pattern: r#"(?i)hostNetwork:\s*true"#,
        severity: "high",
        cwe: "CWE-284",
        description: "Kubernetes pod uses host network — bypasses network isolation",
        file_patterns: &["*.yml", "*.yaml"],
        whole_file: false,
    },
    ConfigRule {
        name: "k8s-host-pid",
        pattern: r#"(?i)hostPID:\s*true"#,
        severity: "high",
        cwe: "CWE-284",
        description: "Kubernetes pod uses host PID namespace — can see all host processes",
        file_patterns: &["*.yml", "*.yaml"],
        whole_file: false,
    },
    ConfigRule {
        name: "k8s-run-as-root",
        pattern: r#"(?i)runAsNonRoot:\s*false"#,
        severity: "high",
        cwe: "CWE-250",
        description: "Kubernetes container explicitly allows running as root",
        file_patterns: &["*.yml", "*.yaml"],
        whole_file: false,
    },
    ConfigRule {
        name: "k8s-latest-image",
        pattern: r#"(?i)image:\s*\S+:latest\b"#,
        severity: "low",
        cwe: "CWE-1104",
        description: "Kubernetes manifest uses :latest image tag — pin to specific version",
        file_patterns: &["*.yml", "*.yaml"],
        whole_file: false,
    },
    ConfigRule {
        name: "k8s-plaintext-secret",
        pattern: r#"(?i)(?:password|secret_?key|api_?key|token):\s*["']?[A-Za-z0-9+/=_-]{8,}["']?"#,
        severity: "high",
        cwe: "CWE-798",
        description: "Potential plaintext secret in Kubernetes manifest — use Secrets or external vault",
        file_patterns: &["*.yml", "*.yaml"],
        whole_file: false,
    },
    ConfigRule {
        name: "k8s-capabilities-all",
        pattern: r#"(?i)capabilities:.*\n\s*add:.*\bALL\b"#,
        severity: "critical",
        cwe: "CWE-250",
        description: "Kubernetes container granted ALL capabilities — use minimal set",
        file_patterns: &["*.yml", "*.yaml"],
        whole_file: false,
    },
    ConfigRule {
        name: "k8s-no-resource-limits",
        pattern: r#"(?i)kind:\s*(?:Deployment|StatefulSet|DaemonSet|Pod)"#,
        severity: "medium",
        cwe: "CWE-770",
        description: "Kubernetes workload detected — verify resource limits are configured",
        file_patterns: &["*.yml", "*.yaml"],
        whole_file: false,
    },
    // -----------------------------------------------------------------------
    // Terraform
    // -----------------------------------------------------------------------
    ConfigRule {
        name: "tf-s3-no-encryption",
        pattern: r#"(?i)resource\s*"aws_s3_bucket"\s"#,
        severity: "high",
        cwe: "CWE-311",
        description: "S3 bucket defined — verify server-side encryption is enabled",
        file_patterns: &["*.tf"],
        whole_file: false,
    },
    ConfigRule {
        name: "tf-security-group-wide-open",
        pattern: r#"(?i)cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]"#,
        severity: "high",
        cwe: "CWE-284",
        description: "Terraform security group allows traffic from 0.0.0.0/0 — restrict source IPs",
        file_patterns: &["*.tf"],
        whole_file: false,
    },
    ConfigRule {
        name: "tf-rds-no-encryption",
        pattern: r#"(?i)storage_encrypted\s*=\s*false"#,
        severity: "high",
        cwe: "CWE-311",
        description: "Terraform RDS instance without encryption at rest",
        file_patterns: &["*.tf"],
        whole_file: false,
    },
    ConfigRule {
        name: "tf-hardcoded-credentials",
        pattern: r#"(?i)(?:access_key|secret_key|password)\s*=\s*"[^"]{8,}""#,
        severity: "critical",
        cwe: "CWE-798",
        description: "Hardcoded credentials in Terraform file — use variables or vault",
        file_patterns: &["*.tf", "*.tfvars"],
        whole_file: false,
    },
    ConfigRule {
        name: "tf-public-subnet-db",
        pattern: r#"(?i)(?:map_public_ip_on_launch|associate_public_ip_address)\s*=\s*true"#,
        severity: "medium",
        cwe: "CWE-284",
        description: "Terraform resource with public IP — ensure databases are in private subnets",
        file_patterns: &["*.tf"],
        whole_file: false,
    },
    ConfigRule {
        name: "tf-no-logging",
        pattern: r#"(?i)enable_logging\s*=\s*false"#,
        severity: "medium",
        cwe: "CWE-778",
        description: "Terraform resource has logging disabled — enable for audit trail",
        file_patterns: &["*.tf"],
        whole_file: false,
    },
    // -----------------------------------------------------------------------
    // CI/CD (GitHub Actions, GitLab CI, etc.)
    // -----------------------------------------------------------------------
    ConfigRule {
        name: "ci-plaintext-secret",
        pattern: r#"(?i)(?:password|secret|token|api_?key):\s*["']?[A-Za-z0-9+/=_-]{16,}["']?"#,
        severity: "critical",
        cwe: "CWE-798",
        description: "Plaintext secret in CI/CD configuration — use encrypted secrets",
        file_patterns: &[
            ".github/workflows/",
            ".gitlab-ci.yml",
            "Jenkinsfile",
            ".circleci/",
        ],
        whole_file: false,
    },
    ConfigRule {
        name: "ci-pull-request-target",
        pattern: r#"(?i)pull_request_target:"#,
        severity: "high",
        cwe: "CWE-284",
        description: "GitHub Actions uses pull_request_target — may allow arbitrary code execution from forks",
        file_patterns: &[".github/workflows/"],
        whole_file: false,
    },
    ConfigRule {
        name: "ci-unpinned-action",
        pattern: r#"(?i)uses:\s+[\w-]+/[\w-]+@v\d+\s*$"#,
        severity: "medium",
        cwe: "CWE-829",
        description: "GitHub Action pinned to mutable tag — use full SHA for supply chain security",
        file_patterns: &[".github/workflows/"],
        whole_file: false,
    },
    ConfigRule {
        name: "ci-self-hosted-runner",
        pattern: r#"(?i)runs-on:\s*self-hosted"#,
        severity: "medium",
        cwe: "CWE-284",
        description: "CI job runs on self-hosted runner — ensure runner security is hardened",
        file_patterns: &[".github/workflows/"],
        whole_file: false,
    },
    ConfigRule {
        name: "ci-permissions-write-all",
        pattern: r#"(?i)permissions:\s*write-all"#,
        severity: "high",
        cwe: "CWE-250",
        description: "GitHub Actions workflow has write-all permissions — use minimal permissions",
        file_patterns: &[".github/workflows/"],
        whole_file: false,
    },
    ConfigRule {
        name: "ci-npm-install",
        pattern: r#"(?i)\bnpm\s+install\b"#,
        severity: "low",
        cwe: "CWE-829",
        description: "npm install in CI — consider using npm ci for reproducible lockfile-based builds",
        file_patterns: &[".github/workflows/", ".gitlab-ci.yml", "Jenkinsfile"],
        whole_file: false,
    },
    // -----------------------------------------------------------------------
    // Environment / Config files
    // -----------------------------------------------------------------------
    ConfigRule {
        name: "env-debug-enabled",
        pattern: r#"(?i)(?:DEBUG\s*=\s*(?:true|1|yes)|FLASK_DEBUG\s*=\s*1|NODE_ENV\s*=\s*development)"#,
        severity: "medium",
        cwe: "CWE-489",
        description: "Debug mode or development environment enabled — disable in production",
        file_patterns: &[".env", ".env.production", "*.env"],
        whole_file: false,
    },
    ConfigRule {
        name: "env-database-password",
        pattern: r#"(?i)(?:DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL)\s*=\s*\S+://\S+:\S+@"#,
        severity: "high",
        cwe: "CWE-798",
        description: "Database connection string with embedded credentials in config file",
        file_patterns: &[
            ".env",
            ".env.production",
            "*.env",
            "*.conf",
            "*.cfg",
            "*.ini",
        ],
        whole_file: false,
    },
    ConfigRule {
        name: "env-default-credentials",
        pattern: r#"(?i)(?:password|passwd|secret)\s*=\s*(?:["']?(?:password|admin|root|default|changeme|12345|test)["']?)\s*$"#,
        severity: "high",
        cwe: "CWE-798",
        description: "Default or weak credentials in configuration file",
        file_patterns: &[
            ".env",
            "*.env",
            "*.conf",
            "*.cfg",
            "*.ini",
            "*.yml",
            "*.yaml",
            "*.properties",
        ],
        whole_file: false,
    },
    ConfigRule {
        name: "env-cors-wildcard",
        pattern: r#"(?i)(?:CORS_ORIGIN|ALLOWED_ORIGINS?|ACCESS_CONTROL_ALLOW_ORIGIN)\s*=\s*\*"#,
        severity: "medium",
        cwe: "CWE-942",
        description: "CORS configured to allow all origins — restrict to specific domains",
        file_patterns: &[".env", "*.env", "*.conf", "*.cfg"],
        whole_file: false,
    },
    ConfigRule {
        name: "env-no-tls",
        pattern: r#"(?i)(?:SSL_VERIFY|TLS_VERIFY|VERIFY_SSL)\s*=\s*(?:false|0|no)"#,
        severity: "high",
        cwe: "CWE-295",
        description: "TLS/SSL verification disabled — enables man-in-the-middle attacks",
        file_patterns: &[".env", "*.env", "*.conf", "*.cfg", "*.yml", "*.yaml"],
        whole_file: false,
    },
    ConfigRule {
        name: "env-secret-in-config",
        pattern: r#"(?i)(?:api_?key|secret_?key|private_?key|access_?token)\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{20,}["']?"#,
        severity: "high",
        cwe: "CWE-798",
        description: "Secret or API key hardcoded in configuration file",
        file_patterns: &[
            ".env",
            "*.env",
            "*.conf",
            "*.cfg",
            "*.ini",
            "*.properties",
            "config.yml",
            "config.yaml",
            "settings.yml",
        ],
        whole_file: false,
    },
    // -----------------------------------------------------------------------
    // Helm Charts
    // -----------------------------------------------------------------------
    ConfigRule {
        name: "helm-default-secret",
        pattern: r#"(?i)(?:password|secret|token):\s*(?:["']?\{\{[^}]*default\s+["'][^"']+["'])"#,
        severity: "medium",
        cwe: "CWE-798",
        description: "Helm chart has default value for secret — ensure override in production",
        file_patterns: &[
            "values.yml",
            "values.yaml",
            "*/templates/*.yml",
            "*/templates/*.yaml",
        ],
        whole_file: false,
    },
    ConfigRule {
        name: "helm-privileged",
        pattern: r#"(?i)privileged:\s*\{\{[^}]*default\s+true"#,
        severity: "high",
        cwe: "CWE-250",
        description: "Helm chart defaults to privileged container",
        file_patterns: &["*/templates/*.yml", "*/templates/*.yaml"],
        whole_file: false,
    },
    // -----------------------------------------------------------------------
    // Nginx / Apache config
    // -----------------------------------------------------------------------
    ConfigRule {
        name: "nginx-autoindex",
        pattern: r#"(?i)autoindex\s+on"#,
        severity: "medium",
        cwe: "CWE-548",
        description: "Nginx directory listing enabled — may expose sensitive files",
        file_patterns: &["nginx.conf", "*.nginx", "*.conf"],
        whole_file: false,
    },
    ConfigRule {
        name: "nginx-server-tokens",
        pattern: r#"(?i)server_tokens\s+on"#,
        severity: "low",
        cwe: "CWE-200",
        description: "Nginx server tokens enabled — exposes server version information",
        file_patterns: &["nginx.conf", "*.nginx", "*.conf"],
        whole_file: false,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_rules_have_valid_severity() {
        let valid = ["critical", "high", "medium", "low"];
        for rule in CONFIG_RULES {
            assert!(
                valid.contains(&rule.severity),
                "Config rule '{}' has invalid severity: {}",
                rule.name,
                rule.severity
            );
        }
    }

    #[test]
    fn test_all_rules_have_cwe() {
        for rule in CONFIG_RULES {
            assert!(
                rule.cwe.starts_with("CWE-"),
                "Config rule '{}' has invalid CWE: {}",
                rule.name,
                rule.cwe
            );
        }
    }

    #[test]
    fn test_all_rules_have_file_patterns() {
        for rule in CONFIG_RULES {
            assert!(
                !rule.file_patterns.is_empty(),
                "Config rule '{}' has no file patterns",
                rule.name
            );
        }
    }

    #[test]
    fn test_dockerfile_latest_tag_matches() {
        let re = regex::Regex::new(
            CONFIG_RULES
                .iter()
                .find(|r| r.name == "docker-latest-tag")
                .unwrap()
                .pattern,
        )
        .unwrap();
        assert!(re.is_match("FROM node:latest"));
        assert!(re.is_match("FROM python:latest AS builder"));
        assert!(!re.is_match("FROM node:18-alpine"));
    }

    #[test]
    fn test_k8s_privileged_matches() {
        let re = regex::Regex::new(
            CONFIG_RULES
                .iter()
                .find(|r| r.name == "k8s-privileged-container")
                .unwrap()
                .pattern,
        )
        .unwrap();
        assert!(re.is_match("    privileged: true"));
        assert!(!re.is_match("    privileged: false"));
    }

    #[test]
    fn test_tf_wide_open_sg_matches() {
        let re = regex::Regex::new(
            CONFIG_RULES
                .iter()
                .find(|r| r.name == "tf-security-group-wide-open")
                .unwrap()
                .pattern,
        )
        .unwrap();
        assert!(re.is_match(r#"  cidr_blocks = ["0.0.0.0/0"]"#));
        assert!(!re.is_match(r#"  cidr_blocks = ["10.0.0.0/8"]"#));
    }

    #[test]
    fn test_env_debug_matches() {
        let re = regex::Regex::new(
            CONFIG_RULES
                .iter()
                .find(|r| r.name == "env-debug-enabled")
                .unwrap()
                .pattern,
        )
        .unwrap();
        assert!(re.is_match("DEBUG=true"));
        assert!(re.is_match("FLASK_DEBUG=1"));
        assert!(re.is_match("NODE_ENV=development"));
    }
}
