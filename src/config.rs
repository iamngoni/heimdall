//
//  heimdall
//  src/config.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use anyhow::{Context, Result};
use std::env;

fn env_nonempty(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_nonempty_or(name: &str, default: &str) -> String {
    env_nonempty(name).unwrap_or_else(|| default.to_string())
}

#[derive(Debug, Clone)]
pub struct Config {
    pub app: AppConfig,
    pub database: DatabaseConfig,
    pub ai: AiConfig,
    pub security: SecurityConfig,
    pub github_oauth: GithubOAuthConfig,
    pub gitlab_oauth: GitlabOAuthConfig,
    pub bitbucket_oauth: BitbucketOAuthConfig,
    pub webhook: WebhookConfig,
    pub semgrep: SemgrepConfig,
}

/// Configuration for the Semgrep static analysis integration.
///
/// Semgrep is a required runtime dependency. `Config::from_env` verifies the
/// binary is on PATH (or at `SEMGREP_BIN`) at startup so deployments fail fast
/// instead of silently producing degraded scans.
#[derive(Debug, Clone)]
pub struct SemgrepConfig {
    /// Path to the semgrep binary. Defaults to `semgrep` (resolved via PATH).
    /// Override with `SEMGREP_BIN` for custom installs (e.g., virtualenv paths).
    pub binary_path: String,
    /// Rule config passed to `semgrep scan --config`. Defaults to `auto`.
    /// Operators may set `SEMGREP_CONFIG` to pin registry rules (`p/owasp-top-ten`),
    /// a local rules directory, or a registry URL.
    pub config: String,
    /// Per-scan timeout passed to semgrep (`--timeout`). Seconds. Default 120.
    pub timeout_seconds: u32,
}

#[derive(Debug, Clone)]
pub struct GithubOAuthConfig {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
}

#[derive(Debug, Clone)]
pub struct GitlabOAuthConfig {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub base_url: String,
}

#[derive(Debug, Clone)]
pub struct BitbucketOAuthConfig {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// 64 hex-char encryption key for AES-256-GCM. Read from ENCRYPTION_KEY env var.
    pub encryption_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub port: u16,
    pub host: String,
    pub tls_enabled: bool,
    pub cors_allowed_origin: String,
    /// Persistent data directory for uploads, scan working copies, etc.
    /// Defaults to `./data`. Set via `DATA_DIR` env var.
    pub data_dir: String,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct AiConfig {
    pub anthropic_api_key: Option<String>,
    pub openai_api_key: Option<String>,
    pub openai_compatible_api_key: Option<String>,
    pub openai_compatible_base_url: Option<String>,
    pub openai_compatible_model: Option<String>,
    pub xai_api_key: Option<String>,
    pub ollama_url: Option<String>,
    pub default_model: String,
}

/// Configuration for webhook signature verification (GitHub / GitLab push events).
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Shared secret used to verify webhook payload signatures.
    /// - GitHub: HMAC-SHA256 verification against `X-Hub-Signature-256`.
    /// - GitLab: direct string comparison against `X-Gitlab-Token`.
    pub webhook_secret: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            app: AppConfig::from_env()?,
            database: DatabaseConfig::from_env()?,
            ai: AiConfig::from_env(),
            security: SecurityConfig::from_env(),
            github_oauth: GithubOAuthConfig::from_env(),
            gitlab_oauth: GitlabOAuthConfig::from_env(),
            bitbucket_oauth: BitbucketOAuthConfig::from_env(),
            webhook: WebhookConfig::from_env(),
            semgrep: SemgrepConfig::from_env()?,
        })
    }
}

impl SemgrepConfig {
    fn from_env() -> Result<Self> {
        let binary_path = env_nonempty_or("SEMGREP_BIN", "semgrep");
        let config = env_nonempty_or("SEMGREP_CONFIG", "auto");
        let timeout_seconds: u32 = env_nonempty("SEMGREP_TIMEOUT_SECS")
            .map(|value| value.parse::<u32>())
            .transpose()
            .context("SEMGREP_TIMEOUT_SECS must be a positive integer")?
            .unwrap_or(120);

        // Fail-fast: verify the binary is invokable. `semgrep --version` exits 0
        // when installed, so any error here means misconfiguration.
        let probe = std::process::Command::new(&binary_path)
            .arg("--version")
            .output();

        match probe {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!(
                    "Semgrep found at `{binary_path}` but `--version` exited with {}: {}. \
                     Install semgrep (`pip install semgrep`) or set SEMGREP_BIN to a valid binary.",
                    output.status,
                    stderr.trim()
                );
            }
            Err(error) => {
                anyhow::bail!(
                    "Semgrep is a required runtime dependency but could not be executed at \
                     `{binary_path}`: {error}. Install semgrep (`pip install semgrep` or `brew install semgrep`) or set \
                     SEMGREP_BIN to the absolute path of the binary.",
                );
            }
        }

        Ok(SemgrepConfig {
            binary_path,
            config,
            timeout_seconds,
        })
    }
}

impl WebhookConfig {
    fn from_env() -> Self {
        WebhookConfig {
            webhook_secret: env_nonempty("WEBHOOK_SECRET"),
        }
    }

    /// Returns true if a webhook secret is configured.
    pub fn is_configured(&self) -> bool {
        self.webhook_secret.is_some()
    }
}

impl AppConfig {
    fn from_env() -> Result<Self> {
        Ok(AppConfig {
            port: env::var("APP_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse::<u16>()
                .context("APP_PORT must be a valid port number")?,
            host: env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            tls_enabled: env::var("TLS_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse::<bool>()
                .unwrap_or(false),
            cors_allowed_origin: env::var("CORS_ALLOWED_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            data_dir: env_nonempty_or("DATA_DIR", "./data"),
        })
    }
}

impl DatabaseConfig {
    fn from_env() -> Result<Self> {
        let url = env::var("DATABASE_URL").context(
            "DATABASE_URL must be set (e.g., postgres://user:<password>@localhost:5432/heimdall)",
        )?;
        Ok(DatabaseConfig { url })
    }
}

impl AiConfig {
    fn from_env() -> Self {
        AiConfig {
            anthropic_api_key: env_nonempty("ANTHROPIC_API_KEY"),
            openai_api_key: env_nonempty("OPENAI_API_KEY"),
            openai_compatible_api_key: env_nonempty("OPENAI_COMPATIBLE_API_KEY")
                .or_else(|| env_nonempty("CUSTOM_OPENAI_API_KEY")),
            openai_compatible_base_url: env_nonempty("OPENAI_COMPATIBLE_BASE_URL")
                .or_else(|| env_nonempty("CUSTOM_OPENAI_BASE_URL")),
            openai_compatible_model: env_nonempty("OPENAI_COMPATIBLE_MODEL")
                .or_else(|| env_nonempty("CUSTOM_OPENAI_MODEL")),
            xai_api_key: env_nonempty("XAI_API_KEY"),
            ollama_url: env_nonempty("OLLAMA_URL"),
            default_model: env_nonempty_or("DEFAULT_AI_MODEL", "claude-sonnet-5"),
        }
    }

    /// Returns true if at least one AI provider is configured.
    pub fn has_provider(&self) -> bool {
        self.anthropic_api_key.is_some()
            || self.openai_api_key.is_some()
            || (self.openai_compatible_base_url.is_some() && self.openai_compatible_model.is_some())
            || self.xai_api_key.is_some()
            || self.ollama_url.is_some()
    }
}

impl SecurityConfig {
    fn from_env() -> Self {
        SecurityConfig {
            encryption_key: env_nonempty("ENCRYPTION_KEY"),
        }
    }
}

impl GithubOAuthConfig {
    fn from_env() -> Self {
        GithubOAuthConfig {
            client_id: env_nonempty("GITHUB_CLIENT_ID"),
            client_secret: env_nonempty("GITHUB_CLIENT_SECRET"),
            redirect_uri: env_nonempty_or(
                "GITHUB_REDIRECT_URI",
                "http://localhost:8080/api/auth/github/callback",
            ),
        }
    }

    /// Returns true if both client_id and client_secret are configured.
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some()
    }
}

impl GitlabOAuthConfig {
    fn from_env() -> Self {
        GitlabOAuthConfig {
            client_id: env_nonempty("GITLAB_CLIENT_ID"),
            client_secret: env_nonempty("GITLAB_CLIENT_SECRET"),
            redirect_uri: env_nonempty_or(
                "GITLAB_REDIRECT_URI",
                "http://localhost:8080/api/auth/gitlab/callback",
            ),
            base_url: env_nonempty_or("GITLAB_BASE_URL", "https://gitlab.com"),
        }
    }

    /// Returns true if both client_id and client_secret are configured.
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some()
    }
}

impl BitbucketOAuthConfig {
    fn from_env() -> Self {
        BitbucketOAuthConfig {
            client_id: env_nonempty("BITBUCKET_CLIENT_ID"),
            client_secret: env_nonempty("BITBUCKET_CLIENT_SECRET"),
            redirect_uri: env_nonempty_or(
                "BITBUCKET_REDIRECT_URI",
                "http://localhost:8080/api/auth/bitbucket/callback",
            ),
        }
    }

    /// Returns true if both client_id and client_secret are configured.
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some()
    }
}
