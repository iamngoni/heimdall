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

#[derive(Debug, Clone)]
pub struct Config {
    pub app: AppConfig,
    pub database: DatabaseConfig,
    pub ai: AiConfig,
    pub security: SecurityConfig,
    pub github_oauth: GithubOAuthConfig,
    pub gitlab_oauth: GitlabOAuthConfig,
    pub webhook: WebhookConfig,
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
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct AiConfig {
    pub anthropic_api_key: Option<String>,
    pub openai_api_key: Option<String>,
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
            webhook: WebhookConfig::from_env(),
        })
    }
}

impl WebhookConfig {
    fn from_env() -> Self {
        WebhookConfig {
            webhook_secret: env::var("WEBHOOK_SECRET").ok().filter(|s| !s.is_empty()),
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
        })
    }
}

impl DatabaseConfig {
    fn from_env() -> Result<Self> {
        let url = env::var("DATABASE_URL").context(
            "DATABASE_URL must be set (e.g., postgres://user:pass@localhost:5432/heimdall)",
        )?;
        Ok(DatabaseConfig { url })
    }
}

impl AiConfig {
    fn from_env() -> Self {
        AiConfig {
            anthropic_api_key: env::var("ANTHROPIC_API_KEY").ok().filter(|s| !s.is_empty()),
            openai_api_key: env::var("OPENAI_API_KEY").ok().filter(|s| !s.is_empty()),
            ollama_url: env::var("OLLAMA_URL").ok().filter(|s| !s.is_empty()),
            default_model: env::var("DEFAULT_AI_MODEL")
                .unwrap_or_else(|_| "claude-sonnet-4-20250514".to_string()),
        }
    }

    /// Returns true if at least one AI provider is configured.
    pub fn has_provider(&self) -> bool {
        self.anthropic_api_key.is_some()
            || self.openai_api_key.is_some()
            || self.ollama_url.is_some()
    }
}

impl SecurityConfig {
    fn from_env() -> Self {
        SecurityConfig {
            encryption_key: env::var("ENCRYPTION_KEY").ok().filter(|s| !s.is_empty()),
        }
    }
}

impl GithubOAuthConfig {
    fn from_env() -> Self {
        GithubOAuthConfig {
            client_id: env::var("GITHUB_CLIENT_ID").ok().filter(|s| !s.is_empty()),
            client_secret: env::var("GITHUB_CLIENT_SECRET")
                .ok()
                .filter(|s| !s.is_empty()),
            redirect_uri: env::var("GITHUB_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:8080/api/auth/github/callback".to_string()),
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
            client_id: env::var("GITLAB_CLIENT_ID").ok().filter(|s| !s.is_empty()),
            client_secret: env::var("GITLAB_CLIENT_SECRET")
                .ok()
                .filter(|s| !s.is_empty()),
            redirect_uri: env::var("GITLAB_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:8080/api/auth/gitlab/callback".to_string()),
            base_url: env::var("GITLAB_BASE_URL")
                .unwrap_or_else(|_| "https://gitlab.com".to_string()),
        }
    }

    /// Returns true if both client_id and client_secret are configured.
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some()
    }
}
