//
//  heimdall
//  src/state.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use log::warn;
use uuid::Uuid;

use crate::ai::{self, ModelProvider, ProviderKind};
use crate::config::{AiConfig, Config};
use crate::crypto;
use crate::db::DatabaseOperations;
use crate::models::ApiKey;
use crate::sse::ScanBroadcaster;
use crate::templates::ThemeRegistry;

#[derive(Clone)]
pub struct ResolvedAiRuntime {
    pub provider: Arc<dyn ModelProvider>,
    pub model: String,
    pub provider_kind: ProviderKind,
    pub source: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeProviderSource {
    Stored,
    Environment,
}

impl RuntimeProviderSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Environment => "environment",
        }
    }
}

struct ResolvedProviderCandidate {
    provider: Box<dyn ModelProvider>,
    model: String,
    provider_kind: ProviderKind,
    source: RuntimeProviderSource,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Arc<DatabaseOperations>,
    pub ai: Option<Arc<dyn ModelProvider>>,
    pub sse: Arc<ScanBroadcaster>,
    pub themes: Arc<ThemeRegistry>,
    pub encryption_key: Option<[u8; 32]>,
    pub worker_enabled: bool,
}

impl AppState {
    pub fn init(
        config: Config,
        db: DatabaseOperations,
        ai: Option<Box<dyn ModelProvider>>,
        sse: ScanBroadcaster,
        themes: Arc<ThemeRegistry>,
        worker_enabled: bool,
    ) -> Self {
        let encryption_key =
            config.security.encryption_key.as_deref().and_then(
                |hex_str| match crypto::parse_hex_key(hex_str) {
                    Ok(key) => Some(key),
                    Err(e) => {
                        log::warn!(
                            "ENCRYPTION_KEY is set but invalid ({e:#}); \
                         falling back to hex encoding for API keys"
                        );
                        None
                    }
                },
            );

        Self {
            config: Arc::new(config),
            db: Arc::new(db),
            ai: ai.map(Arc::from),
            sse: Arc::new(sse),
            themes,
            encryption_key,
            worker_enabled,
        }
    }

    /// Returns the AI provider or an error if none is configured.
    pub fn require_ai(&self) -> anyhow::Result<&dyn ModelProvider> {
        self.ai.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "No AI provider configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_URL."
            )
        })
    }

    pub async fn resolve_ai_for_user(&self, user_id: Uuid) -> anyhow::Result<ResolvedAiRuntime> {
        let stored_keys = self.db.list_runtime_api_keys_by_user(user_id).await?;
        let preferred_provider = ai::provider_kind_from_model(&self.config.ai.default_model);
        let mut candidates = self.resolve_ai_candidates(&stored_keys, preferred_provider);

        if candidates.is_empty() {
            anyhow::bail!(
                "No AI provider configured. Add an Anthropic, OpenAI, or Ollama key in Settings, or configure server env vars."
            );
        }

        let primary_provider_kind = candidates[0].provider_kind;
        let primary_model = candidates[0].model.clone();
        let primary_source = candidates[0].source.as_str();

        let provider: Arc<dyn ModelProvider> = if candidates.len() == 1 {
            Arc::from(candidates.remove(0).provider)
        } else {
            let mut chain = ai::fallback::FallbackProvider::new();
            for candidate in candidates {
                chain = chain.add(candidate.provider, candidate.model);
            }
            let provider: Box<dyn ModelProvider> = Box::new(chain);
            Arc::from(provider)
        };

        Ok(ResolvedAiRuntime {
            provider,
            model: primary_model,
            provider_kind: primary_provider_kind,
            source: primary_source,
        })
    }

    fn resolve_ai_candidates(
        &self,
        stored_keys: &[ApiKey],
        preferred_provider: Option<ProviderKind>,
    ) -> Vec<ResolvedProviderCandidate> {
        let mut candidates = Vec::new();

        for (provider_kind, source) in
            runtime_provider_plan(&self.config.ai, stored_keys, preferred_provider)
        {
            match source {
                RuntimeProviderSource::Stored => {
                    let Some(api_key) = stored_keys
                        .iter()
                        .find(|key| key.provider.as_deref() == Some(provider_kind.as_str()))
                    else {
                        continue;
                    };

                    match self.provider_candidate_from_stored_key(provider_kind, api_key) {
                        Ok(candidate) => candidates.push(candidate),
                        Err(error) => {
                            warn!(
                                "Failed to initialize stored {} provider for user {}: {error:#}",
                                provider_kind.as_str(),
                                api_key.user_id
                            );
                        }
                    }
                }
                RuntimeProviderSource::Environment => {
                    if let Some(candidate) = self.provider_candidate_from_env(provider_kind) {
                        candidates.push(candidate);
                    }
                }
            }
        }

        candidates
    }

    fn provider_candidate_from_stored_key(
        &self,
        provider_kind: ProviderKind,
        api_key: &ApiKey,
    ) -> anyhow::Result<ResolvedProviderCandidate> {
        let secret =
            crypto::decode_stored_secret(&api_key.encrypted_key, self.encryption_key.as_ref())?;
        Ok(ResolvedProviderCandidate {
            model: ai::model_for_provider(provider_kind, &self.config.ai.default_model),
            provider_kind,
            provider: ai::build_provider_for_kind(provider_kind, secret),
            source: RuntimeProviderSource::Stored,
        })
    }

    fn provider_candidate_from_env(
        &self,
        provider_kind: ProviderKind,
    ) -> Option<ResolvedProviderCandidate> {
        let credential = env_credential_for_provider(&self.config.ai, provider_kind)?;
        Some(ResolvedProviderCandidate {
            model: ai::model_for_provider(provider_kind, &self.config.ai.default_model),
            provider_kind,
            provider: ai::build_provider_for_kind(provider_kind, credential),
            source: RuntimeProviderSource::Environment,
        })
    }
}

fn runtime_provider_order(preferred_provider: Option<ProviderKind>) -> Vec<ProviderKind> {
    let mut provider_order = Vec::new();
    if let Some(provider) = preferred_provider {
        provider_order.push(provider);
    }
    for provider in ProviderKind::ordered() {
        if Some(provider) != preferred_provider {
            provider_order.push(provider);
        }
    }
    provider_order
}

fn runtime_provider_plan(
    config: &AiConfig,
    stored_keys: &[ApiKey],
    preferred_provider: Option<ProviderKind>,
) -> Vec<(ProviderKind, RuntimeProviderSource)> {
    let mut plan = Vec::new();

    for provider_kind in runtime_provider_order(preferred_provider) {
        if stored_keys
            .iter()
            .any(|key| key.provider.as_deref() == Some(provider_kind.as_str()))
        {
            plan.push((provider_kind, RuntimeProviderSource::Stored));
        }

        if env_credential_for_provider(config, provider_kind).is_some() {
            plan.push((provider_kind, RuntimeProviderSource::Environment));
        }
    }

    plan
}

fn env_credential_for_provider(config: &AiConfig, provider_kind: ProviderKind) -> Option<String> {
    match provider_kind {
        ProviderKind::Anthropic => config.anthropic_api_key.clone(),
        ProviderKind::OpenAi => config.openai_api_key.clone(),
        ProviderKind::Ollama => config.ollama_url.clone(),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn ai_config(
        anthropic_api_key: Option<&str>,
        openai_api_key: Option<&str>,
        ollama_url: Option<&str>,
        default_model: &str,
    ) -> AiConfig {
        AiConfig {
            anthropic_api_key: anthropic_api_key.map(str::to_string),
            openai_api_key: openai_api_key.map(str::to_string),
            ollama_url: ollama_url.map(str::to_string),
            default_model: default_model.to_string(),
        }
    }

    fn stored_key(provider: &str) -> ApiKey {
        ApiKey {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            org_id: None,
            key_type: "llm_provider".to_string(),
            provider: Some(provider.to_string()),
            label: None,
            key_hash: "hash".to_string(),
            encrypted_key: "encrypted".to_string(),
            last_used_at: None,
            created_at: Utc::now(),
            deleted_at: None,
        }
    }

    #[test]
    fn runtime_plan_keeps_env_fallback_when_stored_provider_is_preferred() {
        let config = ai_config(None, Some("sk-openai"), None, "claude-sonnet-4-20250514");
        let stored_keys = vec![stored_key("anthropic")];

        let plan = runtime_provider_plan(
            &config,
            &stored_keys,
            ai::provider_kind_from_model(&config.default_model),
        );

        assert_eq!(
            plan,
            vec![
                (ProviderKind::Anthropic, RuntimeProviderSource::Stored),
                (ProviderKind::OpenAi, RuntimeProviderSource::Environment),
            ]
        );
    }

    #[test]
    fn runtime_plan_prefers_model_matched_provider_before_others() {
        let config = ai_config(
            Some("sk-ant"),
            Some("sk-openai"),
            Some("http://localhost:11434"),
            "gpt-4o",
        );
        let stored_keys = vec![stored_key("anthropic")];

        let plan = runtime_provider_plan(
            &config,
            &stored_keys,
            ai::provider_kind_from_model(&config.default_model),
        );

        assert_eq!(
            plan,
            vec![
                (ProviderKind::OpenAi, RuntimeProviderSource::Environment),
                (ProviderKind::Anthropic, RuntimeProviderSource::Stored),
                (ProviderKind::Anthropic, RuntimeProviderSource::Environment),
                (ProviderKind::Ollama, RuntimeProviderSource::Environment),
            ]
        );
    }

    #[test]
    fn runtime_plan_includes_both_stored_and_env_for_same_provider() {
        let config = ai_config(
            Some("sk-ant-env"),
            Some("sk-openai"),
            None,
            "claude-3-7-sonnet",
        );
        let stored_keys = vec![stored_key("anthropic")];

        let plan = runtime_provider_plan(
            &config,
            &stored_keys,
            ai::provider_kind_from_model(&config.default_model),
        );

        assert_eq!(
            plan,
            vec![
                (ProviderKind::Anthropic, RuntimeProviderSource::Stored),
                (ProviderKind::Anthropic, RuntimeProviderSource::Environment),
                (ProviderKind::OpenAi, RuntimeProviderSource::Environment),
            ]
        );
    }
}
