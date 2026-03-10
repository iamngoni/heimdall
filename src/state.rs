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
use crate::config::Config;
use crate::crypto;
use crate::db::DatabaseOperations;
use crate::models::ApiKey;
use crate::sse::ScanBroadcaster;
use crate::templates::TemplateEngine;

#[derive(Clone)]
pub struct ResolvedAiRuntime {
    pub provider: Arc<dyn ModelProvider>,
    pub model: String,
    pub provider_kind: ProviderKind,
    pub source: &'static str,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Arc<DatabaseOperations>,
    pub ai: Option<Arc<dyn ModelProvider>>,
    pub sse: Arc<ScanBroadcaster>,
    pub templates: Arc<TemplateEngine>,
    pub encryption_key: Option<[u8; 32]>,
    pub worker_enabled: bool,
}

impl AppState {
    pub fn init(
        config: Config,
        db: DatabaseOperations,
        ai: Option<Box<dyn ModelProvider>>,
        sse: ScanBroadcaster,
        templates: Arc<TemplateEngine>,
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
            ai: ai.map(|p| Arc::from(p)),
            sse: Arc::new(sse),
            templates,
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

        if let Some(runtime) = self.resolve_stored_ai(&stored_keys, preferred_provider) {
            return Ok(runtime);
        }

        self.env_ai_runtime().ok_or_else(|| {
            anyhow::anyhow!(
                "No AI provider configured. Add an Anthropic, OpenAI, or Ollama key in Settings, or configure server env vars."
            )
        })
    }

    fn resolve_stored_ai(
        &self,
        stored_keys: &[ApiKey],
        preferred_provider: Option<ProviderKind>,
    ) -> Option<ResolvedAiRuntime> {
        let mut provider_order = Vec::new();
        if let Some(provider) = preferred_provider {
            provider_order.push(provider);
        }
        for provider in ProviderKind::ordered() {
            if Some(provider) != preferred_provider {
                provider_order.push(provider);
            }
        }

        for provider in provider_order {
            if let Some(api_key) = stored_keys
                .iter()
                .find(|key| key.provider.as_deref() == Some(provider.as_str()))
            {
                match self.runtime_from_stored_key(provider, api_key) {
                    Ok(runtime) => return Some(runtime),
                    Err(error) => {
                        warn!(
                            "Failed to initialize stored {} provider for user {}: {error:#}",
                            provider.as_str(),
                            api_key.user_id
                        );
                    }
                }
            }
        }

        None
    }

    fn runtime_from_stored_key(
        &self,
        provider_kind: ProviderKind,
        api_key: &ApiKey,
    ) -> anyhow::Result<ResolvedAiRuntime> {
        let secret =
            crypto::decode_stored_secret(&api_key.encrypted_key, self.encryption_key.as_ref())?;
        Ok(ResolvedAiRuntime {
            model: ai::model_for_provider(provider_kind, &self.config.ai.default_model),
            provider_kind,
            provider: Arc::from(ai::build_provider_for_kind(provider_kind, secret)),
            source: "stored",
        })
    }

    fn env_ai_runtime(&self) -> Option<ResolvedAiRuntime> {
        let provider_kind = ai::configured_provider_kind(&self.config.ai)?;
        let provider = self.ai.as_ref().map(Arc::clone)?;

        Some(ResolvedAiRuntime {
            model: ai::model_for_provider(provider_kind, &self.config.ai.default_model),
            provider_kind,
            provider,
            source: "environment",
        })
    }
}
