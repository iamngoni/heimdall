//
//  heimdall
//  src/state.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use log::warn;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::ai::{self, ModelProvider, ProviderKind};
use crate::config::{AiConfig, Config};
use crate::crypto;
use crate::db::DatabaseOperations;
use crate::models::{ApiKey, User};
use crate::sse::ScanBroadcaster;
use crate::templates::ThemeRegistry;

/// In-flight Codex OAuth login awaiting the redirect callback. Keyed by the
/// OAuth `state` parameter so a callback can be matched back to its initiator.
#[derive(Clone, Debug)]
pub struct CodexPendingLogin {
    pub user_id: Uuid,
    pub code_verifier: String,
    pub return_url: String,
    pub expires_at: DateTime<Utc>,
}

/// In-flight Grok Subscription OAuth login awaiting either the local loopback
/// callback or the configured hosted callback.
#[derive(Clone, Debug)]
pub struct XaiOAuthPendingLogin {
    pub user_id: Uuid,
    pub code_verifier: String,
    pub code_challenge: String,
    pub token_endpoint: String,
    pub return_url: String,
    pub expires_at: DateTime<Utc>,
}

/// In-flight Claude Code (Claude.ai subscription) OAuth login awaiting the
/// user to paste back the authorization code from
/// `console.anthropic.com/oauth/code/callback`. Keyed by the OAuth `state`
/// parameter so the paste-back form can be matched to its initiator.
#[derive(Clone, Debug)]
pub struct ClaudeCodePendingLogin {
    pub user_id: Uuid,
    pub code_verifier: String,
    pub return_url: String,
    pub expires_at: DateTime<Utc>,
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
struct AiRoutingPreferences {
    preferred_provider: Option<ProviderKind>,
    fallbacks_enabled: bool,
    fallback_order: Vec<ProviderKind>,
    provider_models: BTreeMap<ProviderKind, String>,
}

impl AiRoutingPreferences {
    fn from_user(user: Option<&User>) -> Self {
        Self {
            preferred_provider: user
                .and_then(|user| user.preferred_ai_provider.as_deref())
                .and_then(ai::provider_kind_from_name),
            fallbacks_enabled: user.map(|user| user.ai_fallbacks_enabled).unwrap_or(false),
            fallback_order: user
                .map(|user| ai::normalize_provider_order(&user.ai_fallback_order))
                .unwrap_or_else(ai::default_provider_order),
            provider_models: user
                .map(|user| ai::parse_provider_models(&user.ai_provider_models))
                .unwrap_or_default(),
        }
    }
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
    /// Local TCP port serving the Codex OAuth callback. The OpenAI OAuth
    /// client only accepts `http://localhost:1455/auth/callback` or
    /// `http://localhost:1457/auth/callback` as redirect URIs, so this value
    /// is bound at startup and used when constructing the authorize URL.
    pub codex_callback_port: u16,
    /// Pending Codex OAuth logins awaiting their redirect callback.
    pub codex_logins: Arc<Mutex<HashMap<String, CodexPendingLogin>>>,
    /// Pending Grok Subscription OAuth logins awaiting callback completion.
    pub xai_oauth_logins: Arc<Mutex<HashMap<String, XaiOAuthPendingLogin>>>,
    /// Pending Claude Code OAuth logins awaiting the user to paste back the
    /// `code#state` blob from the Anthropic console redirect page.
    pub claude_code_logins: Arc<Mutex<HashMap<String, ClaudeCodePendingLogin>>>,
}

impl AppState {
    pub fn init(
        config: Config,
        db: DatabaseOperations,
        ai: Option<Box<dyn ModelProvider>>,
        sse: ScanBroadcaster,
        themes: Arc<ThemeRegistry>,
        worker_enabled: bool,
        codex_callback_port: u16,
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
            codex_callback_port,
            codex_logins: Arc::new(Mutex::new(HashMap::new())),
            xai_oauth_logins: Arc::new(Mutex::new(HashMap::new())),
            claude_code_logins: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns the AI provider or an error if none is configured.
    pub fn require_ai(&self) -> anyhow::Result<&dyn ModelProvider> {
        self.ai.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "No AI provider configured. Connect Claude Code, Codex, or Grok Subscription in Settings, or set ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENAI_COMPATIBLE_BASE_URL plus OPENAI_COMPATIBLE_MODEL with optional OPENAI_COMPATIBLE_API_KEY, XAI_API_KEY, or OLLAMA_URL."
            )
        })
    }

    pub async fn resolve_ai_for_user(&self, user_id: Uuid) -> anyhow::Result<ResolvedAiRuntime> {
        let stored_keys = self.db.list_runtime_api_keys_by_user(user_id).await?;
        let db_user = self.db.get_user_by_id(user_id).await?;
        let preferences = AiRoutingPreferences::from_user(db_user.as_ref());
        let mut candidates = self.resolve_ai_candidates(&stored_keys, &preferences);

        if candidates.is_empty() {
            anyhow::bail!(
                "No AI provider configured. Connect Claude Code, Codex, or add an Anthropic, OpenAI, OpenAI-compatible, Grok, or Ollama provider in Settings, or configure server env vars."
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
        preferences: &AiRoutingPreferences,
    ) -> Vec<ResolvedProviderCandidate> {
        let mut candidates = Vec::new();

        for (provider_kind, source) in
            runtime_provider_plan(&self.config.ai, stored_keys, preferences)
        {
            match source {
                RuntimeProviderSource::Stored => {
                    let Some(api_key) = stored_keys
                        .iter()
                        .find(|key| key.provider.as_deref() == Some(provider_kind.as_str()))
                    else {
                        continue;
                    };

                    match self.provider_candidate_from_stored_key(
                        provider_kind,
                        api_key,
                        preferences,
                    ) {
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
                    if let Some(candidate) =
                        self.provider_candidate_from_env(provider_kind, preferences)
                    {
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
        preferences: &AiRoutingPreferences,
    ) -> anyhow::Result<ResolvedProviderCandidate> {
        let secret =
            crypto::decode_stored_secret(&api_key.encrypted_key, self.encryption_key.as_ref())?;
        let provider: Box<dyn ModelProvider> = match provider_kind {
            ProviderKind::Codex => Box::new(ai::codex::CodexProvider::with_persistence(
                secret,
                ai::codex::CodexTokenPersistence {
                    db: Arc::clone(&self.db),
                    api_key_id: api_key.id,
                    encryption_key: self.encryption_key,
                },
            )?),
            ProviderKind::XaiOAuth => Box::new(ai::xai_oauth::XaiOAuthProvider::with_persistence(
                secret,
                ai::xai_oauth::XaiOAuthTokenPersistence {
                    db: Arc::clone(&self.db),
                    api_key_id: api_key.id,
                    encryption_key: self.encryption_key,
                },
            )?),
            ProviderKind::ClaudeCode => {
                Box::new(ai::claude_code::ClaudeCodeProvider::with_persistence(
                    secret,
                    ai::claude_code::ClaudeCodeTokenPersistence {
                        db: Arc::clone(&self.db),
                        api_key_id: api_key.id,
                        encryption_key: self.encryption_key,
                    },
                )?)
            }
            _ => ai::build_provider_for_kind(provider_kind, secret),
        };
        Ok(ResolvedProviderCandidate {
            model: model_for_provider_with_preferences(
                provider_kind,
                &self.config.ai,
                preferences,
            )?,
            provider_kind,
            provider,
            source: RuntimeProviderSource::Stored,
        })
    }

    fn provider_candidate_from_env(
        &self,
        provider_kind: ProviderKind,
        preferences: &AiRoutingPreferences,
    ) -> Option<ResolvedProviderCandidate> {
        let credential = env_credential_for_provider(&self.config.ai, provider_kind)?;
        let model = match model_for_provider_with_preferences(
            provider_kind,
            &self.config.ai,
            preferences,
        ) {
            Ok(model) => model,
            Err(error) => {
                warn!(
                    "Failed to initialize environment {} provider: {error:#}",
                    provider_kind.as_str()
                );
                return None;
            }
        };
        Some(ResolvedProviderCandidate {
            model,
            provider_kind,
            provider: ai::build_provider_for_kind(provider_kind, credential),
            source: RuntimeProviderSource::Environment,
        })
    }
}

fn model_for_provider_with_preferences(
    provider: ProviderKind,
    config: &AiConfig,
    preferences: &AiRoutingPreferences,
) -> anyhow::Result<String> {
    let override_model = preferences
        .provider_models
        .get(&provider)
        .map(String::as_str);
    if provider == ProviderKind::OpenAiCompatible {
        let model = override_model
            .map(str::trim)
            .filter(|model| !model.is_empty())
            .or(config.openai_compatible_model.as_deref());
        let Some(model) = model.map(str::trim).filter(|model| !model.is_empty()) else {
            anyhow::bail!(
                "OpenAI Compatible model is required. Set it in Settings with the provider endpoint or set OPENAI_COMPATIBLE_MODEL."
            );
        };
        return Ok(model.to_string());
    }

    Ok(ai::resolve_model_for_provider(
        provider,
        override_model,
        &config.default_model,
    ))
}

fn runtime_provider_plan(
    config: &AiConfig,
    stored_keys: &[ApiKey],
    preferences: &AiRoutingPreferences,
) -> Vec<(ProviderKind, RuntimeProviderSource)> {
    let mut plan = Vec::new();
    let Some(primary_provider) = selected_primary_provider(config, stored_keys, preferences) else {
        return plan;
    };

    let mut provider_order = vec![primary_provider];
    if preferences.fallbacks_enabled {
        for provider in &preferences.fallback_order {
            ai::push_provider_once(&mut provider_order, *provider);
        }
        for provider in ai::default_provider_order() {
            ai::push_provider_once(&mut provider_order, provider);
        }
    }

    for provider_kind in provider_order {
        if !provider_is_configured(config, stored_keys, preferences, provider_kind) {
            continue;
        }
        if let Some(source) = runtime_source_for_provider(config, stored_keys, provider_kind) {
            plan.push((provider_kind, source));
        }
    }

    plan
}

fn selected_primary_provider(
    config: &AiConfig,
    stored_keys: &[ApiKey],
    preferences: &AiRoutingPreferences,
) -> Option<ProviderKind> {
    if let Some(provider) = preferences.preferred_provider
        && provider_is_configured(config, stored_keys, preferences, provider)
    {
        return Some(provider);
    }

    if let Some(provider) = ai::provider_kind_from_model(&config.default_model)
        && provider_is_configured(config, stored_keys, preferences, provider)
    {
        return Some(provider);
    }

    ai::default_provider_order()
        .into_iter()
        .find(|provider| provider_is_configured(config, stored_keys, preferences, *provider))
}

fn provider_is_configured(
    config: &AiConfig,
    stored_keys: &[ApiKey],
    preferences: &AiRoutingPreferences,
    provider_kind: ProviderKind,
) -> bool {
    if provider_kind == ProviderKind::OpenAiCompatible
        && !provider_has_explicit_model(config, preferences, provider_kind)
    {
        return false;
    }
    runtime_source_for_provider(config, stored_keys, provider_kind).is_some()
}

fn provider_has_explicit_model(
    config: &AiConfig,
    preferences: &AiRoutingPreferences,
    provider_kind: ProviderKind,
) -> bool {
    preferences
        .provider_models
        .get(&provider_kind)
        .map(|model| !model.trim().is_empty())
        .unwrap_or_else(|| {
            provider_kind == ProviderKind::OpenAiCompatible
                && config
                    .openai_compatible_model
                    .as_deref()
                    .map(str::trim)
                    .filter(|model| !model.is_empty())
                    .is_some()
        })
}

fn runtime_source_for_provider(
    config: &AiConfig,
    stored_keys: &[ApiKey],
    provider_kind: ProviderKind,
) -> Option<RuntimeProviderSource> {
    if stored_keys
        .iter()
        .any(|key| key.provider.as_deref() == Some(provider_kind.as_str()))
    {
        return Some(RuntimeProviderSource::Stored);
    }

    env_credential_for_provider(config, provider_kind).map(|_| RuntimeProviderSource::Environment)
}

fn env_credential_for_provider(config: &AiConfig, provider_kind: ProviderKind) -> Option<String> {
    match provider_kind {
        ProviderKind::Anthropic => config.anthropic_api_key.clone(),
        ProviderKind::Codex | ProviderKind::ClaudeCode | ProviderKind::XaiOAuth => None,
        ProviderKind::Xai => config.xai_api_key.clone(),
        ProviderKind::OpenAi => config.openai_api_key.clone(),
        ProviderKind::OpenAiCompatible => {
            config
                .openai_compatible_model
                .as_deref()
                .map(str::trim)
                .filter(|model| !model.is_empty())?;
            config
                .openai_compatible_base_url
                .as_deref()
                .and_then(|base_url| {
                    ai::openai::encode_openai_compatible_secret(
                        config
                            .openai_compatible_api_key
                            .as_deref()
                            .unwrap_or_default(),
                        base_url,
                    )
                    .ok()
                })
        }
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
        openai_compatible_api_key: Option<&str>,
        openai_compatible_base_url: Option<&str>,
        openai_compatible_model: Option<&str>,
        xai_api_key: Option<&str>,
        ollama_url: Option<&str>,
        default_model: &str,
    ) -> AiConfig {
        AiConfig {
            anthropic_api_key: anthropic_api_key.map(str::to_string),
            openai_api_key: openai_api_key.map(str::to_string),
            openai_compatible_api_key: openai_compatible_api_key.map(str::to_string),
            openai_compatible_base_url: openai_compatible_base_url.map(str::to_string),
            openai_compatible_model: openai_compatible_model.map(str::to_string),
            xai_api_key: xai_api_key.map(str::to_string),
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
    fn runtime_plan_uses_only_primary_provider_when_fallbacks_disabled() {
        let config = ai_config(
            None,
            Some("sk-openai"),
            None,
            None,
            None,
            None,
            None,
            "claude-sonnet-4-20250514",
        );
        let stored_keys = vec![stored_key("anthropic")];
        let preferences = AiRoutingPreferences {
            preferred_provider: None,
            fallbacks_enabled: false,
            fallback_order: ai::default_provider_order(),
            provider_models: BTreeMap::new(),
        };

        let plan = runtime_provider_plan(&config, &stored_keys, &preferences);

        assert_eq!(
            plan,
            vec![(ProviderKind::Anthropic, RuntimeProviderSource::Stored)]
        );
    }

    #[test]
    fn runtime_plan_prefers_user_selected_provider() {
        let config = ai_config(
            None,
            Some("sk-openai"),
            None,
            None,
            None,
            None,
            None,
            "claude-sonnet-4-20250514",
        );
        let stored_keys = vec![stored_key("anthropic")];
        let preferences = AiRoutingPreferences {
            preferred_provider: Some(ProviderKind::OpenAi),
            fallbacks_enabled: false,
            fallback_order: ai::default_provider_order(),
            provider_models: BTreeMap::new(),
        };

        let plan = runtime_provider_plan(&config, &stored_keys, &preferences);

        assert_eq!(
            plan,
            vec![(ProviderKind::OpenAi, RuntimeProviderSource::Environment)]
        );
    }

    #[test]
    fn runtime_plan_uses_configured_fallback_order_when_enabled() {
        let config = ai_config(
            None,
            Some("sk-openai"),
            None,
            None,
            None,
            None,
            Some("http://localhost:11434"),
            "gpt-4o",
        );
        let stored_keys = vec![stored_key("anthropic")];
        let preferences = AiRoutingPreferences {
            preferred_provider: Some(ProviderKind::OpenAi),
            fallbacks_enabled: true,
            fallback_order: vec![
                ProviderKind::OpenAi,
                ProviderKind::Anthropic,
                ProviderKind::Ollama,
            ],
            provider_models: BTreeMap::new(),
        };

        let plan = runtime_provider_plan(&config, &stored_keys, &preferences);

        assert_eq!(
            plan,
            vec![
                (ProviderKind::OpenAi, RuntimeProviderSource::Environment),
                (ProviderKind::Anthropic, RuntimeProviderSource::Stored),
                (ProviderKind::Ollama, RuntimeProviderSource::Environment),
            ]
        );
    }

    #[test]
    fn runtime_plan_ignores_unconfigured_preferred_provider() {
        let config = ai_config(
            None,
            Some("sk-openai"),
            None,
            None,
            None,
            None,
            None,
            "claude-3-7-sonnet",
        );
        let stored_keys = Vec::new();
        let preferences = AiRoutingPreferences {
            preferred_provider: Some(ProviderKind::Anthropic),
            fallbacks_enabled: false,
            fallback_order: ai::default_provider_order(),
            provider_models: BTreeMap::new(),
        };

        let plan = runtime_provider_plan(&config, &stored_keys, &preferences);

        assert_eq!(
            plan,
            vec![(ProviderKind::OpenAi, RuntimeProviderSource::Environment)]
        );
    }

    #[test]
    fn runtime_plan_uses_xai_env_provider_for_grok_model() {
        let config = ai_config(
            None,
            None,
            None,
            None,
            None,
            Some("xai-env"),
            None,
            "grok-build-0.1",
        );
        let stored_keys = Vec::new();
        let preferences = AiRoutingPreferences {
            preferred_provider: None,
            fallbacks_enabled: false,
            fallback_order: ai::default_provider_order(),
            provider_models: BTreeMap::new(),
        };

        let plan = runtime_provider_plan(&config, &stored_keys, &preferences);

        assert_eq!(
            plan,
            vec![(ProviderKind::Xai, RuntimeProviderSource::Environment)]
        );
    }

    #[test]
    fn runtime_plan_uses_openai_compatible_env_provider_when_configured() {
        let config = ai_config(
            None,
            None,
            Some("sk-custom"),
            Some("http://localhost:1234/v1"),
            Some("custom-model"),
            None,
            None,
            "custom-model",
        );
        let stored_keys = Vec::new();
        let preferences = AiRoutingPreferences {
            preferred_provider: Some(ProviderKind::OpenAiCompatible),
            fallbacks_enabled: false,
            fallback_order: ai::default_provider_order(),
            provider_models: BTreeMap::from([(
                ProviderKind::OpenAiCompatible,
                "custom-model".to_string(),
            )]),
        };

        let plan = runtime_provider_plan(&config, &stored_keys, &preferences);

        assert_eq!(
            plan,
            vec![(
                ProviderKind::OpenAiCompatible,
                RuntimeProviderSource::Environment
            )]
        );
    }

    #[test]
    fn runtime_plan_uses_openai_compatible_env_provider_without_api_key() {
        let config = ai_config(
            None,
            None,
            None,
            Some("http://localhost:1234/v1"),
            Some("custom-model"),
            None,
            None,
            "custom-model",
        );
        let stored_keys = Vec::new();
        let preferences = AiRoutingPreferences {
            preferred_provider: Some(ProviderKind::OpenAiCompatible),
            fallbacks_enabled: false,
            fallback_order: ai::default_provider_order(),
            provider_models: BTreeMap::from([(
                ProviderKind::OpenAiCompatible,
                "custom-model".to_string(),
            )]),
        };

        let plan = runtime_provider_plan(&config, &stored_keys, &preferences);

        assert_eq!(
            plan,
            vec![(
                ProviderKind::OpenAiCompatible,
                RuntimeProviderSource::Environment
            )]
        );
    }

    #[test]
    fn runtime_plan_skips_openai_compatible_when_model_is_not_explicit() {
        let config = ai_config(
            None,
            None,
            Some("sk-custom"),
            Some("http://localhost:1234/v1"),
            None,
            None,
            None,
            "gpt-4o",
        );
        let stored_keys = Vec::new();
        let preferences = AiRoutingPreferences {
            preferred_provider: Some(ProviderKind::OpenAiCompatible),
            fallbacks_enabled: false,
            fallback_order: ai::default_provider_order(),
            provider_models: BTreeMap::new(),
        };

        let plan = runtime_provider_plan(&config, &stored_keys, &preferences);

        assert!(plan.is_empty());
    }

    #[test]
    fn runtime_plan_prefers_stored_key_over_env_for_same_provider() {
        let config = ai_config(
            Some("sk-ant-env"),
            Some("sk-openai"),
            None,
            None,
            None,
            None,
            None,
            "claude-3-7-sonnet",
        );
        let stored_keys = vec![stored_key("anthropic")];
        let preferences = AiRoutingPreferences {
            preferred_provider: Some(ProviderKind::Anthropic),
            fallbacks_enabled: true,
            fallback_order: ai::default_provider_order(),
            provider_models: BTreeMap::new(),
        };

        let plan = runtime_provider_plan(&config, &stored_keys, &preferences);

        assert_eq!(
            plan,
            vec![
                (ProviderKind::Anthropic, RuntimeProviderSource::Stored),
                (ProviderKind::OpenAi, RuntimeProviderSource::Environment),
            ]
        );
    }
}
