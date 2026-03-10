//
//  heimdall
//  src/state.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use crate::ai::ModelProvider;
use crate::config::Config;
use crate::crypto;
use crate::db::DatabaseOperations;
use crate::sse::ScanBroadcaster;
use crate::templates::TemplateEngine;

pub struct AppState {
    pub config: Arc<Config>,
    pub db: Arc<DatabaseOperations>,
    pub ai: Option<Arc<dyn ModelProvider>>,
    pub sse: Arc<ScanBroadcaster>,
    pub templates: Arc<TemplateEngine>,
    pub encryption_key: Option<[u8; 32]>,
}

impl AppState {
    pub fn init(
        config: Config,
        db: DatabaseOperations,
        ai: Option<Box<dyn ModelProvider>>,
        sse: ScanBroadcaster,
        templates: Arc<TemplateEngine>,
    ) -> Self {
        let encryption_key = config
            .security
            .encryption_key
            .as_deref()
            .and_then(|hex_str| match crypto::parse_hex_key(hex_str) {
                Ok(key) => Some(key),
                Err(e) => {
                    log::warn!(
                        "ENCRYPTION_KEY is set but invalid ({e:#}); \
                         falling back to hex encoding for API keys"
                    );
                    None
                }
            });

        Self {
            config: Arc::new(config),
            db: Arc::new(db),
            ai: ai.map(|p| Arc::from(p)),
            sse: Arc::new(sse),
            templates,
            encryption_key,
        }
    }

    /// Returns the AI provider or an error if none is configured.
    pub fn require_ai(&self) -> anyhow::Result<&dyn ModelProvider> {
        self.ai
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No AI provider configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_URL."))
    }
}
