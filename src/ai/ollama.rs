//
//  heimdall
//  src/ai/ollama.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, CompletionResponse};
use crate::models::HeimdallResult;

pub struct OllamaProvider {
    pub base_url: String,
}

impl OllamaProvider {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }

    pub fn default_local() -> Self {
        Self {
            base_url: "http://localhost:11434".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl ModelProvider for OllamaProvider {
    async fn complete(&self, _request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
        anyhow::bail!("OllamaProvider::complete — not yet implemented")
    }

    fn provider_name(&self) -> &str {
        "ollama"
    }
}
