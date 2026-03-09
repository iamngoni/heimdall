//
//  heimdall
//  src/ai/claude.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, CompletionResponse};
use crate::models::HeimdallResult;

pub struct ClaudeProvider {
    pub api_key: String,
    pub base_url: String,
}

impl ClaudeProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            base_url: "https://api.anthropic.com".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl ModelProvider for ClaudeProvider {
    async fn complete(&self, _request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
        anyhow::bail!("ClaudeProvider::complete — not yet implemented")
    }

    fn provider_name(&self) -> &str {
        "claude"
    }
}
