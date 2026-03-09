//
//  heimdall
//  src/ai/openai.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, CompletionResponse};
use crate::models::HeimdallResult;

pub struct OpenAiProvider {
    pub api_key: String,
    pub base_url: String,
}

impl OpenAiProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            base_url: "https://api.openai.com".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl ModelProvider for OpenAiProvider {
    async fn complete(&self, _request: CompletionRequest) -> HeimdallResult<CompletionResponse> {
        anyhow::bail!("OpenAiProvider::complete — not yet implemented")
    }

    fn provider_name(&self) -> &str {
        "openai"
    }
}
