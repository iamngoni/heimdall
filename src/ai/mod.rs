//
//  heimdall
//  src/ai/mod.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod claude;
pub mod ollama;
pub mod openai;
pub mod types;

use crate::models::HeimdallResult;
use types::{CompletionRequest, CompletionResponse};

/// Model-agnostic AI provider trait. All AI backends (Claude, OpenAI, Ollama)
/// implement this trait to provide a unified completion interface.
#[async_trait::async_trait]
pub trait ModelProvider: Send + Sync {
    async fn complete(&self, request: CompletionRequest) -> HeimdallResult<CompletionResponse>;

    /// Returns the provider name for logging and diagnostics.
    fn provider_name(&self) -> &str;
}
