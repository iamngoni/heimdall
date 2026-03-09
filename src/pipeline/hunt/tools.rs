//
//  heimdall
//  src/pipeline/hunt/tools.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::models::HeimdallResult;
use serde::{Deserialize, Serialize};

/// Tools available to the hunt agent for code investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTool {
    ReadFile,
    SearchCode,
    GetCallers,
    GetDependencies,
}

/// Result of executing an agent tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool: AgentTool,
    pub output: String,
    pub success: bool,
}

impl AgentTool {
    pub async fn execute(&self, _params: &serde_json::Value) -> HeimdallResult<ToolResult> {
        let tool_name = format!("{self:?}");
        log::info!("AgentTool::{tool_name}::execute — not yet implemented");

        Ok(ToolResult {
            tool: self.clone(),
            output: format!("{tool_name} — not yet implemented"),
            success: false,
        })
    }
}
