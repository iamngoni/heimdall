//
//  heimdall
//  src/pipeline/hunt/agent.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::models::HeimdallResult;

/// Maximum number of agent loop iterations before forced termination.
pub const MAX_ITERATIONS: u32 = 25;

/// Represents the current state of a hunt agent's execution loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    Planning,
    AwaitingLlm,
    ExecutingTool,
    ReportingFinding,
    Completed,
}

/// A single hunt agent that investigates a potential vulnerability
/// through iterative LLM reasoning and tool execution.
pub struct HuntAgent {
    pub scan_id: String,
    pub state: AgentState,
    pub iteration: u32,
}

impl HuntAgent {
    pub fn new(scan_id: String) -> Self {
        Self {
            scan_id,
            state: AgentState::Planning,
            iteration: 0,
        }
    }

    pub async fn investigate(&mut self) -> HeimdallResult<()> {
        log::info!(
            "[{}] HuntAgent::investigate — not yet implemented",
            self.scan_id
        );
        self.state = AgentState::Completed;
        Ok(())
    }
}
