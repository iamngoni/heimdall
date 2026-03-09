//
//  heimdall
//  src/pipeline/static_analysis/mod.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::models::HeimdallResult;

/// Static analysis stage using tree-sitter AST parsing for polyglot support.
pub struct StaticAnalysisStage {
    pub scan_id: String,
}

impl StaticAnalysisStage {
    pub fn new(scan_id: String) -> Self {
        Self { scan_id }
    }

    pub async fn run(&self) -> HeimdallResult<()> {
        log::info!(
            "[{}] StaticAnalysisStage::run — not yet implemented",
            self.scan_id
        );
        Ok(())
    }
}
