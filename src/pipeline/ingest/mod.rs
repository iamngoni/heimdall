//
//  heimdall
//  src/pipeline/ingest/mod.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::models::HeimdallResult;

/// Handles repository ingestion: clone/download, file enumeration, language detection.
pub struct IngestStage {
    pub scan_id: String,
}

impl IngestStage {
    pub fn new(scan_id: String) -> Self {
        Self { scan_id }
    }

    pub async fn run(&self) -> HeimdallResult<()> {
        log::info!("[{}] IngestStage::run — not yet implemented", self.scan_id);
        Ok(())
    }
}
