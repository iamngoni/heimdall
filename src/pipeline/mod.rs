//
//  heimdall
//  src/pipeline/mod.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod garmr;
pub mod hunt;
pub mod ingest;
pub mod report;
pub mod static_analysis;
pub mod tyr;

use crate::models::HeimdallResult;

/// Orchestrates the full scan pipeline:
/// Ingest -> Tyr (threat model) -> Hunt (agentic vuln discovery) -> Garmr (sandbox) -> Report
pub struct ScanPipeline {
    pub scan_id: String,
}

impl ScanPipeline {
    pub fn new(scan_id: String) -> Self {
        Self { scan_id }
    }

    pub async fn run(&self) -> HeimdallResult<()> {
        log::info!("Starting scan pipeline for scan_id={}", self.scan_id);

        // Stage 1: Ingest
        let _ingest = ingest::IngestStage::new(self.scan_id.clone());
        log::info!("[{}] Ingest stage — placeholder", self.scan_id);

        // Stage 2: Tyr (Threat Model)
        let _tyr = tyr::TyrStage::new(self.scan_id.clone());
        log::info!("[{}] Tyr stage — placeholder", self.scan_id);

        // Stage 3: Static analysis
        let _static_analysis = static_analysis::StaticAnalysisStage::new(self.scan_id.clone());
        log::info!("[{}] Static analysis stage — placeholder", self.scan_id);

        // Stage 4: Hunt (Agentic)
        let _hunt = hunt::HuntStage::new(self.scan_id.clone());
        log::info!("[{}] Hunt stage — placeholder", self.scan_id);

        // Stage 5: Garmr (Sandbox validation)
        let _garmr = garmr::GarmrStage::new(self.scan_id.clone());
        log::info!("[{}] Garmr stage — placeholder", self.scan_id);

        // Stage 6: Report
        let _report = report::ReportStage::new(self.scan_id.clone());
        log::info!("[{}] Report stage — placeholder", self.scan_id);

        log::info!("Scan pipeline completed for scan_id={}", self.scan_id);
        Ok(())
    }
}
