//
//  heimdall
//  src/db/schema/snapshot.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::db::schema::types::SchemaDef;
use std::path::Path;

const SNAPSHOT_PATH: &str = "migrations/.schema_snapshot.json";

/// Load the previous schema snapshot from disk, if it exists.
pub fn load_snapshot() -> Option<SchemaDef> {
    let path = Path::new(SNAPSHOT_PATH);
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Save the current schema definition as a JSON snapshot.
pub fn save_snapshot(schema: &SchemaDef) -> std::io::Result<()> {
    let path = Path::new(SNAPSHOT_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(schema)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, json)
}
