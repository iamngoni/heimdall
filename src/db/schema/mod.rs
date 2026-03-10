//
//  heimdall
//  src/db/schema/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod builder;
pub mod definition;
pub mod diff;
pub mod generator;
pub mod incremental;
pub mod snapshot;
pub mod types;

use incremental::IncrementalGenerator;

pub use builder::Schema;
pub use definition::heimdall_schema;
pub use generator::{
    DbDriver, MigrationGenerator, MongoGenerator, MysqlGenerator, PostgresGenerator,
    SqliteGenerator,
};
pub use types::*;

/// Result of a migration generation run
pub enum MigrationResult {
    /// No snapshot found — generated full initial migration
    Initial,
    /// Schema changed — generated incremental migration
    Incremental { change_count: usize },
    /// No changes detected
    NoChanges,
}

/// Generate a full initial migration for the given driver and write to a file.
pub fn generate_migration(driver: DbDriver, output_path: &std::path::Path) -> std::io::Result<()> {
    let schema = heimdall_schema();
    let output = match driver {
        DbDriver::Postgres => PostgresGenerator.generate(&schema),
        DbDriver::Sqlite => SqliteGenerator.generate(&schema),
        DbDriver::Mysql => MysqlGenerator.generate(&schema),
        DbDriver::Mongo => MongoGenerator.generate(&schema),
    };
    std::fs::write(output_path, output)
}

/// Smart migration: diffs against snapshot and generates either a full or incremental migration.
/// Does NOT save the snapshot — caller is responsible for calling `snapshot::save_snapshot`
/// after all drivers have been generated (important for `all` mode).
pub fn generate_smart_migration(
    driver: DbDriver,
    output_path: &std::path::Path,
) -> std::io::Result<MigrationResult> {
    let schema = heimdall_schema();

    match snapshot::load_snapshot() {
        None => {
            // No snapshot — generate full initial migration
            generate_migration(driver, output_path)?;
            Ok(MigrationResult::Initial)
        }
        Some(old_schema) => {
            let changes = diff::diff_schemas(&old_schema, &schema);

            if changes.is_empty() {
                return Ok(MigrationResult::NoChanges);
            }

            let output = match driver {
                DbDriver::Postgres => incremental::PostgresIncremental.generate(&changes, &schema),
                DbDriver::Sqlite => incremental::SqliteIncremental.generate(&changes, &schema),
                DbDriver::Mysql => incremental::MysqlIncremental.generate(&changes, &schema),
                DbDriver::Mongo => incremental::MongoIncremental.generate(&changes, &schema),
            };

            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(output_path, output)?;

            let change_count = changes.len();
            Ok(MigrationResult::Incremental { change_count })
        }
    }
}
