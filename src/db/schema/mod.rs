//
//  heimdall
//  src/db/schema/mod.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod types;
pub mod builder;
pub mod generator;
pub mod definition;

pub use builder::Schema;
pub use definition::heimdall_schema;
pub use generator::{
    DbDriver, MigrationGenerator, MongoGenerator, MysqlGenerator, PostgresGenerator,
    SqliteGenerator,
};
pub use types::*;

/// Generate migration for the given driver and write to a file
pub fn generate_migration(
    driver: DbDriver,
    output_path: &std::path::Path,
) -> std::io::Result<()> {
    let schema = heimdall_schema();
    let output = match driver {
        DbDriver::Postgres => PostgresGenerator.generate(&schema),
        DbDriver::Sqlite => SqliteGenerator.generate(&schema),
        DbDriver::Mysql => MysqlGenerator.generate(&schema),
        DbDriver::Mongo => MongoGenerator.generate(&schema),
    };
    std::fs::write(output_path, output)
}
