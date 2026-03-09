//
//  heimdall
//  src/bin/schema_gen.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use heimdall::db::schema::{generate_migration, DbDriver};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let driver = match args.get(1).map(|s| s.as_str()) {
        Some("postgres") | Some("pg") => DbDriver::Postgres,
        Some("sqlite") => DbDriver::Sqlite,
        Some("mysql") => DbDriver::Mysql,
        Some("mongo") | Some("mongodb") => DbDriver::Mongo,
        Some("all") => {
            run_generation(DbDriver::Postgres, args.get(2).map(|s| s.as_str()));
            run_generation(DbDriver::Sqlite, None);
            run_generation(DbDriver::Mysql, None);
            run_generation(DbDriver::Mongo, None);
            return;
        }
        _ => {
            eprintln!("Usage: schema_gen <postgres|sqlite|mysql|mongo|all> [output_path]");
            eprintln!();
            eprintln!("Examples:");
            eprintln!("  schema_gen postgres                          # writes to migrations/");
            eprintln!("  schema_gen sqlite                            # writes to migrations/sqlite/");
            eprintln!("  schema_gen mysql                             # writes to migrations/mysql/");
            eprintln!("  schema_gen mongo                             # writes to migrations/mongo/");
            eprintln!("  schema_gen all                               # writes all drivers");
            eprintln!("  schema_gen postgres my_migration.sql         # custom output path");
            std::process::exit(1);
        }
    };

    run_generation(driver, args.get(2).map(|s| s.as_str()));
}

fn run_generation(driver: DbDriver, custom_path: Option<&str>) {
    let default_path = match driver {
        DbDriver::Postgres => "migrations/20260309000000_initial_schema.sql",
        DbDriver::Sqlite => "migrations/sqlite/20260309000000_initial_schema.sql",
        DbDriver::Mysql => "migrations/mysql/20260309000000_initial_schema.sql",
        DbDriver::Mongo => "migrations/mongo/20260309000000_initial_schema.js",
    };
    let output = custom_path.unwrap_or(default_path);
    let output_path = Path::new(output);

    // Create parent directory if needed
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Failed to create directory {}: {e}", parent.display());
            std::process::exit(1);
        });
    }

    generate_migration(driver, output_path).unwrap_or_else(|e| {
        eprintln!("Failed to write migration to {output}: {e}");
        std::process::exit(1);
    });

    let driver_name = match driver {
        DbDriver::Postgres => "PostgreSQL",
        DbDriver::Sqlite => "SQLite",
        DbDriver::Mysql => "MySQL",
        DbDriver::Mongo => "MongoDB",
    };
    println!("[{driver_name}] Migration written to {output}");
}
