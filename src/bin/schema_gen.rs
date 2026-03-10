//
//  heimdall
//  src/bin/schema_gen.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use heimdall::db::schema::{
    DbDriver, MigrationResult, generate_migration, generate_smart_migration, heimdall_schema,
};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let force_initial = args.iter().any(|a| a == "--init" || a == "--force-initial");

    let driver = match args.get(1).map(|s| s.as_str()) {
        Some("postgres") | Some("pg") => DbDriver::Postgres,
        Some("sqlite") => DbDriver::Sqlite,
        Some("mysql") => DbDriver::Mysql,
        Some("mongo") | Some("mongodb") => DbDriver::Mongo,
        Some("all") => {
            // Generate all drivers but don't copy to active/
            // Use single-driver mode (e.g. `schema_gen postgres`) to set the active driver
            run_generation(DbDriver::Postgres, None, force_initial, false);
            run_generation(DbDriver::Sqlite, None, force_initial, false);
            run_generation(DbDriver::Mysql, None, force_initial, false);
            run_generation(DbDriver::Mongo, None, force_initial, false);
            save_snapshot();
            return;
        }
        _ => {
            eprintln!("Usage: schema_gen <postgres|sqlite|mysql|mongo|all> [output_path] [--init]");
            eprintln!();
            eprintln!("Options:");
            eprintln!("  --init              Force a full initial migration (ignores snapshot)");
            eprintln!();
            eprintln!("Examples:");
            eprintln!(
                "  schema_gen postgres                          # smart migration to migrations/postgres/"
            );
            eprintln!(
                "  schema_gen sqlite                            # smart migration to migrations/sqlite/"
            );
            eprintln!(
                "  schema_gen mysql                             # smart migration to migrations/mysql/"
            );
            eprintln!(
                "  schema_gen mongo                             # smart migration to migrations/mongo/"
            );
            eprintln!("  schema_gen all                               # all four drivers");
            eprintln!(
                "  schema_gen postgres --init                   # force full initial migration"
            );
            eprintln!(
                "  schema_gen postgres my_migration.sql         # custom output path (full migration)"
            );
            std::process::exit(1);
        }
    };

    let custom_path = args.get(2).and_then(|s| {
        if s.starts_with("--") {
            None
        } else {
            Some(s.as_str())
        }
    });

    run_generation(driver, custom_path, force_initial, true);
    save_snapshot();
}

fn save_snapshot() {
    let schema = heimdall_schema();
    heimdall::db::schema::snapshot::save_snapshot(&schema).unwrap_or_else(|e| {
        eprintln!("Failed to save snapshot: {e}");
        std::process::exit(1);
    });
}

fn run_generation(
    driver: DbDriver,
    custom_path: Option<&str>,
    force_initial: bool,
    copy_active: bool,
) {
    let driver_name = match driver {
        DbDriver::Postgres => "PostgreSQL",
        DbDriver::Sqlite => "SQLite",
        DbDriver::Mysql => "MySQL",
        DbDriver::Mongo => "MongoDB",
    };
    let ext = match driver {
        DbDriver::Mongo => "js",
        _ => "sql",
    };
    let driver_dir = match driver {
        DbDriver::Postgres => "postgres",
        DbDriver::Sqlite => "sqlite",
        DbDriver::Mysql => "mysql",
        DbDriver::Mongo => "mongo",
    };

    // Custom path: always generate a full migration
    if let Some(path) = custom_path {
        let output_path = Path::new(path);
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                eprintln!("Failed to create directory {}: {e}", parent.display());
                std::process::exit(1);
            });
        }
        generate_migration(driver, output_path).unwrap_or_else(|e| {
            eprintln!("Failed to write migration to {path}: {e}");
            std::process::exit(1);
        });
        println!("[{driver_name}] Full migration written to {path}");
        return;
    }

    // Force initial: generate full migration with timestamp
    if force_initial {
        let timestamp = now_timestamp();
        let filename = format!("{timestamp}_initial_schema.{ext}");
        let output = format!("migrations/{driver_dir}/{filename}");
        let output_path = Path::new(&output);

        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                eprintln!("Failed to create directory {}: {e}", parent.display());
                std::process::exit(1);
            });
        }
        generate_migration(driver, output_path).unwrap_or_else(|e| {
            eprintln!("Failed to write migration: {e}");
            std::process::exit(1);
        });

        println!("[{driver_name}] Initial migration written to {output}");
        if copy_active {
            copy_to_active(&output, driver, driver_name);
        }
        return;
    }

    // Smart migration: diff against snapshot
    let timestamp = now_timestamp();
    let temp_path = format!("migrations/{driver_dir}/.pending_migration.{ext}");
    let temp = Path::new(&temp_path);

    if let Some(parent) = temp.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Failed to create directory {}: {e}", parent.display());
            std::process::exit(1);
        });
    }

    match generate_smart_migration(driver, temp) {
        Ok(MigrationResult::NoChanges) => {
            let _ = std::fs::remove_file(temp);
            println!("[{driver_name}] No schema changes detected.");
        }
        Ok(MigrationResult::Initial) => {
            let filename = format!("{timestamp}_initial_schema.{ext}");
            let final_path = format!("migrations/{driver_dir}/{filename}");
            std::fs::rename(temp, &final_path).unwrap_or_else(|e| {
                eprintln!("Failed to rename migration: {e}");
                std::process::exit(1);
            });
            println!("[{driver_name}] Initial migration written to {final_path}");
            if copy_active {
                copy_to_active(&final_path, driver, driver_name);
            }
        }
        Ok(MigrationResult::Incremental { change_count }) => {
            let filename = format!("{timestamp}_schema_update.{ext}");
            let final_path = format!("migrations/{driver_dir}/{filename}");
            std::fs::rename(temp, &final_path).unwrap_or_else(|e| {
                eprintln!("Failed to rename migration: {e}");
                std::process::exit(1);
            });
            println!(
                "[{driver_name}] Incremental migration written to {final_path} ({change_count} changes)"
            );
            if copy_active {
                copy_to_active(&final_path, driver, driver_name);
            }
        }
        Err(e) => {
            let _ = std::fs::remove_file(temp);
            eprintln!("Failed to generate migration: {e}");
            std::process::exit(1);
        }
    }
}

/// Copy a SQL migration to migrations/active/ for sqlx::migrate!
/// Accumulates — does not replace existing files.
fn copy_to_active(source: &str, driver: DbDriver, driver_name: &str) {
    if driver == DbDriver::Mongo {
        return;
    }

    let active_dir = Path::new("migrations/active");
    std::fs::create_dir_all(active_dir).unwrap_or_else(|e| {
        eprintln!("Failed to create directory {}: {e}", active_dir.display());
        std::process::exit(1);
    });

    let source_path = Path::new(source);
    let filename = source_path.file_name().unwrap();
    let active_path = active_dir.join(filename);

    std::fs::copy(source_path, &active_path).unwrap_or_else(|e| {
        eprintln!("Failed to copy migration to {}: {e}", active_path.display());
        std::process::exit(1);
    });
    println!(
        "[{driver_name}] Active migration copied to {}",
        active_path.display()
    );
}

fn now_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let secs = now.as_secs();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut y = 1970i64;
    let mut remaining = days as i64;

    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }

    let days_in_months = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 1u32;
    for &dim in &days_in_months {
        if remaining < dim {
            break;
        }
        remaining -= dim;
        m += 1;
    }
    let d = remaining + 1;

    format!("{y:04}{m:02}{d:02}{hours:02}{minutes:02}{seconds:02}")
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
