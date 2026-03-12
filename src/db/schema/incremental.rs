//
//  heimdall
//  src/db/schema/incremental.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::db::schema::diff::SchemaChange;
use crate::db::schema::generator::*;
use crate::db::schema::types::*;
use std::collections::HashMap;

/// Generates incremental migration SQL/JS from a list of schema changes.
pub trait IncrementalGenerator {
    fn driver(&self) -> DbDriver;
    fn generate(&self, changes: &[SchemaChange], new_schema: &SchemaDef) -> String;
}

// ===========================================================================
// Postgres
// ===========================================================================

pub struct PostgresIncremental;

impl IncrementalGenerator for PostgresIncremental {
    fn driver(&self) -> DbDriver {
        DbDriver::Postgres
    }

    fn generate(&self, changes: &[SchemaChange], _new_schema: &SchemaDef) -> String {
        let pg = PostgresGenerator;
        let mut out = Vec::new();

        out.push("-- Heimdall Incremental Migration (PostgreSQL)".to_string());
        out.push("-- Generated from schema DSL — do not edit manually".to_string());
        out.push(String::new());

        for change in changes {
            match change {
                SchemaChange::AddExtension(ext) => {
                    out.push(format!("CREATE EXTENSION IF NOT EXISTS \"{ext}\";"));
                }
                SchemaChange::DropExtension(ext) => {
                    out.push(format!("DROP EXTENSION IF EXISTS \"{ext}\";"));
                }
                SchemaChange::AddTable(table) => {
                    out.push(format!("-- Add table: {}", table.name));
                    out.push(pg.generate_table(table));
                    if table.has_updated_at {
                        out.push(pg.generate_trigger_function());
                        out.push(pg.generate_trigger(&table.name));
                    }
                    out.push(String::new());
                }
                SchemaChange::DropTable(name) => {
                    out.push(format!("-- Drop table: {name}"));
                    out.push(format!("DROP TABLE IF EXISTS {name} CASCADE;"));
                    out.push(String::new());
                }
                SchemaChange::AddColumn { table, column } => {
                    out.push(format!(
                        "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {};",
                        pg.generate_column(column)
                    ));
                }
                SchemaChange::DropColumn { table, column_name } => {
                    out.push(format!(
                        "ALTER TABLE {table} DROP COLUMN IF EXISTS {column_name};"
                    ));
                }
                SchemaChange::AlterColumn { table, old, new } => {
                    out.push(format!("-- Alter column: {table}.{}", new.name));
                    if old.col_type != new.col_type {
                        out.push(format!(
                            "ALTER TABLE {table} ALTER COLUMN {} TYPE {};",
                            new.name,
                            pg.col_type(&new.col_type)
                        ));
                    }
                    if old.nullable && !new.nullable {
                        out.push(format!(
                            "ALTER TABLE {table} ALTER COLUMN {} SET NOT NULL;",
                            new.name
                        ));
                    }
                    if !old.nullable && new.nullable {
                        out.push(format!(
                            "ALTER TABLE {table} ALTER COLUMN {} DROP NOT NULL;",
                            new.name
                        ));
                    }
                    if old.default != new.default {
                        if let Some(ref dv) = new.default {
                            out.push(format!(
                                "ALTER TABLE {table} ALTER COLUMN {} SET DEFAULT {};",
                                new.name,
                                pg.default_value(dv)
                            ));
                        } else {
                            out.push(format!(
                                "ALTER TABLE {table} ALTER COLUMN {} DROP DEFAULT;",
                                new.name
                            ));
                        }
                    }
                    if old.unique != new.unique {
                        if new.unique {
                            out.push(format!(
                                "ALTER TABLE {table} ADD CONSTRAINT uq_{table}_{} UNIQUE ({});",
                                new.name, new.name
                            ));
                        } else {
                            out.push(format!(
                                "ALTER TABLE {table} DROP CONSTRAINT IF EXISTS uq_{table}_{};",
                                new.name
                            ));
                        }
                    }
                }
                SchemaChange::AddIndex(idx) => {
                    out.push(pg.generate_index(idx));
                }
                SchemaChange::DropIndex { index_name } => {
                    out.push(format!("DROP INDEX IF EXISTS {index_name};"));
                }
                SchemaChange::AddUniqueConstraint { table, columns } => {
                    let cols = columns.join(", ");
                    let name = format!("uq_{}_{}", table, columns.join("_"));
                    out.push(format!(
                        "ALTER TABLE {table} ADD CONSTRAINT {name} UNIQUE ({cols});"
                    ));
                }
                SchemaChange::DropUniqueConstraint { table, columns } => {
                    let name = format!("uq_{}_{}", table, columns.join("_"));
                    out.push(format!(
                        "ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name};"
                    ));
                }
                SchemaChange::AddUpdatedAtTrigger { table } => {
                    out.push(pg.generate_trigger_function());
                    out.push(pg.generate_trigger(table));
                }
                SchemaChange::DropUpdatedAtTrigger { table } => {
                    out.push(format!(
                        "DROP TRIGGER IF EXISTS update_{table}_updated_at ON {table};"
                    ));
                }
            }
        }

        out.join("\n")
    }
}

// ===========================================================================
// SQLite
// ===========================================================================

pub struct SqliteIncremental;

impl IncrementalGenerator for SqliteIncremental {
    fn driver(&self) -> DbDriver {
        DbDriver::Sqlite
    }

    fn generate(&self, changes: &[SchemaChange], new_schema: &SchemaDef) -> String {
        let sqlite = SqliteGenerator;
        let new_tables: HashMap<&str, &TableDef> = new_schema
            .tables
            .iter()
            .map(|t| (t.name.as_str(), t))
            .collect();
        let mut out = Vec::new();

        out.push("-- Heimdall Incremental Migration (SQLite)".to_string());
        out.push("-- Generated from schema DSL — do not edit manually".to_string());
        out.push(String::new());
        out.push("PRAGMA foreign_keys = ON;".to_string());
        out.push(String::new());

        for change in changes {
            match change {
                SchemaChange::AddExtension(_) | SchemaChange::DropExtension(_) => {
                    // No extensions in SQLite
                }
                SchemaChange::AddTable(table) => {
                    out.push(format!("-- Add table: {}", table.name));
                    out.push(sqlite.generate_table(table));
                    out.push(String::new());
                }
                SchemaChange::DropTable(name) => {
                    out.push(format!("DROP TABLE IF EXISTS {name};"));
                    out.push(String::new());
                }
                SchemaChange::AddColumn { table, column } => {
                    out.push(format!(
                        "ALTER TABLE {table} ADD COLUMN {};",
                        sqlite.generate_column(column)
                    ));
                }
                SchemaChange::DropColumn { table, column_name } => {
                    // SQLite 3.35+
                    out.push(format!("ALTER TABLE {table} DROP COLUMN {column_name};"));
                }
                SchemaChange::AlterColumn { table, .. } => {
                    // SQLite cannot ALTER COLUMN — recreate the table
                    if let Some(new_table) = new_tables.get(table.as_str()) {
                        out.push(format!(
                            "-- Recreate table {table} (SQLite cannot ALTER COLUMN)"
                        ));
                        out.push(format!("ALTER TABLE {table} RENAME TO {table}_old;"));
                        out.push(sqlite.generate_table(new_table));

                        // Copy data for columns that exist in both old and new
                        let col_names: Vec<&str> =
                            new_table.columns.iter().map(|c| c.name.as_str()).collect();
                        let cols = col_names.join(", ");
                        out.push(format!(
                            "INSERT INTO {table} ({cols}) SELECT {cols} FROM {table}_old;",
                        ));
                        out.push(format!("DROP TABLE {table}_old;"));
                        out.push(String::new());
                    }
                }
                SchemaChange::AddIndex(idx) => {
                    out.push(sqlite.generate_index(idx));
                }
                SchemaChange::DropIndex { index_name } => {
                    out.push(format!("DROP INDEX IF EXISTS {index_name};"));
                }
                SchemaChange::AddUniqueConstraint { table, .. }
                | SchemaChange::DropUniqueConstraint { table, .. } => {
                    // SQLite: recreate table for constraint changes
                    if let Some(new_table) = new_tables.get(table.as_str()) {
                        out.push(format!(
                            "-- Recreate table {table} (SQLite unique constraint change)"
                        ));
                        out.push(format!("ALTER TABLE {table} RENAME TO {table}_old;"));
                        out.push(sqlite.generate_table(new_table));
                        let col_names: Vec<&str> =
                            new_table.columns.iter().map(|c| c.name.as_str()).collect();
                        let cols = col_names.join(", ");
                        out.push(format!(
                            "INSERT INTO {table} ({cols}) SELECT {cols} FROM {table}_old;",
                        ));
                        out.push(format!("DROP TABLE {table}_old;"));
                        out.push(String::new());
                    }
                }
                SchemaChange::AddUpdatedAtTrigger { .. }
                | SchemaChange::DropUpdatedAtTrigger { .. } => {
                    // No triggers in SQLite — app layer handles updated_at
                }
            }
        }

        out.join("\n")
    }
}

// ===========================================================================
// MySQL
// ===========================================================================

pub struct MysqlIncremental;

impl IncrementalGenerator for MysqlIncremental {
    fn driver(&self) -> DbDriver {
        DbDriver::Mysql
    }

    fn generate(&self, changes: &[SchemaChange], _new_schema: &SchemaDef) -> String {
        let mysql = MysqlGenerator;
        let mut out = Vec::new();

        out.push("-- Heimdall Incremental Migration (MySQL)".to_string());
        out.push("-- Generated from schema DSL — do not edit manually".to_string());
        out.push(String::new());

        for change in changes {
            match change {
                SchemaChange::AddExtension(_) | SchemaChange::DropExtension(_) => {
                    // No extensions in MySQL
                }
                SchemaChange::AddTable(table) => {
                    out.push(format!("-- Add table: {}", table.name));
                    out.push(mysql.generate_table(table));
                    if table.has_updated_at {
                        out.push(mysql.generate_trigger(&table.name));
                    }
                    out.push(String::new());
                }
                SchemaChange::DropTable(name) => {
                    out.push(format!("DROP TABLE IF EXISTS `{name}`;"));
                    out.push(String::new());
                }
                SchemaChange::AddColumn { table, column } => {
                    out.push(format!(
                        "ALTER TABLE `{table}` ADD COLUMN {};",
                        mysql.generate_column(column)
                    ));
                    if let Some(ref fk) = column.references {
                        out.push(format!(
                            "ALTER TABLE `{table}` ADD FOREIGN KEY (`{}`) REFERENCES `{}`(`{}`) ON DELETE {};",
                            column.name, fk.table, fk.column,
                            match fk.on_delete {
                                OnDelete::Cascade => "CASCADE",
                                OnDelete::SetNull => "SET NULL",
                                OnDelete::Restrict => "RESTRICT",
                            }
                        ));
                    }
                }
                SchemaChange::DropColumn { table, column_name } => {
                    out.push(format!(
                        "ALTER TABLE `{table}` DROP COLUMN `{column_name}`;"
                    ));
                }
                SchemaChange::AlterColumn { table, new, .. } => {
                    // MySQL MODIFY COLUMN redefines the column entirely
                    out.push(format!(
                        "ALTER TABLE `{table}` MODIFY COLUMN {};",
                        mysql.generate_column(new)
                    ));
                }
                SchemaChange::AddIndex(idx) => {
                    out.push(mysql.generate_index(idx));
                }
                SchemaChange::DropIndex { index_name } => {
                    // MySQL requires the table name for DROP INDEX — find it from context
                    out.push(format!("DROP INDEX `{index_name}`;"));
                }
                SchemaChange::AddUniqueConstraint { table, columns } => {
                    let cols = columns
                        .iter()
                        .map(|c| format!("`{c}`"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let name = format!("uq_{}_{}", table, columns.join("_"));
                    out.push(format!(
                        "ALTER TABLE `{table}` ADD CONSTRAINT `{name}` UNIQUE ({cols});"
                    ));
                }
                SchemaChange::DropUniqueConstraint { table, columns } => {
                    let name = format!("uq_{}_{}", table, columns.join("_"));
                    out.push(format!("ALTER TABLE `{table}` DROP INDEX `{name}`;"));
                }
                SchemaChange::AddUpdatedAtTrigger { table } => {
                    out.push(mysql.generate_trigger(table));
                }
                SchemaChange::DropUpdatedAtTrigger { table } => {
                    out.push(format!(
                        "DROP TRIGGER IF EXISTS `update_{table}_updated_at`;"
                    ));
                }
            }
        }

        out.join("\n")
    }
}

// ===========================================================================
// MongoDB
// ===========================================================================

pub struct MongoIncremental;

impl IncrementalGenerator for MongoIncremental {
    fn driver(&self) -> DbDriver {
        DbDriver::Mongo
    }

    fn generate(&self, changes: &[SchemaChange], new_schema: &SchemaDef) -> String {
        let mongo = MongoGenerator;
        let new_tables: HashMap<&str, &TableDef> = new_schema
            .tables
            .iter()
            .map(|t| (t.name.as_str(), t))
            .collect();
        let mut out = Vec::new();

        out.push("// Heimdall Incremental Migration (MongoDB)".to_string());
        out.push("// Generated from schema DSL — do not edit manually".to_string());
        out.push("// Run with: mongosh < this_file.js".to_string());
        out.push(String::new());

        for change in changes {
            match change {
                SchemaChange::AddExtension(_) | SchemaChange::DropExtension(_) => {}
                SchemaChange::AddTable(table) => {
                    out.push(format!("// Add collection: {}", table.name));
                    out.push(mongo.generate_collection(table));
                    // Unique column indexes
                    for col in &table.columns {
                        if col.unique && !col.primary_key {
                            out.push(format!(
                                "db.{}.createIndex({{ {}: 1 }}, {{ unique: true }});",
                                table.name, col.name
                            ));
                        }
                    }
                    for uc in &table.unique_constraints {
                        out.push(mongo.generate_unique_index(&table.name, &uc.columns));
                    }
                    out.push(String::new());
                }
                SchemaChange::DropTable(name) => {
                    out.push(format!("db.{name}.drop();"));
                    out.push(String::new());
                }
                SchemaChange::AddColumn { table, .. }
                | SchemaChange::DropColumn { table, .. }
                | SchemaChange::AlterColumn { table, .. }
                | SchemaChange::AddUniqueConstraint { table, .. }
                | SchemaChange::DropUniqueConstraint { table, .. } => {
                    // Mongo: regenerate the full validator via collMod
                    if let Some(new_table) = new_tables.get(table.as_str()) {
                        out.push(format!("// Update validator for: {table}"));
                        // Build the validator JSON
                        let validator = build_mongo_validator(new_table);
                        out.push(format!(
                            "db.runCommand({{ collMod: \"{table}\", validator: {validator} }});",
                        ));
                        out.push(String::new());
                    }
                }
                SchemaChange::AddIndex(idx) => {
                    out.push(mongo.generate_index(&idx.table, idx));
                }
                SchemaChange::DropIndex { index_name } => {
                    out.push(format!("// Drop index: {index_name}"));
                    out.push(format!(
                        "// Note: use db.<collection>.dropIndex(\"{index_name}\") with the correct collection"
                    ));
                }
                SchemaChange::AddUpdatedAtTrigger { .. }
                | SchemaChange::DropUpdatedAtTrigger { .. } => {
                    // No triggers in Mongo — app layer handles updated_at
                }
            }
        }

        out.join("\n")
    }
}

/// Build a $jsonSchema validator object for a MongoDB collection.
fn build_mongo_validator(table: &TableDef) -> String {
    let mongo = MongoGenerator;
    let mut properties = Vec::new();
    let mut required = Vec::new();

    for col in &table.columns {
        if col.primary_key {
            properties.push(
                "        _id: { bsonType: \"string\", description: \"UUIDv7 primary key\" }"
                    .to_string(),
            );
            required.push("\"_id\"".to_string());
            continue;
        }

        let bson = mongo.bson_type(&col.col_type);
        let desc = if let Some(ref fk) = col.references {
            format!(", description: \"References {}.{}\"", fk.table, fk.column)
        } else {
            String::new()
        };

        properties.push(format!(
            "        {}: {{ bsonType: \"{bson}\"{desc} }}",
            col.name
        ));

        if !col.nullable {
            required.push(format!("\"{}\"", col.name));
        }
    }

    format!(
        "{{ $jsonSchema: {{ bsonType: \"object\", required: [{}], properties: {{\n{}\n    }} }} }}",
        required.join(", "),
        properties.join(",\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::builder::Schema;
    use crate::db::schema::diff::diff_schemas;

    #[test]
    fn test_postgres_add_column() {
        let old = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").not_null();
            })
            .build();
        let new = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").not_null();
                t.text("display_name");
            })
            .build();

        let changes = diff_schemas(&old, &new);
        let sql = PostgresIncremental.generate(&changes, &new);
        assert!(sql.contains("ALTER TABLE users ADD COLUMN display_name TEXT"));
    }

    #[test]
    fn test_postgres_alter_column_type() {
        let old = Schema::new()
            .table("t", |t| {
                t.uuid_pk("id");
                t.text("score");
            })
            .build();
        let new = Schema::new()
            .table("t", |t| {
                t.uuid_pk("id");
                t.integer("score");
            })
            .build();

        let changes = diff_schemas(&old, &new);
        let sql = PostgresIncremental.generate(&changes, &new);
        assert!(sql.contains("ALTER TABLE t ALTER COLUMN score TYPE INT"));
    }

    #[test]
    fn test_postgres_add_table_with_trigger() {
        let old = Schema::new().build();
        let new = Schema::new()
            .table("logs", |t| {
                t.uuid_pk("id");
                t.text("message").not_null();
                t.timestamps();
            })
            .build();

        let changes = diff_schemas(&old, &new);
        let sql = PostgresIncremental.generate(&changes, &new);
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS logs"));
        assert!(sql.contains("update_logs_updated_at"));
    }

    #[test]
    fn test_mysql_modify_column() {
        let old = Schema::new()
            .table("t", |t| {
                t.uuid_pk("id");
                t.text("name");
            })
            .build();
        let new = Schema::new()
            .table("t", |t| {
                t.uuid_pk("id");
                t.text("name").not_null();
            })
            .build();

        let changes = diff_schemas(&old, &new);
        let sql = MysqlIncremental.generate(&changes, &new);
        assert!(sql.contains("ALTER TABLE `t` MODIFY COLUMN `name` TEXT NOT NULL"));
    }

    #[test]
    fn test_sqlite_alter_column_recreates() {
        let old = Schema::new()
            .table("t", |t| {
                t.uuid_pk("id");
                t.text("name");
            })
            .build();
        let new = Schema::new()
            .table("t", |t| {
                t.uuid_pk("id");
                t.integer("name").not_null();
            })
            .build();

        let changes = diff_schemas(&old, &new);
        let sql = SqliteIncremental.generate(&changes, &new);
        assert!(sql.contains("ALTER TABLE t RENAME TO t_old"));
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS t"));
        assert!(sql.contains("DROP TABLE t_old"));
    }

    #[test]
    fn test_mongo_add_collection() {
        let old = Schema::new().build();
        let new = Schema::new()
            .table("logs", |t| {
                t.uuid_pk("id");
                t.text("message").not_null();
            })
            .build();

        let changes = diff_schemas(&old, &new);
        let js = MongoIncremental.generate(&changes, &new);
        assert!(js.contains("db.createCollection(\"logs\""));
    }

    #[test]
    fn test_mongo_collmod_on_column_change() {
        let old = Schema::new()
            .table("t", |t| {
                t.uuid_pk("id");
                t.text("name");
            })
            .build();
        let new = Schema::new()
            .table("t", |t| {
                t.uuid_pk("id");
                t.text("name").not_null();
                t.text("email");
            })
            .build();

        let changes = diff_schemas(&old, &new);
        let js = MongoIncremental.generate(&changes, &new);
        assert!(js.contains("db.runCommand"));
        assert!(js.contains("collMod"));
    }
}
