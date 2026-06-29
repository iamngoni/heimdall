//
//  heimdall
//  src/db/schema/generator.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::db::schema::types::*;

/// Target database driver
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbDriver {
    Postgres,
    Sqlite,
    Mysql,
    Mongo,
}

/// Generates SQL migration strings from a schema definition
pub trait MigrationGenerator {
    fn driver(&self) -> DbDriver;
    fn generate(&self, schema: &SchemaDef) -> String;
}

// ===========================================================================
// PostgresGenerator
// ===========================================================================

pub struct PostgresGenerator;

impl PostgresGenerator {
    pub fn col_type(&self, ct: &ColumnType) -> &'static str {
        match ct {
            ColumnType::Uuid => "UUID",
            ColumnType::Text => "TEXT",
            ColumnType::Integer => "INT",
            ColumnType::Boolean => "BOOLEAN",
            ColumnType::Timestamp => "TIMESTAMPTZ",
            ColumnType::Jsonb => "JSONB",
        }
    }

    pub fn default_value(&self, dv: &DefaultValue) -> String {
        match dv {
            DefaultValue::UuidGenerate => "gen_random_uuid()".to_string(),
            DefaultValue::Now => "now()".to_string(),
            DefaultValue::Literal(s) => s.clone(),
            DefaultValue::Integer(n) => n.to_string(),
            DefaultValue::Boolean(b) => if *b { "TRUE" } else { "FALSE" }.to_string(),
        }
    }

    fn on_delete(&self, od: &OnDelete) -> &'static str {
        match od {
            OnDelete::Cascade => "CASCADE",
            OnDelete::SetNull => "SET NULL",
            OnDelete::Restrict => "RESTRICT",
        }
    }

    pub fn generate_column(&self, col: &ColumnDef) -> String {
        let mut parts = Vec::new();
        parts.push(col.name.clone());
        parts.push(self.col_type(&col.col_type).to_string());

        if col.primary_key {
            parts.push("PRIMARY KEY".to_string());
        }

        if !col.nullable {
            parts.push("NOT NULL".to_string());
        }

        if col.unique {
            parts.push("UNIQUE".to_string());
        }

        if let Some(ref dv) = col.default {
            parts.push(format!("DEFAULT {}", self.default_value(dv)));
        }

        if let Some(ref fk) = col.references {
            parts.push(format!(
                "REFERENCES {}({}) ON DELETE {}",
                fk.table,
                fk.column,
                self.on_delete(&fk.on_delete)
            ));
        }

        parts.join(" ")
    }

    pub fn generate_table(&self, table: &TableDef) -> String {
        let mut lines: Vec<String> = table
            .columns
            .iter()
            .map(|c| format!("    {}", self.generate_column(c)))
            .collect();

        for uc in &table.unique_constraints {
            lines.push(format!("    UNIQUE({})", uc.columns.join(", ")));
        }

        format!(
            "CREATE TABLE IF NOT EXISTS {} (\n{}\n);",
            table.name,
            lines.join(",\n")
        )
    }

    pub fn generate_index(&self, idx: &StandaloneIndex) -> String {
        let unique = if idx.unique { "UNIQUE " } else { "" };
        format!(
            "CREATE {}INDEX IF NOT EXISTS {} ON {}({});",
            unique,
            idx.name,
            idx.table,
            idx.columns.join(", ")
        )
    }

    pub fn generate_trigger_function(&self) -> String {
        "CREATE OR REPLACE FUNCTION update_updated_at_column()\n\
         RETURNS TRIGGER AS $$\n\
         BEGIN\n\
             NEW.updated_at = now();\n\
             RETURN NEW;\n\
         END;\n\
         $$ language 'plpgsql';"
            .to_string()
    }

    pub fn generate_trigger(&self, table_name: &str) -> String {
        format!(
            "DROP TRIGGER IF EXISTS update_{table_name}_updated_at ON {table_name};\n\
             CREATE TRIGGER update_{table_name}_updated_at BEFORE UPDATE ON {table_name} FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();"
        )
    }
}

impl MigrationGenerator for PostgresGenerator {
    fn driver(&self) -> DbDriver {
        DbDriver::Postgres
    }

    fn generate(&self, schema: &SchemaDef) -> String {
        let mut out = Vec::new();

        out.push("-- Heimdall Schema Migration (PostgreSQL)".to_string());
        out.push("-- Generated from schema DSL — do not edit manually".to_string());
        out.push(String::new());

        // Extensions
        for ext in &schema.extensions {
            out.push(format!("CREATE EXTENSION IF NOT EXISTS \"{ext}\";"));
        }
        if !schema.extensions.is_empty() {
            out.push(String::new());
        }

        // Tables
        for (i, table) in schema.tables.iter().enumerate() {
            out.push(format!("-- {}. {}", i + 1, table.name));
            out.push(self.generate_table(table));
            out.push(String::new());
        }

        // Standalone indexes
        if !schema.standalone_indexes.is_empty() {
            out.push("-- Indexes".to_string());
            for idx in &schema.standalone_indexes {
                out.push(self.generate_index(idx));
            }
            out.push(String::new());
        }

        // Trigger function + triggers for tables with updated_at
        let tables_with_updated_at: Vec<&TableDef> =
            schema.tables.iter().filter(|t| t.has_updated_at).collect();

        if !tables_with_updated_at.is_empty() {
            out.push("-- Auto-update updated_at triggers".to_string());
            out.push(self.generate_trigger_function());
            out.push(String::new());
            for table in &tables_with_updated_at {
                out.push(self.generate_trigger(&table.name));
            }
            out.push(String::new());
        }

        // Idempotent column additions — ensures columns added after initial
        // table creation are present on existing databases. Every column in
        // the DSL gets an `ADD COLUMN IF NOT EXISTS` so new fields are
        // picked up automatically on restart.
        out.push("-- Idempotent column sync".to_string());
        for table in &schema.tables {
            for col in &table.columns {
                let col_type = self.col_type(&col.col_type);
                let mut def = col_type.to_string();
                if !col.nullable {
                    def.push_str(" NOT NULL");
                }
                if let Some(ref dv) = col.default {
                    def.push_str(&format!(" DEFAULT {}", self.default_value(dv)));
                }
                out.push(format!(
                    "ALTER TABLE {} ADD COLUMN IF NOT EXISTS {} {};",
                    table.name, col.name, def
                ));
            }
        }
        out.push(String::new());

        out.join("\n")
    }
}

// ===========================================================================
// SqliteGenerator
// ===========================================================================

pub struct SqliteGenerator;

impl SqliteGenerator {
    pub fn col_type(&self, ct: &ColumnType) -> &'static str {
        match ct {
            ColumnType::Uuid => "TEXT",
            ColumnType::Text => "TEXT",
            ColumnType::Integer => "INTEGER",
            ColumnType::Boolean => "INTEGER",
            ColumnType::Timestamp => "TEXT",
            ColumnType::Jsonb => "TEXT",
        }
    }

    fn default_value(&self, dv: &DefaultValue) -> Option<String> {
        match dv {
            // SQLite doesn't have gen_random_uuid() — app layer handles it
            DefaultValue::UuidGenerate => None,
            DefaultValue::Now => Some("datetime('now')".to_string()),
            DefaultValue::Literal(s) => Some(s.clone()),
            DefaultValue::Integer(n) => Some(n.to_string()),
            DefaultValue::Boolean(b) => Some(if *b { "1" } else { "0" }.to_string()),
        }
    }

    fn on_delete(&self, od: &OnDelete) -> &'static str {
        match od {
            OnDelete::Cascade => "CASCADE",
            OnDelete::SetNull => "SET NULL",
            OnDelete::Restrict => "RESTRICT",
        }
    }

    pub fn generate_column(&self, col: &ColumnDef) -> String {
        let mut parts = Vec::new();
        parts.push(col.name.clone());
        parts.push(self.col_type(&col.col_type).to_string());

        if col.primary_key {
            parts.push("PRIMARY KEY".to_string());
        }

        if !col.nullable {
            parts.push("NOT NULL".to_string());
        }

        if col.unique {
            parts.push("UNIQUE".to_string());
        }

        if let Some(ref dv) = col.default
            && let Some(val) = self.default_value(dv)
        {
            parts.push(format!("DEFAULT {val}"));
        }

        if let Some(ref fk) = col.references {
            parts.push(format!(
                "REFERENCES {}({}) ON DELETE {}",
                fk.table,
                fk.column,
                self.on_delete(&fk.on_delete)
            ));
        }

        parts.join(" ")
    }

    pub fn generate_table(&self, table: &TableDef) -> String {
        let mut lines: Vec<String> = table
            .columns
            .iter()
            .map(|c| format!("    {}", self.generate_column(c)))
            .collect();

        for uc in &table.unique_constraints {
            lines.push(format!("    UNIQUE({})", uc.columns.join(", ")));
        }

        format!(
            "CREATE TABLE IF NOT EXISTS {} (\n{}\n);",
            table.name,
            lines.join(",\n")
        )
    }

    pub fn generate_index(&self, idx: &StandaloneIndex) -> String {
        let unique = if idx.unique { "UNIQUE " } else { "" };
        format!(
            "CREATE {}INDEX IF NOT EXISTS {} ON {}({});",
            unique,
            idx.name,
            idx.table,
            idx.columns.join(", ")
        )
    }
}

impl MigrationGenerator for SqliteGenerator {
    fn driver(&self) -> DbDriver {
        DbDriver::Sqlite
    }

    fn generate(&self, schema: &SchemaDef) -> String {
        let mut out = Vec::new();

        out.push("-- Heimdall Schema Migration (SQLite)".to_string());
        out.push("-- Generated from schema DSL — do not edit manually".to_string());
        out.push(String::new());
        out.push("PRAGMA foreign_keys = ON;".to_string());
        out.push(String::new());

        // Tables
        for (i, table) in schema.tables.iter().enumerate() {
            out.push(format!("-- {}. {}", i + 1, table.name));
            out.push(self.generate_table(table));
            out.push(String::new());
        }

        // Standalone indexes
        if !schema.standalone_indexes.is_empty() {
            out.push("-- Indexes".to_string());
            for idx in &schema.standalone_indexes {
                out.push(self.generate_index(idx));
            }
            out.push(String::new());
        }

        // No triggers for SQLite — app layer handles updated_at

        out.join("\n")
    }
}

// ===========================================================================
// MysqlGenerator
// ===========================================================================

pub struct MysqlGenerator;

impl MysqlGenerator {
    pub fn col_type(&self, ct: &ColumnType) -> &'static str {
        match ct {
            ColumnType::Uuid => "CHAR(36)",
            ColumnType::Text => "TEXT",
            ColumnType::Integer => "INT",
            ColumnType::Boolean => "TINYINT(1)",
            ColumnType::Timestamp => "TIMESTAMP",
            ColumnType::Jsonb => "JSON",
        }
    }

    pub fn default_value(&self, dv: &DefaultValue) -> Option<String> {
        match dv {
            // MySQL 8+ supports UUID() but not as a column default — app layer handles it
            DefaultValue::UuidGenerate => None,
            DefaultValue::Now => Some("CURRENT_TIMESTAMP".to_string()),
            DefaultValue::Literal(s) => Some(s.clone()),
            DefaultValue::Integer(n) => Some(n.to_string()),
            DefaultValue::Boolean(b) => Some(if *b { "1" } else { "0" }.to_string()),
        }
    }

    fn on_delete(&self, od: &OnDelete) -> &'static str {
        match od {
            OnDelete::Cascade => "CASCADE",
            OnDelete::SetNull => "SET NULL",
            OnDelete::Restrict => "RESTRICT",
        }
    }

    pub fn generate_column(&self, col: &ColumnDef) -> String {
        let mut parts = Vec::new();
        parts.push(format!("`{}`", col.name));
        parts.push(self.col_type(&col.col_type).to_string());

        if !col.nullable {
            parts.push("NOT NULL".to_string());
        }

        if col.unique && !col.primary_key {
            parts.push("UNIQUE".to_string());
        }

        if let Some(ref dv) = col.default
            && let Some(val) = self.default_value(dv)
        {
            parts.push(format!("DEFAULT {val}"));
        }

        parts.join(" ")
    }

    pub fn generate_table(&self, table: &TableDef) -> String {
        let mut lines: Vec<String> = table
            .columns
            .iter()
            .map(|c| format!("    {}", self.generate_column(c)))
            .collect();

        // Primary key
        if let Some(pk) = table.columns.iter().find(|c| c.primary_key) {
            lines.push(format!("    PRIMARY KEY (`{}`)", pk.name));
        }

        // Foreign keys
        for col in &table.columns {
            if let Some(ref fk) = col.references {
                lines.push(format!(
                    "    FOREIGN KEY (`{}`) REFERENCES `{}`(`{}`) ON DELETE {}",
                    col.name,
                    fk.table,
                    fk.column,
                    self.on_delete(&fk.on_delete)
                ));
            }
        }

        // Unique constraints
        for uc in &table.unique_constraints {
            let cols = uc
                .columns
                .iter()
                .map(|c| format!("`{c}`"))
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!("    UNIQUE ({cols})"));
        }

        format!(
            "CREATE TABLE IF NOT EXISTS `{}` (\n{}\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;",
            table.name,
            lines.join(",\n")
        )
    }

    pub fn generate_index(&self, idx: &StandaloneIndex) -> String {
        let unique = if idx.unique { "UNIQUE " } else { "" };
        let cols = idx
            .columns
            .iter()
            .map(|c| format!("`{c}`"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "CREATE {unique}INDEX `{}` ON `{}`({cols});",
            idx.name, idx.table
        )
    }

    pub fn generate_trigger(&self, table_name: &str) -> String {
        format!(
            "DROP TRIGGER IF EXISTS `update_{table_name}_updated_at`;\n\
             CREATE TRIGGER `update_{table_name}_updated_at` BEFORE UPDATE ON `{table_name}`\n\
             FOR EACH ROW SET NEW.`updated_at` = CURRENT_TIMESTAMP;"
        )
    }
}

impl MigrationGenerator for MysqlGenerator {
    fn driver(&self) -> DbDriver {
        DbDriver::Mysql
    }

    fn generate(&self, schema: &SchemaDef) -> String {
        let mut out = Vec::new();

        out.push("-- Heimdall Schema Migration (MySQL)".to_string());
        out.push("-- Generated from schema DSL — do not edit manually".to_string());
        out.push(String::new());
        out.push("SET NAMES utf8mb4;".to_string());
        out.push("SET FOREIGN_KEY_CHECKS = 0;".to_string());
        out.push(String::new());

        // Tables
        for (i, table) in schema.tables.iter().enumerate() {
            out.push(format!("-- {}. {}", i + 1, table.name));
            out.push(self.generate_table(table));
            out.push(String::new());
        }

        // Standalone indexes
        if !schema.standalone_indexes.is_empty() {
            out.push("-- Indexes".to_string());
            for idx in &schema.standalone_indexes {
                out.push(self.generate_index(idx));
            }
            out.push(String::new());
        }

        // Triggers for updated_at
        let tables_with_updated_at: Vec<&TableDef> =
            schema.tables.iter().filter(|t| t.has_updated_at).collect();

        if !tables_with_updated_at.is_empty() {
            out.push("-- Auto-update updated_at triggers".to_string());
            for table in &tables_with_updated_at {
                out.push(self.generate_trigger(&table.name));
            }
            out.push(String::new());
        }

        out.push("SET FOREIGN_KEY_CHECKS = 1;".to_string());
        out.push(String::new());

        out.join("\n")
    }
}

// ===========================================================================
// MongoGenerator — Laravel-style collection + JSON Schema validators
// ===========================================================================

pub struct MongoGenerator;

impl MongoGenerator {
    pub fn bson_type(&self, ct: &ColumnType) -> &'static str {
        match ct {
            ColumnType::Uuid => "string",
            ColumnType::Text => "string",
            ColumnType::Integer => "int",
            ColumnType::Boolean => "bool",
            ColumnType::Timestamp => "date",
            ColumnType::Jsonb => "object",
        }
    }

    pub fn generate_collection(&self, table: &TableDef) -> String {
        let mut out = Vec::new();

        // Build JSON Schema properties
        let mut properties = Vec::new();
        let mut required = Vec::new();

        for col in &table.columns {
            if col.primary_key {
                // MongoDB uses _id — map the PK
                properties.push("        _id: {\n            bsonType: \"string\",\n            description: \"UUIDv7 primary key\"\n        }".to_string());
                required.push("\"_id\"".to_string());
                continue;
            }

            let bson = self.bson_type(&col.col_type);

            // For FK references, add a description
            let desc = if let Some(ref fk) = col.references {
                format!(
                    ",\n            description: \"References {}.{}\"",
                    fk.table, fk.column
                )
            } else {
                String::new()
            };

            properties.push(format!(
                "        {}: {{\n            bsonType: \"{bson}\"{desc}\n        }}",
                col.name
            ));

            if !col.nullable {
                required.push(format!("\"{}\"", col.name));
            }
        }

        out.push(format!("db.createCollection(\"{}\", {{", table.name));
        out.push("    validator: {".to_string());
        out.push("        $jsonSchema: {".to_string());
        out.push("            bsonType: \"object\",".to_string());
        out.push(format!("            required: [{}],", required.join(", ")));
        out.push("            properties: {".to_string());
        out.push(properties.join(",\n"));
        out.push("            }".to_string());
        out.push("        }".to_string());
        out.push("    }".to_string());
        out.push("});".to_string());

        out.join("\n")
    }

    pub fn generate_index(&self, collection: &str, idx: &StandaloneIndex) -> String {
        let fields: Vec<String> = idx.columns.iter().map(|c| format!("{c}: 1")).collect();
        let unique = if idx.unique { ", { unique: true }" } else { "" };
        format!(
            "db.{collection}.createIndex({{ {} }}{unique});",
            fields.join(", ")
        )
    }

    pub fn generate_unique_index(&self, collection: &str, columns: &[String]) -> String {
        let fields: Vec<String> = columns.iter().map(|c| format!("{c}: 1")).collect();
        format!(
            "db.{collection}.createIndex({{ {} }}, {{ unique: true }});",
            fields.join(", ")
        )
    }
}

impl MigrationGenerator for MongoGenerator {
    fn driver(&self) -> DbDriver {
        DbDriver::Mongo
    }

    fn generate(&self, schema: &SchemaDef) -> String {
        let mut out = Vec::new();

        out.push("// Heimdall Schema Migration (MongoDB)".to_string());
        out.push("// Generated from schema DSL — do not edit manually".to_string());
        out.push("// Run with: mongosh < this_file.js".to_string());
        out.push(String::new());

        // Collections with validators
        for (i, table) in schema.tables.iter().enumerate() {
            out.push(format!("// {}. {}", i + 1, table.name));
            out.push(self.generate_collection(table));
            out.push(String::new());

            // Unique column indexes (from column-level unique)
            for col in &table.columns {
                if col.unique && !col.primary_key {
                    out.push(format!(
                        "db.{}.createIndex({{ {}: 1 }}, {{ unique: true }});",
                        table.name, col.name
                    ));
                }
            }

            // Composite unique constraints
            for uc in &table.unique_constraints {
                out.push(self.generate_unique_index(&table.name, &uc.columns));
            }

            out.push(String::new());
        }

        // Standalone indexes
        if !schema.standalone_indexes.is_empty() {
            out.push("// Indexes".to_string());
            for idx in &schema.standalone_indexes {
                out.push(self.generate_index(&idx.table, idx));
            }
            out.push(String::new());
        }

        out.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::builder::Schema;

    #[test]
    fn test_postgres_basic_table() {
        let schema = Schema::new()
            .extension("pgcrypto")
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").unique().not_null();
                t.text("role").not_null().default_str("'user'");
                t.timestamps();
            })
            .build();

        let sql = PostgresGenerator.generate(&schema);
        assert!(sql.contains("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\""));
        assert!(sql.contains("id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid()"));
        assert!(sql.contains("email TEXT NOT NULL UNIQUE"));
        assert!(sql.contains("role TEXT NOT NULL DEFAULT 'user'"));
        assert!(sql.contains("created_at TIMESTAMPTZ NOT NULL DEFAULT now()"));
        assert!(sql.contains("updated_at TIMESTAMPTZ NOT NULL DEFAULT now()"));
        assert!(sql.contains("update_updated_at_column()"));
        assert!(sql.contains("update_users_updated_at"));
    }

    #[test]
    fn test_sqlite_basic_table() {
        let schema = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").unique().not_null();
                t.boolean("active").not_null().default_bool(true);
                t.timestamps();
            })
            .build();

        let sql = SqliteGenerator.generate(&schema);
        assert!(sql.contains("PRAGMA foreign_keys = ON"));
        assert!(sql.contains("id TEXT PRIMARY KEY NOT NULL"));
        // No gen_random_uuid() default for SQLite
        assert!(!sql.contains("gen_random_uuid"));
        assert!(sql.contains("email TEXT NOT NULL UNIQUE"));
        assert!(sql.contains("active INTEGER NOT NULL DEFAULT 1"));
        assert!(sql.contains("created_at TEXT NOT NULL DEFAULT datetime('now')"));
        // No triggers
        assert!(!sql.contains("TRIGGER"));
    }

    #[test]
    fn test_postgres_foreign_keys() {
        let schema = Schema::new()
            .table("repos", |t| {
                t.uuid_pk("id");
                t.uuid("user_id")
                    .not_null()
                    .references("users", "id")
                    .on_delete(OnDelete::Cascade);
                t.uuid("org_id")
                    .references("organizations", "id")
                    .on_delete(OnDelete::SetNull);
            })
            .build();

        let sql = PostgresGenerator.generate(&schema);
        assert!(sql.contains("user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE"));
        assert!(sql.contains("org_id UUID REFERENCES organizations(id) ON DELETE SET NULL"));
    }

    #[test]
    fn test_unique_together_constraint() {
        let schema = Schema::new()
            .table("org_members", |t| {
                t.uuid_pk("id");
                t.uuid("org_id").not_null();
                t.uuid("user_id").not_null();
                t.unique_together(&["org_id", "user_id"]);
            })
            .build();

        let sql = PostgresGenerator.generate(&schema);
        assert!(sql.contains("UNIQUE(org_id, user_id)"));
    }

    #[test]
    fn test_standalone_indexes() {
        let schema = Schema::new()
            .table("findings", |t| {
                t.uuid_pk("id");
                t.text("fingerprint").not_null();
                t.uuid("scan_id").not_null();
                t.text("severity").not_null();
            })
            .index("idx_findings_fingerprint", "findings", &["fingerprint"])
            .index(
                "idx_findings_scan_severity",
                "findings",
                &["scan_id", "severity"],
            )
            .build();

        let sql = PostgresGenerator.generate(&schema);
        assert!(sql.contains(
            "CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)"
        ));
        assert!(sql.contains(
            "CREATE INDEX IF NOT EXISTS idx_findings_scan_severity ON findings(scan_id, severity)"
        ));
    }

    #[test]
    fn test_mysql_basic_table() {
        let schema = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").unique().not_null();
                t.boolean("active").not_null().default_bool(true);
                t.timestamps();
            })
            .build();

        let sql = MysqlGenerator.generate(&schema);
        assert!(sql.contains("SET NAMES utf8mb4"));
        assert!(sql.contains("SET FOREIGN_KEY_CHECKS = 0"));
        assert!(sql.contains("`id` CHAR(36) NOT NULL"));
        assert!(sql.contains("PRIMARY KEY (`id`)"));
        assert!(sql.contains("`email` TEXT NOT NULL UNIQUE"));
        assert!(sql.contains("`active` TINYINT(1) NOT NULL DEFAULT 1"));
        assert!(sql.contains("`created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"));
        assert!(sql.contains("ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"));
        assert!(sql.contains("update_users_updated_at"));
        assert!(sql.contains("SET FOREIGN_KEY_CHECKS = 1"));
    }

    #[test]
    fn test_mysql_foreign_keys() {
        let schema = Schema::new()
            .table("repos", |t| {
                t.uuid_pk("id");
                t.uuid("user_id")
                    .not_null()
                    .references("users", "id")
                    .on_delete(OnDelete::Cascade);
                t.uuid("org_id")
                    .references("organizations", "id")
                    .on_delete(OnDelete::SetNull);
            })
            .build();

        let sql = MysqlGenerator.generate(&schema);
        assert!(sql.contains("FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE"));
        assert!(sql.contains(
            "FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`) ON DELETE SET NULL"
        ));
    }

    #[test]
    fn test_mysql_indexes() {
        let schema = Schema::new()
            .table("findings", |t| {
                t.uuid_pk("id");
                t.text("fingerprint").not_null();
            })
            .index("idx_fingerprint", "findings", &["fingerprint"])
            .build();

        let sql = MysqlGenerator.generate(&schema);
        assert!(sql.contains("CREATE INDEX `idx_fingerprint` ON `findings`(`fingerprint`)"));
    }

    #[test]
    fn test_mongo_basic_collection() {
        let schema = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").unique().not_null();
                t.text("role").not_null().default_str("'user'");
                t.jsonb("metadata");
                t.timestamps();
            })
            .build();

        let js = MongoGenerator.generate(&schema);
        assert!(js.contains("db.createCollection(\"users\""));
        assert!(js.contains("$jsonSchema"));
        assert!(js.contains("bsonType: \"string\""));
        assert!(js.contains("bsonType: \"object\""));
        assert!(js.contains("bsonType: \"date\""));
        assert!(js.contains("\"_id\""));
        assert!(js.contains("\"email\""));
        // Unique index for email
        assert!(js.contains("db.users.createIndex({ email: 1 }, { unique: true })"));
    }

    #[test]
    fn test_mongo_indexes() {
        let schema = Schema::new()
            .table("findings", |t| {
                t.uuid_pk("id");
                t.text("fingerprint").not_null();
                t.uuid("scan_id").not_null();
            })
            .index("idx_findings_fp", "findings", &["fingerprint"])
            .build();

        let js = MongoGenerator.generate(&schema);
        assert!(js.contains("db.findings.createIndex({ fingerprint: 1 })"));
    }

    #[test]
    fn test_mongo_composite_unique() {
        let schema = Schema::new()
            .table("org_members", |t| {
                t.uuid_pk("id");
                t.uuid("org_id").not_null();
                t.uuid("user_id").not_null();
                t.unique_together(&["org_id", "user_id"]);
            })
            .build();

        let js = MongoGenerator.generate(&schema);
        assert!(
            js.contains("db.org_members.createIndex({ org_id: 1, user_id: 1 }, { unique: true })")
        );
    }
}
