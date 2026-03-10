//
//  heimdall
//  src/db/schema/types.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use serde::{Deserialize, Serialize};

/// Driver-agnostic column types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColumnType {
    Uuid,
    Text,
    Integer,
    Boolean,
    Timestamp,
    Jsonb,
}

/// Foreign key ON DELETE behavior
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnDelete {
    Cascade,
    SetNull,
    Restrict,
}

/// Driver-agnostic default values
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefaultValue {
    /// PG: gen_random_uuid(), SQLite: app-layer UUID generation
    UuidGenerate,
    /// PG: now(), SQLite: datetime('now')
    Now,
    /// Literal SQL string, passed through verbatim (e.g., "'user'", "'free'")
    Literal(String),
    /// Integer default (e.g., 0, 1, 3)
    Integer(i64),
    /// Boolean default — PG: TRUE/FALSE, SQLite: 1/0
    Boolean(bool),
}

/// Foreign key reference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignKey {
    pub table: String,
    pub column: String,
    pub on_delete: OnDelete,
}

/// A single column definition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnDef {
    pub name: String,
    pub col_type: ColumnType,
    pub nullable: bool,
    pub primary_key: bool,
    pub unique: bool,
    pub default: Option<DefaultValue>,
    pub references: Option<ForeignKey>,
}

impl ColumnDef {
    pub fn new(name: impl Into<String>, col_type: ColumnType) -> Self {
        Self {
            name: name.into(),
            col_type,
            nullable: true,
            primary_key: false,
            unique: false,
            default: None,
            references: None,
        }
    }
}

/// An index on a table
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexDef {
    pub name: Option<String>,
    pub columns: Vec<String>,
    pub unique: bool,
}

/// Composite unique constraint: UNIQUE(col_a, col_b)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniqueConstraint {
    pub columns: Vec<String>,
}

/// A full table definition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableDef {
    pub name: String,
    pub columns: Vec<ColumnDef>,
    pub indexes: Vec<IndexDef>,
    pub unique_constraints: Vec<UniqueConstraint>,
    pub has_updated_at: bool,
}

/// Standalone index (not inline in a table definition)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandaloneIndex {
    pub name: String,
    pub table: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

/// The complete schema definition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaDef {
    pub tables: Vec<TableDef>,
    pub standalone_indexes: Vec<StandaloneIndex>,
    pub extensions: Vec<String>,
}
