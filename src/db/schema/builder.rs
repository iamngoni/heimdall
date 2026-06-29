//
//  heimdall
//  src/db/schema/builder.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::db::schema::types::*;

// ---------------------------------------------------------------------------
// Schema (top-level builder)
// ---------------------------------------------------------------------------

pub struct Schema {
    def: SchemaDef,
}

impl Default for Schema {
    fn default() -> Self {
        Self::new()
    }
}

impl Schema {
    pub fn new() -> Self {
        Self {
            def: SchemaDef {
                tables: Vec::new(),
                standalone_indexes: Vec::new(),
                extensions: Vec::new(),
            },
        }
    }

    pub fn extension(mut self, name: &str) -> Self {
        self.def.extensions.push(name.to_string());
        self
    }

    pub fn table(mut self, name: &str, f: impl FnOnce(&mut TableBuilder)) -> Self {
        let mut tb = TableBuilder::new(name);
        f(&mut tb);
        self.def.tables.push(tb.build());
        self
    }

    pub fn index(mut self, name: &str, table: &str, columns: &[&str]) -> Self {
        self.def.standalone_indexes.push(StandaloneIndex {
            name: name.to_string(),
            table: table.to_string(),
            columns: columns.iter().map(|s| s.to_string()).collect(),
            unique: false,
        });
        self
    }

    pub fn unique_index(mut self, name: &str, table: &str, columns: &[&str]) -> Self {
        self.def.standalone_indexes.push(StandaloneIndex {
            name: name.to_string(),
            table: table.to_string(),
            columns: columns.iter().map(|s| s.to_string()).collect(),
            unique: true,
        });
        self
    }

    pub fn build(self) -> SchemaDef {
        self.def
    }
}

// ---------------------------------------------------------------------------
// TableBuilder
// ---------------------------------------------------------------------------

pub struct TableBuilder {
    def: TableDef,
}

impl TableBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            def: TableDef {
                name: name.to_string(),
                columns: Vec::new(),
                indexes: Vec::new(),
                unique_constraints: Vec::new(),
                has_updated_at: false,
            },
        }
    }

    /// UUID primary key with auto-generation default
    pub fn uuid_pk(&mut self, name: &str) -> &mut Self {
        let mut col = ColumnDef::new(name, ColumnType::Uuid);
        col.primary_key = true;
        col.nullable = false;
        col.default = Some(DefaultValue::UuidGenerate);
        self.def.columns.push(col);
        self
    }

    /// UUID column
    pub fn uuid(&mut self, name: &str) -> ColumnBuilder<'_> {
        self.push_column(ColumnDef::new(name, ColumnType::Uuid))
    }

    /// Text column
    pub fn text(&mut self, name: &str) -> ColumnBuilder<'_> {
        self.push_column(ColumnDef::new(name, ColumnType::Text))
    }

    /// Integer column
    pub fn integer(&mut self, name: &str) -> ColumnBuilder<'_> {
        self.push_column(ColumnDef::new(name, ColumnType::Integer))
    }

    /// Alias for integer
    pub fn int(&mut self, name: &str) -> ColumnBuilder<'_> {
        self.integer(name)
    }

    /// Boolean column
    pub fn boolean(&mut self, name: &str) -> ColumnBuilder<'_> {
        self.push_column(ColumnDef::new(name, ColumnType::Boolean))
    }

    /// Timestamp column (with timezone semantics)
    pub fn timestamp(&mut self, name: &str) -> ColumnBuilder<'_> {
        self.push_column(ColumnDef::new(name, ColumnType::Timestamp))
    }

    /// JSONB column
    pub fn jsonb(&mut self, name: &str) -> ColumnBuilder<'_> {
        self.push_column(ColumnDef::new(name, ColumnType::Jsonb))
    }

    /// Adds created_at (NOT NULL DEFAULT now()) + updated_at (NOT NULL DEFAULT now())
    pub fn timestamps(&mut self) -> &mut Self {
        let mut created = ColumnDef::new("created_at", ColumnType::Timestamp);
        created.nullable = false;
        created.default = Some(DefaultValue::Now);
        self.def.columns.push(created);

        let mut updated = ColumnDef::new("updated_at", ColumnType::Timestamp);
        updated.nullable = false;
        updated.default = Some(DefaultValue::Now);
        self.def.columns.push(updated);

        self.def.has_updated_at = true;
        self
    }

    /// Adds deleted_at (nullable timestamp) for soft deletes
    pub fn soft_delete(&mut self) -> &mut Self {
        let col = ColumnDef::new("deleted_at", ColumnType::Timestamp);
        // nullable by default
        self.def.columns.push(col);
        self
    }

    /// Table-level index
    pub fn index(&mut self, columns: &[&str]) -> &mut Self {
        self.def.indexes.push(IndexDef {
            name: None,
            columns: columns.iter().map(|s| s.to_string()).collect(),
            unique: false,
        });
        self
    }

    /// Table-level unique index
    pub fn unique_index(&mut self, columns: &[&str]) -> &mut Self {
        self.def.indexes.push(IndexDef {
            name: None,
            columns: columns.iter().map(|s| s.to_string()).collect(),
            unique: true,
        });
        self
    }

    /// Composite unique constraint: UNIQUE(col_a, col_b)
    pub fn unique_together(&mut self, columns: &[&str]) -> &mut Self {
        self.def.unique_constraints.push(UniqueConstraint {
            columns: columns.iter().map(|s| s.to_string()).collect(),
        });
        self
    }

    fn push_column(&mut self, col: ColumnDef) -> ColumnBuilder<'_> {
        let idx = self.def.columns.len();
        self.def.columns.push(col);
        ColumnBuilder {
            table: self,
            col_index: idx,
        }
    }

    pub fn build(self) -> TableDef {
        self.def
    }
}

// ---------------------------------------------------------------------------
// ColumnBuilder — mutates an already-pushed column via index
// ---------------------------------------------------------------------------

pub struct ColumnBuilder<'a> {
    table: &'a mut TableBuilder,
    col_index: usize,
}

impl<'a> ColumnBuilder<'a> {
    fn col(&mut self) -> &mut ColumnDef {
        &mut self.table.def.columns[self.col_index]
    }

    pub fn not_null(mut self) -> Self {
        self.col().nullable = false;
        self
    }

    pub fn nullable(mut self) -> Self {
        self.col().nullable = true;
        self
    }

    pub fn unique(mut self) -> Self {
        self.col().unique = true;
        self
    }

    pub fn default(mut self, val: DefaultValue) -> Self {
        self.col().default = Some(val);
        self
    }

    /// Shorthand for a literal SQL default (e.g., "'user'", "'free'")
    pub fn default_str(self, val: &str) -> Self {
        self.default(DefaultValue::Literal(val.to_string()))
    }

    /// Shorthand for integer default
    pub fn default_int(self, val: i64) -> Self {
        self.default(DefaultValue::Integer(val))
    }

    /// Shorthand for boolean default
    pub fn default_bool(self, val: bool) -> Self {
        self.default(DefaultValue::Boolean(val))
    }

    /// Begin a foreign key reference
    pub fn references(mut self, table: &str, column: &str) -> FkBuilder<'a> {
        self.col().references = Some(ForeignKey {
            table: table.to_string(),
            column: column.to_string(),
            on_delete: OnDelete::Restrict, // default
        });
        FkBuilder { inner: self }
    }
}

// ---------------------------------------------------------------------------
// FkBuilder — sets ON DELETE behavior, then returns to ColumnBuilder
// ---------------------------------------------------------------------------

pub struct FkBuilder<'a> {
    inner: ColumnBuilder<'a>,
}

impl<'a> FkBuilder<'a> {
    pub fn on_delete(mut self, behavior: OnDelete) -> ColumnBuilder<'a> {
        if let Some(ref mut fk) = self.inner.col().references {
            fk.on_delete = behavior;
        }
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_table_builder() {
        let schema = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").unique().not_null();
                t.text("display_name");
                t.timestamps();
                t.soft_delete();
            })
            .build();

        assert_eq!(schema.tables.len(), 1);
        let table = &schema.tables[0];
        assert_eq!(table.name, "users");
        assert_eq!(table.columns.len(), 6); // id, email, display_name, created_at, updated_at, deleted_at
        assert!(table.has_updated_at);

        let id_col = &table.columns[0];
        assert!(id_col.primary_key);
        assert!(!id_col.nullable);
        assert_eq!(id_col.default, Some(DefaultValue::UuidGenerate));

        let email_col = &table.columns[1];
        assert!(email_col.unique);
        assert!(!email_col.nullable);

        let display_col = &table.columns[2];
        assert!(display_col.nullable);
    }

    #[test]
    fn test_foreign_key_builder() {
        let schema = Schema::new()
            .table("repos", |t| {
                t.uuid_pk("id");
                t.uuid("user_id")
                    .not_null()
                    .references("users", "id")
                    .on_delete(OnDelete::Cascade);
            })
            .build();

        let col = &schema.tables[0].columns[1];
        assert_eq!(col.name, "user_id");
        assert!(!col.nullable);
        let fk = col.references.as_ref().unwrap();
        assert_eq!(fk.table, "users");
        assert_eq!(fk.column, "id");
        assert_eq!(fk.on_delete, OnDelete::Cascade);
    }

    #[test]
    fn test_unique_together() {
        let schema = Schema::new()
            .table("org_members", |t| {
                t.uuid_pk("id");
                t.uuid("org_id").not_null();
                t.uuid("user_id").not_null();
                t.unique_together(&["org_id", "user_id"]);
            })
            .build();

        assert_eq!(schema.tables[0].unique_constraints.len(), 1);
        assert_eq!(
            schema.tables[0].unique_constraints[0].columns,
            vec!["org_id", "user_id"]
        );
    }

    #[test]
    fn test_standalone_indexes() {
        let schema = Schema::new()
            .table("findings", |t| {
                t.uuid_pk("id");
                t.text("fingerprint").not_null();
            })
            .index("idx_findings_fingerprint", "findings", &["fingerprint"])
            .build();

        assert_eq!(schema.standalone_indexes.len(), 1);
        assert_eq!(
            schema.standalone_indexes[0].name,
            "idx_findings_fingerprint"
        );
        assert_eq!(schema.standalone_indexes[0].table, "findings");
    }
}
