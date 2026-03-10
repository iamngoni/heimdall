//
//  heimdall
//  src/db/schema/diff.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::db::schema::types::*;
use std::collections::HashMap;

/// A single change between two schema versions
#[derive(Debug, Clone)]
pub enum SchemaChange {
    AddExtension(String),
    DropExtension(String),
    AddTable(TableDef),
    DropTable(String),
    AddColumn {
        table: String,
        column: ColumnDef,
    },
    DropColumn {
        table: String,
        column_name: String,
    },
    AlterColumn {
        table: String,
        old: ColumnDef,
        new: ColumnDef,
    },
    AddIndex(StandaloneIndex),
    DropIndex {
        index_name: String,
    },
    AddUniqueConstraint {
        table: String,
        columns: Vec<String>,
    },
    DropUniqueConstraint {
        table: String,
        columns: Vec<String>,
    },
    AddUpdatedAtTrigger {
        table: String,
    },
    DropUpdatedAtTrigger {
        table: String,
    },
}

/// Compare two schema definitions and produce an ordered list of changes.
/// No rename detection — a renamed table/column appears as drop + add.
pub fn diff_schemas(old: &SchemaDef, new: &SchemaDef) -> Vec<SchemaChange> {
    let mut changes = Vec::new();

    // Extensions
    diff_extensions(old, new, &mut changes);

    // Tables
    let old_tables: HashMap<&str, &TableDef> =
        old.tables.iter().map(|t| (t.name.as_str(), t)).collect();
    let new_tables: HashMap<&str, &TableDef> =
        new.tables.iter().map(|t| (t.name.as_str(), t)).collect();

    // Drop tables (in reverse order to handle FK deps)
    for old_table in old.tables.iter().rev() {
        if !new_tables.contains_key(old_table.name.as_str()) {
            changes.push(SchemaChange::DropTable(old_table.name.clone()));
        }
    }

    // Add tables (in definition order to respect FK deps)
    for new_table in &new.tables {
        if !old_tables.contains_key(new_table.name.as_str()) {
            changes.push(SchemaChange::AddTable(new_table.clone()));
        }
    }

    // Diff existing tables
    for new_table in &new.tables {
        if let Some(old_table) = old_tables.get(new_table.name.as_str()) {
            diff_table(old_table, new_table, &mut changes);
        }
    }

    // Standalone indexes
    diff_standalone_indexes(old, new, &mut changes);

    changes
}

fn diff_extensions(old: &SchemaDef, new: &SchemaDef, changes: &mut Vec<SchemaChange>) {
    for ext in &new.extensions {
        if !old.extensions.contains(ext) {
            changes.push(SchemaChange::AddExtension(ext.clone()));
        }
    }
    for ext in &old.extensions {
        if !new.extensions.contains(ext) {
            changes.push(SchemaChange::DropExtension(ext.clone()));
        }
    }
}

fn diff_table(old: &TableDef, new: &TableDef, changes: &mut Vec<SchemaChange>) {
    let old_cols: HashMap<&str, &ColumnDef> =
        old.columns.iter().map(|c| (c.name.as_str(), c)).collect();
    let new_cols: HashMap<&str, &ColumnDef> =
        new.columns.iter().map(|c| (c.name.as_str(), c)).collect();

    // Dropped columns
    for old_col in &old.columns {
        if !new_cols.contains_key(old_col.name.as_str()) {
            changes.push(SchemaChange::DropColumn {
                table: old.name.clone(),
                column_name: old_col.name.clone(),
            });
        }
    }

    // Added columns (in definition order)
    for new_col in &new.columns {
        if !old_cols.contains_key(new_col.name.as_str()) {
            changes.push(SchemaChange::AddColumn {
                table: new.name.clone(),
                column: new_col.clone(),
            });
        }
    }

    // Altered columns
    for new_col in &new.columns {
        if let Some(old_col) = old_cols.get(new_col.name.as_str()) {
            if *old_col != new_col {
                changes.push(SchemaChange::AlterColumn {
                    table: new.name.clone(),
                    old: (*old_col).clone(),
                    new: new_col.clone(),
                });
            }
        }
    }

    // Unique constraints
    for uc in &new.unique_constraints {
        if !old.unique_constraints.contains(uc) {
            changes.push(SchemaChange::AddUniqueConstraint {
                table: new.name.clone(),
                columns: uc.columns.clone(),
            });
        }
    }
    for uc in &old.unique_constraints {
        if !new.unique_constraints.contains(uc) {
            changes.push(SchemaChange::DropUniqueConstraint {
                table: old.name.clone(),
                columns: uc.columns.clone(),
            });
        }
    }

    // updated_at trigger changes
    if new.has_updated_at && !old.has_updated_at {
        changes.push(SchemaChange::AddUpdatedAtTrigger {
            table: new.name.clone(),
        });
    }
    if !new.has_updated_at && old.has_updated_at {
        changes.push(SchemaChange::DropUpdatedAtTrigger {
            table: old.name.clone(),
        });
    }
}

fn diff_standalone_indexes(old: &SchemaDef, new: &SchemaDef, changes: &mut Vec<SchemaChange>) {
    let old_idx: HashMap<&str, &StandaloneIndex> = old
        .standalone_indexes
        .iter()
        .map(|i| (i.name.as_str(), i))
        .collect();
    let new_idx: HashMap<&str, &StandaloneIndex> = new
        .standalone_indexes
        .iter()
        .map(|i| (i.name.as_str(), i))
        .collect();

    // Dropped indexes
    for (name, _) in &old_idx {
        if !new_idx.contains_key(name) {
            changes.push(SchemaChange::DropIndex {
                index_name: name.to_string(),
            });
        }
    }

    // Added indexes
    for (name, idx) in &new_idx {
        if !old_idx.contains_key(name) {
            changes.push(SchemaChange::AddIndex((*idx).clone()));
        }
    }

    // Changed indexes (same name, different definition) — drop + re-add
    for (name, new_index) in &new_idx {
        if let Some(old_index) = old_idx.get(name) {
            if *old_index != *new_index {
                changes.push(SchemaChange::DropIndex {
                    index_name: name.to_string(),
                });
                changes.push(SchemaChange::AddIndex((*new_index).clone()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::builder::Schema;

    fn base_schema() -> SchemaDef {
        Schema::new()
            .extension("pgcrypto")
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").unique().not_null();
                t.text("role").not_null().default_str("'user'");
                t.timestamps();
            })
            .index("idx_users_email", "users", &["email"])
            .build()
    }

    #[test]
    fn test_no_changes() {
        let old = base_schema();
        let new = base_schema();
        let changes = diff_schemas(&old, &new);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_add_table() {
        let old = base_schema();
        let new = Schema::new()
            .extension("pgcrypto")
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").unique().not_null();
                t.text("role").not_null().default_str("'user'");
                t.timestamps();
            })
            .table("repos", |t| {
                t.uuid_pk("id");
                t.text("name").not_null();
            })
            .index("idx_users_email", "users", &["email"])
            .build();

        let changes = diff_schemas(&old, &new);
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, SchemaChange::AddTable(t) if t.name == "repos"))
        );
    }

    #[test]
    fn test_drop_table() {
        let old = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
            })
            .table("obsolete", |t| {
                t.uuid_pk("id");
            })
            .build();
        let new = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
            })
            .build();

        let changes = diff_schemas(&old, &new);
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, SchemaChange::DropTable(name) if name == "obsolete"))
        );
    }

    #[test]
    fn test_add_column() {
        let old = base_schema();
        let new = Schema::new()
            .extension("pgcrypto")
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").unique().not_null();
                t.text("role").not_null().default_str("'user'");
                t.text("display_name");
                t.timestamps();
            })
            .index("idx_users_email", "users", &["email"])
            .build();

        let changes = diff_schemas(&old, &new);
        assert!(changes.iter().any(
            |c| matches!(c, SchemaChange::AddColumn { table, column } if table == "users" && column.name == "display_name")
        ));
    }

    #[test]
    fn test_drop_column() {
        let old = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").not_null();
                t.text("obsolete_field");
            })
            .build();
        let new = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").not_null();
            })
            .build();

        let changes = diff_schemas(&old, &new);
        assert!(changes.iter().any(
            |c| matches!(c, SchemaChange::DropColumn { table, column_name } if table == "users" && column_name == "obsolete_field")
        ));
    }

    #[test]
    fn test_alter_column_nullable() {
        let old = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email");
            })
            .build();
        let new = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").not_null();
            })
            .build();

        let changes = diff_schemas(&old, &new);
        assert!(changes.iter().any(
            |c| matches!(c, SchemaChange::AlterColumn { table, old, new } if table == "users" && old.nullable && !new.nullable)
        ));
    }

    #[test]
    fn test_alter_column_type() {
        let old = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("score");
            })
            .build();
        let new = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.integer("score");
            })
            .build();

        let changes = diff_schemas(&old, &new);
        assert!(changes.iter().any(
            |c| matches!(c, SchemaChange::AlterColumn { new: col, .. } if col.col_type == ColumnType::Integer)
        ));
    }

    #[test]
    fn test_add_and_drop_index() {
        let old = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").not_null();
            })
            .index("idx_old", "users", &["email"])
            .build();
        let new = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").not_null();
            })
            .index("idx_new", "users", &["email"])
            .build();

        let changes = diff_schemas(&old, &new);
        assert!(changes.iter().any(
            |c| matches!(c, SchemaChange::DropIndex { index_name } if index_name == "idx_old")
        ));
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, SchemaChange::AddIndex(idx) if idx.name == "idx_new"))
        );
    }

    #[test]
    fn test_add_unique_constraint() {
        let old = Schema::new()
            .table("members", |t| {
                t.uuid_pk("id");
                t.uuid("org_id").not_null();
                t.uuid("user_id").not_null();
            })
            .build();
        let new = Schema::new()
            .table("members", |t| {
                t.uuid_pk("id");
                t.uuid("org_id").not_null();
                t.uuid("user_id").not_null();
                t.unique_together(&["org_id", "user_id"]);
            })
            .build();

        let changes = diff_schemas(&old, &new);
        assert!(changes.iter().any(
            |c| matches!(c, SchemaChange::AddUniqueConstraint { table, columns } if table == "members" && columns == &["org_id", "user_id"])
        ));
    }

    #[test]
    fn test_add_extension() {
        let old = Schema::new()
            .table("t", |t| {
                t.uuid_pk("id");
            })
            .build();
        let new = Schema::new()
            .extension("pgcrypto")
            .table("t", |t| {
                t.uuid_pk("id");
            })
            .build();

        let changes = diff_schemas(&old, &new);
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, SchemaChange::AddExtension(e) if e == "pgcrypto"))
        );
    }

    #[test]
    fn test_multiple_changes() {
        let old = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").not_null();
                t.text("old_field");
            })
            .build();

        let new = Schema::new()
            .table("users", |t| {
                t.uuid_pk("id");
                t.text("email").unique().not_null();
                t.text("new_field");
            })
            .table("repos", |t| {
                t.uuid_pk("id");
                t.text("name").not_null();
            })
            .build();

        let changes = diff_schemas(&old, &new);
        // Should have: DropColumn(old_field), AddColumn(new_field), AlterColumn(email unique changed), AddTable(repos)
        assert!(changes.len() >= 4);
    }
}
