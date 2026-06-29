//
//  heimdall
//  src/bin/render_report.rs
//
//  Created by Ngonidzashe Mangudya on 2026/05/04.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

//! Smoke-test the scan report renderer against the live DB.
//!
//! Usage:
//!   DATABASE_URL=postgres://… cargo run --bin render_report -- \
//!       <scan-id> <user-id> [out.html]
//!
//! Renders the report HTML for the given scan/user pair and writes it to disk
//! (default: `/tmp/heimdall-scan-report.html`). Open the file in a browser to
//! verify visual output before shipping.

use std::sync::Arc;

use heimdall::db::DatabaseOperations;
use heimdall::reports::build_context;
use heimdall::templates::ThemeRegistry;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let scan_id = args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: render_report <scan-id> <user-id> [out.html]"))?;
    let user_id = args
        .get(2)
        .ok_or_else(|| anyhow::anyhow!("missing user-id"))?;
    let out_path = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "/tmp/heimdall-scan-report.html".to_string());

    let scan_id: Uuid = scan_id.parse()?;
    let user_id: Uuid = user_id.parse()?;

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://modestnerd@localhost:5432/heimdall".to_string());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .connect(&database_url)
        .await?;
    let db = Arc::new(DatabaseOperations::new(pool));

    let ctx = build_context(&db, scan_id, user_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("scan not found or not owned by user"))?;

    let template_root = std::env::var("TEMPLATE_DIR").unwrap_or_else(|_| "templates".to_string());
    let themes = ThemeRegistry::new(&template_root);
    let html = themes
        .get("oatmeal")
        .render("pages/scan_report.html", &ctx)?;

    std::fs::write(&out_path, &html)?;
    println!(
        "wrote {} bytes to {} (scan {scan_id}, user {user_id})",
        html.len(),
        out_path
    );
    Ok(())
}
