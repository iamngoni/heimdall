//
//  heimdall
//  src/bin/mcp.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/20.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use log::info;
use rmcp::ServiceExt;
use sqlx::postgres::PgPoolOptions;

use heimdall::db::DatabaseOperations;
use heimdall::mcp::HeimdallMcp;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // MCP servers communicate over stdio — logs go to stderr
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .init();

    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect(
        "DATABASE_URL must be set (e.g., postgres://user:password@localhost:5432/heimdall)",
    );

    info!("Connecting to database...");
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&database_url)
        .await?;

    let db = Arc::new(DatabaseOperations::new(pool));
    let server = HeimdallMcp::new(db);

    info!("Starting Heimdall MCP server over stdio");
    let service = server
        .serve(rmcp::transport::io::stdio())
        .await?;

    service.waiting().await?;
    Ok(())
}
