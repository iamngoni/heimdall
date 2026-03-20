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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .init();

    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect(
        "DATABASE_URL must be set (e.g., postgres://user:password@localhost:5432/heimdall)",
    );

    info!("Connecting to database...");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    let db = Arc::new(DatabaseOperations::new(pool));

    let transport = std::env::var("MCP_TRANSPORT").unwrap_or_default();

    if transport.eq_ignore_ascii_case("sse") {
        let bind = std::env::var("MCP_HOST").unwrap_or_else(|_| "0.0.0.0".into());
        let port = std::env::var("MCP_PORT").unwrap_or_else(|_| "45637".into());
        let addr: std::net::SocketAddr = format!("{bind}:{port}").parse()?;

        info!("Starting Heimdall MCP server over SSE at {addr}");
        let ct = rmcp::transport::sse_server::SseServer::serve(addr)
            .await?
            .with_service(move || HeimdallMcp::new(db.clone()));

        tokio::signal::ctrl_c().await?;
        ct.cancel();
    } else {
        info!("Starting Heimdall MCP server over stdio");
        let server = HeimdallMcp::new(db);
        let service = server.serve(rmcp::transport::io::stdio()).await?;
        service.waiting().await?;
    }

    Ok(())
}
