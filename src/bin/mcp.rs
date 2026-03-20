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
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use sqlx::postgres::PgPoolOptions;
use tokio_util::sync::CancellationToken;

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

    if transport.eq_ignore_ascii_case("sse") || transport.eq_ignore_ascii_case("http") {
        let bind = std::env::var("MCP_HOST").unwrap_or_else(|_| "0.0.0.0".into());
        let port = std::env::var("MCP_PORT").unwrap_or_else(|_| "45637".into());
        let addr: std::net::SocketAddr = format!("{bind}:{port}").parse()?;

        let ct = CancellationToken::new();
        let service: StreamableHttpService<HeimdallMcp, LocalSessionManager> =
            StreamableHttpService::new(
                move || Ok(HeimdallMcp::new(db.clone())),
                Default::default(),
                StreamableHttpServerConfig {
                    stateful_mode: true,
                    cancellation_token: ct.child_token(),
                    ..Default::default()
                },
            );

        let router = axum::Router::new().nest_service("/mcp", service);
        let tcp_listener = tokio::net::TcpListener::bind(addr).await?;

        info!("Starting Heimdall MCP server over Streamable HTTP at {addr}/mcp");
        axum::serve(tcp_listener, router)
            .with_graceful_shutdown(async move {
                tokio::signal::ctrl_c().await.ok();
                ct.cancel();
            })
            .await?;
    } else {
        info!("Starting Heimdall MCP server over stdio");
        let server = HeimdallMcp::new(db);
        let service = server.serve(rmcp::transport::io::stdio()).await?;
        service.waiting().await?;
    }

    Ok(())
}
