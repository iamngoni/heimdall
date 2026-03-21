//
//  heimdall
//  src/bin/mcp.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/20.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use log::{info, warn};
use rmcp::ServiceExt;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use sqlx::postgres::PgPoolOptions;
use tokio_util::sync::CancellationToken;

use heimdall::ai;
use heimdall::config::Config;
use heimdall::db::DatabaseOperations;
use heimdall::mcp::HeimdallMcp;
use heimdall::sse::ScanBroadcaster;
use heimdall::state::AppState;
use heimdall::templates;
use heimdall::worker::ScanWorker;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .init();

    dotenvy::dotenv().ok();
    let config = Config::from_env()?;

    info!("Connecting to database...");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database.url)
        .await?;

    let ddl = heimdall::db::schema::generate_ddl(heimdall::db::schema::DbDriver::Postgres);
    sqlx::raw_sql(&ddl).execute(&pool).await?;

    let ai_provider = ai::build_provider(&config.ai);
    if ai_provider.is_some() {
        info!("AI provider configured for MCP server");
    } else {
        warn!("No environment AI provider configured for MCP server");
    }

    let db = DatabaseOperations::new(pool);
    let worker_enabled = std::env::var("WORKER_ENABLED")
        .unwrap_or_else(|_| "true".to_string())
        .parse::<bool>()
        .unwrap_or(true);
    let state = Arc::new(AppState::init(
        config.clone(),
        db,
        ai_provider,
        ScanBroadcaster::new(),
        templates::init_templates("templates"),
        worker_enabled,
    ));

    if worker_enabled {
        let poll_secs = std::env::var("WORKER_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(5u64);
        let stale_mins = std::env::var("WORKER_STALE_TIMEOUT_MINS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(10i32);
        let worker = Arc::new(ScanWorker::new(
            Arc::clone(&state),
            std::time::Duration::from_secs(poll_secs),
            stale_mins,
        ));
        tokio::spawn(worker.run());
        info!(
            "Scan worker started inside MCP server (poll={}s, stale_timeout={}min)",
            poll_secs, stale_mins
        );
    } else {
        info!("Scan worker disabled for MCP server via WORKER_ENABLED=false");
    }

    let transport = std::env::var("MCP_TRANSPORT").unwrap_or_default();

    if transport.eq_ignore_ascii_case("sse") || transport.eq_ignore_ascii_case("http") {
        let bind = std::env::var("MCP_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port = std::env::var("MCP_PORT").unwrap_or_else(|_| "45637".into());
        let addr: std::net::SocketAddr = format!("{bind}:{port}").parse()?;

        let ct = CancellationToken::new();
        let service: StreamableHttpService<HeimdallMcp, LocalSessionManager> =
            StreamableHttpService::new(
                {
                    let state = Arc::clone(&state);
                    move || Ok(HeimdallMcp::new(Arc::clone(&state)))
                },
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
        let server = HeimdallMcp::new(state);
        let service = server.serve(rmcp::transport::io::stdio()).await?;
        service.waiting().await?;
    }

    Ok(())
}
