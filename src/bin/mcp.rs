//
//  heimdall
//  src/bin/mcp.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/20.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use axum::middleware;
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

fn public_base_url(bind: &str, port: &str) -> String {
    std::env::var("MCP_PUBLIC_BASE_URL")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            let host = match bind {
                "0.0.0.0" | "::" => "localhost",
                value => value,
            };
            format!("http://{host}:{port}")
        })
}

fn web_app_base_url(config: &Config) -> String {
    std::env::var("APP_PUBLIC_BASE_URL")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            let host = match config.app.host.as_str() {
                "0.0.0.0" | "::" => "localhost",
                value => value,
            };
            let scheme = if config.app.tls_enabled {
                "https"
            } else {
                "http"
            };
            format!("{scheme}://{host}:{}", config.app.port)
        })
}

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
    heimdall::db::apply_runtime_schema_updates(&pool).await?;

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
        templates::init_themes("templates"),
        worker_enabled,
        // The MCP binary does not host the Codex OAuth callback; use the
        // default Codex callback port as a placeholder for AppState.
        heimdall::ai::codex::CODEX_CALLBACK_PORTS[0],
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
        let public_base_url = public_base_url(&bind, &port);
        let oauth_state = heimdall::mcp::oauth::OAuthServerState {
            app_state: Arc::clone(&state),
            public_base_url: public_base_url.clone(),
            web_app_base_url: web_app_base_url(&config),
        };

        let ct = CancellationToken::new();
        let mut server_config = StreamableHttpServerConfig::default();
        server_config.stateful_mode = true;
        server_config.cancellation_token = ct.child_token();

        let service: StreamableHttpService<HeimdallMcp, LocalSessionManager> =
            StreamableHttpService::new(
                {
                    let state = Arc::clone(&state);
                    move || Ok(HeimdallMcp::new(Arc::clone(&state)))
                },
                Default::default(),
                server_config,
            );

        let mcp_router = axum::Router::new().nest_service("/mcp", service).layer(
            middleware::from_fn_with_state(
                oauth_state.clone(),
                heimdall::mcp::oauth::require_oauth,
            ),
        );
        let router = heimdall::mcp::oauth::router(oauth_state).merge(mcp_router);
        let tcp_listener = tokio::net::TcpListener::bind(addr).await?;

        if transport.eq_ignore_ascii_case("sse") {
            warn!("MCP_TRANSPORT=sse is treated as Streamable HTTP for backward compatibility");
        }
        info!("Starting Heimdall MCP server over OAuth-protected Streamable HTTP at {addr}/mcp");
        info!("MCP OAuth issuer: {public_base_url}");
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
