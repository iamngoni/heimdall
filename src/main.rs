//
//  heimdall
//  src/main.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_cors::Cors;
use actix_web::{App, HttpServer, middleware as actix_middleware, web};
use log::{info, warn};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

use heimdall::ai;
use heimdall::config;
use heimdall::db;
use heimdall::middleware::csrf::CsrfProtection;
use heimdall::routes;
use heimdall::sse;
use heimdall::state;
use heimdall::templates;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init();

    println!("*** Heimdall — The All-Seeing Guardian ***");

    let config = config::Config::from_env()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e:#}")))?;

    info!("Configuration loaded");

    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database.url)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Database connection failed: {e}"),
            )
        })?;

    info!("Database connected");

    // Apply schema idempotently from the DSL — no file-based migration tracking.
    // Every statement uses IF NOT EXISTS / IF NOT EXISTS so this is safe on every startup.
    let ddl = heimdall::db::schema::generate_ddl(heimdall::db::schema::DbDriver::Postgres);
    sqlx::raw_sql(&ddl).execute(&db_pool).await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Schema apply failed: {e}"),
        )
    })?;

    info!("Schema applied");

    let ai_provider = ai::build_provider(&config.ai);
    if ai_provider.is_some() {
        info!("AI provider configured");
    } else {
        warn!("No environment AI provider configured — stored user keys will be used if available");
    }

    if config.security.encryption_key.is_some() {
        info!("ENCRYPTION_KEY configured — API keys will be encrypted with AES-256-GCM");
    } else {
        warn!(
            "ENCRYPTION_KEY not set — API keys will be stored with hex encoding only. \
             Set ENCRYPTION_KEY (64 hex chars) for production use."
        );
    }

    let template_engine = templates::init_templates("templates");

    let db_ops = db::DatabaseOperations::new(db_pool);
    let broadcaster = sse::ScanBroadcaster::new();
    let worker_enabled = std::env::var("WORKER_ENABLED")
        .unwrap_or_else(|_| "true".to_string())
        .parse::<bool>()
        .unwrap_or(true);
    let app_state = web::Data::new(state::AppState::init(
        config.clone(),
        db_ops,
        ai_provider,
        broadcaster,
        template_engine,
        worker_enabled,
    ));

    let port = config.app.port;
    let host = config.app.host.clone();
    let cors_origin = config.app.cors_allowed_origin.clone();

    if worker_enabled {
        let poll_secs = std::env::var("WORKER_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5u64);
        let stale_mins = std::env::var("WORKER_STALE_TIMEOUT_MINS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10i32);

        let worker = Arc::new(heimdall::worker::ScanWorker::new(
            Arc::new(app_state.get_ref().clone()),
            std::time::Duration::from_secs(poll_secs),
            stale_mins,
        ));
        tokio::spawn(worker.run());
        info!(
            "Scan worker started (poll={}s, stale_timeout={}min)",
            poll_secs, stale_mins
        );
    } else {
        info!("Scan worker disabled via WORKER_ENABLED=false");
    }

    // Spawn background session cleanup task
    let cleanup_db = Arc::clone(&app_state.get_ref().db);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match cleanup_db.delete_expired_sessions().await {
                Ok(count) => {
                    if count > 0 {
                        info!("Cleaned up {count} expired sessions");
                    }
                }
                Err(e) => warn!("Session cleanup failed: {e:#}"),
            }
        }
    });

    info!("Starting HTTP server on {}:{}", host, port);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&cors_origin)
            .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE"])
            .allowed_headers(vec![
                "Content-Type",
                "Authorization",
                "HX-Request",
                "X-CSRF-Token",
            ])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(app_state.clone())
            .wrap(cors)
            .wrap(CsrfProtection)
            .wrap(actix_middleware::Logger::default())
            .service(actix_files::Files::new("/static", "static"))
            .configure(routes::init)
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
