//
//  heimdall
//  src/main.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::{web, App, HttpServer, middleware as actix_middleware};
use log::info;
use sqlx::postgres::PgPoolOptions;

use heimdall::config;
use heimdall::db;
use heimdall::routes;
use heimdall::state;

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

    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Migration failed: {e}"),
            )
        })?;

    info!("Migrations applied");

    let db_ops = db::DatabaseOperations::new(db_pool);
    let app_state = web::Data::new(state::AppState::init(config.clone(), db_ops));

    let port = config.app.port;
    let host = config.app.host.clone();

    info!("Starting HTTP server on {}:{}", host, port);

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(actix_middleware::Logger::default())
            .configure(routes::init)
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
