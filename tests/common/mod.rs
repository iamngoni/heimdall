//
//  heimdall
//  tests/common/mod.rs
//
//  Shared test utilities for integration tests.
//

use actix_web::web;

use heimdall::config::Config;
use heimdall::db::DatabaseOperations;
use heimdall::sse::ScanBroadcaster;
use heimdall::state::AppState;
use heimdall::templates;

/// Create an AppState suitable for testing.
///
/// Requires a running Postgres instance with migrations applied.
/// No AI provider or encryption key is configured.
pub async fn test_app_state(db_pool: sqlx::PgPool) -> web::Data<AppState> {
    let config = Config::from_env().expect("Test config from env");
    let db_ops = DatabaseOperations::new(db_pool);
    let broadcaster = ScanBroadcaster::new();
    let template_engine = templates::init_templates("templates");

    web::Data::new(AppState::init(
        config,
        db_ops,
        None, // no AI provider in tests
        broadcaster,
        template_engine,
    ))
}
