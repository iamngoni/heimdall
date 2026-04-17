//
//  heimdall
//  tests/common/mod.rs
//
//  Shared test utilities for integration tests.
//

use actix_web::web;
use chrono::{Duration, Utc};

use heimdall::auth;
use heimdall::config::Config;
use heimdall::db::DatabaseOperations;
use heimdall::models::db_models::User;
use heimdall::sse::ScanBroadcaster;
use heimdall::state::AppState;
use heimdall::templates;
use uuid::Uuid;

/// Create an AppState suitable for testing.
///
/// Requires a running Postgres instance with migrations applied.
/// No AI provider or encryption key is configured.
#[allow(dead_code)]
pub async fn test_app_state(db_pool: sqlx::PgPool) -> web::Data<AppState> {
    test_app_state_with_options(db_pool, false, None).await
}

#[allow(dead_code)]
pub async fn test_app_state_with_options(
    db_pool: sqlx::PgPool,
    worker_enabled: bool,
    openai_api_key: Option<&str>,
) -> web::Data<AppState> {
    let mut config = Config::from_env().expect("Test config from env");
    if let Some(key) = openai_api_key {
        config.ai.openai_api_key = Some(key.to_string());
        config.ai.anthropic_api_key = None;
        config.ai.ollama_url = None;
        config.ai.default_model = "gpt-4o".to_string();
    }
    let db_ops = DatabaseOperations::new(db_pool);
    let broadcaster = ScanBroadcaster::new();
    let template_engine = templates::init_themes("templates");

    web::Data::new(AppState::init(
        config,
        db_ops,
        None, // no AI provider in tests
        broadcaster,
        template_engine,
        worker_enabled,
    ))
}

#[allow(dead_code)]
pub async fn test_pool() -> Option<sqlx::PgPool> {
    let db_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("Skipping integration test: DATABASE_URL not set");
            return None;
        }
    };

    let pool = sqlx::PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to database");
    sqlx::migrate!("./migrations/active")
        .run(&pool)
        .await
        .expect("Failed to run migrations");
    Some(pool)
}

#[allow(dead_code)]
pub async fn create_user_with_session(state: &web::Data<AppState>, label: &str) -> (User, String) {
    let email = format!("{label}-{}@example.com", Uuid::now_v7());
    let password_hash = auth::hash_password("integration-test-password")
        .expect("Failed to hash integration test password");
    let user = state
        .db
        .create_user(&email, &password_hash, Some(label))
        .await
        .expect("Failed to create integration test user");

    let token = auth::generate_session_token();
    let token_hash = auth::hash_token(&token);
    state
        .db
        .create_session(
            user.id,
            &token_hash,
            None,
            Some("integration-test"),
            Utc::now() + Duration::days(30),
        )
        .await
        .expect("Failed to create integration test session");

    (user, token)
}
