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
use heimdall::db::{self, DatabaseOperations};
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
        heimdall::ai::codex::CODEX_CALLBACK_PORTS[0],
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
    apply_test_schema(&pool).await;
    Some(pool)
}

#[allow(dead_code)]
pub async fn apply_test_schema(pool: &sqlx::PgPool) {
    const SCHEMA_LOCK_ID: i64 = 0x4845_494d_4441_4c4c;

    let ddl = db::schema::generate_ddl(db::schema::DbDriver::Postgres);
    let mut conn = pool
        .acquire()
        .await
        .expect("Failed to acquire connection for test schema setup");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(SCHEMA_LOCK_ID)
        .execute(&mut *conn)
        .await
        .expect("Failed to acquire test schema lock");

    let schema_result: Result<(), sqlx::Error> = async {
        sqlx::raw_sql(&ddl).execute(&mut *conn).await?;
        sqlx::raw_sql(db::runtime_schema_updates_sql())
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
    .await;

    let unlock_result = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(SCHEMA_LOCK_ID)
        .execute(&mut *conn)
        .await;

    schema_result.expect("Failed to apply generated test schema");
    unlock_result.expect("Failed to release test schema lock");
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
