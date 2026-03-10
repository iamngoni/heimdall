//
//  heimdall
//  tests/health_test.rs
//
//  Integration test for the health check endpoint.
//  Requires a running Postgres instance (set DATABASE_URL).
//

mod common;

use actix_web::{App, test};
use heimdall::routes;

#[actix_rt::test]
async fn test_health_check() {
    // Skip if DATABASE_URL is not set (CI without Postgres)
    let db_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("Skipping test_health_check: DATABASE_URL not set");
            return;
        }
    };

    let pool = sqlx::PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to database");
    sqlx::migrate!("./migrations/active")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let app_state = common::test_app_state(pool).await;

    let app = test::init_service(
        App::new()
            .app_data(app_state)
            .configure(routes::health::init),
    )
    .await;

    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}
