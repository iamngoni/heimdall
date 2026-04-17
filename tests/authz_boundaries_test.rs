mod common;

use actix_web::{
    App,
    http::{StatusCode, header},
    test,
};
use heimdall::models::db_models::FindingEvidence;
use heimdall::routes;
use serde_json::json;
use uuid::Uuid;

struct Fixture {
    repo_id: Uuid,
    scan_id: Uuid,
    finding_id: Uuid,
    threat_model_id: Uuid,
}

struct Setup {
    state: actix_web::web::Data<heimdall::state::AppState>,
    owner_token: String,
    outsider_token: String,
    fixture: Fixture,
}

async fn setup() -> Option<Setup> {
    let pool = common::test_pool().await?;
    let state = common::test_app_state(pool).await;
    let (owner, owner_token) = common::create_user_with_session(&state, "owner").await;
    let (_outsider, outsider_token) = common::create_user_with_session(&state, "outsider").await;

    let repo = state
        .db
        .create_repo(
            owner.id,
            &format!("repo-{}", Uuid::now_v7()),
            "git_url",
            Some(&format!("https://example.com/{}.git", Uuid::now_v7())),
            Some("main"),
            None,
        )
        .await
        .expect("Failed to create test repo");

    let scan = state
        .db
        .create_scan(repo.id, "full", Some(owner.id), None, None, None)
        .await
        .expect("Failed to create test scan");

    let finding = state
        .db
        .create_finding_full(
            scan.id,
            repo.id,
            "static_analysis",
            "high",
            "high",
            "Hardcoded secret",
            Some("A test finding."),
            Some("CWE-798"),
            "src/main.rs",
            12,
            Some(12),
            &format!("fingerprint-{}", Uuid::now_v7()),
            None,
            &FindingEvidence::code_change(
                "let secret = \"abc\";",
                "@@ -1 +1 @@\n-let secret = \"abc\";\n+let secret = std::env::var(\"APP_SECRET\")?;",
                "Load the secret from a runtime secret store instead of hardcoding it.",
            ),
        )
        .await
        .expect("Failed to create test finding");

    let threat_model = state
        .db
        .create_threat_model(
            scan.id,
            repo.id,
            Some("Test threat model"),
            None,
            None,
            None,
        )
        .await
        .expect("Failed to create test threat model");

    Some(Setup {
        state,
        owner_token,
        outsider_token,
        fixture: Fixture {
            repo_id: repo.id,
            scan_id: scan.id,
            finding_id: finding.id,
            threat_model_id: threat_model.id,
        },
    })
}

fn bearer(token: &str) -> (header::HeaderName, String) {
    (header::AUTHORIZATION, format!("Bearer {token}"))
}

#[actix_rt::test]
async fn test_api_routes_block_cross_user_resource_access() {
    let Some(setup) = setup().await else {
        return;
    };

    let app = test::init_service(
        App::new()
            .app_data(setup.state.clone())
            .configure(routes::init),
    )
    .await;

    let owner_repo_req = test::TestRequest::get()
        .uri(&format!("/api/repos/{}", setup.fixture.repo_id))
        .insert_header(bearer(&setup.owner_token))
        .to_request();
    let owner_repo_resp = test::call_service(&app, owner_repo_req).await;
    assert_eq!(owner_repo_resp.status(), StatusCode::OK);

    let owner_scan_req = test::TestRequest::get()
        .uri(&format!("/api/scans/{}", setup.fixture.scan_id))
        .insert_header(bearer(&setup.owner_token))
        .to_request();
    let owner_scan_resp = test::call_service(&app, owner_scan_req).await;
    assert_eq!(owner_scan_resp.status(), StatusCode::OK);

    let owner_finding_req = test::TestRequest::get()
        .uri(&format!("/api/findings/{}", setup.fixture.finding_id))
        .insert_header(bearer(&setup.owner_token))
        .to_request();
    let owner_finding_resp = test::call_service(&app, owner_finding_req).await;
    assert_eq!(owner_finding_resp.status(), StatusCode::OK);

    let owner_threat_model_req = test::TestRequest::get()
        .uri(&format!(
            "/api/threat-models/{}",
            setup.fixture.threat_model_id
        ))
        .insert_header(bearer(&setup.owner_token))
        .to_request();
    let owner_threat_model_resp = test::call_service(&app, owner_threat_model_req).await;
    assert_eq!(owner_threat_model_resp.status(), StatusCode::OK);

    let outsider_paths = [
        format!("/api/repos/{}", setup.fixture.repo_id),
        format!("/api/repos/{}/branches", setup.fixture.repo_id),
        format!("/api/repos/{}/check-issue-tracker", setup.fixture.repo_id),
        format!("/api/scans/{}", setup.fixture.scan_id),
        format!("/api/scans/{}/live", setup.fixture.scan_id),
        format!("/api/scans/{}/findings", setup.fixture.scan_id),
        format!("/api/scans/{}/threat-model", setup.fixture.scan_id),
        format!("/api/scans/{}/patches", setup.fixture.scan_id),
        format!("/api/scans/{}/progress/stream", setup.fixture.scan_id),
        format!("/api/findings/{}", setup.fixture.finding_id),
        format!("/api/findings/{}/events", setup.fixture.finding_id),
        format!("/api/threat-models/{}", setup.fixture.threat_model_id),
    ];

    for path in outsider_paths {
        let req = test::TestRequest::get()
            .uri(&path)
            .insert_header(bearer(&setup.outsider_token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "expected 404 for {path}"
        );
    }

    let outsider_scan_req = test::TestRequest::post()
        .uri(&format!("/api/repos/{}/scan", setup.fixture.repo_id))
        .insert_header(bearer(&setup.outsider_token))
        .to_request();
    let outsider_scan_resp = test::call_service(&app, outsider_scan_req).await;
    assert_eq!(outsider_scan_resp.status(), StatusCode::NOT_FOUND);

    let outsider_severity_req = test::TestRequest::patch()
        .uri(&format!(
            "/api/findings/{}/severity",
            setup.fixture.finding_id
        ))
        .insert_header(bearer(&setup.outsider_token))
        .set_json(json!({ "severity": "critical" }))
        .to_request();
    let outsider_severity_resp = test::call_service(&app, outsider_severity_req).await;
    assert_eq!(outsider_severity_resp.status(), StatusCode::NOT_FOUND);

    let outsider_threat_model_patch_req = test::TestRequest::patch()
        .uri(&format!(
            "/api/threat-models/{}",
            setup.fixture.threat_model_id
        ))
        .insert_header(bearer(&setup.outsider_token))
        .set_json(json!({ "summary": "mutated" }))
        .to_request();
    let outsider_threat_model_patch_resp =
        test::call_service(&app, outsider_threat_model_patch_req).await;
    assert_eq!(
        outsider_threat_model_patch_resp.status(),
        StatusCode::NOT_FOUND
    );
}

#[actix_rt::test]
async fn test_protected_pages_hide_cross_user_resources() {
    let Some(setup) = setup().await else {
        return;
    };

    let app = test::init_service(
        App::new()
            .app_data(setup.state.clone())
            .configure(routes::init),
    )
    .await;

    let owner_paths = [
        format!("/repos/{}", setup.fixture.repo_id),
        format!("/scans/{}", setup.fixture.scan_id),
        format!("/scans/{}/findings", setup.fixture.scan_id),
        format!("/findings/{}", setup.fixture.finding_id),
        format!("/scans/{}/threat-model", setup.fixture.scan_id),
    ];

    for path in owner_paths {
        let req = test::TestRequest::get()
            .uri(&path)
            .insert_header(bearer(&setup.owner_token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK, "expected 200 for {path}");
    }

    let outsider_paths = [
        format!("/repos/{}", setup.fixture.repo_id),
        format!("/scans/{}", setup.fixture.scan_id),
        format!("/scans/{}/findings", setup.fixture.scan_id),
        format!("/findings/{}", setup.fixture.finding_id),
        format!("/scans/{}/threat-model", setup.fixture.scan_id),
    ];

    for path in outsider_paths {
        let req = test::TestRequest::get()
            .uri(&path)
            .insert_header(bearer(&setup.outsider_token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "expected 404 for {path}"
        );
    }
}

#[actix_rt::test]
async fn test_update_severity_rejects_invalid_values() {
    let Some(setup) = setup().await else {
        return;
    };

    let app = test::init_service(
        App::new()
            .app_data(setup.state.clone())
            .configure(routes::init),
    )
    .await;

    let req = test::TestRequest::patch()
        .uri(&format!(
            "/api/findings/{}/severity",
            setup.fixture.finding_id
        ))
        .insert_header(bearer(&setup.owner_token))
        .set_json(json!({ "severity": "urgent" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let finding = setup
        .state
        .db
        .get_finding_by_id(setup.fixture.finding_id)
        .await
        .expect("Failed to fetch finding after invalid severity attempt")
        .expect("Finding disappeared after invalid severity attempt");
    assert_eq!(finding.severity, "high");
}
