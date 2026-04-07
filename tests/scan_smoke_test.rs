mod common;

use actix_web::{
    App,
    http::{StatusCode, header},
    test,
};
use heimdall::routes;
use serde_json::Value;
use uuid::Uuid;

fn bearer(token: &str) -> (header::HeaderName, String) {
    (header::AUTHORIZATION, format!("Bearer {token}"))
}

#[actix_rt::test]
async fn test_repo_scan_findings_smoke_flow() {
    let Some(pool) = common::test_pool().await else {
        return;
    };

    let state = common::test_app_state_with_options(pool, true, Some("test-openai-key")).await;
    let (user, token) = common::create_user_with_session(&state, "smoke").await;

    let repo = state
        .db
        .create_repo(
            user.id,
            &format!("smoke-repo-{}", Uuid::now_v7()),
            "git_url",
            Some(&format!("https://example.com/{}.git", Uuid::now_v7())),
            Some("main"),
            None,
        )
        .await
        .expect("Failed to create smoke test repo");

    let app = test::init_service(App::new().app_data(state.clone()).configure(routes::init)).await;

    let scan_req = test::TestRequest::post()
        .uri(&format!("/api/repos/{}/scan", repo.id))
        .insert_header(bearer(&token))
        .to_request();
    let scan_resp = test::call_service(&app, scan_req).await;
    assert_eq!(scan_resp.status(), StatusCode::ACCEPTED);

    let scan_body: Value = test::read_body_json(scan_resp).await;
    let scan_id = scan_body["data"]["scan"]["id"]
        .as_str()
        .expect("Scan id should be present in trigger_scan response");
    let scan_id = Uuid::parse_str(scan_id).expect("Returned scan id should be valid");

    let finding = state
        .db
        .create_finding_full(
            scan_id,
            repo.id,
            "static_analysis",
            "high",
            "high",
            "Smoke test finding",
            Some("Used to verify the repo -> scan -> findings flow."),
            Some("CWE-89"),
            "src/lib.rs",
            41,
            Some(44),
            Some("let query = format!(\"SELECT * FROM users WHERE id = {}\", user_id);"),
            &format!("smoke-fingerprint-{}", Uuid::now_v7()),
            Some("@@ -1 +1 @@\n-let query = format!(...)\n+let query = \"SELECT * FROM users WHERE id = $1\";"),
        )
        .await
        .expect("Failed to create smoke test finding");

    let findings_api_req = test::TestRequest::get()
        .uri(&format!("/api/scans/{scan_id}/findings"))
        .insert_header(bearer(&token))
        .to_request();
    let findings_api_resp = test::call_service(&app, findings_api_req).await;
    assert_eq!(findings_api_resp.status(), StatusCode::OK);
    let findings_api_body = String::from_utf8(test::read_body(findings_api_resp).await.to_vec())
        .expect("API findings response should be utf-8");
    assert!(findings_api_body.contains("Smoke test finding"));

    let findings_page_req = test::TestRequest::get()
        .uri(&format!("/scans/{scan_id}/findings"))
        .insert_header(bearer(&token))
        .to_request();
    let findings_page_resp = test::call_service(&app, findings_page_req).await;
    assert_eq!(findings_page_resp.status(), StatusCode::OK);
    let findings_page_body = String::from_utf8(test::read_body(findings_page_resp).await.to_vec())
        .expect("Findings page response should be utf-8");
    assert!(findings_page_body.contains("Smoke test finding"));
    assert!(findings_page_body.contains("src/lib.rs"));

    let finding_detail_req = test::TestRequest::get()
        .uri(&format!("/findings/{}", finding.id))
        .insert_header(bearer(&token))
        .to_request();
    let finding_detail_resp = test::call_service(&app, finding_detail_req).await;
    assert_eq!(finding_detail_resp.status(), StatusCode::OK);
}
