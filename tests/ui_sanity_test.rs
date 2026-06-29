mod common;

use actix_web::{
    App,
    http::{StatusCode, header},
    test,
};
use heimdall::models::db_models::FindingEvidence;
use heimdall::routes;
use uuid::Uuid;

fn bearer(token: &str) -> (header::HeaderName, String) {
    (header::AUTHORIZATION, format!("Bearer {token}"))
}

#[actix_rt::test]
async fn test_public_auth_pages_render_structured_error_handling() {
    let Some(pool) = common::test_pool().await else {
        return;
    };

    let state = common::test_app_state(pool).await;
    let app = test::init_service(App::new().app_data(state.clone()).configure(routes::init)).await;

    for path in ["/login", "/register"] {
        let req = test::TestRequest::get().uri(path).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK, "expected 200 for {path}");
        let body = String::from_utf8(test::read_body(resp).await.to_vec())
            .expect("Auth page should render utf-8");
        assert!(
            body.contains("typeof data.error === 'string'") && body.contains("data.error.message"),
            "expected structured error handling in {path}"
        );
    }
}

#[actix_rt::test]
async fn test_dashboard_repos_and_finding_detail_regressions_stay_fixed() {
    let Some(pool) = common::test_pool().await else {
        return;
    };

    let state = common::test_app_state(pool).await;
    let (user, token) = common::create_user_with_session(&state, "ui").await;

    let repo = state
        .db
        .create_repo(
            user.id,
            &format!("ui-repo-{}", Uuid::now_v7()),
            "git_url",
            Some(&format!("https://example.com/{}.git", Uuid::now_v7())),
            Some("main"),
            None,
        )
        .await
        .expect("Failed to create UI test repo");
    let scan = state
        .db
        .create_scan(repo.id, "full", Some(user.id), None, None, None)
        .await
        .expect("Failed to create UI test scan");
    let finding = state
        .db
        .create_finding_full(
            scan.id,
            repo.id,
            "static_analysis",
            "medium",
            "high",
            "UI regression finding",
            Some("Used to verify honest patch copy."),
            Some("CWE-79"),
            "src/app.js",
            8,
            Some(9),
            &format!("ui-fingerprint-{}", Uuid::now_v7()),
            None,
            &FindingEvidence::code_change(
                "element.innerHTML = userInput;",
                "@@ -1 +1 @@\n-element.innerHTML = userInput;\n+element.textContent = userInput;",
                "Render untrusted input as text instead of raw HTML.",
            ),
        )
        .await
        .expect("Failed to create UI test finding");
    let patch = state
        .db
        .create_patch(
            finding.id,
            scan.id,
            "@@ -1 +1 @@\n-element.innerHTML = userInput;\n+element.textContent = userInput;",
            Some("Escape user input"),
            true,
        )
        .await
        .expect("Failed to create UI test patch");
    state
        .db
        .mark_patch_applied(patch.id, user.id)
        .await
        .expect("Failed to mark patch applied in UI test");

    let app = test::init_service(App::new().app_data(state.clone()).configure(routes::init)).await;

    for path in ["/dashboard", "/dashboard/"] {
        let req = test::TestRequest::get()
            .uri(path)
            .insert_header(bearer(&token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK, "expected 200 for {path}");
    }

    let repos_req = test::TestRequest::get()
        .uri("/repos")
        .insert_header(bearer(&token))
        .to_request();
    let repos_resp = test::call_service(&app, repos_req).await;
    assert_eq!(repos_resp.status(), StatusCode::OK);
    let repos_body = String::from_utf8(test::read_body(repos_resp).await.to_vec())
        .expect("Repos page should render utf-8");
    assert!(repos_body.contains("repo-search"));
    assert!(repos_body.contains("row.classList.toggle('hidden'"));
    assert!(repos_body.contains(&repo.name));

    let finding_req = test::TestRequest::get()
        .uri(&format!("/findings/{}", finding.id))
        .insert_header(bearer(&token))
        .to_request();
    let finding_resp = test::call_service(&app, finding_req).await;
    assert_eq!(finding_resp.status(), StatusCode::OK);
    let finding_body = String::from_utf8(test::read_body(finding_resp).await.to_vec())
        .expect("Finding detail page should render utf-8");
    assert!(finding_body.contains("Suggested Fix"));
    assert!(finding_body.contains("no repository write-back recorded"));
    assert!(finding_body.contains("Marked applied in Heimdall"));
}
