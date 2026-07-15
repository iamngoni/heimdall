mod common;

use actix_web::{
    App,
    http::{StatusCode, header},
    test,
};
use heimdall::models::db_models::FindingEvidence;
use heimdall::routes;
use heimdall::templates::TemplateEngine;
use serde_json::json;
use uuid::Uuid;

fn bearer(token: &str) -> (header::HeaderName, String) {
    (header::AUTHORIZATION, format!("Bearer {token}"))
}

#[actix_rt::test]
async fn threat_model_pages_render_expanded_lifecycle_sections() {
    let ctx = json!({
        "user": {
            "email": "ui@example.com",
            "display_name": "UI Test",
        },
        "user_initial": "U",
        "repo": {
            "id": Uuid::now_v7().to_string(),
            "name": "heimdall",
        },
        "scan": {
            "id": Uuid::now_v7().to_string(),
            "status": "completed",
            "finding_count": 2,
        },
        "scan_id": Uuid::now_v7().to_string(),
        "threat_model": {
            "id": Uuid::now_v7().to_string(),
            "summary": "Repository scanner threat model.",
            "model_version": 1,
            "updated_at": "2026-07-03 20:00",
        },
        "scope": {
            "subject": "heimdall",
            "system_type": "web application",
            "in_scope": ["scan orchestration"],
            "out_of_scope": ["production network"],
            "assets": ["OAuth tokens"],
            "entry_points": ["/api/repos"],
        },
        "assumptions": [{
            "statement": "OAuth callbacks terminate in the app.",
            "why_it_matters": "Token handling depends on this boundary.",
            "how_to_validate": "Review callback configuration.",
            "stale_if": "OAuth provider settings change.",
        }],
        "boundaries": [{
            "name": "Browser to API",
            "description": "User requests enter the server.",
            "from_zone": "browser",
            "to_zone": "api",
        }],
        "surfaces": [{
            "name": "Repository import",
            "description": "Imports user-selected repositories.",
            "endpoint": "/api/repos",
            "file": "src/routes/repos.rs",
            "line": null,
            "risk_level": "high",
        }],
        "data_flows": [{
            "name": "OAuth token storage",
            "description": "Provider tokens are stored for repository access.",
            "source": "oauth provider",
            "sink": "database",
            "sensitive_data": "access tokens",
        }],
        "threats": [{
            "name": "Token misuse through import endpoint",
            "description": "A caller could trigger privileged repository operations.",
            "related_surface": "Repository import",
            "stride": ["elevation_of_privilege"],
            "likelihood": "medium",
            "impact": "high",
            "risk_level": "high",
            "risk_treatment": "mitigate",
            "mitre_attack": [{
                "tactic": "Initial Access",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "confidence": "medium",
            }],
        }],
        "mitigations": [{
            "threat": "Token misuse through import endpoint",
            "action": "Require ownership checks before import.",
            "risk_treatment": "mitigate",
            "status": "existing",
            "validation": "Run authorization boundary tests.",
            "owner": "repos",
        }],
        "validation_plan": [{
            "target": "Repository import",
            "method": "Authorization integration test",
            "expected_evidence": "Cross-user requests are rejected.",
            "automation": "cargo test",
            "status": "existing",
        }],
        "assurance_claims": [{
            "claim": "Repository imports enforce ownership.",
            "evidence": ["authz tests"],
            "gaps": [],
            "confidence": "high",
        }],
    });

    for theme in ["sentinel", "oatmeal", "editorial"] {
        let engine = TemplateEngine::new(&format!("templates/themes/{theme}"));
        let body = engine
            .render("pages/threat_model.html", ctx.clone())
            .unwrap_or_else(|error| panic!("{theme} threat model should render: {error}"));

        assert!(body.contains("Threats"));
        assert!(body.contains("ATT&amp;CK"));
        assert!(body.contains("Validation"));
        assert!(body.contains("Assurance"));
    }
}

#[actix_rt::test]
async fn settings_page_renders_compact_openai_compatible_editor() {
    let engine = TemplateEngine::new("templates/themes/sentinel");
    let body = engine
        .render(
            "pages/settings.html",
            json!({
                "current_theme": "sentinel",
                "available_themes": ["sentinel", "oatmeal", "editorial"],
                "integration_error": null,
                "user": {
                    "email": "ui@example.com",
                    "display_name": "UI Test",
                },
                "user_initial": "U",
                "integrations": {
                    "github": { "connected": false, "scopes": [], "token_source": null, "updated_at": null },
                    "gitlab": { "connected": false, "scopes": [], "token_source": null, "updated_at": null },
                    "bitbucket": { "connected": false, "scopes": [], "token_source": null, "updated_at": null },
                },
                "api_keys": [],
                "ai_config": {
                    "default_model": "gpt-5.6-terra",
                    "fallback_order": ["openai_compatible", "codex", "claude_code"],
                    "fallback_order_csv": "openai_compatible,codex,claude_code",
                    "fallbacks_enabled": true,
                    "has_any_provider": true,
                    "preferred_provider": "openai_compatible",
                    "has_anthropic": false,
                    "has_claude_code": true,
                    "has_codex": true,
                    "has_xai_oauth": false,
                    "has_xai": false,
                    "has_openai": false,
                    "has_openai_compatible": true,
                    "has_ollama": false,
                    "stored_anthropic": false,
                    "stored_claude_code": true,
                    "stored_codex": true,
                    "stored_xai_oauth": false,
                    "stored_xai": false,
                    "stored_openai": false,
                    "stored_openai_compatible": true,
                    "stored_ollama": false,
                    "provider_models": {
                        "anthropic": "",
                        "claude_code": "claude-sonnet-5",
                        "codex": "gpt-5.6-terra",
                        "xai_oauth": "",
                        "xai": "",
                        "openai": "",
                        "openai_compatible": "mlx-community/Ornith-Llama-3-8B",
                        "ollama": "",
                    },
                },
            }),
        )
        .expect("settings page should render");

    assert!(body.contains("OpenAI Compatible"));
    assert!(body.contains("explicit model id."));
    assert!(body.contains(
        "lg:grid-cols-[minmax(220px,1.25fr)_minmax(220px,1.35fr)_minmax(180px,0.9fr)_auto]"
    ));
    let endpoint_form_start = body
        .find("hx-post=\"/api/settings/api-keys\"")
        .expect("endpoint form should be rendered");
    let endpoint_form_end = body[endpoint_form_start..]
        .find("</form>")
        .map(|offset| endpoint_form_start + offset)
        .expect("endpoint form should close");
    let endpoint_form = &body[endpoint_form_start..endpoint_form_end];
    assert_eq!(endpoint_form.matches("name=\"model\"").count(), 1);
    assert!(!body.contains("name=\"model_openai_compatible\""));
    assert_eq!(body.matches("Save endpoint").count(), 1);
    assert!(body.contains("Paste-back"));
    assert!(body.contains("hx-post=\"/api/settings/codex/exchange\""));
    assert!(body.contains("Paste callback URL"));
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
    state
        .db
        .upsert_oauth_connection(
            user.id,
            "github",
            "ui-test-user",
            Some("fake-token"),
            None,
            Some("repo read:user user:email"),
            None,
        )
        .await
        .expect("Failed to create GitHub connection for UI test");

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

    let repo_new_req = test::TestRequest::get()
        .uri("/repos/new?source=github")
        .insert_header(bearer(&token))
        .to_request();
    let repo_new_resp = test::call_service(&app, repo_new_req).await;
    assert_eq!(repo_new_resp.status(), StatusCode::OK);
    let repo_new_body = String::from_utf8(test::read_body(repo_new_resp).await.to_vec())
        .expect("Add repository page should render utf-8");
    assert!(repo_new_body.contains("data-repo-search-input"));
    assert!(repo_new_body.contains("data-repo-search-url=\"/api/repos/github/list\""));
    assert!(repo_new_body.contains("data-repo-search-results"));
    assert!(repo_new_body.contains("initSearch()"));
    assert!(repo_new_body.contains("Loading recent GitHub repositories"));

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
