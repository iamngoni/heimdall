//
//  heimdall
//  tests/template_render_smoke_test.rs
//
//  Created by Ngonidzashe Mangudya on 2026/07/18.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//
// Renders every heimdall page + partial under Chainable undefined behavior so
// missing data never aborts the render. This exercises every line and surfaces
// genuine structural bugs (unknown filter/method/macro/test/function, syntax
// errors) regardless of context completeness — the class of regression that
// slips past data-specific integration tests.
use minijinja::{Environment, UndefinedBehavior, path_loader};
use serde_json::json;

#[test]
fn every_template_renders_without_structural_errors() {
    let mut env = Environment::new();
    env.set_loader(path_loader("templates/themes/heimdall"));
    env.set_undefined_behavior(UndefinedBehavior::Chainable);
    // Mirror the production filters registered in TemplateEngine::new so
    // templates using them don't trip a false "unknown filter" here.
    env.add_filter("short_dt", |v: Option<String>| -> String {
        match v {
            Some(s) if !s.trim().is_empty() => {
                s.trim().replacen('T', " ", 1).chars().take(16).collect()
            }
            _ => "—".to_string(),
        }
    });

    let templates = [
        "pages/dashboard.html",
        "pages/error.html",
        "pages/finding_detail.html",
        "pages/findings.html",
        "pages/login.html",
        "pages/register.html",
        "pages/repo_detail.html",
        "pages/repo_new.html",
        "pages/repos.html",
        "pages/scan_report.html",
        "pages/scan.html",
        "pages/settings.html",
        "pages/threat_model.html",
        "partials/repo_import_list.html",
        "partials/api_key_row.html",
        "partials/finding_status_controls.html",
        "partials/finding_ai_review.html",
        "partials/finding_issue_panel.html",
        "partials/finding_remediation_panel.html",
        "partials/finding_recent_activity.html",
    ];

    let empty: Vec<serde_json::Value> = vec![];
    let mut ctx = json!({
        "user": { "email": "u@example.com", "display_name": "U" },
        "user_initial": "U",
        "active_source": "github",
        "provider_name": "GitHub",
        "scan": { "id": "00000000-0000-0000-0000-000000000000" },
        "scan_id": "00000000-0000-0000-0000-000000000000",
        "repo": { "id": "00000000-0000-0000-0000-000000000000", "name": "x" },
        "ai_config": { "provider_models": {}, "fallback_order": [], "fallback_order_csv": "" },
        "threat_model": {},
    });
    // Seed every top-level collection as an empty array so `| length` and
    // `for` loops don't abort under Chainable, letting every line execute.
    let collections = [
        "activities",
        "assets",
        "assumptions",
        "assurance_claims",
        "attck",
        "ai_provider_catalog",
        "api_keys",
        "boundaries",
        "data_flows",
        "entry_points",
        "events",
        "evidence",
        "finding_buckets",
        "findings",
        "gaps",
        "in_scope",
        "mitigations",
        "mitre_attack",
        "out_of_scope",
        "recent_scans",
        "references",
        "repo_summaries",
        "repos",
        "scans",
        "stages",
        "stride",
        "surfaces",
        "threats",
        "validation_plan",
        "verify_review",
    ];
    let obj = ctx.as_object_mut().unwrap();
    for key in collections {
        obj.insert(key.to_string(), json!(empty));
    }

    let structural = [
        "unknown filter",
        "unknown method",
        "unknown test",
        "unknown function",
        "no method named",
        "syntax error",
        "not callable",
        "template not found",
        "unknown attribute",
    ];

    let mut failures = Vec::new();
    for name in templates {
        let tmpl = match env.get_template(name) {
            Ok(t) => t,
            Err(e) => {
                failures.push(format!("{name} (compile): {e:#}"));
                continue;
            }
        };
        if let Err(e) = tmpl.render(&ctx) {
            let msg = format!("{e:#}").to_lowercase();
            if structural.iter().any(|m| msg.contains(m)) {
                failures.push(format!("{name}: {e:#}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "structural render errors:\n{}",
        failures.join("\n\n")
    );
}
