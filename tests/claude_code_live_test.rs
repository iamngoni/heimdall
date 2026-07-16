mod common;

use std::sync::Arc;

use heimdall::ai::ModelProvider;
use heimdall::ai::claude_code::ClaudeCodeProvider;
use heimdall::db::DatabaseOperations;
use heimdall::pipeline::{ingest::IngestStage, tyr::TyrStage};
use heimdall::routes::scans::build_scan_live_snapshot;
use heimdall::sse::ScanBroadcaster;
use uuid::Uuid;

#[actix_rt::test]
#[ignore = "requires a local Postgres database, GitHub access, and live Claude Code credentials"]
async fn live_claude_code_runs_real_nexus_tyr_stage() {
    let secret = std::env::var("HEIMDALL_CLAUDE_CODE_TEST_SECRET")
        .expect("HEIMDALL_CLAUDE_CODE_TEST_SECRET must be set");
    let pool = common::test_pool()
        .await
        .expect("DATABASE_URL must point to a local test database");
    let db = Arc::new(DatabaseOperations::new(pool));
    let run_id = Uuid::now_v7();

    let user = db
        .create_user(
            &format!("claude-code-live-{run_id}@example.com"),
            "unused-live-test-password-hash",
            Some("Claude Code live test"),
        )
        .await
        .expect("live test user should be created");
    let repo = db
        .create_repo(
            user.id,
            &format!("nexus-live-{run_id}"),
            "github",
            Some("https://github.com/iamngoni/nexus.git"),
            Some("main"),
            None,
        )
        .await
        .expect("live test repository should be created");
    let scan = db
        .create_scan(repo.id, "full", Some(user.id), None, None, None)
        .await
        .expect("live test scan should be created");

    let data_dir = std::env::temp_dir()
        .join(format!("heimdall-claude-code-live-{run_id}"))
        .to_string_lossy()
        .into_owned();
    let ingest = IngestStage::new(
        scan.id,
        Arc::clone(&db),
        Arc::new(ScanBroadcaster::new()),
        None,
        data_dir.clone(),
    );
    let ingest_output = ingest
        .run(&repo)
        .await
        .expect("nexus should ingest successfully");

    let provider: Arc<dyn ModelProvider> = Arc::new(
        ClaudeCodeProvider::from_secret(secret).expect("Claude Code credentials should parse"),
    );
    let tyr = TyrStage::new(
        scan.id,
        repo.id,
        Arc::clone(&db),
        provider,
        "claude-sonnet-5".to_string(),
    );
    let threat_model = tyr
        .run(&ingest_output.code_index)
        .await
        .expect("the real Tyr request should complete through Claude Code");

    assert!(!threat_model.summary.trim().is_empty());
    let snapshot = build_scan_live_snapshot(&db, scan.id)
        .await
        .expect("live snapshot should load")
        .expect("live snapshot should exist");
    assert!(
        snapshot["activity"]
            .as_array()
            .expect("activity should be an array")
            .iter()
            .any(|event| event["title"] == "Threat model generated")
    );

    let _ = std::fs::remove_dir_all(data_dir);
}
