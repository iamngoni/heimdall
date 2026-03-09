-- Heimdall Schema Migration (SQLite)
-- Generated from schema DSL — do not edit manually

PRAGMA foreign_keys = ON;

-- 1. users
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    avatar_url TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT datetime('now'),
    updated_at TEXT NOT NULL DEFAULT datetime('now'),
    deleted_at TEXT
);

-- 2. organizations
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    plan TEXT NOT NULL DEFAULT 'free',
    created_at TEXT NOT NULL DEFAULT datetime('now'),
    updated_at TEXT NOT NULL DEFAULT datetime('now'),
    deleted_at TEXT
);

-- 3. org_members
CREATE TABLE IF NOT EXISTS org_members (
    id TEXT PRIMARY KEY NOT NULL,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TEXT NOT NULL DEFAULT datetime('now'),
    UNIQUE(org_id, user_id)
);

-- 4. sessions
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT datetime('now')
);

-- 5. oauth_connections
CREATE TABLE IF NOT EXISTS oauth_connections (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    access_token_enc TEXT,
    refresh_token_enc TEXT,
    scopes TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT datetime('now'),
    updated_at TEXT NOT NULL DEFAULT datetime('now'),
    UNIQUE(user_id, provider)
);

-- 6. api_keys
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id TEXT REFERENCES organizations(id) ON DELETE SET NULL,
    key_type TEXT NOT NULL,
    provider TEXT,
    label TEXT,
    key_hash TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,
    last_used_at TEXT,
    created_at TEXT NOT NULL DEFAULT datetime('now'),
    deleted_at TEXT
);

-- 7. repos
CREATE TABLE IF NOT EXISTS repos (
    id TEXT PRIMARY KEY NOT NULL,
    org_id TEXT REFERENCES organizations(id) ON DELETE SET NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    remote_url TEXT,
    default_branch TEXT,
    last_commit_sha TEXT,
    oauth_connection_id TEXT REFERENCES oauth_connections(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT datetime('now'),
    updated_at TEXT NOT NULL DEFAULT datetime('now'),
    deleted_at TEXT
);

-- 8. scans
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY NOT NULL,
    repo_id TEXT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    scan_type TEXT NOT NULL DEFAULT 'full',
    status TEXT NOT NULL DEFAULT 'queued',
    commit_sha TEXT,
    base_commit_sha TEXT,
    parent_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
    triggered_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    finding_count INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    completed_at TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT datetime('now'),
    updated_at TEXT NOT NULL DEFAULT datetime('now')
);

-- 9. scan_stages
CREATE TABLE IF NOT EXISTS scan_stages (
    id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    stage TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt INTEGER NOT NULL DEFAULT 1,
    started_at TEXT,
    completed_at TEXT,
    error_message TEXT,
    metadata_json TEXT,
    created_at TEXT NOT NULL DEFAULT datetime('now')
);

-- 10. scan_jobs
CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    priority INTEGER NOT NULL DEFAULT 0,
    worker_id TEXT,
    run_after TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    last_error TEXT,
    claimed_at TEXT,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT datetime('now'),
    updated_at TEXT NOT NULL DEFAULT datetime('now')
);

-- 11. file_snapshots
CREATE TABLE IF NOT EXISTS file_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    repo_id TEXT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    language TEXT,
    line_count INTEGER,
    byte_size INTEGER,
    ast_summary_json TEXT,
    created_at TEXT NOT NULL DEFAULT datetime('now')
);

-- 12. findings
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    source TEXT NOT NULL DEFAULT 'ai',
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    cwe_id TEXT,
    cve_id TEXT,
    file_path TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER,
    code_snippet TEXT,
    suggested_patch TEXT,
    poc_exploit_json TEXT,
    poc_validated INTEGER NOT NULL DEFAULT 0,
    fingerprint TEXT NOT NULL,
    agent_reasoning TEXT,
    created_at TEXT NOT NULL DEFAULT datetime('now'),
    updated_at TEXT NOT NULL DEFAULT datetime('now')
);

-- 13. finding_events
CREATE TABLE IF NOT EXISTS finding_events (
    id TEXT PRIMARY KEY NOT NULL,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    comment TEXT,
    created_at TEXT NOT NULL DEFAULT datetime('now')
);

-- 14. patches
CREATE TABLE IF NOT EXISTS patches (
    id TEXT PRIMARY KEY NOT NULL,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    diff_content TEXT NOT NULL,
    description TEXT,
    applies_cleanly INTEGER NOT NULL DEFAULT 1,
    applied INTEGER NOT NULL DEFAULT 0,
    applied_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    applied_at TEXT,
    created_at TEXT NOT NULL DEFAULT datetime('now')
);

-- 15. agent_tool_calls
CREATE TABLE IF NOT EXISTS agent_tool_calls (
    id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    stage TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    input_json TEXT,
    output_json TEXT,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    total_tokens INTEGER,
    duration_ms INTEGER,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT datetime('now')
);

-- 16. threat_models
CREATE TABLE IF NOT EXISTS threat_models (
    id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    summary TEXT,
    boundaries_json TEXT,
    surfaces_json TEXT,
    data_flows_json TEXT,
    model_version INTEGER NOT NULL DEFAULT 1,
    edited_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT datetime('now'),
    updated_at TEXT NOT NULL DEFAULT datetime('now')
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_file_snapshots_dedup ON file_snapshots(repo_id, file_path, content_hash);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_scan_severity ON findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_polling ON scan_jobs(status, run_after, priority);
CREATE INDEX IF NOT EXISTS idx_scans_repo_commit ON scans(repo_id, commit_sha);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_repos_user ON repos(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
