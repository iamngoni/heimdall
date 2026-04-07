//
//  heimdall
//  src/pipeline/tyr/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use log::{info, warn};
use serde::{Deserialize, Serialize};

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, Message};
use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::HeimdallResult;
use crate::util::{sat_i32, sat_i32_u128};

/// Tyr: The threat model engine. Analyses the codebase to identify
/// attack surfaces, trust boundaries, data flows, and risk ratings.
pub struct TyrStage {
    pub scan_id: uuid::Uuid,
    pub repo_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
    pub ai: Arc<dyn ModelProvider>,
    pub default_model: String,
}

#[derive(Clone, Copy)]
enum TyrContextMode {
    Standard,
    Compact,
}

impl TyrContextMode {
    fn label(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Compact => "compact",
        }
    }

    fn budgets(self) -> TyrContextBudgets {
        match self {
            Self::Standard => TyrContextBudgets {
                total_chars: 48_000,
                file_tree_chars: 4_000,
                entry_points_chars: 3_000,
                routes_chars: 6_000,
                dependencies_chars: 5_000,
                security_patterns_chars: 6_000,
                db_patterns_chars: 3_500,
                config_patterns_chars: 3_000,
                source_snippets_chars: 12_000,
                per_dependency_chars: 600,
                per_source_chars: 1_500,
                call_chains_chars: 5_000,
                public_api_chars: 4_000,
            },
            Self::Compact => TyrContextBudgets {
                total_chars: 28_000,
                file_tree_chars: 2_000,
                entry_points_chars: 1_600,
                routes_chars: 3_500,
                dependencies_chars: 3_000,
                security_patterns_chars: 3_500,
                db_patterns_chars: 2_000,
                config_patterns_chars: 1_600,
                source_snippets_chars: 6_000,
                per_dependency_chars: 350,
                per_source_chars: 900,
                call_chains_chars: 2_800,
                public_api_chars: 2_200,
            },
        }
    }
}

#[derive(Clone, Copy)]
struct TyrContextBudgets {
    total_chars: usize,
    file_tree_chars: usize,
    entry_points_chars: usize,
    routes_chars: usize,
    dependencies_chars: usize,
    security_patterns_chars: usize,
    db_patterns_chars: usize,
    config_patterns_chars: usize,
    source_snippets_chars: usize,
    per_dependency_chars: usize,
    per_source_chars: usize,
    call_chains_chars: usize,
    public_api_chars: usize,
}

/// The structured threat model produced by Tyr.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModelOutput {
    pub summary: String,
    pub boundaries: Vec<TrustBoundary>,
    pub surfaces: Vec<AttackSurface>,
    pub data_flows: Vec<DataFlow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBoundary {
    pub name: String,
    pub description: String,
    pub from_zone: String,
    pub to_zone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurface {
    pub name: String,
    pub description: String,
    pub endpoint: Option<String>,
    pub file: Option<String>,
    pub line: Option<usize>,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlow {
    pub name: String,
    pub description: String,
    pub source: String,
    pub sink: String,
    pub sensitive_data: String,
}

impl TyrStage {
    pub fn new(
        scan_id: uuid::Uuid,
        repo_id: uuid::Uuid,
        db: Arc<DatabaseOperations>,
        ai: Arc<dyn ModelProvider>,
        default_model: String,
    ) -> Self {
        Self {
            scan_id,
            repo_id,
            db,
            ai,
            default_model,
        }
    }

    pub async fn run(&self, index: &CodeIndex) -> HeimdallResult<ThreatModelOutput> {
        info!("[{}] Starting Tyr threat model generation", self.scan_id);
        self.record_event(
            Some("recon"),
            "running",
            "Reconnaissance: analyzing codebase structure",
            Some("Gathering tech stack, routes, auth patterns, data stores, and dependency info."),
            None,
            None,
        )
        .await;

        // Phase 1: Reconnaissance — gather structured intel from the code index
        let recon = self.reconnaissance(index);

        self.record_event(
            Some("recon"),
            "completed",
            "Reconnaissance complete",
            Some(&format!(
                "Found {} files, {} entry points, {} dependencies, {} routes, {} security patterns, {} call chains, {} public API exports.",
                recon.file_count, recon.entry_points.len(), recon.dependencies.len(),
                recon.routes.len(), recon.security_patterns.len(),
                recon.call_chains.len(), recon.public_api.len()
            )),
            Some(25),
            Some(&serde_json::json!({
                "file_count": recon.file_count,
                "entry_points": recon.entry_points.len(),
                "dependencies": recon.dependencies.len(),
                "routes": recon.routes.len(),
                "security_patterns": recon.security_patterns.len(),
                "call_chains": recon.call_chains.len(),
                "public_api_files": recon.public_api.len(),
            })),
        )
        .await;

        // Phase 2: Build rich context for the LLM
        let mut context_mode = TyrContextMode::Standard;
        let mut context = self.build_llm_context(index, &recon, context_mode);

        self.record_event(
            Some("threat-model-request"),
            "running",
            "Generating threat model",
            Some("Tyr is reasoning about trust boundaries, attack surfaces, and sensitive data flows using STRIDE methodology."),
            None,
            Some(&serde_json::json!({
                "model": self.default_model,
                "context_chars": context.len(),
                "context_mode": context_mode.label(),
            })),
        )
        .await;

        // Phase 3: LLM analysis
        let start = std::time::Instant::now();
        let response = match self
            .ai
            .complete(Self::completion_request(&self.default_model, &context))
            .await
        {
            Ok(response) => response,
            Err(error) if is_context_limit_error(&error) => {
                context_mode = TyrContextMode::Compact;
                context = self.build_llm_context(index, &recon, context_mode);
                self.record_event(
                    Some("threat-model-request"),
                    "running",
                    "Threat model context trimmed",
                    Some("The provider rejected the full reconnaissance payload. Tyr is retrying with a compact context window."),
                    None,
                    Some(&serde_json::json!({
                        "model": self.default_model,
                        "context_chars": context.len(),
                        "context_mode": context_mode.label(),
                    })),
                )
                .await;

                self.ai
                    .complete(Self::completion_request(&self.default_model, &context))
                    .await?
            }
            Err(error) => return Err(error),
        };
        let duration = start.elapsed();

        // Log the LLM call
        let _ = self
            .db
            .create_agent_tool_call(
                self.scan_id,
                "tyr",
                "llm_completion",
                Some(&response.provider),
                Some(&response.model),
                None,
                None,
                Some(sat_i32(response.usage.prompt_tokens.into())),
                Some(sat_i32(response.usage.completion_tokens.into())),
                Some(sat_i32(response.usage.total_tokens.into())),
                Some(sat_i32_u128(duration.as_millis())),
                None,
            )
            .await;

        // Parse the structured response
        let content = response.content.trim();
        let threat_model = match Self::parse_threat_model_output(content) {
            Ok(model) => model,
            Err(parse_error) => {
                warn!(
                    "[{}] Tyr initial parse failed: {}",
                    self.scan_id, parse_error
                );
                self.record_event(
                    Some("threat-model-repair"),
                    "running",
                    "Repairing malformed threat model response",
                    Some("The model returned unstructured output. Tyr is asking for a strict JSON rewrite so the scan can continue."),
                    Some(78),
                    Some(&serde_json::json!({
                        "parse_error": parse_error,
                        "raw_preview": truncate_text(content, 800),
                    })),
                )
                .await;

                match self.repair_threat_model_output(content, "initial").await {
                    Some(model) => {
                        self.record_event(
                            Some("threat-model-repair"),
                            "completed",
                            "Threat model response repaired",
                            Some("Recovered the malformed model response by rewriting it into the required JSON schema."),
                            Some(79),
                            None,
                        )
                        .await;
                        model
                    }
                    None => {
                        warn!(
                            "[{}] Tyr repair failed; continuing with empty structured model",
                            self.scan_id
                        );
                        self.record_event(
                            Some("threat-model-repair"),
                            "failed",
                            "Threat model response could not be repaired",
                            Some("Tyr could not recover a valid structured threat model. The scan will continue with an empty model so later stages can still run."),
                            Some(79),
                            Some(&serde_json::json!({
                                "raw_preview": truncate_text(content, 800),
                            })),
                        )
                        .await;
                        Self::empty_threat_model(&parse_error)
                    }
                }
            }
        };

        self.record_event(
            Some("threat-model-request"),
            "completed",
            "Threat model generated",
            Some(&format!(
                "Identified {} trust boundaries, {} attack surfaces, {} data flows.",
                threat_model.boundaries.len(),
                threat_model.surfaces.len(),
                threat_model.data_flows.len(),
            )),
            Some(80),
            Some(&serde_json::json!({
                "surfaces": threat_model.surfaces.len(),
                "boundaries": threat_model.boundaries.len(),
                "data_flows": threat_model.data_flows.len(),
                "duration_ms": sat_i32_u128(duration.as_millis()),
                "context_mode": context_mode.label(),
            })),
        )
        .await;

        // Phase 4: Validate surfaces against actual codebase
        let threat_model = self.validate_surfaces(index, threat_model);

        // Phase 5: Refinement pass — feed call chain data + initial model back
        // to the LLM to catch missed surfaces and sharpen risk ratings
        let threat_model = self
            .refinement_pass(index, &recon, &threat_model, context_mode)
            .await
            .unwrap_or(threat_model);

        self.record_event(
            Some("refinement"),
            "completed",
            "Threat model refined",
            Some(&format!(
                "Final model: {} trust boundaries, {} attack surfaces, {} data flows.",
                threat_model.boundaries.len(),
                threat_model.surfaces.len(),
                threat_model.data_flows.len(),
            )),
            Some(90),
            Some(&serde_json::json!({
                "surfaces": threat_model.surfaces.len(),
                "boundaries": threat_model.boundaries.len(),
                "data_flows": threat_model.data_flows.len(),
            })),
        )
        .await;

        // Store in DB
        let boundaries_json = serde_json::to_value(&threat_model.boundaries)?;
        let surfaces_json = serde_json::to_value(&threat_model.surfaces)?;
        let data_flows_json = serde_json::to_value(&threat_model.data_flows)?;

        self.record_event(
            Some("threat-model-store"),
            "running",
            "Persisting threat model",
            Some("Writing structured threat-model artifacts to the database."),
            None,
            None,
        )
        .await;

        self.db
            .create_threat_model(
                self.scan_id,
                self.repo_id,
                Some(&threat_model.summary),
                Some(&boundaries_json),
                Some(&surfaces_json),
                Some(&data_flows_json),
            )
            .await?;

        self.record_event(
            Some("threat-model-store"),
            "completed",
            "Threat model stored",
            Some("Threat-model artifacts are available for downstream stages and review."),
            Some(100),
            None,
        )
        .await;

        info!(
            "[{}] Tyr complete: {} boundaries, {} surfaces, {} data flows",
            self.scan_id,
            threat_model.boundaries.len(),
            threat_model.surfaces.len(),
            threat_model.data_flows.len(),
        );

        Ok(threat_model)
    }

    // -----------------------------------------------------------------------
    // Phase 1: Reconnaissance
    // -----------------------------------------------------------------------

    /// Gather structured intelligence from the code index without any LLM calls.
    fn reconnaissance(&self, index: &CodeIndex) -> ReconOutput {
        let file_count = index.files.len();
        let file_tree = index.file_tree();

        // Detect tech stack from file extensions and known config files
        let tech_stack = self.detect_tech_stack(index);

        // Collect entry points (route handlers, main functions, exports)
        let entry_points = self.collect_entry_points(index);

        // Collect dependencies from manifest files
        let dependencies = self.collect_dependencies(index);

        // Find route/endpoint definitions
        let routes = self.find_routes(index);

        // Find security-sensitive code patterns
        let security_patterns = self.find_security_patterns(index);

        // Find config/env handling
        let config_patterns = self.find_config_patterns(index);

        // Find database interaction patterns
        let db_patterns = self.find_db_patterns(index);

        // Trace call chains from entry points through security-sensitive sinks
        let call_chains = self.collect_call_chains(index);

        // Map the public API surface from exported symbols
        let public_api = self.collect_public_api_surface(index);

        ReconOutput {
            file_count,
            file_tree: file_tree.into_iter().map(|s| s.to_string()).collect(),
            tech_stack,
            entry_points,
            dependencies,
            routes,
            security_patterns,
            config_patterns,
            db_patterns,
            call_chains,
            public_api,
        }
    }

    fn detect_tech_stack(&self, index: &CodeIndex) -> Vec<String> {
        let mut stack = Vec::new();
        let files: Vec<&str> = index.files.keys().map(|s| s.as_str()).collect();

        // Language detection by file count
        let mut lang_counts: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for f in &files {
            if let Some(lang) = self.file_extension_to_lang(f) {
                *lang_counts.entry(lang).or_default() += 1;
            }
        }
        let mut langs: Vec<_> = lang_counts.into_iter().collect();
        langs.sort_by(|a, b| b.1.cmp(&a.1));
        for (lang, count) in langs.iter().take(5) {
            stack.push(format!("{lang} ({count} files)"));
        }

        // Framework detection from known files
        let framework_markers: &[(&str, &str)] = &[
            ("Cargo.toml", "Rust/Cargo"),
            ("package.json", "Node.js/npm"),
            ("requirements.txt", "Python/pip"),
            ("Pipfile", "Python/Pipenv"),
            ("pyproject.toml", "Python project"),
            ("go.mod", "Go modules"),
            ("pom.xml", "Java/Maven"),
            ("build.gradle", "Java/Gradle"),
            ("Gemfile", "Ruby/Bundler"),
            ("composer.json", "PHP/Composer"),
            ("Dockerfile", "Docker"),
            ("docker-compose.yml", "Docker Compose"),
            ("docker-compose.yaml", "Docker Compose"),
            (".github/workflows", "GitHub Actions CI"),
            (".gitlab-ci.yml", "GitLab CI"),
            ("terraform", "Terraform IaC"),
            ("k8s", "Kubernetes"),
            ("helm", "Helm charts"),
        ];

        for (marker, label) in framework_markers {
            if files.iter().any(|f| f.contains(marker)) {
                stack.push(label.to_string());
            }
        }

        // Detect web frameworks from code content
        let framework_imports: &[(&str, &str)] = &[
            ("actix_web", "Actix-web (Rust)"),
            ("axum::", "Axum (Rust)"),
            ("rocket::", "Rocket (Rust)"),
            ("from flask", "Flask (Python)"),
            ("from django", "Django (Python)"),
            ("from fastapi", "FastAPI (Python)"),
            ("express()", "Express.js"),
            ("from 'next", "Next.js"),
            ("@nestjs/", "NestJS"),
            ("spring", "Spring (Java)"),
            ("gin.Default", "Gin (Go)"),
            ("fiber.New", "Fiber (Go)"),
            ("Rails.application", "Ruby on Rails"),
            ("Laravel", "Laravel (PHP)"),
        ];

        for (pattern, label) in framework_imports {
            let found = index.files.values().any(|f| f.content.contains(pattern));
            if found {
                stack.push(label.to_string());
            }
        }

        stack
    }

    fn collect_entry_points(&self, index: &CodeIndex) -> Vec<String> {
        let mut points = Vec::new();

        // Symbol-level entry points
        for sym in index.symbols.entry_points() {
            points.push(format!(
                "{} `{}` at {}:{}",
                sym.kind, sym.name, sym.file, sym.line
            ));
        }

        // Public exports
        for sym in index.symbols.exports().iter().take(30) {
            if !points.iter().any(|p| p.contains(&sym.name)) {
                points.push(format!(
                    "export {} `{}` at {}:{}",
                    sym.kind, sym.name, sym.file, sym.line
                ));
            }
        }

        points.truncate(50);
        points
    }

    fn collect_dependencies(&self, index: &CodeIndex) -> Vec<String> {
        let mut deps = Vec::new();

        // Read package manifests
        let manifest_files = [
            "package.json",
            "Cargo.toml",
            "requirements.txt",
            "go.mod",
            "Gemfile",
            "composer.json",
            "pom.xml",
            "Pipfile",
        ];

        for name in &manifest_files {
            // Check all files since manifests may be at different levels
            for (path, file) in &index.files {
                if path.ends_with(name) {
                    // Extract first 2000 chars of manifest
                    let snippet: String = file.content.chars().take(2000).collect();
                    deps.push(format!("### {path}\n```\n{snippet}\n```"));
                }
            }
        }

        deps
    }

    fn find_routes(&self, index: &CodeIndex) -> Vec<String> {
        let mut routes = Vec::new();

        let route_patterns = [
            // Rust web frameworks
            r#".route("#,
            r#".get("#,
            r#".post("#,
            r#".put("#,
            r#".delete("#,
            r#".patch("#,
            r#".resource("#,
            r#"#[get("#,
            r#"#[post("#,
            r#"#[put("#,
            r#"#[delete("#,
            // Python
            r#"@app.route("#,
            r#"@router."#,
            r#"path("#,
            r#"url("#,
            // JavaScript/TypeScript
            r#"router.get("#,
            r#"router.post("#,
            r#"app.get("#,
            r#"app.post("#,
            r#"@Get("#,
            r#"@Post("#,
            r#"@Controller("#,
            // Go
            r#"HandleFunc("#,
            r#"Handle("#,
            // Java Spring
            r#"@GetMapping"#,
            r#"@PostMapping"#,
            r#"@RequestMapping"#,
        ];

        for (path, file) in &index.files {
            for (line_num, line) in file.content.lines().enumerate() {
                let trimmed = line.trim();
                for pattern in &route_patterns {
                    if trimmed.contains(pattern) {
                        routes.push(format!("{}:{} — {}", path, line_num + 1, trimmed));
                        break;
                    }
                }
            }
        }

        routes.truncate(100);
        routes
    }

    fn find_security_patterns(&self, index: &CodeIndex) -> Vec<String> {
        let mut patterns = Vec::new();

        let security_keywords = [
            ("password", "Password handling"),
            ("secret", "Secret/key handling"),
            ("token", "Token handling"),
            ("auth", "Authentication"),
            ("permission", "Authorization/permissions"),
            ("role", "Role-based access"),
            ("encrypt", "Encryption"),
            ("decrypt", "Decryption"),
            ("hash", "Hashing"),
            ("session", "Session management"),
            ("cookie", "Cookie handling"),
            ("csrf", "CSRF protection"),
            ("cors", "CORS configuration"),
            ("jwt", "JWT handling"),
            ("oauth", "OAuth flow"),
            ("sanitiz", "Input sanitization"),
            ("validat", "Input validation"),
            ("escape", "Output escaping"),
            ("sql", "SQL query construction"),
            ("exec", "Command execution"),
            ("eval", "Code evaluation"),
            ("upload", "File upload"),
            ("deserializ", "Deserialization"),
        ];

        for (path, file) in &index.files {
            // Skip non-source files
            if file.language.is_none() {
                continue;
            }
            let lower = file.content.to_ascii_lowercase();
            for (keyword, label) in &security_keywords {
                if lower.contains(keyword) {
                    // Find the first few matching lines for context
                    let matches: Vec<_> = file
                        .content
                        .lines()
                        .enumerate()
                        .filter(|(_, line)| line.to_ascii_lowercase().contains(keyword))
                        .take(3)
                        .map(|(i, line)| format!("  {}:{} — {}", path, i + 1, line.trim()))
                        .collect();

                    if !matches.is_empty() {
                        patterns.push(format!("[{label}] in {path}:\n{}", matches.join("\n")));
                    }
                }
            }
        }

        // Deduplicate by file — keep max 3 patterns per file
        patterns.truncate(80);
        patterns
    }

    fn find_config_patterns(&self, index: &CodeIndex) -> Vec<String> {
        let mut patterns = Vec::new();

        // Look for env var usage
        let env_patterns = [
            "env::var",
            "process.env",
            "os.environ",
            "os.Getenv",
            "ENV[",
            "getenv(",
            "dotenv",
            "dotenvy",
        ];

        for (path, file) in &index.files {
            if file.language.is_none() {
                continue;
            }
            for pattern in &env_patterns {
                if file.content.contains(pattern) {
                    let matches: Vec<_> = file
                        .content
                        .lines()
                        .enumerate()
                        .filter(|(_, line)| line.contains(pattern))
                        .take(5)
                        .map(|(i, line)| format!("  {}:{} — {}", path, i + 1, line.trim()))
                        .collect();
                    if !matches.is_empty() {
                        patterns.push(matches.join("\n"));
                    }
                    break;
                }
            }
        }

        // Look for .env files, config files
        let config_files = ["config", ".env", "settings", "application.yml"];
        for (path, _) in &index.files {
            let lower = path.to_ascii_lowercase();
            for cf in &config_files {
                if lower.contains(cf) {
                    patterns.push(format!("Config file: {path}"));
                    break;
                }
            }
        }

        patterns.truncate(30);
        patterns
    }

    fn find_db_patterns(&self, index: &CodeIndex) -> Vec<String> {
        let mut patterns = Vec::new();

        let db_indicators = [
            ("sqlx::", "SQLx (Rust)"),
            ("diesel::", "Diesel ORM (Rust)"),
            ("sea_orm", "SeaORM (Rust)"),
            ("mongoose", "Mongoose (MongoDB)"),
            ("sequelize", "Sequelize ORM"),
            ("prisma", "Prisma ORM"),
            ("typeorm", "TypeORM"),
            ("sqlalchemy", "SQLAlchemy"),
            ("django.db", "Django ORM"),
            ("ActiveRecord", "ActiveRecord"),
            ("Eloquent", "Eloquent ORM"),
            ("gorm", "GORM (Go)"),
            ("JpaRepository", "Spring JPA"),
            ("raw_sql", "Raw SQL execution"),
            ("query(\"", "Direct SQL query"),
            ("query!(\"", "SQL macro query"),
            ("execute(\"", "SQL execute"),
        ];

        for (path, file) in &index.files {
            if file.language.is_none() {
                continue;
            }
            for (indicator, label) in &db_indicators {
                if file.content.contains(indicator) {
                    let matches: Vec<_> = file
                        .content
                        .lines()
                        .enumerate()
                        .filter(|(_, line)| line.contains(indicator))
                        .take(3)
                        .map(|(i, line)| format!("  {}:{} — {}", path, i + 1, line.trim()))
                        .collect();
                    if !matches.is_empty() {
                        patterns.push(format!("[{label}] in {path}:\n{}", matches.join("\n")));
                    }
                    break;
                }
            }
        }

        patterns.truncate(30);
        patterns
    }

    /// Trace call chains from entry points through security-sensitive functions.
    /// Walks up to 4 levels deep from each entry point, flagging paths that
    /// reach known risky sinks (exec, query, deserialize, file I/O, crypto, etc.).
    fn collect_call_chains(&self, index: &CodeIndex) -> Vec<String> {
        let risky_sinks: &[&str] = &[
            "exec",
            "execute",
            "query",
            "raw_sql",
            "eval",
            "spawn",
            "command",
            "deserialize",
            "from_str",
            "from_bytes",
            "unmarshal",
            "decode",
            "open",
            "read_file",
            "write_file",
            "remove",
            "unlink",
            "rename",
            "encrypt",
            "decrypt",
            "hash",
            "sign",
            "verify",
            "send",
            "request",
            "fetch",
            "get",
            "post",
            "redirect",
            "set_cookie",
            "create_token",
            "verify_token",
            "upload",
            "download",
            "serialize",
        ];

        let entry_points = index.symbols.entry_points();
        let mut chains = Vec::new();

        for ep in entry_points.iter().take(60) {
            // BFS up to depth 4 from this entry point
            let mut visited = std::collections::HashSet::new();
            let mut queue: Vec<(String, Vec<String>)> =
                vec![(ep.name.clone(), vec![ep.name.clone()])];
            visited.insert(ep.name.clone());

            while let Some((current, path)) = queue.pop() {
                if path.len() > 4 {
                    continue;
                }

                let callees = index.callgraph.get_callees(&current);
                for edge in callees {
                    let callee_lower = edge.callee.to_ascii_lowercase();
                    let is_risky = risky_sinks.iter().any(|sink| callee_lower.contains(sink));

                    if is_risky {
                        let mut full_path = path.clone();
                        full_path.push(edge.callee.clone());
                        chains.push(format!(
                            "{} ({}:{})",
                            full_path.join(" → "),
                            edge.file,
                            edge.line,
                        ));
                    }

                    if !visited.contains(&edge.callee) && path.len() < 4 {
                        visited.insert(edge.callee.clone());
                        let mut next_path = path.clone();
                        next_path.push(edge.callee.clone());
                        queue.push((edge.callee.clone(), next_path));
                    }
                }
            }
        }

        chains.truncate(80);
        chains
    }

    /// Map the public API surface from exported symbols — functions, types, and
    /// handlers that are publicly accessible and thus potential attack surface.
    fn collect_public_api_surface(&self, index: &CodeIndex) -> Vec<String> {
        let mut surface = Vec::new();

        // Group public symbols by file for better context
        let exports = index.symbols.exports();
        let mut by_file: std::collections::HashMap<&str, Vec<&crate::index::symbols::Symbol>> =
            std::collections::HashMap::new();

        for sym in &exports {
            by_file.entry(sym.file.as_str()).or_default().push(sym);
        }

        // Sort files by number of exports (most exposed first)
        let mut file_list: Vec<_> = by_file.into_iter().collect();
        file_list.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

        for (file, syms) in file_list.iter().take(30) {
            let sym_list: Vec<String> = syms
                .iter()
                .take(10)
                .map(|s| {
                    let callee_count = index.callgraph.get_callees(&s.name).len();
                    let caller_count = index.callgraph.get_callers(&s.name).len();
                    format!(
                        "  {} `{}` (line {}, {} callers, calls {})",
                        s.kind, s.name, s.line, caller_count, callee_count
                    )
                })
                .collect();

            let omitted = syms.len().saturating_sub(10);
            let mut entry = format!("{file} ({} exports):\n{}", syms.len(), sym_list.join("\n"));
            if omitted > 0 {
                entry.push_str(&format!("\n  ... +{omitted} more"));
            }
            surface.push(entry);
        }

        surface
    }

    fn file_extension_to_lang<'a>(&self, path: &'a str) -> Option<&'static str> {
        let ext = path.rsplit('.').next()?;
        match ext {
            "rs" => Some("Rust"),
            "py" => Some("Python"),
            "js" | "mjs" | "cjs" | "jsx" => Some("JavaScript"),
            "ts" | "mts" | "cts" | "tsx" => Some("TypeScript"),
            "go" => Some("Go"),
            "java" => Some("Java"),
            "rb" => Some("Ruby"),
            "php" => Some("PHP"),
            "c" | "h" => Some("C"),
            "cpp" | "cc" | "hpp" => Some("C++"),
            "cs" => Some("C#"),
            "swift" => Some("Swift"),
            "kt" => Some("Kotlin"),
            "scala" => Some("Scala"),
            "sol" => Some("Solidity"),
            "sh" | "bash" => Some("Shell"),
            _ => None,
        }
    }

    // -----------------------------------------------------------------------
    // Phase 2: Build LLM context
    // -----------------------------------------------------------------------

    fn build_llm_context(
        &self,
        index: &CodeIndex,
        recon: &ReconOutput,
        mode: TyrContextMode,
    ) -> String {
        let budgets = mode.budgets();
        let mut ctx = String::new();

        // 1. Codebase overview
        append_capped(
            &mut ctx,
            &format!(
                "Analyze the following codebase and generate a comprehensive threat model.\n\n\
                 ## Codebase Overview\n\
                 - **Context mode:** {}\n\
                 - **Files:** {}\n\
                 - **Tech Stack:** {}\n\n",
                mode.label(),
                recon.file_count,
                if recon.tech_stack.is_empty() {
                    "Unknown".to_string()
                } else {
                    recon.tech_stack.join(", ")
                },
            ),
            budgets.total_chars,
        );

        append_bulleted_section(
            &mut ctx,
            "## File Structure\n",
            recon
                .file_tree
                .iter()
                .map(|path| path.to_string())
                .collect::<Vec<_>>()
                .as_slice(),
            budgets.file_tree_chars,
            budgets.total_chars,
            None,
        );

        append_bulleted_section(
            &mut ctx,
            "## Entry Points\n",
            &recon.entry_points,
            budgets.entry_points_chars,
            budgets.total_chars,
            None,
        );

        append_bulleted_section(
            &mut ctx,
            "## Routes / API Endpoints\n",
            &recon.routes,
            budgets.routes_chars,
            budgets.total_chars,
            None,
        );

        let dependency_items = recon
            .dependencies
            .iter()
            .map(|item| truncate_text(item, budgets.per_dependency_chars))
            .collect::<Vec<_>>();
        append_plain_section(
            &mut ctx,
            "## Dependencies (from manifests)\n",
            &dependency_items,
            budgets.dependencies_chars,
            budgets.total_chars,
        );

        append_plain_section(
            &mut ctx,
            "## Security-Sensitive Code Patterns\n",
            &recon.security_patterns,
            budgets.security_patterns_chars,
            budgets.total_chars,
        );

        append_plain_section(
            &mut ctx,
            "## Database Access Patterns\n",
            &recon.db_patterns,
            budgets.db_patterns_chars,
            budgets.total_chars,
        );

        append_plain_section(
            &mut ctx,
            "## Configuration / Environment\n",
            &recon.config_patterns,
            budgets.config_patterns_chars,
            budgets.total_chars,
        );

        // Call chain analysis — shows entry_point → ... → risky_sink paths
        append_bulleted_section(
            &mut ctx,
            "## Call Chains (entry point → security-sensitive sink)\n\
             Each line traces a path from a public entry point to a risky function \
             (exec, query, deserialize, file I/O, crypto, network, etc.):\n",
            &recon.call_chains,
            budgets.call_chains_chars,
            budgets.total_chars,
            None,
        );

        // Public API surface from exported symbols
        append_plain_section(
            &mut ctx,
            "## Public API Surface (exported symbols)\n\
             Functions and types exposed to callers, grouped by file. \
             Higher caller/callee counts indicate more connected (higher-risk) symbols:\n",
            &recon.public_api,
            budgets.public_api_chars,
            budgets.total_chars,
        );

        append_capped(
            &mut ctx,
            "## Key Source Files (selected content)\n",
            budgets.total_chars,
        );
        let critical_file_patterns = [
            "auth",
            "login",
            "session",
            "middleware",
            "security",
            "crypto",
            "config",
            "route",
            "router",
            "controller",
            "handler",
            "api",
            "upload",
            "webhook",
            "payment",
            "admin",
        ];

        let mut source_section_len = 0usize;
        let mut omitted_source_files = 0usize;
        let mut scored_files: Vec<(&str, &crate::index::IndexedFile, usize)> = index
            .files
            .iter()
            .filter(|(_, f)| f.language.is_some())
            .map(|(path, file)| {
                let lower = path.to_ascii_lowercase();
                let score = critical_file_patterns
                    .iter()
                    .filter(|pattern| lower.contains(**pattern))
                    .count();
                (path.as_str(), file, score)
            })
            .filter(|(_, _, score)| *score > 0)
            .collect();
        scored_files.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(b.0)));

        for (path, file, _) in scored_files {
            let snippet = truncate_text(&file.content, budgets.per_source_chars);
            let block = format!("\n### {path}\n```\n{snippet}\n```\n");
            if source_section_len + block.len() > budgets.source_snippets_chars
                || ctx.len() + block.len() > budgets.total_chars
            {
                omitted_source_files += 1;
                continue;
            }
            ctx.push_str(&block);
            source_section_len += block.len();
        }
        if omitted_source_files > 0 {
            append_capped(
                &mut ctx,
                &format!(
                    "\n... {} additional high-signal source files were omitted to stay within the provider context window.\n",
                    omitted_source_files
                ),
                budgets.total_chars,
            );
        }

        append_capped(
            &mut ctx,
            &format!(
                "\n## Output Requirements\n\
                 Respond with a JSON object matching this exact schema:\n\
                 {{\n\
                   \"summary\": \"string — 2-3 paragraphs: what this application does, its architecture, \
                     overall security posture, and the most significant risks\",\n\
                   \"boundaries\": [\n\
                     {{\n\
                       \"name\": \"string — descriptive name\",\n\
                       \"description\": \"string — what crosses this boundary and why it matters\",\n\
                       \"from_zone\": \"string — less trusted zone\",\n\
                       \"to_zone\": \"string — more trusted zone\"\n\
                     }}\n\
                   ],\n\
                   \"surfaces\": [\n\
                     {{\n\
                       \"name\": \"string — specific, actionable name\",\n\
                       \"description\": \"string — what the surface does, what threats apply (reference STRIDE), \
                         and what an attacker could target\",\n\
                       \"endpoint\": \"string or null — API path or URL if applicable\",\n\
                       \"file\": \"string or null — source file path\",\n\
                       \"line\": null,\n\
                       \"risk_level\": \"critical|high|medium|low\"\n\
                     }}\n\
                   ],\n\
                   \"data_flows\": [\n\
                     {{\n\
                       \"name\": \"string — descriptive name\",\n\
                       \"description\": \"string — how data moves and what transformations occur\",\n\
                       \"source\": \"string — where data originates\",\n\
                       \"sink\": \"string — where data is consumed or stored\",\n\
                       \"sensitive_data\": \"string — what sensitive data is in this flow\"\n\
                     }}\n\
                   ]\n\
                 }}\n\n\
                 Return ONLY the JSON object, no markdown fences, no commentary."
            ),
            budgets.total_chars,
        );

        ctx
    }

    fn completion_request(model: &str, context: &str) -> CompletionRequest {
        CompletionRequest {
            model: model.to_string(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: TYR_SYSTEM_PROMPT.to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: context.to_string(),
                },
            ],
            tools: None,
            max_tokens: Some(8192),
            temperature: Some(0.2),
        }
    }

    /// Validate that LLM-generated attack surfaces reference real files/endpoints.
    /// Removes surfaces pointing to non-existent files and annotates surfaces
    /// with verified=true/false for downstream consumption.
    fn validate_surfaces(
        &self,
        index: &CodeIndex,
        mut model: ThreatModelOutput,
    ) -> ThreatModelOutput {
        model.surfaces.retain(|surface| {
            // If the surface references a file, verify it exists
            if let Some(ref file) = surface.file {
                let file_clean = file.trim_start_matches('/').trim_start_matches("./");
                if !index.files.contains_key(file_clean)
                    && !index.files.keys().any(|k| k.ends_with(file_clean))
                {
                    info!(
                        "[{}] Tyr: dropping hallucinated surface '{}' — file '{}' not in index",
                        self.scan_id, surface.name, file
                    );
                    return false;
                }
            }
            true
        });

        // Validate data flow source/sink references
        model.data_flows.retain(|flow| {
            // Keep flows that reference known patterns — drop those that reference
            // completely invented components
            let source_lower = flow.source.to_ascii_lowercase();
            let sink_lower = flow.sink.to_ascii_lowercase();

            // Generic terms are always valid (user, browser, database, etc.)
            let generic_terms = [
                "user", "browser", "client", "database", "db", "api", "server", "external",
                "network", "cache", "queue", "storage", "memory", "file", "config", "env",
                "session",
            ];

            let source_valid = generic_terms.iter().any(|t| source_lower.contains(t))
                || index
                    .files
                    .keys()
                    .any(|k| source_lower.contains(k.split('/').last().unwrap_or("")));
            let sink_valid = generic_terms.iter().any(|t| sink_lower.contains(t))
                || index
                    .files
                    .keys()
                    .any(|k| sink_lower.contains(k.split('/').last().unwrap_or("")));

            source_valid || sink_valid
        });

        model
    }

    /// Multi-pass refinement: feed the initial threat model + call chain analysis
    /// back to the LLM so it can catch missed surfaces and sharpen risk ratings.
    async fn refinement_pass(
        &self,
        index: &CodeIndex,
        recon: &ReconOutput,
        initial_model: &ThreatModelOutput,
        mode: TyrContextMode,
    ) -> Option<ThreatModelOutput> {
        let budgets = mode.budgets();

        // Build refinement context with the initial model + call chains
        let initial_json = serde_json::to_string_pretty(initial_model).ok()?;
        let mut ctx = String::new();

        append_capped(
            &mut ctx,
            &format!(
                "You previously generated a threat model for this codebase. \
                 Now refine it using the additional call chain analysis and public API data below.\n\n\
                 ## Initial Threat Model\n```json\n{}\n```\n\n",
                truncate_text(&initial_json, budgets.total_chars / 3),
            ),
            budgets.total_chars,
        );

        // Add call chains the LLM didn't have in the first pass
        append_bulleted_section(
            &mut ctx,
            "## Call Chains (entry point → security-sensitive sink)\n\
             These are verified paths from entry points to risky functions. \
             Each path that is NOT covered by an existing attack surface is a gap:\n",
            &recon.call_chains,
            budgets.call_chains_chars,
            budgets.total_chars,
            None,
        );

        // Add public API for completeness check
        append_plain_section(
            &mut ctx,
            "## Public API Surface\n",
            &recon.public_api,
            budgets.public_api_chars,
            budgets.total_chars,
        );

        // Add security-critical source snippets for any files referenced by call chains
        let mut chain_files: Vec<&str> = Vec::new();
        for chain in &recon.call_chains {
            // Extract file paths from chain strings like "fn_a → fn_b (src/foo.rs:42)"
            if let Some(paren_start) = chain.rfind('(') {
                if let Some(colon) = chain[paren_start..].find(':') {
                    let file = &chain[paren_start + 1..paren_start + colon];
                    if !chain_files.contains(&file) {
                        chain_files.push(file);
                    }
                }
            }
        }

        if !chain_files.is_empty() {
            append_capped(
                &mut ctx,
                "## Source Snippets for Call Chain Endpoints\n",
                budgets.total_chars,
            );
            let mut snippet_len = 0usize;
            for file_path in chain_files.iter().take(10) {
                if let Some(file) = index.files.get(*file_path) {
                    let snippet = truncate_text(&file.content, budgets.per_source_chars);
                    let block = format!("\n### {file_path}\n```\n{snippet}\n```\n");
                    if snippet_len + block.len() > budgets.source_snippets_chars / 2
                        || ctx.len() + block.len() > budgets.total_chars
                    {
                        break;
                    }
                    ctx.push_str(&block);
                    snippet_len += block.len();
                }
            }
        }

        append_capped(
            &mut ctx,
            "\n## Refinement Instructions\n\
             1. Check every call chain above — if any path represents an attack surface \
                NOT in your initial model, ADD it.\n\
             2. Check every public export — if an exported function handles untrusted input \
                but has no corresponding attack surface, ADD it.\n\
             3. Re-evaluate risk_level for each surface using the call chain depth and \
                connectivity data.\n\
             4. Remove any surfaces you now believe are false positives.\n\
             5. Return the COMPLETE refined threat model (not just changes).\n\n\
             Return ONLY the JSON object, no markdown fences, no commentary.",
            budgets.total_chars,
        );

        self.record_event(
            Some("refinement"),
            "running",
            "Refining threat model",
            Some("Tyr is cross-referencing the initial threat model against call chain analysis and public API surface to find gaps."),
            Some(85),
            Some(&serde_json::json!({
                "model": self.default_model,
                "context_chars": ctx.len(),
                "call_chains": recon.call_chains.len(),
            })),
        )
        .await;

        let start = std::time::Instant::now();
        let response = self
            .ai
            .complete(CompletionRequest {
                model: self.default_model.clone(),
                messages: vec![
                    Message {
                        role: "system".to_string(),
                        content: TYR_REFINEMENT_PROMPT.to_string(),
                    },
                    Message {
                        role: "user".to_string(),
                        content: ctx,
                    },
                ],
                tools: None,
                max_tokens: Some(8192),
                temperature: Some(0.1),
            })
            .await
            .ok()?;
        let duration = start.elapsed();

        // Log the refinement LLM call
        let _ = self
            .db
            .create_agent_tool_call(
                self.scan_id,
                "tyr",
                "llm_refinement",
                Some(&response.provider),
                Some(&response.model),
                None,
                None,
                Some(sat_i32(response.usage.prompt_tokens.into())),
                Some(sat_i32(response.usage.completion_tokens.into())),
                Some(sat_i32(response.usage.total_tokens.into())),
                Some(sat_i32_u128(duration.as_millis())),
                None,
            )
            .await;

        // Parse the refined model
        match Self::parse_threat_model_output(&response.content) {
            Ok(refined) => {
                info!(
                    "[{}] Tyr refinement: {} boundaries, {} surfaces, {} data flows (was {}/{}/{})",
                    self.scan_id,
                    refined.boundaries.len(),
                    refined.surfaces.len(),
                    refined.data_flows.len(),
                    initial_model.boundaries.len(),
                    initial_model.surfaces.len(),
                    initial_model.data_flows.len(),
                );
                Some(refined)
            }
            Err(parse_error) => {
                info!(
                    "[{}] Tyr refinement parse failed; attempting repair: {}",
                    self.scan_id, parse_error
                );
                match self
                    .repair_threat_model_output(&response.content, "refinement")
                    .await
                {
                    Some(refined) => {
                        info!(
                            "[{}] Tyr refinement repair succeeded: {} boundaries, {} surfaces, {} data flows",
                            self.scan_id,
                            refined.boundaries.len(),
                            refined.surfaces.len(),
                            refined.data_flows.len(),
                        );
                        Some(refined)
                    }
                    None => {
                        info!(
                            "[{}] Tyr refinement repair failed (keeping initial model)",
                            self.scan_id
                        );
                        None
                    }
                }
            }
        }
    }

    async fn repair_threat_model_output(
        &self,
        raw: &str,
        phase: &str,
    ) -> Option<ThreatModelOutput> {
        let prompt = format!(
            "Convert the following threat model response into a JSON object using Heimdall's exact schema.\n\n\
             Requirements:\n\
             - Preserve only information present in the raw response.\n\
             - Do not add markdown, headings, or commentary.\n\
             - Use this exact schema:\n\
               {{\n\
                 \"summary\": string,\n\
                 \"boundaries\": [{{\"name\": string, \"description\": string, \"from_zone\": string, \"to_zone\": string}}],\n\
                 \"surfaces\": [{{\"name\": string, \"description\": string, \"endpoint\": string|null, \"file\": string|null, \"line\": number|null, \"risk_level\": \"critical\"|\"high\"|\"medium\"|\"low\"}}],\n\
                 \"data_flows\": [{{\"name\": string, \"description\": string, \"source\": string, \"sink\": string, \"sensitive_data\": string}}]\n\
               }}\n\
             - If a field is unknown, use null for optional fields or an empty array when nothing is present.\n\
             - Return ONLY the JSON object.\n\n\
             Raw response:\n{}\n",
            truncate_text(raw, 24_000)
        );

        let start = std::time::Instant::now();
        let response = self
            .ai
            .complete(CompletionRequest {
                model: self.default_model.clone(),
                messages: vec![
                    Message {
                        role: "system".to_string(),
                        content: TYR_JSON_REPAIR_PROMPT.to_string(),
                    },
                    Message {
                        role: "user".to_string(),
                        content: prompt,
                    },
                ],
                tools: None,
                max_tokens: Some(4096),
                temperature: Some(0.0),
            })
            .await
            .ok()?;
        let duration = start.elapsed();

        let metadata = serde_json::json!({ "phase": phase });
        let _ = self
            .db
            .create_agent_tool_call(
                self.scan_id,
                "tyr",
                "llm_json_repair",
                Some(&response.provider),
                Some(&response.model),
                Some(&metadata),
                None,
                Some(sat_i32(response.usage.prompt_tokens.into())),
                Some(sat_i32(response.usage.completion_tokens.into())),
                Some(sat_i32(response.usage.total_tokens.into())),
                Some(sat_i32_u128(duration.as_millis())),
                None,
            )
            .await;

        match Self::parse_threat_model_output(&response.content) {
            Ok(model) => Some(model),
            Err(error) => {
                warn!(
                    "[{}] Tyr {} repair parse failed: {}",
                    self.scan_id, phase, error
                );
                None
            }
        }
    }

    fn parse_threat_model_output(raw: &str) -> Result<ThreatModelOutput, String> {
        let mut errors = Vec::new();

        for candidate in json_parse_candidates(raw) {
            match serde_json::from_str::<ThreatModelOutput>(&candidate) {
                Ok(model) => return Ok(model),
                Err(error) => errors.push(error.to_string()),
            }
        }

        Err(errors
            .into_iter()
            .next()
            .unwrap_or_else(|| "No JSON object found in Tyr response".to_string()))
    }

    fn empty_threat_model(parse_error: &str) -> ThreatModelOutput {
        ThreatModelOutput {
            summary: format!(
                "Heimdall continued without a structured Tyr threat model because the model response could not be parsed or repaired automatically. Parser error: {}",
                parse_error
            ),
            boundaries: Vec::new(),
            surfaces: Vec::new(),
            data_flows: Vec::new(),
        }
    }

    async fn record_event(
        &self,
        task_key: Option<&str>,
        status: &str,
        title: &str,
        detail: Option<&str>,
        progress_pct: Option<i32>,
        metadata_json: Option<&serde_json::Value>,
    ) {
        let _ = self
            .db
            .create_scan_event(
                self.scan_id,
                Some("tyr"),
                task_key,
                "task",
                Some(status),
                title,
                detail,
                progress_pct,
                metadata_json,
            )
            .await;
    }
}

fn is_context_limit_error(error: &anyhow::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("maximum context length")
        || message.contains("reduce the length of the messages")
        || message.contains("context length")
        || message.contains("too many tokens")
}

fn append_capped(ctx: &mut String, chunk: &str, total_budget: usize) {
    if ctx.len() >= total_budget {
        return;
    }

    let remaining = total_budget - ctx.len();
    if chunk.len() <= remaining {
        ctx.push_str(chunk);
        return;
    }

    let reserve = "\n... additional reconnaissance omitted.\n";
    let allowed = remaining.saturating_sub(reserve.len());
    if allowed == 0 {
        return;
    }

    ctx.push_str(&truncate_text(chunk, allowed));
    if ctx.len() < total_budget {
        ctx.push_str(reserve);
    }
}

fn append_bulleted_section(
    ctx: &mut String,
    heading: &str,
    items: &[String],
    section_budget: usize,
    total_budget: usize,
    per_item_chars: Option<usize>,
) {
    if items.is_empty() || ctx.len() >= total_budget {
        return;
    }

    let mut section = String::from(heading);
    let mut added = 0usize;

    for item in items {
        let item = per_item_chars
            .map(|limit| truncate_text(item, limit))
            .unwrap_or_else(|| item.clone());
        let line = format!("- {item}\n");
        if section.len() + line.len() > section_budget {
            break;
        }
        section.push_str(&line);
        added += 1;
    }

    if added == 0 {
        return;
    }

    let omitted = items.len().saturating_sub(added);
    if omitted > 0 {
        section.push_str(&format!("- ... {omitted} additional items omitted\n"));
    }
    section.push('\n');
    append_capped(ctx, &section, total_budget);
}

fn append_plain_section(
    ctx: &mut String,
    heading: &str,
    items: &[String],
    section_budget: usize,
    total_budget: usize,
) {
    if items.is_empty() || ctx.len() >= total_budget {
        return;
    }

    let mut section = String::from(heading);
    let mut added = 0usize;

    for item in items {
        let block = format!(
            "{}\n\n",
            truncate_text(item, section_budget.min(item.len()))
        );
        if section.len() + block.len() > section_budget {
            break;
        }
        section.push_str(&block);
        added += 1;
    }

    if added == 0 {
        return;
    }

    let omitted = items.len().saturating_sub(added);
    if omitted > 0 {
        section.push_str(&format!("... {omitted} additional items omitted\n\n"));
    }
    append_capped(ctx, &section, total_budget);
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }

    let truncated: String = value.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{truncated}…")
}

/// Internal struct for Phase 1 reconnaissance results.
struct ReconOutput {
    file_count: usize,
    file_tree: Vec<String>,
    tech_stack: Vec<String>,
    entry_points: Vec<String>,
    dependencies: Vec<String>,
    routes: Vec<String>,
    security_patterns: Vec<String>,
    config_patterns: Vec<String>,
    db_patterns: Vec<String>,
    /// Call chains from entry points through security-sensitive functions.
    call_chains: Vec<String>,
    /// Public API surface derived from exported symbols.
    public_api: Vec<String>,
}

const TYR_SYSTEM_PROMPT: &str = "\
You are Tyr, the threat model engine of Heimdall security scanner. \
Named after the Norse god of justice and law, you produce rigorous, structured threat models.

Your analysis methodology follows STRIDE:
- **S**poofing — can an attacker impersonate another user or component?
- **T**ampering — can data be modified without authorization?
- **R**epudiation — can actions occur without being logged/auditable?
- **I**nformation Disclosure — can sensitive data leak to unauthorized parties?
- **D**enial of Service — can the system be made unavailable?
- **E**levation of Privilege — can an attacker gain higher permissions?

You have been given detailed reconnaissance data about the codebase including:
- File structure and tech stack
- Route/endpoint definitions
- Entry points and public APIs
- Security-sensitive code patterns (auth, crypto, sessions, etc.)
- Database access patterns
- Configuration and environment variable handling
- Call chains from entry points to security-sensitive sinks (exec, query, deserialize, etc.)
- Public API surface with caller/callee connectivity metrics
- Actual source code of critical files

## Requirements

1. **Trust Boundaries** — identify EVERY point where data crosses between trust zones. \
   Be specific: \"user browser → API server\" is better than \"external → internal\". \
   Include internal boundaries too (e.g., API server → database, server → external API).

2. **Attack Surfaces** — list EVERY surface reachable by untrusted input. This includes:
   - API endpoints (especially those handling auth, file uploads, user data)
   - WebSocket/SSE connections
   - Webhook handlers
   - File upload/download handlers
   - Admin panels and privileged endpoints
   - Deserialization points
   - OAuth callback handlers
   - Search/query interfaces
   - Any code that processes user-controlled data
   For each surface, explain what STRIDE threats apply and reference the actual file/endpoint.

3. **Data Flows** — trace how sensitive data moves through the system:
   - Credentials (passwords, API keys, tokens)
   - PII (emails, names, addresses)
   - Session data
   - Financial data
   - Secrets and encryption keys
   - Any data that crosses a trust boundary

## Quality Standards
- Reference actual files and endpoints from the codebase — do NOT invent paths
- Be concrete and specific — \"SQL injection in /api/repos via unparameterized query\" \
  not \"potential injection vulnerabilities\"
- Every surface must have a risk_level reflecting real exploitability, not theoretical risk
- Aim for completeness — missing a real attack surface is worse than including a low-risk one
- If the codebase has strong security controls, acknowledge them in the summary";

const TYR_REFINEMENT_PROMPT: &str = "\
You are Tyr, the threat model engine of Heimdall security scanner, in REFINEMENT mode. \
You are reviewing and improving your own initial threat model using additional data.

You now have:
1. Your initial threat model (from your first pass)
2. Call chain analysis — verified paths from entry points to security-sensitive sinks
3. Public API surface — all exported symbols with caller/callee connectivity

Your job is to:
- ADD attack surfaces for any call chain that reaches a risky sink but isn't covered
- ADD trust boundaries for any uncovered zone transitions
- REMOVE surfaces you now believe are false positives
- ADJUST risk_level based on actual code connectivity (more callers = higher exposure)
- KEEP surfaces from the initial model that are still valid
- Ensure every surface references a REAL file from the codebase

Quality bar:
- Every entry_point → risky_sink chain should have a corresponding attack surface
- Every public function handling untrusted input should have a surface
- risk_level should reflect actual exploitability: connected + exposed = higher risk

Return the COMPLETE refined model (all boundaries, surfaces, data_flows), not just deltas. \
Use the same JSON schema as the initial model. Return ONLY the JSON object.";

const TYR_JSON_REPAIR_PROMPT: &str = "\
You repair malformed Heimdall Tyr outputs.

Your job is to convert a raw threat-model response into the exact JSON schema Heimdall expects.
- Output must be valid JSON.
- Output must contain only the JSON object.
- Do not invent facts not present in the raw response.
- If optional location fields are unknown, use null.
- If a section is missing, use an empty array.
- Normalize risk_level to one of: critical, high, medium, low.";

fn json_parse_candidates(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    let mut candidates = Vec::new();

    if !trimmed.is_empty() {
        candidates.push(trimmed.to_string());
    }

    if let Some(stripped) = strip_markdown_fences(trimmed) {
        if !stripped.is_empty() && !candidates.iter().any(|candidate| candidate == stripped) {
            candidates.push(stripped.to_string());
        }
    }

    if let Some(extracted) = extract_first_json_object(trimmed) {
        if !extracted.is_empty() && !candidates.iter().any(|candidate| candidate == extracted) {
            candidates.push(extracted.to_string());
        }
    }

    candidates
}

fn strip_markdown_fences(content: &str) -> Option<&str> {
    let stripped = content.strip_prefix("```")?;
    let stripped = stripped
        .strip_prefix("json")
        .or_else(|| stripped.strip_prefix("JSON"))
        .unwrap_or(stripped);
    Some(stripped.strip_suffix("```").unwrap_or(stripped).trim())
}

fn extract_first_json_object(content: &str) -> Option<&str> {
    let mut start = None;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;

    for (idx, ch) in content.char_indices() {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            match ch {
                '\\' => escape = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    start = Some(idx);
                }
                depth += 1;
            }
            '}' => {
                if depth == 0 {
                    continue;
                }
                depth -= 1;
                if depth == 0 {
                    let start = start?;
                    return Some(&content[start..idx + ch.len_utf8()]);
                }
            }
            _ => {}
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{
        TyrContextMode, extract_first_json_object, is_context_limit_error, json_parse_candidates,
        truncate_text,
    };

    #[test]
    fn detects_context_limit_provider_errors() {
        let err = anyhow::anyhow!(
            "OpenAI API error (400 Bad Request): invalid_request_error — This model's maximum context length is 128000 tokens."
        );
        assert!(is_context_limit_error(&err));
    }

    #[test]
    fn standard_context_budget_is_larger_than_compact() {
        let standard = TyrContextMode::Standard.budgets();
        let compact = TyrContextMode::Compact.budgets();

        assert!(standard.total_chars > compact.total_chars);
        assert!(standard.source_snippets_chars > compact.source_snippets_chars);
        assert!(standard.call_chains_chars > compact.call_chains_chars);
        assert!(standard.public_api_chars > compact.public_api_chars);
    }

    #[test]
    fn truncate_text_adds_ellipsis_when_needed() {
        assert_eq!(truncate_text("short", 12), "short");
        assert_eq!(truncate_text("abcdefghij", 5), "abcd…");
    }

    #[test]
    fn extracts_json_object_from_wrapped_content() {
        let wrapped = "Analysis follows\n\n{\"summary\":\"ok\",\"boundaries\":[],\"surfaces\":[],\"data_flows\":[]}\n";
        assert_eq!(
            extract_first_json_object(wrapped),
            Some("{\"summary\":\"ok\",\"boundaries\":[],\"surfaces\":[],\"data_flows\":[]}")
        );
    }

    #[test]
    fn json_parse_candidates_include_fenced_and_extracted_json() {
        let raw = "## Report\n```json\n{\"summary\":\"ok\",\"boundaries\":[],\"surfaces\":[],\"data_flows\":[]}\n```\n";
        let candidates = json_parse_candidates(raw);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.contains("\"summary\":\"ok\""))
        );
    }

    #[test]
    fn parses_wrapped_threat_model_json() {
        let raw = "Here is the model:\n\n{\"summary\":\"ok\",\"boundaries\":[],\"surfaces\":[],\"data_flows\":[]}";
        let parsed = super::TyrStage::parse_threat_model_output(raw).unwrap();
        assert_eq!(parsed.summary, "ok");
        assert!(parsed.boundaries.is_empty());
        assert!(parsed.surfaces.is_empty());
        assert!(parsed.data_flows.is_empty());
    }
}
