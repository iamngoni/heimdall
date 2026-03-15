//
//  heimdall
//  src/pipeline/tyr/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use log::info;
use serde::{Deserialize, Serialize};

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, Message};
use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::HeimdallResult;

/// Tyr: The threat model engine. Analyses the codebase to identify
/// attack surfaces, trust boundaries, data flows, and risk ratings.
pub struct TyrStage {
    pub scan_id: uuid::Uuid,
    pub repo_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
    pub ai: Arc<dyn ModelProvider>,
    pub default_model: String,
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
                "Found {} files, {} entry points, {} dependencies, {} routes, {} security-sensitive patterns.",
                recon.file_count, recon.entry_points.len(), recon.dependencies.len(),
                recon.routes.len(), recon.security_patterns.len()
            )),
            Some(30),
            Some(&serde_json::json!({
                "file_count": recon.file_count,
                "entry_points": recon.entry_points.len(),
                "dependencies": recon.dependencies.len(),
                "routes": recon.routes.len(),
                "security_patterns": recon.security_patterns.len(),
            })),
        )
        .await;

        // Phase 2: Build rich context for the LLM
        let context = self.build_llm_context(index, &recon);

        self.record_event(
            Some("threat-model-request"),
            "running",
            "Generating threat model",
            Some("Tyr is reasoning about trust boundaries, attack surfaces, and sensitive data flows using STRIDE methodology."),
            None,
            Some(&serde_json::json!({
                "model": self.default_model,
                "context_chars": context.len(),
            })),
        )
        .await;

        // Phase 3: LLM analysis
        let start = std::time::Instant::now();
        let request = CompletionRequest {
            model: self.default_model.clone(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: TYR_SYSTEM_PROMPT.to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: context,
                },
            ],
            tools: None,
            max_tokens: Some(8192),
            temperature: Some(0.2),
        };

        let response = self.ai.complete(request).await?;
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
                Some(response.usage.prompt_tokens as i32),
                Some(response.usage.completion_tokens as i32),
                Some(response.usage.total_tokens as i32),
                Some(duration.as_millis() as i32),
                None,
            )
            .await;

        // Parse the structured response
        let content = response.content.trim();
        let json_str = if content.starts_with("```") {
            content
                .trim_start_matches("```json")
                .trim_start_matches("```")
                .trim_end_matches("```")
                .trim()
        } else {
            content
        };

        let threat_model: ThreatModelOutput = serde_json::from_str(json_str).map_err(|e| {
            anyhow::anyhow!("Failed to parse Tyr threat model response: {e}\nRaw: {json_str}")
        })?;

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
                "duration_ms": duration.as_millis() as i32,
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

    fn build_llm_context(&self, index: &CodeIndex, recon: &ReconOutput) -> String {
        let mut ctx = String::new();

        // 1. Codebase overview
        ctx.push_str(&format!(
            "Analyze the following codebase and generate a comprehensive threat model.\n\n\
             ## Codebase Overview\n\
             - **Files:** {}\n\
             - **Tech Stack:** {}\n\n",
            recon.file_count,
            if recon.tech_stack.is_empty() {
                "Unknown".to_string()
            } else {
                recon.tech_stack.join(", ")
            },
        ));

        // 2. File tree (truncated)
        ctx.push_str("## File Structure\n");
        for (i, path) in recon.file_tree.iter().enumerate() {
            if ctx.len() > 8000 {
                ctx.push_str(&format!(
                    "... and {} more files\n",
                    recon.file_tree.len() - i
                ));
                break;
            }
            ctx.push_str(&format!("- {path}\n"));
        }
        ctx.push('\n');

        // 3. Entry points
        if !recon.entry_points.is_empty() {
            ctx.push_str("## Entry Points\n");
            for ep in &recon.entry_points {
                ctx.push_str(&format!("- {ep}\n"));
            }
            ctx.push('\n');
        }

        // 4. Route/endpoint definitions
        if !recon.routes.is_empty() {
            ctx.push_str("## Routes / API Endpoints\n");
            for route in &recon.routes {
                ctx.push_str(&format!("- {route}\n"));
            }
            ctx.push('\n');
        }

        // 5. Dependencies
        if !recon.dependencies.is_empty() {
            ctx.push_str("## Dependencies (from manifests)\n");
            for dep in &recon.dependencies {
                ctx.push_str(dep);
                ctx.push('\n');
            }
            ctx.push('\n');
        }

        // 6. Security-sensitive patterns
        if !recon.security_patterns.is_empty() {
            ctx.push_str("## Security-Sensitive Code Patterns\n");
            for pattern in &recon.security_patterns {
                ctx.push_str(pattern);
                ctx.push('\n');
            }
            ctx.push('\n');
        }

        // 7. Database access patterns
        if !recon.db_patterns.is_empty() {
            ctx.push_str("## Database Access Patterns\n");
            for pattern in &recon.db_patterns {
                ctx.push_str(pattern);
                ctx.push('\n');
            }
            ctx.push('\n');
        }

        // 8. Config/environment patterns
        if !recon.config_patterns.is_empty() {
            ctx.push_str("## Configuration / Environment\n");
            for pattern in &recon.config_patterns {
                ctx.push_str(pattern);
                ctx.push('\n');
            }
            ctx.push('\n');
        }

        // 9. Key source files — include actual content of critical files
        ctx.push_str("## Key Source Files (selected content)\n");
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

        let mut included_bytes = 0usize;
        let max_source_bytes = 24000;

        // Sort files by security relevance
        let mut scored_files: Vec<(&str, &crate::index::IndexedFile, usize)> = index
            .files
            .iter()
            .filter(|(_, f)| f.language.is_some())
            .map(|(path, file)| {
                let lower = path.to_ascii_lowercase();
                let score = critical_file_patterns
                    .iter()
                    .filter(|p| lower.contains(**p))
                    .count();
                (path.as_str(), file, score)
            })
            .filter(|(_, _, score)| *score > 0)
            .collect();
        scored_files.sort_by(|a, b| b.2.cmp(&a.2));

        for (path, file, _) in scored_files {
            if included_bytes >= max_source_bytes {
                break;
            }
            let content_len = file
                .content
                .len()
                .min(max_source_bytes - included_bytes)
                .min(4000);
            let snippet: String = file.content.chars().take(content_len).collect();
            ctx.push_str(&format!("\n### {path}\n```\n{snippet}\n```\n"));
            included_bytes += content_len;
        }

        // 10. Output schema
        ctx.push_str(&format!(
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
        ));

        ctx
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
