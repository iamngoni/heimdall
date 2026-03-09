# Heimdall — Coding Rules

> Strict conventions for all Rust code in this project. Every contributor and AI agent MUST follow these rules.

## Table of Contents

- [File Headers](#file-headers)
- [Module Structure](#module-structure)
- [Error Handling](#error-handling)
- [Configuration](#configuration)
- [Application State](#application-state)
- [API Responses](#api-responses)
- [Route Handlers](#route-handlers)
- [Middleware](#middleware)
- [Database Operations](#database-operations)
- [Validation](#validation)
- [Logging](#logging)
- [Async Patterns](#async-patterns)
- [Serialization](#serialization)
- [Testing](#testing)
- [Git Conventions](#git-conventions)

---

## File Headers

Every `.rs` file MUST begin with this header:

```rust
//
//  heimdall
//  <module-path>/<filename>
//
//  Created by <author> on <YYYY/MM/DD>.
//  Copyright (c) <YEAR> Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//
```

**Rules:**
- Product name is always `heimdall` (lowercase)
- Module path matches the file's location under `src/` (e.g., `pipeline/ingest/mod.rs`)
- Include the SPDX license identifier exactly as shown in the header template
- No ASCII art, no decorative borders
- Blank line after the header before `use` statements

---

## Module Structure

### Top-level layout

```
src/
├── main.rs              # Entry point, server setup
├── config.rs            # Config struct, from_env()
├── state.rs             # AppState definition
├── logging.rs           # Logger setup
├── db/
│   └── mod.rs           # DatabaseOperations struct
├── models/
│   ├── mod.rs           # Re-exports
│   ├── api_response.rs  # ApiResponse<T>
│   └── typedefs.rs      # Type aliases (HeimdallResult<T>)
├── routes/
│   ├── mod.rs           # pub fn init(cfg) — top-level router
│   ├── health.rs        # Health check
│   ├── pages.rs         # HTMX page routes
│   └── api.rs           # API routes
├── middleware/
│   ├── mod.rs           # Re-exports
│   └── request_context.rs
├── pipeline/
│   ├── mod.rs           # ScanPipeline orchestrator
│   ├── ingest/
│   ├── tyr/
│   ├── hunt/
│   └── garmr/
├── templates/           # Askama/minijinja templates
└── utils/
    └── mod.rs
```

### Module declaration rules

- Declare all modules in `main.rs` with `mod name;`
- Each module directory has a `mod.rs` that re-exports public items
- Route modules export `pub fn init(cfg: &mut ServiceConfig)`
- Keep files under 400 lines; split when they grow beyond that

```rust
// main.rs — module declarations at top
mod config;
mod db;
mod logging;
mod middleware;
mod models;
mod pipeline;
mod routes;
mod state;
mod utils;
```

---

## Error Handling

### Type alias

Define a project-wide result alias in `src/models/typedefs.rs`:

```rust
pub type HeimdallResult<T> = anyhow::Result<T>;
```

### Rules

| Rule | Example |
|------|---------|
| Use `anyhow::Result<T>` everywhere via `HeimdallResult<T>` | `fn foo() -> HeimdallResult<Bar>` |
| Use `.context()` on every fallible call | `.context("Failed to parse config")?` |
| NEVER use `.unwrap()` in production code | Use `?`, `.context()`, or `.unwrap_or()` |
| `.expect()` is allowed ONLY for invariants proven at compile time | `channel.send().expect("receiver alive")` |
| Use `thiserror` for domain error enums when needed | Pipeline stage errors, AI provider errors |
| Return early with `?` — avoid deep nesting | — |

### Context pattern

```rust
use anyhow::Context;

let port = env::var("APP_PORT")
    .context("APP_PORT must be set")?
    .parse::<u16>()
    .context("APP_PORT must be a valid port number")?;
```

### Domain errors (when needed)

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PipelineError {
    #[error("Ingest failed: {0}")]
    Ingest(String),

    #[error("AI provider error: {0}")]
    AiProvider(#[from] anyhow::Error),

    #[error("Sandbox timeout after {seconds}s")]
    SandboxTimeout { seconds: u64 },
}
```

---

## Configuration

### Pattern

```rust
use anyhow::{Context, Result};
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub app: AppConfig,
    pub database: DatabaseConfig,
    pub ai: AiConfig,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub port: u16,
    pub host: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            app: AppConfig::from_env()?,
            database: DatabaseConfig::from_env()?,
            ai: AiConfig::from_env()?,
        })
    }
}

impl AppConfig {
    fn from_env() -> Result<Self> {
        Ok(AppConfig {
            port: env::var("APP_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse::<u16>()
                .context("APP_PORT must be a valid port number")?,
            host: env::var("APP_HOST")
                .unwrap_or_else(|_| "0.0.0.0".to_string()),
        })
    }
}
```

### Rules

| Rule | Detail |
|------|--------|
| All config comes from environment variables | No config files, no YAML, no TOML at runtime |
| Split config into nested structs by domain | `AppConfig`, `DatabaseConfig`, `AiConfig`, etc. |
| Required vars use `.context("VAR must be set")?` | Crash early with a clear message |
| Optional vars use `.unwrap_or_else(\|_\| default)` | Always provide sensible defaults |
| `Config::from_env()` returns `Result<Self>` | Called once in `main()` |
| Load `.env` via `dotenv().ok()` at the top of `main()` | Silent failure is fine — env vars may come from the OS |

---

## Application State

### Pattern

```rust
use std::sync::Arc;

pub struct AppState {
    pub config: Arc<Config>,
    pub db: Arc<DatabaseOperations>,
}

impl AppState {
    pub fn init(config: Config, db: DatabaseOperations) -> Self {
        Self {
            config: Arc::new(config),
            db: Arc::new(db),
        }
    }
}
```

### Rules

| Rule | Detail |
|------|--------|
| One `AppState` struct in `src/state.rs` | Single source of shared application state |
| Wrap expensive/shared fields in `Arc` | Config, DB pools, caches |
| Use `Arc<TokioMutex<T>>` for mutable shared state | Never `std::sync::Mutex` in async code |
| Initialize in `main()`, pass via `web::Data` | `let state = web::Data::new(AppState::init(...));` |
| Constructor is `pub fn init(...)` or `pub async fn new(...)` | `init` for sync, `new` for async initialization |

---

## API Responses

### Pattern

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issues: Option<Vec<String>>,
    pub version: u8,
}

impl<T> ApiResponse<T> {
    pub fn success(message: &str, data: Option<T>) -> Self {
        Self {
            success: true,
            message: Some(message.to_string()),
            data,
            issues: None,
            version: 1,
        }
    }

    pub fn error(message: &str, issues: Vec<String>) -> Self {
        Self {
            success: false,
            message: Some(message.to_string()),
            data: None,
            issues: Some(issues),
            version: 1,
        }
    }
}
```

### Rules

| Rule | Detail |
|------|--------|
| ALL JSON API responses use `ApiResponse<T>` | No raw structs as top-level responses |
| `skip_serializing_if = "Option::is_none"` on optional fields | Clean JSON output |
| Success responses: `HttpResponse::Ok().json(ApiResponse::success(...))` | — |
| Error responses include `issues` array | Machine-readable error list |
| HTMX fragment responses return HTML, not JSON | Only API endpoints use `ApiResponse` |

---

## Route Handlers

### Pattern

```rust
// routes/mod.rs
use actix_web::web::ServiceConfig;

pub mod api;
pub mod health;
pub mod pages;

pub fn init(cfg: &mut ServiceConfig) {
    health::init(cfg);
    pages::init(cfg);
    api::init(cfg);
}

// routes/health.rs
use actix_web::{web, HttpResponse};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health_check));
}

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(ApiResponse::<()>::success("ok", None))
}
```

### Rules

| Rule | Detail |
|------|--------|
| Every route module has `pub fn init(cfg: &mut ServiceConfig)` | Registered in parent `mod.rs` |
| Use `web::scope("/prefix")` for grouped routes | API, auth, pages |
| Handler functions are `async fn` returning `impl Responder` or `HttpResponse` | — |
| Extract `state: Data<AppState>` as first parameter | Then path, query, body params |
| Validate request body immediately after extraction | Before any business logic |
| Use attribute macros (`#[get("/")]`, `#[post("/")]`) OR `.route()` — pick one per module | Don't mix styles |

---

## Middleware

### Pattern

Implement `Transform` + `Service` traits:

```rust
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::Error;
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};

pub struct MyMiddleware;

impl<S, B> Transform<S, ServiceRequest> for MyMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = MyMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(MyMiddlewareService { service }))
    }
}

pub struct MyMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for MyMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}
```

### Rules

| Rule | Detail |
|------|--------|
| Each middleware gets its own file in `src/middleware/` | e.g., `request_context.rs` |
| Store per-request data via `req.extensions_mut().insert(...)` | Use typed structs, not strings |
| Skip health check endpoints in logging/metrics middleware | Check path before processing |
| Middleware order in `App::new()` matters | Applied bottom-to-top (last `.wrap()` runs first) |

---

## Database Operations

### Pattern

```rust
use sqlx::SqlitePool;

pub struct DatabaseOperations {
    pool: SqlitePool,
}

impl DatabaseOperations {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn get_repo_by_id(&self, id: i64) -> HeimdallResult<Option<Repo>> {
        let repo = sqlx::query_as!(
            Repo,
            r#"SELECT id, name, url, source_type as "source_type: _"
               FROM repos WHERE id = ?"#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch repo")?;

        Ok(repo)
    }
}
```

### Rules

| Rule | Detail |
|------|--------|
| All queries go through `DatabaseOperations` struct | No raw pool access in handlers |
| Use `sqlx::query_as!()` macro for compile-time checked queries | Fall back to `query_as::<_, T>()` only when macros don't work |
| Models derive `FromRow`, `Serialize` | `#[derive(Debug, Clone, FromRow, Serialize)]` |
| Use `fetch_optional` for single rows, `fetch_all` for lists | Never `fetch_one` unless existence is guaranteed |
| Add `.context("description")?` after every `.await` on queries | Clear error messages |
| SQLite for v1, Postgres later | Write portable SQL — avoid dialect-specific features |

---

## Validation

### Pattern

```rust
use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateRepoRequest {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,

    #[validate(url(message = "Must be a valid URL"))]
    pub url: String,

    #[validate(nested)]
    pub settings: Option<RepoSettings>,
}
```

### Rules

| Rule | Detail |
|------|--------|
| Use `validator` crate with derive macros | `#[derive(Validate)]` on all request DTOs |
| Validate in handler before business logic | `if let Err(errors) = request.validate() { ... }` |
| Flatten validation errors into `Vec<String>` | Use a `flatten_validation_errors()` utility |
| Return `400 Bad Request` with `ApiResponse::error(...)` on failure | Include flattened errors in `issues` |
| Use `#[validate(nested)]` for nested structs | Validates the entire tree |

---

## Logging

### Rules

| Rule | Detail |
|------|--------|
| Use `log` crate macros (`info!`, `warn!`, `error!`) | Never `println!` except in `main()` startup banner |
| Log at appropriate levels | `error!` = broken, `warn!` = degraded, `info!` = milestones, `debug!` = detail |
| Include context in log messages | `info!("Scan {} moved to stage: {}", scan_id, stage)` |
| Use emoji sparingly in startup logs only | `info!("Database connected 🔗")` — only during boot |
| Never log secrets, tokens, or full request bodies | Redact sensitive fields |

---

## Async Patterns

### Rules

| Rule | Detail |
|------|--------|
| Use `tokio` as the async runtime | Via `#[actix_web::main]` |
| Share mutable state with `Arc<tokio::sync::Mutex<T>>` | NEVER `std::sync::Mutex` in async |
| Use `mpsc` channels for fire-and-forget work | Log shipping, metrics, background tasks |
| Use `tokio::spawn` for concurrent pipeline stages | With `Arc<CodeIndex>` for shared read access |
| Set timeouts on all external calls | AI providers, Docker exec, git clone |
| Use `tokio::select!` for cancellation | Pipeline abort, timeout racing |

---

## Serialization

### Rules

| Rule | Detail |
|------|--------|
| Derive `Serialize, Deserialize` on all data structs | `use serde::{Serialize, Deserialize};` |
| Use `#[serde(skip_serializing_if = "Option::is_none")]` | On all `Option<T>` API fields |
| Use `#[serde(rename_all = "snake_case")]` on enums | Consistent JSON keys |
| DateTime fields use `chrono::DateTime<Utc>` | Serialize as ISO 8601 / RFC 3339 |
| Use `serde_json::json!()` for ad-hoc metadata | Not for structured API responses |

---

## Testing

### Rules

| Rule | Detail |
|------|--------|
| Unit tests go in the same file: `#[cfg(test)] mod tests { ... }` | — |
| Integration tests go in `tests/` directory | Mark with `#[ignore]` if they need external services |
| Test naming: `test_<what>_<condition>_<expected>` | `test_scan_missing_repo_returns_404` |
| Use `#[actix_web::test]` for handler tests | With `actix_web::test::TestRequest` |
| Mock external services (AI, Docker) with traits | Implement mock versions for testing |
| Every public function should have at least one test | Enforced in CI |

---

## Git Conventions

### Commit format

```
<emoji> <type>: <description>
```

| Emoji | Type | Use |
|-------|------|-----|
| ✨ | feat | New feature |
| 🐛 | fix | Bug fix |
| ♻️ | refactor | Code restructure, no behavior change |
| 📦 | deps | Dependency changes |
| 🧪 | test | Adding/fixing tests |
| 📝 | docs | Documentation |
| 🔧 | chore | Config, CI, tooling |
| 🚀 | perf | Performance improvement |
| 🔒 | security | Security fix |

### Rules

| Rule | Detail |
|------|--------|
| One logical change per commit | Don't bundle unrelated changes |
| Imperative mood in description | "Add scan pipeline" not "Added scan pipeline" |
| Keep description under 72 characters | Details go in the body |
| Reference issue numbers when applicable | `✨ feat: Add scan progress SSE (#42)` |

---

## General Rules

| Rule | Detail |
|------|--------|
| `cargo clippy -- -D warnings` must pass | Zero warnings policy |
| `cargo fmt` before every commit | Consistent formatting |
| No `unsafe` without a comment explaining why | And approval in code review |
| Prefer `&str` over `String` in function parameters | Clone only when you need ownership |
| Use `impl Into<String>` for flexible APIs | When callers may pass `&str` or `String` |
| Keep functions under 50 lines | Extract helpers when they grow |
| No magic numbers — use named constants | `const MAX_HUNT_ITERATIONS: u32 = 25;` |
