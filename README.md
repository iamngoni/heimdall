# Heimdall

**Agentic, context-aware security scanner for source code repositories.**

Heimdall goes beyond pattern matching: it builds a threat model of your application, deploys an AI agent that reasons about your codebase to discover real vulnerabilities, validates them in a sandboxed environment, and produces ranked findings with patches and proof-of-concept exploits.

## Table of Contents

- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Local Development](#local-development)
  - [Docker](#docker)
- [Configuration](#configuration)
- [Running](#running)
- [Scan Pipeline](#scan-pipeline)
- [Architecture](#architecture)
- [The Hunt Agent](#the-hunt-agent)
- [Garmr Sandbox](#garmr-sandbox)
- [Findings](#findings)
- [API Reference](#api-reference)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Deployment](#deployment)
- [License](#license)

## How It Works

```mermaid
graph LR
    A[Connect Repo] --> B[Run Scan]
    B --> C[6-Stage Pipeline]
    C --> D[View Findings]
    D --> E[Apply Patches]
```

1. **Connect a repository** — GitHub OAuth, GitLab OAuth, public git URL, or zip upload
2. **Run a scan** — manually triggered, the pipeline takes over
3. **Review findings** — severity-ranked, with code context, explanations, and patches
4. **Apply fixes** — accept suggested patches as unified diffs

## Quick Start

The fastest way to get running locally:

```bash
# 1. Clone the repo
git clone https://github.com/modestnerd/heimdall.git
cd heimdall

# 2. Start Postgres
docker compose -f docker-compose.dev.yml up -d

# 3. Configure environment
cp .env.example .env
# Edit .env — set at least one AI provider key (ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_URL)

# 4. Generate database migrations
cargo run --bin schema_gen -- postgres

# 5. Run the server
cargo run --bin heimdall

# 6. Open http://localhost:8080
```

## Prerequisites

| Dependency | Version | Required | Purpose |
|-----------|---------|----------|---------|
| **Rust** | 1.85+ (2024 edition) | Yes | Compilation |
| **PostgreSQL** | 14+ | Yes | Primary database |
| **Docker** | 20+ | Recommended | Garmr sandbox (PoC validation) |
| **Git** | 2.25+ | Yes | Repository cloning |
| **AI API Key** | — | Yes (at least one) | Claude, OpenAI, or Ollama |

### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
```

### Install PostgreSQL

**macOS:**
```bash
brew install postgresql@17
brew services start postgresql@17
```

**Ubuntu/Debian:**
```bash
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
```

**Or use Docker** (recommended for dev):
```bash
docker compose -f docker-compose.dev.yml up -d
```

### Install Docker (optional, for Garmr sandbox)

Garmr executes proof-of-concept exploits in isolated Docker containers. Without Docker, scans still work — sandbox validation is skipped gracefully.

**macOS:** Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)

**Linux:**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

## Installation

### Local Development

```bash
# Clone
git clone https://github.com/modestnerd/heimdall.git
cd heimdall

# Start Postgres (pick one)
docker compose -f docker-compose.dev.yml up -d          # Option A: Docker
createdb heimdall                                         # Option B: Local Postgres

# Configure
cp .env.example .env
```

Edit `.env` with your settings:

```bash
# Required
DATABASE_URL=postgres://heimdall:heimdall@localhost:5432/heimdall

# At least one AI provider (BYOK)
ANTHROPIC_API_KEY=sk-ant-...          # Claude (recommended)
# OPENAI_API_KEY=sk-...               # GPT-4o
# OLLAMA_URL=http://localhost:11434    # Local models

# Security (generate these)
ENCRYPTION_KEY=$(openssl rand -hex 32)
```

Generate migrations and build:

```bash
# Generate the database schema migration
cargo run --bin schema_gen -- postgres

# Build the project
cargo build

# Run
cargo run --bin heimdall
```

The server starts at `http://localhost:8080`.

### Docker

Build and run the full stack with Docker Compose:

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your AI provider key(s)

# Start Heimdall + Postgres
docker compose --profile postgres up -d

# Or build from source
docker compose --profile postgres up -d --build
```

The Dockerfile handles migration generation and compilation in a multi-stage build automatically.

#### Docker Compose Profiles

```bash
docker compose --profile postgres up -d   # PostgreSQL (default, recommended)
docker compose --profile mysql up -d      # MySQL 8.4
docker compose --profile mongo up -d      # MongoDB 7
```

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and customize:

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_HOST` | `0.0.0.0` | Bind address |
| `APP_PORT` | `8080` | Listen port |
| `TLS_ENABLED` | `false` | Enable TLS (set `true` only if not behind a reverse proxy) |
| `CORS_ALLOWED_ORIGIN` | `http://localhost:8080` | CORS allowed origin |

### Database

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |

Example: `postgres://heimdall:heimdall@localhost:5432/heimdall`

### AI Providers (BYOK)

Set **at least one**. Heimdall selects the first available in this order: Anthropic > OpenAI > Ollama.

| Variable | Provider | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Claude | Anthropic API key (`sk-ant-...`) |
| `OPENAI_API_KEY` | OpenAI | OpenAI API key (`sk-...`) |
| `OLLAMA_URL` | Ollama | Ollama server URL (e.g. `http://localhost:11434`) |
| `DEFAULT_AI_MODEL` | — | Override default model (default: `claude-sonnet-4-20250514`) |

Users can also add API keys through the Settings UI after registration.

### OAuth (optional)

For GitHub/GitLab login and repository import:

| Variable | Description |
|----------|-------------|
| `GITHUB_CLIENT_ID` | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth app client secret |
| `GITHUB_REDIRECT_URI` | Callback URL (default: `http://localhost:8080/api/auth/github/callback`) |
| `GITLAB_CLIENT_ID` | GitLab OAuth app client ID |
| `GITLAB_CLIENT_SECRET` | GitLab OAuth app client secret |
| `GITLAB_REDIRECT_URI` | Callback URL (default: `http://localhost:8080/api/auth/gitlab/callback`) |
| `GITLAB_BASE_URL` | GitLab base URL (default: `https://gitlab.com`) |

### Security

| Variable | Description | How to Generate |
|----------|-------------|-----------------|
| `ENCRYPTION_KEY` | 32-byte hex key for AES-256-GCM encryption of stored API keys | `openssl rand -hex 32` |
| `WEBHOOK_SECRET` | Shared secret for GitHub/GitLab webhook signature verification | `openssl rand -hex 20` |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info,heimdall=debug` | Log filter ([env_logger syntax](https://docs.rs/env_logger)) |

## Running

### Development

```bash
# Start database
docker compose -f docker-compose.dev.yml up -d

# Generate migrations (only needed once, or after schema changes)
cargo run --bin schema_gen -- postgres

# Run with hot logging
RUST_LOG=debug cargo run --bin heimdall
```

### Production

```bash
# Build optimized binary
cargo build --release

# Run
./target/release/heimdall
```

Or via Docker:

```bash
docker compose --profile postgres up -d
```

### Verify it's running

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

Open `http://localhost:8080` in your browser. Register an account, add a repository, and trigger a scan.

## Scan Pipeline

```mermaid
flowchart TD
    subgraph Pipeline["Scan Pipeline"]
        direction TB
        I["1. Ingest\n<i>Clone + AST parse</i>"]
        T["2. Tyr\n<i>Threat modeling</i>"]
        S["3. Static Analysis\n<i>Pattern matching + secrets + deps</i>"]
        H["4. Hunt\n<i>Agentic discovery</i>"]
        G["5. Garmr\n<i>Sandbox validation</i>"]
        R["6. Report\n<i>Rank + patch + explain</i>"]
    end

    I --> T --> S --> H --> G --> R

    I -.- i1["tree-sitter AST\nSymbol table\nCall graph\nData flows"]
    T -.- t1["Trust boundaries\nAttack surfaces\nSensitive data flows"]
    S -.- s1["Semgrep-style patterns\nSecret detection\nDependency audit\nTaint analysis"]
    H -.- h1["Per-threat AI agents\nMax 25 iterations\nTool-assisted reasoning"]
    G -.- g1["Docker sandbox\nPoC execution\nNo network, 30s timeout"]
    R -.- r1["Severity ranking\nCWE/CVE classification\nUnified diff patches"]
```

| Stage | Engine | Purpose | Speed |
|-------|--------|---------|-------|
| **Ingest** | tree-sitter | Clone repo, build code index (AST, symbols, call graph, data flows) | Seconds |
| **Tyr** | LLM | Generate structured threat model (boundaries, surfaces, data flows) | ~30s |
| **Static Analysis** | tree-sitter + regex | Deterministic pattern matching, secret detection, dependency audit | Seconds |
| **Hunt** | LLM Agent | Reason about code per-threat, discover real vulnerabilities | Minutes |
| **Garmr** | Docker + LLM | Execute PoC exploits in sandboxed containers to confirm findings | ~30s/finding |
| **Report** | LLM | Rank findings, generate patches as unified diffs, explain in plain English | ~30s |

### Supported Languages

Tree-sitter AST parsing (full symbol extraction, call graphs):

| Language | Grammar | Status |
|----------|---------|--------|
| Rust | tree-sitter-rust | Full |
| Python | tree-sitter-python | Full |
| JavaScript | tree-sitter-javascript | Full |
| TypeScript | tree-sitter-typescript | Full |
| Go | tree-sitter-go | Full |
| Java | tree-sitter-java | Full |
| Ruby | regex fallback | Basic |
| PHP | regex fallback | Basic |

Static analysis rules cover: SQL injection, command injection, XSS, hardcoded secrets, path traversal, unsafe deserialization, weak crypto, CSRF, open redirects, and more.

## Architecture

```mermaid
graph TB
    subgraph Client["Browser"]
        HTMX["HTMX + Tailwind"]
    end

    subgraph Server["Heimdall Server"]
        AW["Actix-web"]
        TPL["Templates\n<i>minijinja</i>"]
        SSE["SSE\n<i>Scan progress</i>"]

        subgraph Core["Core"]
            Pipeline["ScanPipeline"]
            Hunt["Hunt Agent"]
            Garmr["Garmr Sandbox"]
            CodeIndex["CodeIndex\n<i>tree-sitter</i>"]
        end

        subgraph AI["AI Backend"]
            MP["ModelProvider trait"]
            Claude["ClaudeProvider"]
            OpenAI["OpenAiProvider"]
            Ollama["OllamaProvider"]
        end
    end

    subgraph Storage["Storage"]
        PG["PostgreSQL"]
        FS["Filesystem\n<i>Cloned repos</i>"]
    end

    subgraph External["External"]
        Docker["Docker\n<i>Garmr containers</i>"]
        GH["GitHub / GitLab\n<i>OAuth + clone</i>"]
    end

    HTMX <-->|HTML fragments| AW
    AW --> TPL
    AW --> SSE
    AW --> Pipeline
    Pipeline --> CodeIndex
    Pipeline --> Hunt
    Pipeline --> Garmr
    Hunt --> MP
    Garmr --> Docker
    MP --> Claude
    MP --> OpenAI
    MP --> Ollama
    Pipeline --> PG
    Pipeline --> FS
    AW --> GH
```

## The Hunt Agent

The Hunt agent is an agentic loop — not a pattern matcher. It reasons about code the way a security researcher does.

```mermaid
stateDiagram-v2
    [*] --> Planning
    Planning --> AwaitingLlm

    AwaitingLlm --> ExecutingTool: Tool call requested
    ExecutingTool --> AwaitingLlm: Return tool result

    AwaitingLlm --> ReportingFinding: Vulnerability found
    ReportingFinding --> AwaitingLlm: Continue investigating

    AwaitingLlm --> Completed: Done or limit reached
    Completed --> [*]
```

**Available tools:**

| Tool | Purpose |
|------|---------|
| `read_file` | Read file contents (15KB truncation for LLM context) |
| `search_code` | Regex search across codebase (30 results max) |
| `get_callers` | Find all call sites of a symbol |
| `get_dependencies` | Get dependency graph for a file |
| `report_finding` | Report a discovered vulnerability |

Each threat/attack surface spawns a parallel investigation (via `tokio::spawn`). Max 25 LLM iterations per investigation.

## Garmr Sandbox

```mermaid
sequenceDiagram
    participant H as Hunt
    participant G as Garmr
    participant L as LLM
    participant D as Docker

    H->>G: Finding (vuln type, file, code)
    G->>L: Generate PoC exploit
    L-->>G: PoC script
    G->>D: Create container (no net, 1 CPU, 512MB, 30s)
    G->>D: Mount repo read-only + PoC script
    G->>D: Execute PoC
    D-->>G: stdout, stderr, exit code
    G->>L: Interpret results
    L-->>G: Confirmed / Unconfirmed / Inconclusive
    G-->>H: Updated finding with PoC results
```

**Container constraints:** No network, 1 CPU, 512MB RAM, 30s timeout, non-root, repo mounted read-only.

If Docker is not available, Garmr is skipped gracefully — findings are still reported but without sandbox validation.

## Findings

Each finding includes:

- **Severity** — Critical, High, Medium, Low
- **CWE/CVE** classification
- **File + line number** with code context
- **Plain English explanation** of the vulnerability
- **Suggested patch** as a unified diff
- **PoC exploit details** (if sandbox-validated)
- **Source badge** — AI (Hunt agent), Static (pattern rules), Dependencies (audit)
- **Confidence** — High (static rules), Medium (AI-discovered), Confirmed (sandbox-validated)

## API Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Register a new account |
| `POST` | `/api/auth/login` | Login (returns session cookie) |
| `POST` | `/api/auth/logout` | Logout (clears session) |
| `GET` | `/api/auth/github/authorize` | Start GitHub OAuth flow |
| `GET` | `/api/auth/gitlab/authorize` | Start GitLab OAuth flow |

### Repositories

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/repos` | Create a repository |
| `GET` | `/api/repos/{id}` | Get repository details |
| `POST` | `/api/repos/{id}/scan` | Trigger a scan |

### Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/scans/{id}` | Get scan metadata |
| `GET` | `/api/scans/{id}/findings` | List findings (supports `?severity=high&status=open&page=1&per_page=25`) |
| `GET` | `/api/scans/{id}/threat-model` | Get threat model |
| `GET` | `/api/scans/{id}/patches` | Get generated patches |
| `GET` | `/api/scans/{id}/progress/stream` | SSE stream for real-time progress |

### Findings

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/findings/{id}` | Get finding details |
| `PATCH` | `/api/findings/{id}/severity` | Update severity |
| `POST` | `/api/findings/{id}/apply-patch` | Apply suggested patch |
| `POST` | `/api/findings/{id}/comments` | Add a comment |
| `GET` | `/api/findings/{id}/events` | Get finding event history |

### Settings

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/settings` | Get AI provider status |
| `PATCH` | `/api/settings/profile` | Update display name |
| `POST` | `/api/settings/change-password` | Change password |
| `POST` | `/api/settings/api-keys` | Store an API key |
| `DELETE` | `/api/settings/api-keys/{id}` | Delete an API key |
| `POST` | `/api/settings/test-connection` | Test an AI provider connection |

### Webhooks

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/webhooks/github` | GitHub push webhook (HMAC-SHA256 verified) |
| `POST` | `/webhooks/gitlab` | GitLab push webhook (token verified) |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Rust (2024 edition) |
| Web framework | Actix-web 4 |
| Frontend | HTMX + Tailwind CSS |
| Templates | minijinja |
| Database | PostgreSQL |
| AST parsing | tree-sitter (Rust, Python, JS, TS, Go, Java) |
| Docker SDK | bollard |
| AI providers | Claude, OpenAI, Ollama (BYOK) |
| Auth | Argon2id + session cookies + CSRF double-submit |
| Encryption | AES-256-GCM (stored API keys) |
| Async runtime | Tokio |

## Data Model

```mermaid
erDiagram
    users ||--o{ repos : owns
    users ||--o{ api_keys : has
    users ||--o{ sessions : has
    repos ||--o{ scans : has
    scans ||--o{ scan_stages : tracks
    scans ||--o{ findings : produces
    scans ||--o{ threat_models : generates
    scans ||--o{ file_snapshots : indexes
    findings ||--o{ patches : has
    findings ||--o{ finding_events : has
    scans ||--o{ agent_tool_calls : logged_by
```

## Project Structure

```
heimdall/
├── src/
│   ├── main.rs                 # Entry point, server startup
│   ├── lib.rs                  # Crate root (public modules)
│   ├── config.rs               # Environment configuration
│   ├── state.rs                # AppState (shared across handlers)
│   ├── auth/                   # Password hashing, session tokens
│   ├── crypto.rs               # AES-256-GCM encrypt/decrypt
│   ├── sse.rs                  # Server-Sent Events broadcaster
│   ├── db/
│   │   ├── mod.rs              # Database operations (all queries)
│   │   └── schema/             # Schema DSL + migration generators
│   ├── models/                 # Domain types, API response wrappers
│   ├── routes/
│   │   ├── mod.rs              # Route registration
│   │   ├── pages.rs            # HTML page handlers
│   │   ├── auth.rs             # Login, register, OAuth
│   │   ├── repos.rs            # Repository CRUD + scan trigger
│   │   ├── scans.rs            # Scan queries + SSE stream
│   │   ├── findings.rs         # Finding CRUD + events
│   │   ├── settings.rs         # User settings + API key management
│   │   └── webhooks.rs         # GitHub/GitLab webhook handlers
│   ├── middleware/
│   │   ├── auth.rs             # Session auth middleware
│   │   └── csrf.rs             # CSRF double-submit cookie
│   ├── pipeline/
│   │   ├── mod.rs              # ScanPipeline orchestrator
│   │   ├── ingest/             # Stage 1: Clone + index
│   │   ├── tyr/                # Stage 2: Threat modeling
│   │   ├── static_analysis/    # Stage 3: Pattern rules
│   │   ├── hunt/               # Stage 4: Agentic discovery
│   │   ├── garmr/              # Stage 5: Sandbox validation
│   │   └── report/             # Stage 6: Patches + ranking
│   ├── ai/
│   │   ├── mod.rs              # ModelProvider trait
│   │   ├── types.rs            # Request/response types
│   │   ├── claude.rs           # Anthropic provider
│   │   ├── openai.rs           # OpenAI provider
│   │   └── ollama.rs           # Ollama provider
│   ├── index/
│   │   ├── mod.rs              # CodeIndex (unified)
│   │   ├── symbols.rs          # tree-sitter symbol extraction
│   │   ├── callgraph.rs        # Call graph
│   │   ├── deps.rs             # Dependency graph
│   │   └── search.rs           # Full-text search
│   └── bin/
│       └── schema_gen.rs       # CLI: generate migrations
├── templates/
│   ├── base.html               # Master layout
│   ├── pages/                  # Full page templates
│   └── partials/               # Reusable components
├── migrations/
│   └── active/                 # Applied migrations (generated)
├── tests/                      # Integration tests
├── docs/
│   └── SPEC.md                 # Full product specification
├── Cargo.toml
├── Dockerfile
├── docker-compose.yml          # Production stack
├── docker-compose.dev.yml      # Dev database only
└── .env.example                # Configuration template
```

## Schema DSL

The database schema is defined once in Rust and generates migrations for any supported driver:

```rust
Schema::new()
    .extension("pgcrypto")
    .table("users", |t| {
        t.uuid_pk("id");
        t.text("email").unique().not_null();
        t.text("role").not_null().default_str("'user'");
        t.timestamps();
        t.soft_delete();
    })
    .index("idx_users_email", "users", &["email"])
    .build()
```

Generate migrations:

```bash
cargo run --bin schema_gen -- postgres   # migrations/active/ (applied at startup)
cargo run --bin schema_gen -- sqlite     # migrations/sqlite/
cargo run --bin schema_gen -- mysql      # migrations/mysql/
cargo run --bin schema_gen -- all        # all drivers
```

Migrations are generated artifacts — the schema definition in `src/db/schema/definition.rs` is the source of truth.

## Testing

```bash
# Run all unit tests (no database required)
cargo test --lib

# Run with verbose output
cargo test --lib -- --nocapture

# Run specific test module
cargo test --lib index::symbols
cargo test --lib pipeline::static_analysis
cargo test --lib crypto
cargo test --lib auth

# Run integration tests (requires DATABASE_URL)
cargo test --test '*'
```

The test suite covers: symbol extraction (all 6 languages), static analysis rules, call graph construction, dependency resolution, full-text search, password hashing, AES-256-GCM encryption, SSE broadcasting, pagination, and API response formatting.

## Deployment

### Single machine (recommended for getting started)

```bash
# Build release binary
cargo build --release

# Generate migrations
./target/release/schema_gen postgres

# Run (ensure .env is configured)
./target/release/heimdall
```

### Docker Compose (production)

```bash
# Configure
cp .env.example .env
# Edit .env

# Start
docker compose --profile postgres up -d

# View logs
docker compose logs -f heimdall
```

### Reverse proxy (Nginx)

```nginx
server {
    listen 443 ssl;
    server_name heimdall.example.com;

    ssl_certificate /etc/ssl/certs/heimdall.pem;
    ssl_certificate_key /etc/ssl/private/heimdall.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # SSE requires no buffering
    location /api/scans/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
    }
}
```

### Webhook setup

**GitHub:**
1. Go to your repo Settings > Webhooks > Add webhook
2. Payload URL: `https://heimdall.example.com/webhooks/github`
3. Content type: `application/json`
4. Secret: same value as `WEBHOOK_SECRET` in your `.env`
5. Events: select "Just the push event"

**GitLab:**
1. Go to your project Settings > Webhooks
2. URL: `https://heimdall.example.com/webhooks/gitlab`
3. Secret token: same value as `WEBHOOK_SECRET`
4. Trigger: Push events

## AI Backend

Heimdall is model-agnostic via the `ModelProvider` trait:

```rust
#[async_trait]
pub trait ModelProvider: Send + Sync {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse>;
    fn provider_name(&self) -> &str;
}
```

**Supported providers:**
- **Claude** (Anthropic) — native tool_use format, recommended
- **OpenAI** — function calling format (GPT-4o, GPT-4o mini)
- **Ollama** — local inference, no API key required (Llama, Mistral, etc.)

**BYOK:** Users bring their own API keys. Keys are encrypted at rest with AES-256-GCM when `ENCRYPTION_KEY` is configured.

## Naming

| Name | Role |
|------|------|
| **Heimdall** | The product. The all-seeing guardian. |
| **Tyr** | Threat model engine. Norse god of justice. |
| **Garmr** | Sandbox validator. Hound guarding the gates of Hel. |

## License

[Functional Source License (FSL)](https://fsl.software/) — open and readable. Self-host with your own AI keys. Converts to fully open-source after a defined period. Commercial use requires a commercial license.

---

Built by [ModestNerd Co.](https://codecraftsolutions.co.za)
