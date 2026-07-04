# Heimdall

**Agentic, context-aware security scanner for source code repositories.**

Heimdall goes beyond pattern matching: it builds a threat model of your application, deploys an AI agent that reasons about your codebase to discover real vulnerabilities, validates them in a sandboxed environment, and produces ranked findings with patches and proof-of-concept exploits.

> **Why Norse mythology?** In Norse myth, **Heimdall** stands on the Bifrost bridge watching over all Nine Realms — he sees everything and hears the grass grow. That's the vibe: a guardian that observes your entire codebase. The internal components follow the same theme — **Tyr**, the god of justice and law, builds the threat model (he decides what matters). **Garmr**, the blood-stained hound chained at the gates of Hel, guards the boundary between safe and dangerous — he runs untrusted exploit code in sandboxed containers so nothing escapes. And **Vidarr**, the silent god known for patience and deliberation, challenges every finding before it reaches you — if a vulnerability can't survive his scrutiny, it was never real.

![Heimdall — Sign In](assets/images/screenshot.png)

## Table of Contents

- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Current Status](#current-status)
- [Contributing](#contributing)
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
- [Background Worker](#background-worker)
- [Findings](#findings)
- [API Reference](#api-reference)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Deployment](#deployment)
- [MCP Server](#mcp-server)
- [License](#license)

## How It Works

```mermaid
graph LR
    A[Connect Repo] --> B[Run Scan]
    B --> C[9-Stage Pipeline]
    C --> D[View Findings]
    D --> E[Review Patches]
```

1. **Connect a repository** — GitHub OAuth, GitLab OAuth, Bitbucket OAuth/PAT, public git URL, or zip upload
2. **Run a scan** — manually triggered, the pipeline takes over
3. **Review findings** — severity-ranked, with code context, explanations, and suggested diffs
4. **Handle fixes** — open a draft GitHub fix PR with the remediation agent, or manually apply/export the suggested diff and mark it handled in Heimdall

## Quick Start

The fastest way to get running locally:

```bash
# 1. Clone the repo
git clone https://github.com/iamngoni/heimdall.git
cd heimdall

# 2. Start Postgres
docker compose -f docker-compose.dev.yml up -d

# 3. Configure environment
cp .env.example .env
# Edit .env for server-level BYOK, or connect Claude Code/Codex/Grok from Settings after registration.

# 4. Run the server (schema is applied automatically on startup)
cargo run --bin heimdall

# 5. Open http://localhost:8080
```

## Current Status

What Heimdall does today:

- Repository intake via GitHub OAuth, GitLab OAuth, Bitbucket OAuth/PAT, public Git URL, or ZIP upload
- Nine-stage scan pipeline: Ingest, Tyr, Static Analysis, Taint Analysis, Config Scan, Hunt, Víðarr, Garmr, Report
- Background scan worker with configurable polling, stale scan detection, and cancellation support
- Live scan progress via SSE, plus persisted execution and tool-call logs in the database
- Finding review with explain, verify, suggested diffs, fix-PR agent runs, and repository issue creation/linking
- Optional per-repo automatic issue creation for supported GitHub/GitLab/Bitbucket repositories
- Print-ready per-scan HTML reports at `/scans/{id}/report`
- SARIF export for active scan findings at `/api/scans/{id}/sarif`
- BYOK via environment variables or user-scoped keys stored in Settings, plus subscription-backed Claude Code, Codex, and Grok connections from Settings
- AI provider fallback chain (Claude Code > Codex > Grok Subscription > Grok API > Anthropic > OpenAI > OpenAI Compatible > Ollama) with automatic retry on transient errors

What is still missing or intentionally not done yet:

- GitHub App / installation-token repository access is not implemented yet
- GitLab and Bitbucket use the same OAuth user-token model; there is no install-style app flow yet
- OSV-based dependency audit runs inside Static Analysis rather than as a separate pipeline stage
- Browser-level E2E now covers registration plus completed-scan report, findings, and SARIF artifact review; the full `repo import -> scan worker -> issue sync` loop is still limited
- Stage-specific artifact views are still spread across scan, findings, threat model, and patch surfaces rather than one dedicated “stage outputs” screen
- Scheduled rescans and baseline/diff comparisons are planned but not implemented yet

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, required checks, schema update flow, and PR expectations.

## Prerequisites

| Dependency | Version | Required | Purpose |
|-----------|---------|----------|---------|
| **Rust** | 1.85+ (2024 edition) | Yes | Compilation |
| **PostgreSQL** | 14+ | Yes | Primary database |
| **Docker** | 20+ | Recommended | Garmr sandbox (PoC validation) |
| **Git** | 2.25+ | Yes | Repository cloning |
| **AI provider** | — | Yes (at least one) | Claude, OpenAI, OpenAI-compatible endpoint, Grok, or Ollama |

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
git clone https://github.com/iamngoni/heimdall.git
cd heimdall

# Start Postgres (pick one)
docker compose -f docker-compose.dev.yml up -d          # Option A: Docker
createdb heimdall                                         # Option B: Local Postgres

# Configure
cp .env.example .env
```

Edit `.env` with your settings:

```bash
# Host-run Heimdall talking to local or Dockerized Postgres
DATABASE_URL=postgres://heimdall:heimdall@localhost:5432/heimdall

# Server-level AI provider fallback (optional if you connect Claude Code/Codex/Grok from Settings)
ANTHROPIC_API_KEY=sk-ant-...          # Claude (recommended)
# OPENAI_API_KEY=sk-...               # GPT-4o
# OPENAI_COMPATIBLE_BASE_URL=http://localhost:1234/v1 # OpenAI-compatible custom endpoint
# OPENAI_COMPATIBLE_MODEL=custom-model-id              # Required for custom endpoints
# OPENAI_COMPATIBLE_API_KEY=sk-...                    # Optional for endpoints that require auth
# XAI_API_KEY=xai-...                 # Grok / Grok Build API-key path
# OLLAMA_URL=http://localhost:11434    # Local models

# Security (generate these)
ENCRYPTION_KEY=$(openssl rand -hex 32)
```

Build and run:

```bash
# Build the project
cargo build

# Run (schema is applied automatically on startup)
cargo run --bin heimdall
```

The server starts at `http://localhost:8080`.

### Docker

Build and run the full stack with Docker Compose:

```bash
# Copy and configure environment
cp .env.example .env
# For full Docker Compose, keep DATABASE_URL pointed at `postgres`
# and edit .env with your AI provider key(s)

# Start Heimdall + Postgres
docker compose up -d

# Or build from source
docker compose up -d --build
```

The Dockerfile handles migration generation and compilation in a multi-stage build automatically.

#### Docker Compose Profiles

```bash
docker compose up -d                 # Heimdall + PostgreSQL
docker compose --profile mcp up -d   # Optional MCP sidecar
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

Host-run app example: `postgres://heimdall:heimdall@localhost:5432/heimdall`

Full Docker Compose example: `postgres://heimdall:heimdall@postgres:5432/heimdall`

### AI Providers

Set **at least one** environment provider, or connect Claude Code/Codex/Grok Subscription from Settings after registration. When multiple providers are configured, Heimdall chains them in a **fallback provider** — if the primary fails with a retryable error (429 rate limit, 500/502/503 server errors, billing/quota exhaustion, or connection failures), requests automatically fall through to the next configured provider. Default priority order: Claude Code > Codex > Grok Subscription > Grok API > Anthropic > OpenAI > OpenAI Compatible > Ollama.

| Variable | Provider | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Claude | Anthropic API key (`sk-ant-...`) |
| `OPENAI_API_KEY` | OpenAI | OpenAI API key (`sk-...`) |
| `OPENAI_COMPATIBLE_BASE_URL` | OpenAI Compatible | Base URL for the custom endpoint; both `http://host` and `http://host/v1` are accepted |
| `OPENAI_COMPATIBLE_MODEL` | OpenAI Compatible | Required model id exposed by the custom endpoint; Heimdall does not infer this |
| `OPENAI_COMPATIBLE_API_KEY` | OpenAI Compatible | Optional API key for custom endpoints that require auth |
| `XAI_API_KEY` | Grok API | xAI API key (`xai-...`), using `grok-build-0.1` by default; set `grok-4.3` for general Grok |
| `XAI_OAUTH_REDIRECT_URI` | Grok Subscription | Optional hosted OAuth callback, e.g. `https://heimdall.antonlabs.cc/api/settings/xai-oauth/callback`; unset keeps local loopback mode |
| `XAI_OAUTH_CLIENT_ID` | Grok Subscription | Optional xAI OAuth client id; defaults to the bundled loopback client |
| `XAI_OAUTH_CLIENT_SECRET` | Grok Subscription | Optional xAI OAuth client secret for hosted/confidential clients |
| `OLLAMA_URL` | Ollama | Ollama server URL (e.g. `http://localhost:11434`) |
| `DEFAULT_AI_MODEL` | — | Override default model (default: `claude-sonnet-5`) |

Every LLM call records which provider and model was actually used (visible in `agent_tool_calls`), so you always know which provider served each request — especially useful when fallback kicks in.

Users can also add API keys through the Settings UI after registration. The OpenAI Compatible provider stores a custom base URL, explicit model id, and optional API key, and can be selected independently in provider routing. Claude Code connects through a Claude.ai OAuth copy/paste flow and bills compatible Anthropic requests to the user's Claude.ai subscription. Codex connects through OpenAI/ChatGPT OAuth on the fixed local callback path `/auth/callback` served on port `1455` or `1457`; on hosted Heimdall, copy the returned `http://localhost:1455/auth/callback?...` URL from the browser and paste it back into Settings so the server can exchange it against the pending login. Grok Subscription connects through xAI OAuth for SuperGrok / X Premium+; local deployments default to `/callback` on `127.0.0.1:56121`, while hosted deployments should set `XAI_OAUTH_REDIRECT_URI` to the public callback path `/api/settings/xai-oauth/callback` on the Heimdall domain.

#### Settings Login Options

Settings login options are not automatic just because the user is already logged in to ChatGPT, Claude.ai, xAI, or a local model server. Heimdall only marks a provider as connected after the final step below succeeds and the provider shows as Active/Ready in Settings.

| Provider | What the user does | Hosted Heimdall behavior | Connected when |
|----------|--------------------|--------------------------|----------------|
| Claude Code | Click **Connect Claude.ai**, approve in the opened tab, then paste the returned `code#state` value into **Paste code**. | Always paste-back. The browser approval does not call Heimdall directly. | The paste-back exchange succeeds and Settings refreshes. |
| Codex | Click **Connect ChatGPT**, approve in the opened tab, then either let the local callback complete or paste the returned localhost callback URL into **Paste callback URL**. | The browser is expected to land on `http://localhost:1455/auth/callback?...` or `http://localhost:1457/auth/callback?...`. Copy that full URL from the address bar and paste it back into hosted Settings. | The pasted callback URL matches the pending login state and exchanges successfully. |
| Grok Subscription | Click **Connect Grok** and approve the xAI OAuth grant. | If `XAI_OAUTH_REDIRECT_URI` is set, xAI returns to the hosted Heimdall callback. If it is unset, the flow uses the local loopback callback. | The xAI callback returns successfully and the account has OAuth/API entitlement. |
| Anthropic/OpenAI/Grok API | Paste the provider API key in Settings or configure the matching environment variable. | No browser OAuth step. The key is stored per user when saved in Settings, or server-wide when configured in the environment. | The key is saved and the provider appears as Active/Ready. |
| OpenAI Compatible | Enter the base URL, explicit model id, and optional API key. | Heimdall does not discover the model id automatically; the entered model must be supported by the endpoint. | The endpoint details are saved. |
| Ollama | Configure `OLLAMA_URL` for the server. | The Heimdall server must be able to reach the Ollama host; the user's browser location does not matter. | The server has a reachable Ollama URL. |

Copy/paste OAuth values are short lived. If a user waits too long, changes account, or opens the approval flow from a different Heimdall login, the exchange is rejected and they should click Connect again from Settings.

Grok has two distinct providers:

- **Grok Subscription** (`xai_oauth`) — browser OAuth, no `XAI_API_KEY`; default model `grok-build-0.1`; uses SuperGrok or X Premium+ where xAI grants API access to the account.
- **Grok API** (`xai`) — xAI API key via `XAI_API_KEY` or a stored Settings key; default model `grok-build-0.1`.

xAI can still reject OAuth-backed API access with HTTP 403 for accounts that have an in-app subscription but are not entitled on the OAuth/API surface. In that case, use the `XAI_API_KEY` path.

Runtime precedence is:

1. Stored user key from Settings
2. Environment-configured provider

If multiple providers are configured in the environment, Heimdall uses the fallback chain described above.

### OAuth (optional)

For GitHub/GitLab login and repository import.

Current state:

- Repository access is currently OAuth user-token based (GitHub, GitLab, Bitbucket)
- Bitbucket also supports Personal Access Tokens (PATs) via the Settings UI
- GitHub App / install-style repo access is planned, but not implemented yet

| Variable | Description |
|----------|-------------|
| `GITHUB_CLIENT_ID` | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth app client secret |
| `GITHUB_REDIRECT_URI` | Callback URL (default: `http://localhost:8080/api/auth/github/callback`) |
| `GITLAB_CLIENT_ID` | GitLab OAuth app client ID |
| `GITLAB_CLIENT_SECRET` | GitLab OAuth app client secret |
| `GITLAB_REDIRECT_URI` | Callback URL (default: `http://localhost:8080/api/auth/gitlab/callback`) |
| `GITLAB_BASE_URL` | GitLab base URL (default: `https://gitlab.com`) |
| `BITBUCKET_CLIENT_ID` | Bitbucket OAuth consumer key |
| `BITBUCKET_CLIENT_SECRET` | Bitbucket OAuth consumer secret |
| `BITBUCKET_REDIRECT_URI` | Callback URL (default: `http://localhost:8080/api/auth/bitbucket/callback`) |

### Security

| Variable | Description | How to Generate |
|----------|-------------|-----------------|
| `ENCRYPTION_KEY` | 32-byte hex key for AES-256-GCM encryption of stored API keys | `openssl rand -hex 32` |
| `WEBHOOK_SECRET` | Shared secret for GitHub/GitLab webhook signature verification | `openssl rand -hex 20` |

`ENCRYPTION_KEY` should be treated as required outside local development. If it is not set, Heimdall falls back to compatibility decoding/storage behavior for API keys, which is useful for local recovery but not the standard you want in a real deployment.

### Worker

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKER_ENABLED` | `true` | Enable/disable the background scan worker |
| `WORKER_POLL_INTERVAL_SECS` | `5` | How often the worker polls for queued scans |
| `WORKER_STALE_TIMEOUT_MINS` | `10` | Timeout for stale/stuck scans |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info,heimdall=debug` | Log filter ([env_logger syntax](https://docs.rs/env_logger)) |

## Running

### Development

```bash
# Start database
docker compose -f docker-compose.dev.yml up -d

# Run with hot logging (schema applied automatically)
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
docker compose up -d
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
        S["3. Static Analysis\n<i>Pattern matching + secrets</i>"]
        TA["3b. Taint Analysis\n<i>Source → sink tracking</i>"]
        CS["3c. Config Scan\n<i>IaC + config audit</i>"]
        H["4. Hunt\n<i>Agentic discovery</i>"]
        V["4b. Víðarr\n<i>Adversarial verification</i>"]
        G["5. Garmr\n<i>Sandbox validation</i>"]
        R["6. Report\n<i>Rank + patch + explain</i>"]
    end

    I --> T --> S --> TA --> CS --> H --> V --> G --> R

    I -.- i1["tree-sitter AST\nSymbol table\nCall graph\nData flows"]
    T -.- t1["Trust boundaries\nAttack surfaces\nSensitive data flows"]
    S -.- s1["Semgrep-style patterns\nSecret detection\n70+ rules"]
    TA -.- ta1["Taint propagation\nFixed-point iteration\nSource/sink mapping"]
    CS -.- cs1["Dockerfile, K8s, Terraform\nCI/CD, env files\nIaC misconfigurations"]
    H -.- h1["Per-threat AI agents\nMax 25 iterations\nSecurity + logic flaws"]
    V -.- v1["Adversarial challenge\nFalse positive filtering\nSeverity adjustment"]
    G -.- g1["Docker sandbox\nPoC execution\nNo network, 30s timeout"]
    R -.- r1["Severity ranking\nCWE/CVE classification\nUnified diff patches"]
```

> **Note:** OSV-based dependency auditing currently runs as part of **Static Analysis**, not as a standalone pipeline stage.

| Stage | Engine | Purpose | Speed |
|-------|--------|---------|-------|
| **Ingest** | tree-sitter | Clone repo, build code index (AST, symbols, call graph, data flows) | Seconds |
| **Tyr** | LLM | Generate structured threat model (boundaries, surfaces, data flows) | ~30s |
| **Static Analysis** | tree-sitter + regex | Deterministic pattern matching, secret detection, and OSV-based dependency audit coverage | Seconds |
| **Taint Analysis** | Fixed-point iteration | Track tainted data from sources (user input, env) to sinks (exec, SQL, file I/O) | Seconds |
| **Config Scan** | Regex | Audit Dockerfiles, Kubernetes manifests, Terraform, CI/CD configs, env files | Seconds |
| **Hunt** | LLM Agent | Reason about code per-threat, discover security vulns + logic flaws | Minutes |
| **Víðarr** | LLM | Adversarial challenge — tries to disprove each finding, filters false positives | ~15s/finding |
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

Static analysis rules cover: SQL injection, command injection, XSS, hardcoded secrets, path traversal, unsafe deserialization, weak crypto, CSRF, open redirects, and more. Taint analysis tracks data flow from user-controlled sources to dangerous sinks across 6+ languages. Config scanning audits Dockerfiles, Kubernetes manifests, Terraform configs, CI/CD pipelines, and environment files for misconfigurations. The Hunt agent also investigates logic flaws: race conditions, off-by-one errors, state machine violations, business logic bypasses, and concurrency bugs.

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
            FB["FallbackProvider\n<i>Auto-retry chain</i>"]
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
    MP --> FB
    FB --> Claude
    FB --> OpenAI
    FB --> Ollama
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

The first four are investigation tools. `report_finding` is the agent's structured output action.

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

## Background Worker

Heimdall includes a background scan worker that polls for queued scans and executes them automatically. This decouples scan submission from execution and handles recovery from stale/stuck scans.

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKER_ENABLED` | `true` | Enable/disable the background scan worker |
| `WORKER_POLL_INTERVAL_SECS` | `5` | How often the worker polls for queued scans |
| `WORKER_STALE_TIMEOUT_MINS` | `10` | Timeout for stale/stuck scans |

When a scan is triggered via `POST /repos/{id}/scan`, it is queued in the database. The worker picks it up, runs the full pipeline, and updates status in real-time via SSE. Users can cancel running scans via `POST /api/scans/{id}/cancel`, which signals the cancellation token — the pipeline stops gracefully at the next stage boundary.

## Findings

Each finding includes:

- **Severity** — Critical, High, Medium, Low
- **CWE/CVE** classification
- **File + line number** with code context
- **Plain English explanation** of the vulnerability
- **Suggested diff** as a unified diff
- **PoC exploit details** (if sandbox-validated)
- **Source badge** — AI (Hunt agent), Static (pattern rules), Dependencies (audit)
- **Confidence** — High (static rules), Medium (AI-discovered), Confirmed (sandbox-validated)
- **Repository issue linkage** — manual from finding review, plus optional per-repo auto-create with severity/confidence gating when the repository provider supports it
- **Fix PR agent** — for provider-connected GitHub repositories, Heimdall can clone the repo, use the selected per-user AI provider to generate/repair a diff, validate it with `git apply --check` and `git diff --check`, push a branch, and open a draft pull request

## API Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Register a new account |
| `POST` | `/api/auth/login` | Login (returns session cookie) |
| `POST` | `/api/auth/logout` | Logout (clears session) |
| `GET` | `/api/auth/github/authorize` | Start GitHub OAuth flow |
| `GET` | `/api/auth/gitlab/authorize` | Start GitLab OAuth flow |
| `GET` | `/api/auth/bitbucket/authorize` | Start Bitbucket OAuth flow |

### Repositories

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/repos` | Create a repository |
| `GET` | `/api/repos/{id}` | Get repository details |
| `DELETE` | `/api/repos/{id}` | Delete a repository (cascades to scans, findings, etc.) |
| `POST` | `/api/repos/{id}/scan` | Trigger a scan |

### Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/scans/{id}` | Get scan metadata |
| `POST` | `/api/scans/{id}/cancel` | Cancel a running scan |
| `GET` | `/api/scans/{id}/findings` | List findings (supports `?severity=high&status=open&page=1&per_page=25`) |
| `GET` | `/api/scans/{id}/sarif` | Download SARIF 2.1.0 for active findings |
| `GET` | `/api/scans/{id}/threat-model` | Get threat model |
| `GET` | `/api/scans/{id}/patches` | Get generated patches |
| `GET` | `/api/scans/{id}/progress/stream` | SSE stream for real-time progress |

### Findings

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/findings/{id}` | Get finding details |
| `PATCH` | `/api/findings/{id}/severity` | Update severity |
| `GET` | `/api/findings/{id}/remediation` | Render the latest fix-PR agent status panel |
| `POST` | `/api/findings/{id}/remediate` | Start the fix-PR agent for a GitHub-backed finding |
| `POST` | `/api/findings/{id}/apply-patch` | Mark a suggested diff as applied in Heimdall metadata (no repo write-back) |
| `POST` | `/api/findings/{id}/comment` | Add a comment |
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
| AI providers | Claude, OpenAI, OpenAI-compatible, Grok, Ollama (BYOK) plus subscription-backed Claude Code, Codex, and Grok |
| Auth | Argon2id + session cookies + CSRF double-submit cookie |
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
│   │   ├── taint/              # Stage 3b: Taint analysis
│   │   ├── config_scan/        # Stage 3c: IaC + config audit
│   │   ├── hunt/               # Stage 4: Agentic discovery
│   │   ├── vidarr/             # Stage 4b: Adversarial verification
│   │   ├── garmr/              # Stage 5: Sandbox validation
│   │   ├── deps_audit/         # Dependency audit helpers used by Static Analysis
│   │   └── report/             # Stage 6: Patches + ranking
│   ├── worker.rs               # Background scan worker (poll + execute)
│   ├── integrations/
│   │   ├── mod.rs              # Integration hub
│   │   ├── issues.rs           # Issue tracker integration (GitHub, GitLab, Bitbucket)
│   │   └── remediation.rs      # Fix-PR remediation agent (GitHub branch + draft PR)
│   ├── ai/
│   │   ├── mod.rs              # ModelProvider trait + provider builder
│   │   ├── types.rs            # Request/response types
│   │   ├── claude.rs           # Anthropic provider
│   │   ├── openai.rs           # OpenAI provider
│   │   ├── ollama.rs           # Ollama provider
│   │   └── fallback.rs         # FallbackProvider (auto-retry chain)
│   ├── index/
│   │   ├── mod.rs              # CodeIndex (unified)
│   │   ├── symbols.rs          # tree-sitter symbol extraction
│   │   ├── callgraph.rs        # Call graph
│   │   ├── deps.rs             # Dependency graph
│   │   └── search.rs           # Full-text search
│   └── bin/
│       └── schema_gen.rs       # CLI: export schema snapshots / DDL
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

The database schema is defined once in Rust. Heimdall itself runs against PostgreSQL, and the schema definition can also export DDL snapshots for other drivers during development:

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

### Automatic schema at startup

On every startup, Heimdall generates the PostgreSQL DDL from the schema definition and applies it using `IF NOT EXISTS` / `DROP TRIGGER IF EXISTS` statements. No migration files or tracking tables needed — this is safe to run repeatedly.

### Generating migration files (optional)

For external tooling, CI, or manual review you can still export SQL snapshots:

```bash
cargo run --bin schema_gen -- postgres   # migrations/active/
cargo run --bin schema_gen -- sqlite     # migrations/sqlite/
cargo run --bin schema_gen -- mysql      # migrations/mysql/
cargo run --bin schema_gen -- all        # all drivers
```

Those extra driver outputs are developer tooling only. The shipped app, Docker stack, and MCP server currently support PostgreSQL as the runtime database.

The schema DSL also supports **smart incremental migrations** — it snapshots the current schema and diffs against it on the next run, generating only `ALTER TABLE` / `CREATE INDEX` / etc. for what changed.

The schema definition in `src/db/schema/definition.rs` is the source of truth.

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

# Security/dependency audit
cargo audit

# Frontend dependency and bundle check
npm ci
npm audit --audit-level=high
npm run build:css
git diff --exit-code -- static/css/app.css

# Browser E2E smoke (requires DATABASE_URL and Chromium)
npm run test:e2e
```

The unit tests cover symbol extraction (all 6 languages), static analysis rules, taint analysis, call graph construction, dependency resolution, full-text search, password hashing, AES-256-GCM encryption, SSE broadcasting, pagination, and API response formatting.

## Deployment

### Single machine (recommended for getting started)

```bash
# Build release binary
cargo build --release

# Run (ensure .env is configured — schema applied automatically)
./target/release/heimdall
```

### Docker Compose (production)

```bash
# Configure
cp .env.example .env
# Edit .env

# Start
docker compose up -d

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
- **Claude Code** — Claude.ai subscription OAuth tokens, default first choice when connected in Settings
- **Codex** — ChatGPT/OpenAI subscription OAuth tokens, second in the default fallback order
- **Grok Subscription** — SuperGrok / X Premium+ OAuth tokens, default Grok path when connected in Settings
- **Grok API** — xAI API key for Grok and Grok Build
- **Claude** (Anthropic) — native tool_use format through an Anthropic API key
- **OpenAI** — function calling/Responses API format
- **OpenAI Compatible** — custom `/v1/chat/completions` endpoint with base URL, explicit model id, and optional API key from Settings or env vars
- **Ollama** — local inference, no API key required (Llama 3.3, Mistral, etc.)

**Automatic fallback:** When multiple providers are configured, Heimdall chains them via `FallbackProvider`. If the primary provider fails with a retryable error (HTTP 429/500/502/503/529, billing/quota errors, or connection failures), the request is automatically retried with the next provider. Non-retryable errors (401, invalid request) propagate immediately.

**Model tracking:** Every LLM call records the actual `provider` and `model` used in the `agent_tool_calls` table, providing full observability into which provider served each request.

**BYOK:** Users bring their own API keys. Keys are encrypted at rest with AES-256-GCM when `ENCRYPTION_KEY` is configured.

## MCP Server

Heimdall ships as an [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server, allowing AI coding tools like Claude Code, Cursor, Windsurf, and other MCP-compatible clients to interact with Heimdall directly from the editor.

### Setup

The MCP server runs as a separate binary (`heimdall-mcp`) that connects to the same PostgreSQL database. It supports two transport modes:

- **stdio** (default and recommended) — for local development, communicates over stdin/stdout
- **HTTP** (optional) — serves over authenticated Streamable HTTP for clients that cannot spawn the binary directly

#### Local (stdio)

```bash
# Build the MCP server
cargo build --release --bin heimdall-mcp
```

Add to your MCP client configuration (e.g., Claude Code `~/.claude.json`, Cursor settings):

```json
{
  "mcpServers": {
    "heimdall": {
      "type": "stdio",
      "command": "/path/to/heimdall-mcp",
      "args": [],
      "env": {
        "DATABASE_URL": "postgres://heimdall:heimdall@localhost:5432/heimdall",
        "MCP_DEFAULT_USER_ID": "<optional-user-uuid>"
      }
    }
  }
}
```

#### Docker (HTTP)

```bash
# Start with MCP profile
docker compose --profile mcp up -d
```

The MCP server listens on port `45637` (configurable via `MCP_PORT`). HTTP transport is protected with OAuth 2.1 style authorization code + PKCE. Heimdall exposes OAuth discovery metadata from the MCP server itself, so clients that support MCP OAuth can register dynamically and launch the browser sign-in flow.

```json
{
  "mcpServers": {
    "heimdall": {
      "type": "http",
      "url": "http://127.0.0.1:45637/mcp"
    }
  }
}
```

Some clients use a slightly different HTTP field name, such as `serverUrl`, or a different transport label, such as `streamableHttp`.

For HTTP MCP, the OAuth access token determines the Heimdall user. Tool calls no longer need `user_id`; if a client sends one, it must match the authenticated OAuth user. `MCP_DEFAULT_USER_ID` is only a local stdio fallback.

If the MCP server is published behind a proxy or non-local hostname, set `MCP_PUBLIC_BASE_URL` to the externally reachable MCP origin and `APP_PUBLIC_BASE_URL` to the web app origin used for sign-in redirects.

### Client Setup Guide

Heimdall works best over `stdio`. Use HTTP when your MCP client supports OAuth discovery and browser authorization.

#### Quick Reference

| Client | Config location | Recommended transport | Notes |
|------|------|------|------|
| Claude Code | `~/.claude.json` or project `.mcp.json` | `stdio` | Use HTTP when the client supports MCP OAuth |
| Cursor | `~/.cursor/mcp.json` or project `.cursor/mcp.json` | `stdio` | Supports project-scoped MCP config |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `stdio` | Remote HTTP needs MCP OAuth support |
| Cline | Configure from the Cline MCP panel | `stdio` | Use remote HTTP when OAuth discovery is supported |
| Continue | `.continue/mcpServers/*.json` | `stdio` | MCP is available in Agent mode |
| Gemini CLI | `~/.gemini/settings.json` or project `.gemini/settings.json` | `stdio` | Remote HTTP needs MCP OAuth support |

#### Claude Code

OAuth HTTP, if you need remote transport:

```json
{
  "mcpServers": {
    "heimdall": {
      "type": "http",
      "url": "http://127.0.0.1:45637/mcp"
    }
  }
}
```

Local stdio:

```json
{
  "mcpServers": {
    "heimdall": {
      "type": "stdio",
      "command": "/absolute/path/to/heimdall-mcp",
      "args": [],
      "env": {
        "DATABASE_URL": "postgres://heimdall:heimdall@localhost:5432/heimdall"
      }
    }
  }
}
```

#### Cursor

Put the config in either `~/.cursor/mcp.json` for a global server or `<project-root>/.cursor/mcp.json` for a project-local server.

HTTP:

```json
{
  "mcpServers": {
    "heimdall": {
      "url": "http://127.0.0.1:45637/mcp"
    }
  }
}
```

stdio:

```json
{
  "mcpServers": {
    "heimdall": {
      "type": "stdio",
      "command": "/absolute/path/to/heimdall-mcp",
      "args": [],
      "env": {
        "DATABASE_URL": "postgres://heimdall:heimdall@localhost:5432/heimdall"
      }
    }
  }
}
```

#### Windsurf

Windsurf stores MCP servers in `~/.codeium/windsurf/mcp_config.json`.

HTTP:

```json
{
  "mcpServers": {
    "heimdall": {
      "serverUrl": "http://127.0.0.1:45637/mcp"
    }
  }
}
```

stdio:

```json
{
  "mcpServers": {
    "heimdall": {
      "command": "/absolute/path/to/heimdall-mcp",
      "args": [],
      "env": {
        "DATABASE_URL": "postgres://heimdall:heimdall@localhost:5432/heimdall"
      }
    }
  }
}
```

#### Cline

The most reliable setup path in Cline is the MCP UI:

1. Open the Cline panel.
2. Open `MCP Servers`.
3. Add a new remote server.
4. Set the name to `heimdall`.
5. Set the URL to `http://127.0.0.1:45637/mcp`.
6. Choose `Streamable HTTP` as the transport.
7. Complete the browser OAuth sign-in when the client prompts for authorization.

Raw remote config:

```json
{
  "mcpServers": {
    "heimdall": {
      "url": "http://127.0.0.1:45637/mcp",
      "type": "streamableHttp"
    }
  }
}
```

Local stdio:

```json
{
  "mcpServers": {
    "heimdall": {
      "command": "/absolute/path/to/heimdall-mcp",
      "args": [],
      "env": {
        "DATABASE_URL": "postgres://heimdall:heimdall@localhost:5432/heimdall"
      }
    }
  }
}
```

#### Continue

Continue reads MCP server definitions from `<project-root>/.continue/mcpServers/`.

Create `<project-root>/.continue/mcpServers/heimdall.json`:

```json
{
  "mcpServers": {
    "heimdall": {
      "type": "http",
      "url": "http://127.0.0.1:45637/mcp"
    }
  }
}
```

stdio:

```json
{
  "mcpServers": {
    "heimdall": {
      "type": "stdio",
      "command": "/absolute/path/to/heimdall-mcp",
      "args": [],
      "env": {
        "DATABASE_URL": "postgres://heimdall:heimdall@localhost:5432/heimdall"
      }
    }
  }
}
```

Continue currently uses MCP only in Agent mode.

#### Gemini CLI

OAuth HTTP, if you need remote transport:

```json
{
  "mcpServers": {
    "heimdall": {
      "url": "http://127.0.0.1:45637/mcp",
      "type": "http"
    }
  }
}
```

Add Heimdall over stdio:

```bash
gemini mcp add -s user -e DATABASE_URL=postgres://heimdall:heimdall@localhost:5432/heimdall heimdall /absolute/path/to/heimdall-mcp
```

Manual stdio config:

```json
{
  "mcpServers": {
    "heimdall": {
      "command": "/absolute/path/to/heimdall-mcp",
      "args": [],
      "env": {
        "DATABASE_URL": "postgres://heimdall:heimdall@localhost:5432/heimdall"
      }
    }
  }
}
```

#### Troubleshooting

- If Claude Code or Gemini CLI reports a schema error for Heimdall over HTTP, add an explicit `"type": "http"` and make sure the client supports MCP OAuth.
- If Windsurf does not pick up the server, use `serverUrl` instead of `url`.
- If Cline cannot connect, make sure the transport is `Streamable HTTP`, not SSE.
- If Continue does not expose the tools, switch to Agent mode.
- If the MCP server is running in Docker but the client is on another machine, replace `127.0.0.1` with the host machine's reachable IP or DNS name.
- If bare `curl` requests to `http://127.0.0.1:45637/mcp` return `401` with `WWW-Authenticate`, the OAuth protected-resource gate is working. A healthy authenticated request still returns `400` unless it speaks MCP correctly.
- For stdio setups, make sure `DATABASE_URL` points to the same Heimdall database the web app uses.

### Available Tools

| Tool | Description |
|------|-------------|
| `list_repositories` | List all connected repositories |
| `add_repository` | Import a repository by URL |
| `get_repository` | Get repository details by ID |
| `delete_repository` | Delete a repository |
| `trigger_scan` | Trigger a new security scan (runs async, poll with `get_scan_status`) |
| `list_scans` | List scan history for a repository |
| `get_scan_status` | Check scan progress and finding counts |
| `cancel_scan` | Cancel a running or queued scan |
| `list_scan_events` | Inspect the full scan audit trail |
| `get_scan_progress_stream` | Get the live scan snapshot plus the SSE endpoint |
| `list_findings` | Query findings with severity/status filters and pagination |
| `get_finding` | Get full finding details (code, patch, reasoning, PoC status) |
| `explain_finding` | Generate an AI explanation for a finding |
| `verify_finding` | Run AI verification review for a finding |
| `list_finding_events` | Get finding event history |
| `comment_on_finding` | Add a note to a finding |
| `apply_patch` | Mark the latest suggested diff as applied in Heimdall metadata |
| `create_fix_pr` | Start the fix-PR remediation agent for a GitHub-backed finding |
| `get_fix_pr_status` | Get the latest fix-PR agent run for a finding |
| `get_threat_model` | Get the STRIDE threat model (boundaries, surfaces, data flows) |
| `update_threat_model` | Update a threat model field |
| `get_patches` | Get all suggested diffs for a scan as unified patches |
| `update_finding_status` | Update finding status (open, confirmed, dismissed, false_positive, fixed) |
| `update_finding_severity` | Update finding severity |
| `create_issue` | Push a finding to GitHub, GitLab, or Bitbucket issues |
| `create_all_issues` | Bulk-create grouped issues for open findings in a scan |
| `list_agent_tool_calls` | Inspect the AI tool calls recorded for a scan |
| `manage_api_keys` | Create, list, or delete stored AI provider keys |
| `test_connection` | Verify provider connectivity with a short completion |

## Naming

| Name | Role |
|------|------|
| **Heimdall** | The product. The all-seeing guardian. |
| **Tyr** | Threat model engine. Norse god of justice. |
| **Víðarr** | Adversarial verification. The silent god who judges with deliberation. |
| **Garmr** | Sandbox validator. Hound guarding the gates of Hel. |

## License

Heimdall is licensed under the [Functional Source License, Version 1.1, MIT Future License (FSL-1.1-MIT)](LICENSE).

**What this means:**

- **Read, use, modify, self-host** — you can freely use Heimdall to scan your own codebases, self-host it for your organization, and modify it however you like.
- **No competing use** — you may not offer Heimdall (or a substantially similar derivative) as a commercial product or hosted service to others.
- **Converts to MIT** — two years after each version is released, that version automatically converts to the fully permissive MIT license with no restrictions.

See [LICENSE](LICENSE) for the full terms, or visit [fsl.software](https://fsl.software/) for more about the FSL.

---

Built by [Codecraft Solutions ZA](https://codecraftsolutions.co.za)
