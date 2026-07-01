# Heimdall -- Comprehensive Product Specification

## 1. Vision & Identity

### What Heimdall Is

Heimdall is an agentic, context-aware security scanner for source code repositories. Inspired by OpenAI Codex Security, it goes beyond pattern matching: it builds a threat model of the target application, then deploys an AI agent that reasons about the codebase to discover real vulnerabilities, validates them in a sandboxed environment, and produces ranked findings with patches and proof-of-concept exploits.

### Naming

| Name | Role |
|------|------|
| **Heimdall** | The product. The all-seeing guardian. The user-facing name, the binary, the brand. |
| **Tyr** | The threat model engine. Named for the Norse god of justice and law. Tyr analyzes the codebase and produces a structured threat model that guides the Hunt agent. |
| **Garmr** | The sandbox validator. Named for the hound that guards the gates of Hel. Garmr executes proof-of-concept exploits in Docker isolation to confirm or reject findings. |

### License

Functional Source License (FSL). The code is open and readable. Users can self-host with their own AI keys (BYOK). The FSL converts to a fully open-source license after a defined period. Commercial use (SaaS, managed hosting) requires a commercial license.

### Target Users

- Individual developers scanning their own projects
- Small teams wanting security review without a dedicated security engineer
- Security teams augmenting manual review with agentic scanning
- Self-hosters running the OSS version with their own LLM API keys
- SaaS customers on the managed hosted platform

---

## 2. How It Works

End-to-end flow, from the user clicking "Run Scan" to viewing findings:

1. **User connects a repository.** They authenticate via GitHub OAuth, GitLab OAuth, paste a public git URL, or upload a zip file. The repo metadata is stored in the `repos` table.

2. **User clicks "Run Scan."** Scans are triggered manually. The system creates a `scans` row (status: `queued`) and enqueues a `scan_jobs` row (status: `pending`).

3. **The job queue picks up the scan.** A worker claims the job (status: `claimed` then `running`). The `ScanPipeline` orchestrator begins executing stages sequentially.

4. **Stage 1 -- Ingest.** The repo is cloned into an isolated working directory. Tree-sitter parses every file to build a code index: AST summaries, a symbol table, a call graph, a dependency graph, entry points, authentication boundaries, and data flow paths. File snapshots are recorded with content hashes for incremental scan support. Scan status moves: `queued` -> `ingesting` -> `ingested`.

5. **Stage 2 -- Tyr (Threat Modeling).** The code index is fed to the LLM with a structured prompt. Tyr produces an editable threat model: what the application does, its trust boundaries, its attack surfaces, and its sensitive data flows. The threat model is stored as a combination of summary text and structured JSON blobs. Status: `ingested` -> `modeling` -> `modeled`.

6. **Stage 3 -- Hunt (Agentic Discovery).** Each threat/attack surface from the Tyr output spawns a parallel investigation. The Hunt agent enters its state machine loop: it plans an investigation, calls the LLM, executes code analysis tools (read_file, search_code, get_callers, get_dependencies), feeds results back to the LLM, and iterates until it either reports a finding or exhausts its iteration budget (max 25 per threat). Multiple threats are investigated concurrently via `tokio::spawn` with `Arc<CodeIndex>`. Status: `modeled` -> `hunting` -> `hunted`.

7. **Stage 4 -- Garmr (Sandbox Validation).** Each finding from Hunt is passed to the LLM to generate a proof-of-concept exploit script. Garmr executes the PoC inside a Docker container with no network access, 1 CPU, 512MB RAM, and a 30-second timeout. The repo is mounted read-only. The LLM then interprets the execution results: confirmed findings are marked `poc_validated = true`; unconfirmed findings are marked as lower confidence. Status: `hunted` -> `validating` -> `validated`.

8. **Stage 5 -- Report.** Findings are ranked by severity and confidence. The LLM generates suggested diffs as unified patches. Each finding gets a plain English explanation, CWE/CVE classification, affected file and line number, and the PoC exploit details. Status: `validated` -> `reporting` -> `completed`.

9. **User views results.** The scan progress screen shows real-time updates via Server-Sent Events. Once complete, the user navigates to the findings list (filterable by severity, status, CWE) and can drill into each finding to see the explanation, code context, PoC details, and suggested diff. They can accept/reject/dismiss findings, start the fix-PR agent for supported GitHub repositories, export or manually apply the suggested diff outside Heimdall, mark it handled in Heimdall, and edit the threat model for future scans.

---

## 3. The Scan Pipeline

### Overview

The pipeline is a sequential chain of nine stages. Each stage is a distinct module in `src/pipeline/`. The `ScanPipeline` orchestrator runs them in order, updating the scan status and creating `scan_stages` rows to log execution.

### Stage 1: Ingest (`pipeline/ingest/`)

**Purpose:** Acquire the source code and build a rich code index.

**Inputs:** Repo metadata (source type, URL/path, credentials)

**Process:**
- Clone the repo (or extract zip) into a working directory
- Identify the commit SHA and record it on the scan
- Walk all files; for each file:
  - Compute content hash (SHA-256)
  - Detect language
  - Parse with tree-sitter to produce AST summary
  - Extract symbols (functions, classes, methods, exports)
  - Extract imports and dependency references
  - Store as a `file_snapshots` row
- Build the in-memory `CodeIndex`:
  - Symbol table (name -> location)
  - Call graph (caller -> callee relationships)
  - Dependency graph (file/module -> dependencies)
  - Entry point detection (main functions, route handlers, exported APIs)
  - Authentication boundary detection (auth middleware, login handlers)
  - Data flow paths (user input -> database/output)

**Outputs:** Populated `CodeIndex` (in-memory), `file_snapshots` rows in DB

**For incremental scans:**
- Run `git diff --name-status base..head` to identify changed files
- Only re-parse changed and added files
- Carry forward `file_snapshots` for unchanged files by content hash match

### Stage 2: Tyr -- Threat Model (`pipeline/tyr/`)

**Purpose:** Generate a structured, editable threat model that guides the Hunt agent.

**Inputs:** `CodeIndex`, repo metadata

**Process:**
- Construct a prompt containing: file tree, entry points, auth boundaries, data flows, dependency list
- Send to LLM via `ModelProvider`
- Parse structured response into threat model components

**Outputs:** A `threat_models` row containing:
- `summary`: Human-readable overview of what the application does
- `boundaries_json`: Trust boundaries (e.g., "public internet -> API server -> database")
- `surfaces_json`: Attack surfaces (e.g., "unauthenticated POST /api/login", "file upload endpoint")
- `data_flows_json`: Sensitive data flows (e.g., "user password -> bcrypt hash -> users table")

**User interaction:** The threat model is viewable and editable in the UI. Users can add, remove, or modify boundaries, surfaces, and flows. Edits persist and guide subsequent scans.

### Stage 3: Static Analysis (`pipeline/static_analysis/`)

**Purpose:** Fast, deterministic vulnerability detection before invoking AI agents. Catches low-hanging fruit — known vulnerability patterns, secrets, dependency issues — so the Hunt agent can focus on complex, logic-level vulnerabilities.

**Inputs:** `CodeIndex`, file snapshots, dependency manifests

**Process:**
- **Pattern matching:** Run tree-sitter-based queries for known vulnerability patterns (SQL injection templates, hardcoded credentials, unsafe deserialization, etc.) using a rule set inspired by Semgrep/CodeQL patterns
- **Secret detection:** Scan for API keys, tokens, private keys, connection strings using entropy analysis and regex patterns (e.g., `AKIA[0-9A-Z]{16}`, high-entropy base64 strings near keywords like `secret`, `key`, `token`)
- **Dependency audit:** Parse `Cargo.lock`, `package-lock.json`, `requirements.txt`, `go.sum`, etc. Cross-reference against known vulnerability databases (RustSec, OSV, NVD)
- **OWASP pattern checks:** Detect common anti-patterns per language — missing CSRF tokens, insecure cookie flags, open redirects, path traversal patterns, command injection sinks
- **Taint analysis (basic):** Use the CodeIndex call graph to trace user input sources to dangerous sinks (SQL queries, shell commands, file system operations) without LLM involvement

**Outputs:**
- `findings` rows with `source = 'static'` — these are deterministic, high-confidence results that skip AI validation
- A `static_analysis_context` summary passed to the Hunt agent, containing:
  - Known issues already found (so Hunt doesn't rediscover them)
  - Suspicious patterns that warrant deeper AI investigation
  - Dependency risk profile

**Key principle:** Static analysis is fast (~seconds), deterministic, and free (no LLM tokens). It provides immediate value and gives the Hunt agent a head start by pre-mapping the attack surface with concrete findings.

### Stage 4: Hunt -- Agentic Discovery (`pipeline/hunt/`)

**Purpose:** Discover real vulnerabilities by reasoning about the codebase, guided by the threat model.

**Inputs:** `CodeIndex`, threat model, `ModelProvider`

**Process:** See Section 4 (The Hunt Agent) for full detail.

**Outputs:** `findings` rows (unvalidated, `poc_validated = false`)

### Stage 5: Garmr -- Sandbox Validation (`pipeline/garmr/`)

**Purpose:** Validate findings by executing proof-of-concept exploits in isolation.

**Inputs:** Findings from Hunt, `CodeIndex`, `ModelProvider`

**Process:** See Section 6 (Sandbox Validation) for full detail.

**Outputs:** Updated `findings` rows with PoC results, `poc_validated` flag, `poc_exploit` JSON

### Stage 6: Report (`pipeline/report/`)

**Purpose:** Rank findings, generate patches, produce the final report.

**Inputs:** Validated findings, `CodeIndex`, `ModelProvider`

**Process:**
- Rank findings by severity (critical > high > medium > low) and confidence
- For each finding, generate a suggested diff:
  - Send the vulnerable code context to the LLM
  - Request a unified diff that fixes the vulnerability
  - Validate that the diff applies cleanly to the source
  - Store as `patches` rows
- Generate plain English explanations for each finding
- Classify with CWE identifiers; map to CVE where applicable
- Update scan status to `completed`

**Outputs:** Final `findings` with patches, explanations, and classifications

Suggested report-stage patches are not repository write-back. Repository write-back is handled by remediation runs: the fix-PR agent clones the connected GitHub repository, asks the selected user AI provider to generate or repair a minimal unified diff, validates the diff with Git, commits and pushes a branch, and opens a draft pull request.

---

## 4. The Hunt Agent

### Overview

The Hunt agent is an agentic loop that investigates potential vulnerabilities. It is not a pattern matcher. It reasons about code the way a security researcher does: forming hypotheses, reading code, tracing call chains, and building evidence.

### Parallel Investigation

Each attack surface / threat from the Tyr output is investigated independently and concurrently. Implementation uses `tokio::spawn` with `Arc<CodeIndex>` shared across all investigation tasks. Each task runs its own agent state machine instance.

### Agent State Machine

```
Planning -> AwaitingLlm -> ExecutingTool -> AwaitingLlm (loop)
                        -> ReportingFinding -> AwaitingLlm (loop)
                        -> Completed
```

**States:**

| State | Description |
|-------|-------------|
| `Planning` | Initial state. The agent receives the threat/attack surface description and the code index summary. It formulates an investigation plan. Transitions to `AwaitingLlm`. |
| `AwaitingLlm` | The agent has sent a message (plan, tool result, or finding report) to the LLM and is waiting for a response. The LLM response determines the next transition. |
| `ExecutingTool` | The LLM has requested a tool call. The agent executes the tool against the `CodeIndex` and transitions back to `AwaitingLlm` with the tool result. |
| `ReportingFinding` | The LLM has identified a vulnerability with sufficient evidence. The agent creates a `findings` row and transitions back to `AwaitingLlm` to continue investigating (there may be more vulnerabilities in the same attack surface). |
| `Completed` | The LLM has indicated investigation is complete, or the iteration limit (25) has been reached. |

### Iteration Bounds

- **Max 25 iterations per threat/attack surface.** One iteration = one LLM call + optional tool execution.
- If the limit is reached, the agent transitions to `Completed` regardless of LLM output.
- The iteration count is tracked per investigation task and logged in `agent_tool_calls`.

### Tools Available to the Hunt Agent

| Tool | Description | Input | Output |
|------|-------------|-------|--------|
| `read_file` | Read the contents of a specific file | `file_path: String` | File contents as string |
| `search_code` | Search across the codebase using text/regex patterns | `query: String, file_glob: Option<String>` | List of matches with file, line, and context |
| `get_callers` | Find all call sites of a given function/method | `symbol: String` | List of caller locations with context |
| `get_dependencies` | Get the dependency graph for a file or module | `file_path: String` | List of dependencies (imports, requires) and dependents |

### Tool Call Logging

Every tool call is recorded in `agent_tool_calls` with: tool name, input parameters, output, token usage, duration in milliseconds, and the associated scan/stage.

### Investigation Flow Example

1. Agent receives: "Investigate SQL injection risk in the user search endpoint at `src/routes/users.rs:45`"
2. `Planning`: Agent formulates a plan to trace user input through the search handler
3. `AwaitingLlm` -> LLM requests `read_file("src/routes/users.rs")`
4. `ExecutingTool`: Agent reads the file, returns contents
5. `AwaitingLlm` -> LLM sees a raw string interpolation in a SQL query, requests `get_callers("build_search_query")`
6. `ExecutingTool`: Agent returns callers
7. `AwaitingLlm` -> LLM confirms the input flows from HTTP request to SQL without sanitization
8. `ReportingFinding`: Agent creates a finding (SQL injection, CWE-89, high severity, with file/line/snippet)
9. `AwaitingLlm` -> LLM continues to check for additional injection points
10. `AwaitingLlm` -> LLM says "investigation complete"
11. `Completed`

---

## 5. AI Backend

### ModelProvider Trait

```rust
#[async_trait]
pub trait ModelProvider: Send + Sync {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse>;
}
```

**Key characteristics:**
- `Send + Sync` -- required for sharing via `Arc` across tokio tasks
- First-class tool call support: `CompletionRequest` includes tool definitions; `CompletionResponse` includes tool call requests
- Token usage tracking: every response includes prompt tokens, completion tokens, and total tokens
- No streaming -- the agent loop operates on complete responses

### CompletionRequest

- `messages: Vec<Message>` -- conversation history (system, user, assistant, tool_result roles)
- `tools: Vec<ToolDefinition>` -- available tools with name, description, JSON schema for parameters
- `temperature: f32`
- `max_tokens: u32`

### CompletionResponse

- `content: Option<String>` -- text response
- `tool_calls: Vec<ToolCall>` -- requested tool executions (name + arguments as JSON)
- `usage: TokenUsage` -- prompt_tokens, completion_tokens, total_tokens
- `model: String` -- which model was used
- `stop_reason: StopReason` -- end_turn, tool_use, max_tokens

### Supported Providers

| Provider | Implementation | Auth |
|----------|---------------|------|
| **Claude** (Anthropic) | `ClaudeProvider` -- HTTP client to Anthropic API. Maps tool definitions to Claude's native tool_use format. | API key (BYOK or managed) |
| **OpenAI** | `OpenAiProvider` -- HTTP client to OpenAI API. Maps tool definitions to OpenAI's function calling format. | API key (BYOK or managed) |
| **Ollama** | `OllamaProvider` -- HTTP client to local Ollama server. Maps tool definitions to Ollama's tool call format. | No auth (local) |

### BYOK (Bring Your Own Key)

- Users store their LLM API keys in the `api_keys` table
- Keys are encrypted at rest (`encrypted_key` column) with a server-side encryption key
- A `key_hash` column allows lookup without decryption
- The `key_type` field distinguishes between LLM provider keys and Heimdall API keys
- Provider is specified in the `provider` field (anthropic, openai, ollama)

### Token Tracking

- Every LLM call logs token usage in `agent_tool_calls`
- Aggregated per scan, per stage, per organization
- Enables cost estimation and billing for SaaS

---

## 6. Sandbox Validation (Garmr)

### Purpose

Garmr eliminates false positives by executing proof-of-concept exploits in a sandboxed Docker container. A finding that cannot be demonstrated is downgraded in confidence.

### Architecture

- Uses **bollard** (Docker SDK for Rust) to manage containers programmatically
- Each validation runs in a fresh, isolated container

### Validation Flow

1. Receive a finding from Hunt (vulnerability type, file, line, code context)
2. Send finding details to LLM with prompt: "Generate a minimal proof-of-concept exploit script that demonstrates this vulnerability"
3. LLM produces a PoC script (Python, shell, or language-appropriate)
4. Create a Docker container with:
   - The repo source mounted read-only at `/repo`
   - The PoC script written to `/poc/exploit.sh` (or `.py`)
   - Appropriate runtime installed (Python, Node, etc.)
5. Execute the PoC inside the container
6. Capture stdout, stderr, and exit code
7. Send execution results back to the LLM: "Did this PoC successfully demonstrate the vulnerability? Analyze the output."
8. LLM interprets results and returns a verdict: confirmed/unconfirmed/inconclusive
9. Update the finding: set `poc_validated`, store PoC details in `poc_exploit` JSON field

### Docker Container Constraints

| Constraint | Value | Reason |
|------------|-------|--------|
| Network | `--network=none` | No outbound connections. PoCs must work locally. |
| CPU | 1 core | Prevent resource abuse |
| Memory | 512 MB | Prevent resource abuse |
| Timeout | 30 seconds | Kill long-running exploits |
| Filesystem | Repo mounted read-only | Prevent tampering with source |
| Privileges | Non-root, no capabilities | Minimal attack surface |

### PoC Exploit JSON Schema

Stored in `findings.poc_exploit`:
```json
{
  "script": "string -- the PoC script content",
  "language": "string -- python/bash/node/etc",
  "exit_code": "integer",
  "stdout": "string",
  "stderr": "string",
  "verdict": "confirmed | unconfirmed | inconclusive",
  "llm_analysis": "string -- LLM interpretation of results"
}
```

---

## 7. Data Model

### Design Principles

- **UUIDv7 primary keys**: TEXT in SQLite, UUID in Postgres. UUIDv7 is time-ordered for efficient B-tree indexing.
- **ISO 8601 TEXT timestamps**: All `created_at`, `updated_at`, `deleted_at` fields.
- **JSON blobs for complex nested data** that is read as a whole (threat model sections, PoC details, AST summaries).
- **Normalized columns for frequently filtered/queried fields** (severity, status, scan_id).
- **Soft deletes** via `deleted_at` column where applicable.

### Table Schemas (16 tables)

#### 1. users

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| email | TEXT | UNIQUE, NOT NULL |
| password_hash | TEXT | NOT NULL, argon2 |
| display_name | TEXT | |
| avatar_url | TEXT | |
| role | TEXT | "admin" or "user" |
| created_at | TEXT | ISO 8601 |
| updated_at | TEXT | ISO 8601 |
| deleted_at | TEXT | nullable, soft delete |

#### 2. organizations

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| name | TEXT | NOT NULL |
| slug | TEXT | UNIQUE, NOT NULL, URL-safe |
| plan | TEXT | "free", "team", "enterprise" |
| created_at | TEXT | ISO 8601 |
| updated_at | TEXT | ISO 8601 |
| deleted_at | TEXT | nullable |

#### 3. org_members

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| org_id | TEXT | FK -> organizations.id, NOT NULL |
| user_id | TEXT | FK -> users.id, NOT NULL |
| role | TEXT | "owner", "admin", "member" |
| created_at | TEXT | ISO 8601 |

UNIQUE constraint on (org_id, user_id).

#### 4. sessions

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| user_id | TEXT | FK -> users.id, NOT NULL |
| token_hash | TEXT | NOT NULL, SHA-256 of session token |
| ip_address | TEXT | |
| user_agent | TEXT | |
| expires_at | TEXT | ISO 8601, NOT NULL |
| created_at | TEXT | ISO 8601 |

#### 5. oauth_connections

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| user_id | TEXT | FK -> users.id, NOT NULL |
| provider | TEXT | "github" or "gitlab" |
| provider_user_id | TEXT | NOT NULL |
| access_token_enc | TEXT | encrypted at rest |
| refresh_token_enc | TEXT | encrypted at rest, nullable |
| scopes | TEXT | comma-separated |
| expires_at | TEXT | ISO 8601, nullable |
| created_at | TEXT | ISO 8601 |
| updated_at | TEXT | ISO 8601 |

UNIQUE constraint on (user_id, provider).

#### 6. api_keys

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| user_id | TEXT | FK -> users.id, NOT NULL |
| org_id | TEXT | FK -> organizations.id, nullable |
| key_type | TEXT | "llm_provider" or "heimdall_api" |
| provider | TEXT | "anthropic", "openai", "ollama", nullable (null for heimdall_api) |
| label | TEXT | user-defined label |
| key_hash | TEXT | SHA-256 hash for lookup, NOT NULL |
| encrypted_key | TEXT | encrypted at rest, NOT NULL |
| last_used_at | TEXT | ISO 8601, nullable |
| created_at | TEXT | ISO 8601 |
| deleted_at | TEXT | nullable, soft delete |

#### 7. repos

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| org_id | TEXT | FK -> organizations.id, nullable (null for personal) |
| user_id | TEXT | FK -> users.id, NOT NULL (owner) |
| name | TEXT | NOT NULL |
| source_type | TEXT | "github", "gitlab", "git_url", "zip" |
| remote_url | TEXT | nullable (null for zip) |
| default_branch | TEXT | e.g., "main" |
| last_commit_sha | TEXT | last scanned commit |
| oauth_connection_id | TEXT | FK -> oauth_connections.id, nullable |
| created_at | TEXT | ISO 8601 |
| updated_at | TEXT | ISO 8601 |
| deleted_at | TEXT | nullable |

#### 8. scans

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| repo_id | TEXT | FK -> repos.id, NOT NULL |
| scan_type | TEXT | "full" or "incremental" |
| status | TEXT | state machine value (see below), NOT NULL |
| commit_sha | TEXT | the commit being scanned |
| base_commit_sha | TEXT | nullable, for incremental scans |
| parent_scan_id | TEXT | FK -> scans.id, nullable, for incremental scans |
| triggered_by | TEXT | FK -> users.id, nullable |
| finding_count | INTEGER | denormalized count, updated at report stage |
| critical_count | INTEGER | denormalized |
| high_count | INTEGER | denormalized |
| medium_count | INTEGER | denormalized |
| low_count | INTEGER | denormalized |
| started_at | TEXT | ISO 8601, nullable |
| completed_at | TEXT | ISO 8601, nullable |
| error_message | TEXT | nullable, populated on failure |
| created_at | TEXT | ISO 8601 |
| updated_at | TEXT | ISO 8601 |

#### 9. scan_stages

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| scan_id | TEXT | FK -> scans.id, NOT NULL |
| stage | TEXT | "ingest", "tyr", "hunt", "garmr", "report" |
| status | TEXT | "pending", "running", "completed", "failed", "skipped" |
| attempt | INTEGER | retry count, starts at 1 |
| started_at | TEXT | ISO 8601, nullable |
| completed_at | TEXT | ISO 8601, nullable |
| error_message | TEXT | nullable |
| metadata_json | TEXT | nullable, stage-specific data (e.g., files parsed count, findings discovered count) |
| created_at | TEXT | ISO 8601 |

#### 10. scan_jobs

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| scan_id | TEXT | FK -> scans.id, NOT NULL, UNIQUE |
| status | TEXT | state machine value (see below), NOT NULL |
| priority | INTEGER | higher = more urgent, default 0 |
| worker_id | TEXT | nullable, ID of the worker that claimed this job |
| run_after | TEXT | ISO 8601, for delayed/scheduled execution |
| attempts | INTEGER | number of attempts, default 0 |
| max_attempts | INTEGER | default 3 |
| last_error | TEXT | nullable |
| claimed_at | TEXT | ISO 8601, nullable |
| started_at | TEXT | ISO 8601, nullable |
| completed_at | TEXT | ISO 8601, nullable |
| created_at | TEXT | ISO 8601 |
| updated_at | TEXT | ISO 8601 |

#### 11. file_snapshots

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| repo_id | TEXT | FK -> repos.id, NOT NULL |
| scan_id | TEXT | FK -> scans.id, NOT NULL |
| file_path | TEXT | relative path from repo root, NOT NULL |
| content_hash | TEXT | SHA-256, NOT NULL |
| language | TEXT | detected language (e.g., "rust", "python", "javascript") |
| line_count | INTEGER | |
| byte_size | INTEGER | |
| ast_summary_json | TEXT | tree-sitter AST summary as JSON |
| created_at | TEXT | ISO 8601 |

#### 12. findings

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| scan_id | TEXT | FK -> scans.id, NOT NULL |
| repo_id | TEXT | FK -> repos.id, NOT NULL |
| status | TEXT | "open", "confirmed", "dismissed", "false_positive", "fixed" |
| severity | TEXT | "critical", "high", "medium", "low" |
| confidence | TEXT | "high", "medium", "low" |
| title | TEXT | short description, NOT NULL |
| description | TEXT | plain English explanation |
| cwe_id | TEXT | e.g., "CWE-89", nullable |
| cve_id | TEXT | e.g., "CVE-2024-XXXX", nullable |
| file_path | TEXT | affected file, NOT NULL |
| line_start | INTEGER | NOT NULL |
| line_end | INTEGER | nullable |
| code_snippet | TEXT | the vulnerable code |
| suggested_patch | TEXT | unified diff format |
| poc_exploit_json | TEXT | JSON blob (see Garmr section), nullable |
| poc_validated | BOOLEAN | false until Garmr confirms |
| fingerprint | TEXT | SHA-256(file_path + cwe_id + normalized_vulnerable_code), NOT NULL |
| agent_reasoning | TEXT | the agent's chain of reasoning that led to this finding |
| created_at | TEXT | ISO 8601 |
| updated_at | TEXT | ISO 8601 |

#### 13. finding_events

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| finding_id | TEXT | FK -> findings.id, NOT NULL |
| user_id | TEXT | FK -> users.id, nullable (null for system events) |
| event_type | TEXT | "status_change", "comment", "patch_applied", "poc_validated", "severity_changed", "remediation_started", "remediation_pr_opened", "remediation_failed" |
| old_value | TEXT | nullable |
| new_value | TEXT | nullable |
| comment | TEXT | nullable, free text |
| metadata | JSONB | provider/run/PR metadata, nullable |
| created_at | TEXT | ISO 8601 |

#### 14. patches

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| finding_id | TEXT | FK -> findings.id, NOT NULL |
| scan_id | TEXT | FK -> scans.id, NOT NULL |
| diff_content | TEXT | unified diff, NOT NULL |
| description | TEXT | what the patch does |
| applies_cleanly | BOOLEAN | whether the diff applies to current HEAD |
| applied | BOOLEAN | whether the user has applied this patch |
| applied_by | TEXT | FK -> users.id, nullable |
| applied_at | TEXT | ISO 8601, nullable |
| created_at | TEXT | ISO 8601 |

#### 15. remediation_runs

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| finding_id | TEXT | FK -> findings.id, NOT NULL |
| patch_id | TEXT | FK -> patches.id, nullable context seed |
| scan_id | TEXT | FK -> scans.id, NOT NULL |
| repo_id | TEXT | FK -> repos.id, NOT NULL |
| user_id | TEXT | FK -> users.id, nullable |
| provider | TEXT | selected provider name |
| model | TEXT | selected model |
| status | TEXT | "queued", "running", "pr_opened", "failed" |
| base_branch | TEXT | PR base branch |
| branch_name | TEXT | generated remediation branch |
| commit_sha | TEXT | commit created by the agent, nullable |
| pr_url | TEXT | draft PR URL, nullable |
| external_pr_id | TEXT | provider PR id, nullable |
| external_pr_number | TEXT | provider PR number, nullable |
| title | TEXT | PR title, nullable |
| summary | TEXT | agent summary, nullable |
| validation_output | TEXT | bounded Git validation output, nullable |
| error_message | TEXT | failure reason, nullable |
| metadata_json | JSONB | provider/run metadata, nullable |
| started_at | TEXT | ISO 8601, nullable |
| completed_at | TEXT | ISO 8601, nullable |
| created_at | TEXT | ISO 8601 |
| updated_at | TEXT | ISO 8601 |

#### 16. agent_tool_calls

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| scan_id | TEXT | FK -> scans.id, NOT NULL |
| stage | TEXT | "hunt" or "garmr" |
| tool_name | TEXT | "read_file", "search_code", "get_callers", "get_dependencies", or LLM call |
| input_json | TEXT | tool input as JSON |
| output_json | TEXT | tool output as JSON (truncated if large) |
| prompt_tokens | INTEGER | nullable (only for LLM calls) |
| completion_tokens | INTEGER | nullable |
| total_tokens | INTEGER | nullable |
| duration_ms | INTEGER | execution time |
| error | TEXT | nullable |
| created_at | TEXT | ISO 8601 |

#### 16. threat_models

| Column | Type | Notes |
|--------|------|-------|
| id | TEXT (UUIDv7) | PK |
| scan_id | TEXT | FK -> scans.id, NOT NULL, UNIQUE |
| repo_id | TEXT | FK -> repos.id, NOT NULL |
| summary | TEXT | human-readable overview of the application |
| boundaries_json | TEXT | JSON array of trust boundaries |
| surfaces_json | TEXT | JSON array of attack surfaces |
| data_flows_json | TEXT | JSON array of sensitive data flows |
| model_version | INTEGER | incremented on user edits, default 1 |
| edited_by | TEXT | FK -> users.id, nullable |
| created_at | TEXT | ISO 8601 |
| updated_at | TEXT | ISO 8601 |

### Scan Status State Machine

```
queued -> ingesting -> ingested -> modeling -> modeled -> hunting -> hunted -> validating -> validated -> reporting -> completed
                                                                                                         \-> failed (from any state)
                                                                                                         \-> cancelled (from any state)
```

Transitions are recorded by updating `scans.status` and creating/updating the corresponding `scan_stages` row.

### Job Queue State Machine (scan_jobs)

```
pending -> claimed -> running -> completed
                              -> failed -> pending (if attempts < max_attempts)
                              -> failed -> dead (if attempts >= max_attempts)
           claimed -> failed (claim timeout)
```

| Status | Description |
|--------|-------------|
| `pending` | Waiting to be picked up by a worker |
| `claimed` | A worker has claimed the job but hasn't started executing |
| `running` | The scan pipeline is actively executing |
| `completed` | Scan finished successfully |
| `failed` | Scan failed; may be retried if under max_attempts |
| `dead` | Exhausted all retry attempts |

### Key Indexes

| Index | Columns | Purpose |
|-------|---------|---------|
| `idx_file_snapshots_dedup` | `repo_id, file_path, content_hash` | Incremental scan deduplication |
| `idx_findings_fingerprint` | `fingerprint` | Cross-scan finding deduplication |
| `idx_findings_scan_severity` | `scan_id, severity` | Findings list page (filtered/sorted) |
| `idx_scan_jobs_polling` | `status, run_after, priority` | Job queue worker polling |
| `idx_scans_repo_commit` | `repo_id, commit_sha` | Incremental scan parent lookup |

### Incremental Scan Strategy

1. User triggers a scan on a repo that has been scanned before.
2. System sets `scan_type = "incremental"`, `base_commit_sha` = previous scan's commit, `parent_scan_id` = previous scan's ID.
3. During Ingest, run `git diff --name-status base_commit_sha..commit_sha`:
   - **Modified files (M)**: Full re-scan through all pipeline stages
   - **Added files (A)**: Full re-scan
   - **Deleted files (D)**: Findings from these files are NOT carried forward
   - **Unchanged files**: Carry forward findings from parent scan by matching `fingerprint`
4. Fingerprint formula: `SHA-256(file_path + cwe_id + normalized_vulnerable_code)`
   - "Normalized" means whitespace-stripped, comment-stripped code
   - If a carried-forward finding's fingerprint matches a new finding, the existing finding is preserved (maintaining its status, events, etc.)

### JSON vs Normalized Decisions

| Field | Storage | Reason |
|-------|---------|--------|
| `threat_models.boundaries_json` | JSON | Read as a whole, rarely queried individually |
| `threat_models.surfaces_json` | JSON | Read as a whole |
| `threat_models.data_flows_json` | JSON | Read as a whole |
| `file_snapshots.ast_summary_json` | JSON | Complex nested structure, read as a whole |
| `findings.poc_exploit_json` | JSON | Complex nested structure, read as a whole |
| `findings.severity` | Normalized column | Frequently filtered |
| `findings.status` | Normalized column | Frequently filtered |
| `findings.fingerprint` | Normalized column | Indexed for dedup queries |
| `scans.status` | Normalized column | Frequently queried for state transitions |

---

## 8. Architecture

### Crate Structure

Single binary, no Cargo workspace. Modules are organized as a flat hierarchy under `src/`. Extraction into separate crates can happen later if needed, but the single-binary approach keeps builds simple and deployment trivial.

```
src/
  main.rs              -- entry point, server startup, graceful shutdown
  lib.rs               -- re-exports, app state construction
  config.rs            -- configuration (env vars, config file, defaults)
  errors.rs            -- thiserror enum with per-module variants

  db/                  -- database layer
    mod.rs             -- pool setup (sqlx + SQLite)
    migrations/        -- SQL migration files
    models.rs          -- Rust structs mapping to DB tables
    queries.rs         -- sqlx query functions (no raw SQL in other modules)

  web/                 -- HTTP layer
    mod.rs             -- Actix-web app factory, middleware
    routes/            -- route handlers grouped by domain
      auth.rs          -- login, logout, OAuth callbacks
      repos.rs         -- repo CRUD, add repo flow
      scans.rs         -- scan CRUD, trigger scan, progress SSE
      findings.rs      -- findings list, detail, status changes, patch apply
      threat_model.rs  -- view, edit threat model sections
      settings.rs      -- user settings, API keys, integrations
      api.rs           -- programmatic API endpoints (for CI/CD)
    templates/         -- askama templates (compile-time checked)
    static/            -- CSS (Tailwind), JS (HTMX, Alpine), images

  pipeline/            -- scan pipeline
    mod.rs             -- ScanPipeline orchestrator
    ingest/            -- Stage 1: clone + tree-sitter indexing
      mod.rs
      clone.rs         -- git clone / zip extract
      parser.rs        -- tree-sitter parsing per language
    tyr/               -- Stage 2: threat model generation
      mod.rs
      prompts.rs       -- LLM prompt templates for threat modeling
    hunt/              -- Stage 3: agentic vulnerability discovery
      mod.rs
      agent.rs         -- agent state machine implementation
      tools.rs         -- tool implementations (read_file, search_code, etc.)
      prompts.rs       -- LLM prompt templates for investigation
    garmr/             -- Stage 4: sandbox validation
      mod.rs
      sandbox.rs       -- Docker container management (bollard)
      prompts.rs       -- LLM prompt templates for PoC generation/analysis
    report/            -- Stage 5: ranking + patch generation
      mod.rs
      ranking.rs       -- severity/confidence ranking logic
      patches.rs       -- diff generation and validation

  ai/                  -- AI/LLM layer
    mod.rs             -- ModelProvider trait definition
    claude.rs          -- Anthropic Claude implementation
    openai.rs          -- OpenAI implementation
    ollama.rs          -- Ollama implementation
    types.rs           -- CompletionRequest, CompletionResponse, ToolDefinition, etc.

  index/               -- code index
    mod.rs             -- CodeIndex struct and public API
    symbols.rs         -- symbol table (functions, classes, methods)
    callgraph.rs       -- caller/callee relationships
    deps.rs            -- file/module dependency graph
    search.rs          -- text/regex search across indexed files

  jobs/                -- job queue
    mod.rs             -- job queue abstraction
    tokio_queue.rs     -- in-process Tokio mpsc implementation
    redis_queue.rs     -- Redis-backed implementation (for multi-worker)
```

### Component Diagram

```
                    +-----------+
                    |  Browser  |
                    +-----+-----+
                          |
                    HTTP / SSE
                          |
                    +-----v-----+
                    | Actix-web |
                    |  (web/)   |
                    +-----+-----+
                          |
              +-----------+-----------+
              |                       |
        +-----v-----+          +-----v-----+
        |    DB      |          |  Job Queue |
        |  (db/)     |          |  (jobs/)   |
        +-----+-----+          +-----+-----+
              |                       |
              |                 +-----v-----+
              |                 |  Pipeline  |
              |                 | (pipeline/)|
              |                 +-----+-----+
              |                       |
              |           +-----------+-----------+-----------+
              |           |           |           |           |
              |     +-----v--+  +----v---+  +----v---+ +-----v--+
              |     | Ingest |  |  Tyr   |  |  Hunt  | | Garmr  |
              |     +--------+  +----+---+  +----+---+ +----+---+
              |                      |           |          |
              |                 +----v-----------v----+     |
              |                 |   AI / ModelProvider |     |
              |                 |       (ai/)         |     |
              |                 +---------------------+     |
              |                                             |
              |                                       +-----v-----+
              |                                       |   Docker   |
              |                                       | (bollard)  |
              +---------------------------------------+-----------+
                              CodeIndex (index/)
                            shared via Arc<CodeIndex>
```

### Data Flow

1. **HTTP Request** -> Actix-web handler -> validates input, checks auth
2. **Scan Trigger** -> handler creates `scans` row + `scan_jobs` row -> returns scan ID
3. **Job Queue** -> worker polls for `pending` jobs -> claims job -> starts `ScanPipeline`
4. **ScanPipeline** -> runs stages sequentially:
   - Each stage reads from DB / CodeIndex, writes results to DB
   - Each stage updates `scans.status` and creates `scan_stages` rows
   - SSE events are emitted at each transition for the progress UI
5. **SSE Stream** -> client connects to `/scans/{id}/progress/stream` -> receives events:
   - `stage` -- stage transition (e.g., "hunting")
   - `log` -- log line from current stage
   - `finding` -- new finding discovered
   - `complete` -- scan finished
   - `error` -- scan failed

### Job Queue

**Implementation 1 (Tokio mpsc):**
- In-process channel with configurable buffer size
- Workers are Tokio tasks polling the `scan_jobs` table
- Suitable for single-instance deployment

**Implementation 2 (Redis):**
- Redis-backed queue for multi-worker deployments
- Workers are separate processes or Tokio tasks
- Uses Redis BRPOPLPUSH for atomic claim
- Suitable for SaaS / high-volume deployments

Both implementations share the same trait interface so the pipeline code is queue-agnostic.

### Error Handling

**Error type:** `thiserror` enum with per-module variants:

```rust
#[derive(Debug, thiserror::Error)]
pub enum HeimdallError {
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("AI provider error: {0}")]
    Ai(String),

    #[error("Pipeline error in {stage}: {message}")]
    Pipeline { stage: String, message: String },

    #[error("Docker error: {0}")]
    Docker(#[from] bollard::errors::Error),

    #[error("Git error: {0}")]
    Git(String),

    #[error("Validation error: {0}")]
    Validation(String),

    // ... additional variants
}
```

**Error strategy by context:**

| Context | Strategy |
|---------|----------|
| Pipeline stage failure | Fail the stage, record error in `scan_stages`, transition scan to `failed` |
| LLM call failure | Retry with exponential backoff, max 3 attempts |
| Agent tool error | Feed error back to LLM as a `ToolResult` with error content; let the agent decide how to proceed |
| Docker failure | Log error, mark PoC as inconclusive, continue to next finding |
| DB error | Propagate up, fail the operation |
| HTTP handler error | Return appropriate HTTP status with error message |

**Logging:** Structured logging via `tracing` crate. Per-scan spans with scan_id. Per-stage sub-spans. All LLM calls and tool calls logged at debug level.

### Concurrency

- Actix-web handles HTTP concurrency via its actor/thread model
- Pipeline stages run sequentially within a scan
- Hunt agent runs multiple threat investigations in parallel via `tokio::spawn`
- `CodeIndex` is shared across parallel investigations via `Arc<CodeIndex>`
- DB access is through sqlx connection pool (concurrent-safe)
- Job queue supports multiple workers claiming different jobs

---

## 9. UI/UX

### Technology

- **Server-side rendering** with askama (compile-time checked Rust templates)
- **HTMX** for dynamic interactions without a JavaScript framework
- **Tailwind CSS** for styling
- **Alpine.js** for minimal client-side state (dropdowns, modals)
- **SSE** (Server-Sent Events) for real-time scan progress

### Layout

Global shell present on all pages except Login:

```
+------------------------------------------------------+
| TOPBAR: Logo | [search] | Settings gear | User avatar |
+------+-----------------------------------------------+
| SIDE  |                                               |
| BAR   |              MAIN CONTENT                     |
|       |           (max-w-6xl mx-auto)                 |
| Dash  |           with breadcrumbs                    |
| Repos |                                               |
| Scans |                                               |
| ---   |                                               |
| Sett  |                                               |
| Docs  |                                               |
+------+-----------------------------------------------+
```

**Sidebar navigation items:**
- Dashboard
- Repositories
- Recent Scans
- Settings
- Docs

### All 12 Screens

#### A1: Login
- Standalone page, no shell
- Email/password form
- "Sign in with GitHub" button
- "Sign in with GitLab" button
- Link to register

#### A2: Settings
- Three tabs: Profile, AI Provider, Integrations
- **Profile tab**: Display name, email, avatar, password change
- **AI Provider tab**: Add/manage BYOK API keys (Anthropic, OpenAI, Ollama URL), test connection button (HTMX fragment returns success/failure)
- **Integrations tab**: Connect/disconnect GitHub OAuth, connect/disconnect GitLab OAuth, manage Heimdall API keys

#### B1: Dashboard / Repo List
- Stats bar at top: total repos, total scans, open findings (by severity)
- Repo card grid: each card shows repo name, source type icon, last scan date, finding counts by severity, "Scan" button
- Empty state: "Connect your first repository" CTA

#### B2: Add Repository
- Four tabs: GitHub, GitLab, Git URL, Upload
- **GitHub tab**: Requires OAuth connection. Lists user's repos (fetched via GitHub API, rendered as HTMX fragment). Select one or more. Import button.
- **GitLab tab**: Same pattern as GitHub.
- **Git URL tab**: Text input for public git URL. Optional branch field. Add button.
- **Upload tab**: Drag-and-drop zone for zip file. Upload button.

#### B3: Repository Detail
- Repo header: name, source, URL, default branch, last commit SHA
- "Run Scan" button (prominent)
- Scan history table: date, commit, type (full/incremental), status, finding counts, duration, link to scan
- Tabs or sections for: scan history, settings (rename, delete, change branch)

#### C1: Scan Progress
- Pipeline stepper at top showing all 5 stages: Ingest, Tyr, Hunt, Garmr, Report
  - Each step shows: pending (gray), running (blue pulse), completed (green check), failed (red X)
- Below the stepper: real-time log stream via SSE
  - Log entries styled by level (info, warning, error)
  - Findings appear inline as they're discovered during Hunt
- SSE connection: `hx-ext="sse"` on the container, `sse-connect="/scans/{id}/progress/stream"`
- SSE event types:
  - `stage` -- update the stepper
  - `log` -- append to log stream
  - `finding` -- show a finding card inline
  - `complete` -- show completion state, link to results
  - `error` -- show error state

#### C2: Findings List
- Filter sidebar (left):
  - Severity: checkboxes (critical, high, medium, low)
  - Status: checkboxes (open, confirmed, dismissed, false_positive, fixed)
  - CWE: searchable dropdown
  - PoC validated: checkbox
  - Filters trigger HTMX requests, replacing the findings list fragment
- Finding cards (main area):
  - Each card: severity badge, title, file:line, CWE, confidence, PoC validated indicator
  - Click card -> navigate to finding detail
- Sort options: severity (default), confidence, file path
- Pagination

#### C3: Finding Detail
- **Header**: severity badge, title, status dropdown (open/confirmed/dismissed/false_positive/fixed)
- **Explanation section**: plain English description of the vulnerability
- **Code section**: affected file with syntax highlighting, vulnerable lines highlighted
- **PoC section** (if available): PoC script, execution output, verdict (confirmed/unconfirmed)
- **Patch section** (D1 -- Diff Viewer): unified diff with syntax highlighting, export/copy controls, and a button to mark the suggestion handled in Heimdall
- **Agent Reasoning section**: collapsible, shows the agent's chain of thought
- **Events/Timeline**: audit trail from `finding_events` (status changes, comments)
- **Actions**: Add comment, change status, change severity, mark patch handled

#### C4: Threat Model Viewer/Editor
- Section-based layout:
  - **Summary**: text block, editable inline (HTMX `hx-put`)
  - **Trust Boundaries**: list of boundaries, each editable/deletable, "Add boundary" button
  - **Attack Surfaces**: list, each editable/deletable, "Add surface" button
  - **Data Flows**: list, each editable/deletable, "Add flow" button
- Inline editing: click "Edit" on a section -> HTMX swaps display fragment for edit fragment -> save/cancel buttons -> HTMX PUT -> swaps back to display fragment
- Changes persist to `threat_models` table, increment `model_version`

#### D1: Diff Viewer (Component)
- Embedded within C3 (Finding Detail) and D2 (Batch Patch Review)
- Side-by-side or unified diff view toggle
- Syntax-highlighted code with red (removed) and green (added) lines
- "Mark Suggested Diff Applied" button
- "Copy Diff" button

#### D2: Batch Patch Review
- List of all findings with patches for a given scan
- Checkbox selection for each
- Preview selected patches (shows each diff)
- Optional bulk mark-as-applied action after patches are handled outside Heimdall
- Status indicators: marked applied / pending review

### HTMX Patterns

| Pattern | Usage |
|---------|-------|
| Full page navigation | Standard `<a href>` links. Every page has a bookmarkable URL. |
| Fragment replacement | `HX-Request` header detected by server. Same route returns full page or fragment based on header presence. |
| Filtering | `hx-get` with query params on filter controls. Target: `#findings-list`. Swap: `innerHTML`. |
| Inline editing | `hx-get` to swap display -> edit form. `hx-put` to save. `hx-target` to swap back. |
| Form submission | `hx-post` for forms (add repo, run scan, mark suggested diffs handled, etc.). |
| SSE streaming | `hx-ext="sse"`, `sse-connect`, `sse-swap` for real-time updates. |
| Status updates | `hx-patch` on status dropdown change. Target: status badge. |
| Loading indicators | `hx-indicator` with spinner class on buttons/forms. |

### Template Structure

```
templates/
  base.html                    -- global shell (topbar, sidebar, content slot)

  components/
    finding_card.html          -- finding card for lists
    severity_badge.html        -- colored severity indicator
    diff_viewer.html           -- unified/side-by-side diff display
    pipeline_stepper.html      -- scan progress timeline
    repo_card.html             -- repo card for dashboard grid

  pages/
    login.html                 -- A1: standalone login page
    dashboard.html             -- B1: stats + repo grid
    repo_new.html              -- B2: add repository tabs
    repo_detail.html           -- B3: repo detail + scan history
    scan_progress.html         -- C1: pipeline stepper + SSE log
    findings_list.html         -- C2: filter sidebar + finding cards
    finding_detail.html        -- C3: full finding view
    threat_model.html          -- C4: threat model viewer/editor
    batch_patches.html         -- D2: batch patch review
    settings.html              -- A2: settings tabs

  fragments/
    findings_list_items.html   -- finding cards list (for HTMX swap)
    finding_status.html        -- status badge (for HTMX swap)
    tm_section_edit.html       -- threat model section edit form
    tm_section_display.html    -- threat model section display
    patch_section.html         -- patch diff + apply button
    github_repo_list.html      -- GitHub repo picker list
    ai_test_result.html        -- AI provider connection test result
```

### Severity Colors

| Severity | Background | Text |
|----------|-----------|------|
| Critical | `bg-red-100` | `text-red-800` |
| High | `bg-orange-100` | `text-orange-800` |
| Medium | `bg-yellow-100` | `text-yellow-800` |
| Low | `bg-blue-100` | `text-blue-800` |

### All 30 Routes (Endpoint Map)

#### Full Page Routes (10)

| Method | Path | Screen | Description |
|--------|------|--------|-------------|
| GET | `/login` | A1 | Login page |
| GET | `/settings` | A2 | Settings page |
| GET | `/repos` | B1 | Dashboard / repo list |
| GET | `/repos/new` | B2 | Add repository page |
| GET | `/repos/{id}` | B3 | Repository detail |
| GET | `/scans/{id}` | C1 | Scan progress page |
| GET | `/scans/{id}/findings` | C2 | Findings list |
| GET | `/findings/{id}` | C3 | Finding detail |
| GET | `/scans/{id}/threat-model` | C4 | Threat model viewer |
| GET | `/scans/{id}/patches` | D2 | Batch patch review |

#### SSE Route (1)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/scans/{id}/progress/stream` | SSE event stream for scan progress |

#### HTMX Fragment Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/scans/{id}/findings/list` | Findings list fragment (for filtering) |
| PATCH | `/findings/{id}/status` | Update finding status |
| POST | `/findings/{id}/apply-patch` | Mark a suggested diff as applied in Heimdall metadata (no repo write-back) |
| GET | `/findings/{id}/remediation` | Render latest fix-PR agent state |
| POST | `/findings/{id}/remediate` | Queue a fix-PR agent run for a GitHub-backed finding |
| GET | `/scans/{id}/threat-model/edit/{section}` | Threat model section edit form fragment |
| PUT | `/scans/{id}/threat-model/{section}` | Save threat model section edit |
| GET | `/scans/{id}/threat-model/display/{section}` | Threat model section display fragment |
| GET | `/repos/new/github/repos` | GitHub repo picker list fragment |
| GET | `/repos/new/gitlab/repos` | GitLab repo picker list fragment |
| POST | `/settings/ai/test` | Test AI provider connection |
| POST | `/findings/{id}/comment` | Add comment to finding |
| PATCH | `/findings/{id}/severity` | Update finding severity |
| POST | `/scans/{id}/patches/apply` | Planned bulk mark-as-applied action (not implemented) |

#### Action Routes (7)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/login` | Submit login form |
| POST | `/logout` | Logout (clear session) |
| GET | `/auth/github/callback` | GitHub OAuth callback |
| GET | `/auth/gitlab/callback` | GitLab OAuth callback |
| POST | `/repos` | Create a new repo |
| POST | `/repos/{id}/scan` | Trigger a new scan |
| PUT | `/settings` | Update settings |

**Total: 30 routes** (10 pages + 1 SSE + 12 fragments + 7 actions)

### User Journeys

#### Journey 1: First-Time Setup
1. User visits `/login`, registers or signs in with GitHub
2. Redirected to `/repos` (empty dashboard)
3. Clicks "Add Repository", goes to `/repos/new`
4. Selects GitHub tab, sees their repos, selects one, clicks Import
5. Redirected to `/repos/{id}` (new repo detail)
6. Optionally goes to `/settings` to configure BYOK AI key

#### Journey 2: Running a Scan
1. User visits `/repos/{id}`
2. Clicks "Run Scan"
3. Redirected to `/scans/{id}` (progress page)
4. Watches pipeline stepper advance through stages in real-time via SSE
5. Sees findings appear inline during Hunt stage
6. Scan completes, clicks "View Findings"

#### Journey 3: Reviewing Findings
1. User visits `/scans/{id}/findings`
2. Filters by severity (Critical + High)
3. Clicks on a critical finding
4. Reads explanation, reviews vulnerable code, checks PoC output
5. Reviews the suggested diff in the diff viewer
6. Copies or manually applies the diff outside Heimdall, then marks it applied in Heimdall or marks the finding as "False Positive"
7. Adds a comment for team context

#### Journey 4: Editing Threat Model
1. User visits `/scans/{id}/threat-model`
2. Reviews auto-generated boundaries, surfaces, and flows
3. Clicks "Edit" on the attack surfaces section
4. Adds a surface the agent missed (e.g., "admin panel at /admin")
5. Saves. Next scan will include this surface in Hunt investigations.

#### Journey 5: Batch Patching
1. User visits `/scans/{id}/patches`
2. Reviews all available patches
3. Selects the ones they want to track as handled (checkboxes)
4. Previews the combined diff
5. Uses the batch action only to update Heimdall state after handling those patches elsewhere
6. For a single supported GitHub finding, starts the fix-PR agent from the finding detail page instead of manually applying the patch
7. Sees queued/running/failed/PR-opened status and links to the draft PR when opened

---

## 10. Repo Connections

### GitHub OAuth
- OAuth app registered with GitHub
- Scopes: `repo` (read access to private repos), `read:user` (profile info)
- Flow: User clicks "Sign in with GitHub" or "Connect GitHub" in settings -> redirect to GitHub authorize URL -> callback at `/auth/github/callback` -> exchange code for access token -> store in `oauth_connections` (encrypted)
- Token refresh handled transparently when tokens expire
- Repo listing: GitHub API `GET /user/repos` for the picker in Add Repository

### GitLab OAuth
- OAuth app registered with GitLab
- Scopes: `read_repository`, `read_user`
- Same flow as GitHub, callback at `/auth/gitlab/callback`
- Store in `oauth_connections`
- Repo listing: GitLab API `GET /projects` (member access)

### Public Git URL
- User pastes any git URL (HTTPS)
- System performs `git clone --depth=1` (shallow clone for speed)
- No OAuth needed; only public repos supported via this method
- Stored in `repos` with `source_type = "git_url"`

### Zip Upload
- User uploads a zip file via the drag-and-drop zone
- Server extracts to a working directory
- No git history available; scans are always "full" type
- Stored in `repos` with `source_type = "zip"`

---

## 11. Monetization & Deployment

### OSS Version (Self-Hosted)
- **License**: Functional Source License (FSL)
- **AI Keys**: BYOK -- users provide their own Anthropic, OpenAI, or Ollama keys
- **Deployment**: Single binary. Download, configure, run. SQLite for storage. Docker optional for Garmr sandbox features.
- **Cost to user**: Free (they pay their own LLM API costs)
- **No vendor lock-in**: Users own their data, run on their infrastructure

### SaaS Version (Managed)
- **License**: Commercial license for the hosted service
- **AI Keys**: Managed by Heimdall -- users do not need their own keys
- **Deployment**: Multi-tenant hosted service
- **Infrastructure**: Managed database (Postgres), managed job queue (Redis), managed Docker for Garmr
- **Pricing**: Tiered plans based on repos, scans, and organization size:
  - Free tier: limited repos and scans
  - Team tier: more repos, more scans, organization features
  - Enterprise tier: unlimited, priority support, SLA

### Self-Hosted with Commercial License
- Organizations that want to self-host but need commercial terms (e.g., not FSL-compatible)
- Same binary, commercial license, optional managed AI keys from Heimdall

### Tech Stack Summary

| Component | Technology |
|-----------|-----------|
| API Server | Rust + Actix-web |
| Frontend | HTMX + Tailwind CSS + Alpine.js |
| Templates | askama (compile-time checked) |
| Database | SQLite (single-instance), Postgres (SaaS/scale) |
| Job Queue | Tokio mpsc (single-instance), Redis (multi-worker) |
| Container Isolation | bollard (Docker SDK for Rust) |
| Code Parsing | tree-sitter (Rust bindings) |
| LLM Integration | Custom ModelProvider trait (Claude, OpenAI, Ollama) |
| Logging | tracing (structured, per-scan spans) |
| Error Handling | thiserror |

---

This concludes the complete Heimdall product specification. Every feature described is part of the product. There are no phases, no deferrals, no future work. This is what Heimdall is.

### Critical Files for Implementation

- `/Users/modestnerd/.claude/projects/-Users-modestnerd-Developer-Projects-heimdall/memory/data-model.md` - Source of truth for all 16 table schemas, state machines, indexes, and incremental scan strategy
- `/Users/modestnerd/.claude/projects/-Users-modestnerd-Developer-Projects-heimdall/memory/architecture.md` - Module tree, agent state machine, ModelProvider trait, error strategy, and Garmr sandbox constraints
- `/Users/modestnerd/.claude/projects/-Users-modestnerd-Developer-Projects-heimdall/memory/ui-ux.md` - All 12 screens, 30 routes, template structure, HTMX patterns, and SSE events
- `/Users/modestnerd/.claude/projects/-Users-modestnerd-Developer-Projects-heimdall/memory/product-definition.md` - Product identity, scan pipeline overview, monetization model, and target users
- `/Users/modestnerd/Developer/Projects/heimdall/Cargo.toml` - Current project state (bare skeleton to build upon)
