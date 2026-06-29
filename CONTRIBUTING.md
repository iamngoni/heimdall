# Contributing to Heimdall

Thank you for contributing.

The standard filename is `CONTRIBUTING.md`, and this repository uses that convention.

## What Good Contributions Look Like

- Small, focused changes with a clear reason
- Behavior that matches the actual implementation, not aspirational product copy
- Grounded security work: fewer false positives, better evidence, tighter UX, cleaner operational behavior
- Documentation updates when the behavior, setup, or limitations change

## Before You Start

- For larger changes, open an issue or start a discussion first so the implementation direction is clear.
- If your change affects product claims, update [README.md](README.md) in the same PR.
- If your change affects scan behavior, prefer adding or updating tests in the same PR.

## Local Setup

```bash
git clone https://github.com/iamngoni/heimdall.git
cd heimdall

# Start Postgres for local development
docker compose -f docker-compose.dev.yml up -d

# Configure environment
cp .env.example .env

# Install frontend tooling
npm install

# Run the app
cargo run --bin heimdall
```

Open `http://localhost:8080`.

## Development Workflow

1. Create a branch for your change.
2. Make the smallest coherent change that solves the problem.
3. Run the relevant checks locally.
4. Update docs, screenshots, or examples if the behavior changed.
5. Open a PR with a concise explanation of what changed and why.

## Required Checks

Run these before opening a PR:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo audit
npm ci
npm audit --audit-level=high
```

If you touched templates, Tailwind classes, or frontend styling, also run:

```bash
npm run build:css
git diff --exit-code -- static/css/app.css
```

For browser-level workflow coverage, run the Playwright smoke against a test
database:

```bash
npm run test:e2e
```

If you want a faster sanity pass while working:

```bash
cargo check
```

## Frontend Contributions

- Tailwind is compiled locally. Do not reintroduce the Tailwind CDN.
- Keep UI changes intentional and restrained. Avoid piling on decorative panels, oversized gradients, or extra chrome without improving clarity.
- Prefer fixing structure and hierarchy before adding more styling.
- For user-facing UI changes, include screenshots in the PR.

Auth pages in particular should:

- fit the viewport cleanly on common desktop sizes
- avoid unnecessary vertical scroll
- use one strong visual idea, not several competing ones

## Backend Contributions

- Keep business logic out of handlers where possible.
- Prefer explicit, testable Rust over clever abstractions.
- Avoid adding dependencies unless there is a strong reason.
- If you touch auth, crypto, scan orchestration, webhooks, or issue automation, add or update tests.

## Schema and Migrations

The schema source of truth is:

- [src/db/schema/definition.rs](src/db/schema/definition.rs)

If you change the schema, regenerate migrations:

```bash
cargo run --bin schema_gen -- postgres
```

If the change is cross-driver relevant, generate all supported outputs:

```bash
cargo run --bin schema_gen -- all
```

## AI and Scan Behavior

Be careful with product claims.

Current constraints that contributors should preserve or document honestly:

- Repository access is currently GitHub/GitLab OAuth user-token based
- GitHub App / installation-token flow is not implemented yet
- Stored user API keys and OAuth-backed Claude Code/Codex connections can take precedence over environment-configured providers
- `ENCRYPTION_KEY` should be treated as required for real deployments
- `cargo audit` may include documented ignores only when the advisory is inactive in `cargo tree` or has no fixed release; include the rationale in `.cargo/audit.toml`

If you improve finding quality:

- prefer better grounding over more aggressive detection
- reduce false positives before increasing automation
- keep suggested patches tied to the actual referenced code

## Security Expectations

- Never commit real API keys, OAuth secrets, webhook secrets, or `.env` contents.
- Sanitize screenshots and logs before attaching them to PRs.
- If you discover a real security issue in Heimdall itself, do not open a public exploit-style issue with secrets or working abuse steps.

## Pull Request Guidelines

Please include:

- what changed
- why it changed
- how you verified it
- any follow-up work still missing

For UI work, include before/after screenshots.

For scan-quality work, include:

- an example repo or scenario
- what was wrong before
- what is improved now

## Documentation

If you change any of the following, update docs in the same PR:

- setup steps
- environment variables
- scan pipeline behavior
- integration behavior
- supported workflows
- limitations or known gaps

At minimum, check whether [README.md](README.md) and [docs/SPEC.md](docs/SPEC.md) need updates.

## Things Not to Commit

- `.env`
- `target/`
- `node_modules/`
- local screenshots or debugging artifacts unless they are intentionally part of the repo

## Questions

If the right direction is unclear, ask before building a large solution around an assumption.
