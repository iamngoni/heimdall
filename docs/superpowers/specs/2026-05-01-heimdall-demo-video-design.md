# Heimdall Demo Video Design

Date: 2026-05-01

## Goal

Create a professional 2-3 minute demo/showcase video for Heimdall that explains what it does, how it works, what users can expect, and how to get started. The video should speak to developers, security/team leads, and self-hosters without becoming a long tutorial.

The final rendered artifact should be saved to the user's Desktop.

## Audience

- Developers evaluating whether Heimdall fits their workflow.
- Security and team leads evaluating whether findings are trustworthy.
- Self-hosters who need to understand the basic setup model.

## Approved Direction

Use the concept **"From Repo To Evidence"** with a short self-host/setup close.

The video follows one promise:

> Heimdall turns a repository into inspectable security evidence: threat model, agentic investigation, validation, findings, patches, and issue follow-through.

The tone is developer-forward with a serious security spine. It should feel practical, credible, and polished rather than theatrical. Heimdall's Norse component names can appear as product moments, but the video should not lean heavily into mythology.

## Format

- Length: 2:15-2:45 target.
- Style: Hybrid of real Heimdall UI capture and designed motion graphics.
- Audio: Narrated voiceover with burned-in captions and quiet music underneath.
- Production approach: HyperFrames HTML composition, with Remotion kept as a fallback for heavier React-driven animation if needed.

## Visual Treatment

Use Heimdall's current Oatmeal/dark product language:

- Dark mist canvas: `#090b0c`.
- Raised dark panels and subtle borders.
- Pale text and restrained contrast.
- Muted state colors: green for validated, amber for running, soft red for critical.
- Familjen Grotesk-style typography for product UI moments.
- Optional serif display moment for the opener, matching the current landing-page feel.

Avoid loud "hacker" visuals, fake terminal overload, generic blue SaaS gradients, and mythology-heavy illustration.

## Narrative Structure

| Time | Beat | Visual Direction |
| ---: | --- | --- |
| 0:00-0:15 | Hook | Fast cuts of noisy findings, opaque AI responses, repo risk. Text: "Security review should show its work." |
| 0:15-0:35 | What Heimdall Is | Real UI: landing/login, dashboard, connected repos. Voiceover defines Heimdall in one sentence. |
| 0:35-0:55 | Setup Path | Quick visual: self-host, Postgres, AI provider key, optional Docker for sandbox validation. |
| 0:55-1:25 | Run A Scan | UI capture: add repo, trigger scan, live stage progress. Motion layer shows repo becoming indexed evidence. |
| 1:25-1:55 | How It Works | Motion graphics for pipeline: Ingest, Tyr, Static/Taint/Config, Hunt, Vidarr, Garmr, Report. |
| 1:55-2:25 | What Users Get | Real UI: findings list, finding detail, code context, AI review, PoC evidence, suggested diff, issue creation. |
| 2:25-2:45 | Close | Product promise plus setup CTA: "Bring your repo. Bring your keys. Heimdall brings the evidence." |

## Scene Script

| Time | Voiceover | Visuals |
| ---: | --- | --- |
| 0:00 | "Security scanners are fast. But too often, they leave teams asking the same question: can we trust this finding?" | Rapid motion cards: noisy alerts, vague AI answer, code snippet, red severity badge. |
| 0:12 | "Heimdall is agentic code security review that shows its work." | Heimdall UI appears. Logo/eye mark, dashboard, connected repo metrics. |
| 0:22 | "Connect a repository from GitHub, GitLab, Bitbucket, a public Git URL, or a zip upload." | UI capture: repo intake options. Motion labels highlight sources. |
| 0:35 | "Run a scan, and Heimdall builds context before it makes claims." | Trigger scan. Repo becomes a structured graph: files, symbols, calls, data flows. |
| 0:50 | "Ingest indexes the codebase. Tyr builds a threat model. Static, taint, and config checks catch deterministic issues." | Pipeline animation, each stage lighting up. |
| 1:10 | "Then Hunt investigates attack surfaces like a security researcher: reading files, tracing callers, checking dependencies, and gathering evidence." | Agent tool-call style motion over real scan progress UI. |
| 1:28 | "Vidarr challenges findings before they reach you. Garmr can validate proof-of-concepts in an isolated Docker sandbox." | Finding enters review, then sandbox box animation: no network, timeout, read-only repo. |
| 1:45 | "The result is not just an alert. It is a ranked finding with code context, explanation, validation evidence, and a suggested patch." | Finding detail UI: severity, file path, explanation, vulnerable code, diff, PoC evidence. |
| 2:08 | "From there, teams can triage, mark status, export patches, or create source-control issues with the evidence attached." | Findings list, status controls, issue creation panel. |
| 2:25 | "Self-host Heimdall with Postgres, your AI provider key, and optional Docker sandboxing." | Minimal setup cards: Postgres, Anthropic/OpenAI/Ollama/Codex, Docker optional. |
| 2:38 | "Bring the repo. Bring your keys. Heimdall brings the evidence." | Final product lockup with dashboard/pipeline behind it. |

## Capture Requirements

Real UI capture should include:

- Login or landing screen.
- Dashboard.
- Add/connect repository flow.
- Scan details with live stages.
- Threat model.
- Findings list.
- Finding detail with patch and validation evidence.
- Settings/provider setup.

If the app cannot be run with realistic data immediately, create placeholder motion scenes first and replace those placeholders with real captures during the capture pass.

## Production Deliverables

- HyperFrames video project folder.
- Written script and shot list.
- Draft MP4 for review.
- Final MP4 saved on the Desktop.

Suggested final output path:

`/Users/modestnerd/Desktop/heimdall-demo-showcase.mp4`

## Open Implementation Notes

- The setup section should remain short and confidence-building, not a full installation tutorial.
- Captions should be burned in and timed to the voiceover.
- The video should make the pipeline inspectable without requiring the viewer to understand every internal module.
- Real UI footage should carry trust; motion graphics should explain what the UI cannot show directly.
