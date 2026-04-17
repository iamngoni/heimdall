//
//  heimdall
//  src/pipeline/hunt/agent.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use log::{debug, info, warn};
use sha2::{Digest, Sha256};

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, Message, StopReason};
use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::{FindingEvidence, FindingFixType, HeimdallResult};
use crate::pipeline::hunt::tools;
use crate::pipeline::tyr::AttackSurface;
use crate::util::{sat_i32, sat_i32_u128};

/// Maximum number of agent loop iterations before forced termination.
pub const MAX_ITERATIONS: u32 = 25;

/// Represents the current state of a hunt agent's execution loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    Planning,
    AwaitingLlm,
    ExecutingTool,
    ReportingFinding,
    Completed,
}

/// A finding reported by the agent during investigation.
#[derive(Debug, Clone)]
pub struct AgentFinding {
    pub title: String,
    pub severity: String,
    pub cwe_id: Option<String>,
    pub file_path: String,
    pub line_start: i32,
    pub line_end: Option<i32>,
    pub description: String,
    pub code_snippet: String,
    pub suggested_patch: String,
    pub fix_summary: String,
    pub fix_type: FindingFixType,
    pub references: Vec<String>,
    pub reasoning: Option<String>,
}

/// A single hunt agent that investigates a potential vulnerability
/// through iterative LLM reasoning and tool execution.
pub struct HuntAgent {
    pub scan_id: uuid::Uuid,
    pub repo_id: uuid::Uuid,
    pub state: AgentState,
    pub iteration: u32,
    pub findings: Vec<AgentFinding>,
    messages: Vec<Message>,
    db: Arc<DatabaseOperations>,
    ai: Arc<dyn ModelProvider>,
    default_model: String,
}

impl HuntAgent {
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
            state: AgentState::Planning,
            iteration: 0,
            findings: Vec::new(),
            messages: Vec::new(),
            db,
            ai,
            default_model,
        }
    }

    /// Investigate an attack surface. Returns discovered findings.
    pub async fn investigate(
        &mut self,
        surface: &AttackSurface,
        index: &CodeIndex,
        static_context: &str,
    ) -> HeimdallResult<Vec<AgentFinding>> {
        info!(
            "[{}] Hunt agent investigating: {}",
            self.scan_id, surface.name
        );
        let surface_key = format!("surface-{}", slugify(&surface.name));
        self.record_event(
            Some(&surface_key),
            "running",
            format!("Investigating {}", surface.name).as_str(),
            Some(&format!(
                "Risk {}. {}",
                surface.risk_level, surface.description
            )),
            Some(&serde_json::json!({
                "surface": surface.name,
                "risk_level": surface.risk_level,
                "endpoint": surface.endpoint,
                "file": surface.file,
                "line": surface.line,
            })),
        )
        .await;

        // Build initial prompt
        let code_summary = index.summary_for_llm(8000);
        let system_msg = Message {
            role: "system".to_string(),
            content: HUNT_SYSTEM_PROMPT.to_string(),
        };

        let user_msg = Message {
            role: "user".to_string(),
            content: format!(
                "## Investigation Target\n\
                 **Attack Surface:** {}\n\
                 **Description:** {}\n\
                 **Risk Level:** {}\n\
                 {}\n\
                 {}\n\n\
                 ## Codebase Overview\n\
                 {code_summary}\n\n\
                 ## Static Analysis Context\n\
                 {static_context}\n\n\
                 Begin your investigation. Use the available tools to read files, search code, \
                 trace callers, and examine dependencies. Report any vulnerabilities you find \
                 using the report_finding tool. When your investigation is complete, \
                 respond with \"INVESTIGATION COMPLETE\".",
                surface.name,
                surface.description,
                surface.risk_level,
                surface
                    .endpoint
                    .as_deref()
                    .map(|e| format!("**Endpoint:** {e}"))
                    .unwrap_or_default(),
                surface
                    .file
                    .as_deref()
                    .map(|f| format!(
                        "**File:** {f}{}",
                        surface.line.map(|l| format!(":{l}")).unwrap_or_default()
                    ))
                    .unwrap_or_default(),
            ),
        };

        self.messages = vec![system_msg, user_msg];
        self.state = AgentState::AwaitingLlm;

        // Agent loop
        while self.iteration < MAX_ITERATIONS && self.state != AgentState::Completed {
            self.iteration += 1;
            debug!(
                "[{}] Hunt agent iteration {}/{}",
                self.scan_id, self.iteration, MAX_ITERATIONS
            );

            let request = CompletionRequest {
                model: self.default_model.clone(),
                messages: self.messages.clone(),
                tools: Some(tools::hunt_tool_definitions()),
                max_tokens: Some(4096),
                temperature: Some(0.3),
            };

            let start = std::time::Instant::now();
            let response = match self.ai.complete(request).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        "[{}] Hunt agent LLM error at iteration {}: {e}",
                        self.scan_id, self.iteration
                    );
                    self.record_event(
                        Some(&surface_key),
                        "failed",
                        format!("Investigation stalled for {}", surface.name).as_str(),
                        Some(&format!(
                            "LLM request failed during iteration {}: {e}",
                            self.iteration
                        )),
                        None,
                    )
                    .await;
                    break;
                }
            };
            let duration = start.elapsed();

            // Log the LLM call
            let _ = self
                .db
                .create_agent_tool_call(
                    self.scan_id,
                    "hunt",
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

            // Check for completion
            if response.content.contains("INVESTIGATION COMPLETE") {
                self.state = AgentState::Completed;
                break;
            }

            // Handle tool calls
            if response.stop_reason == StopReason::ToolUse {
                if let Some(ref tool_calls) = response.tool_calls {
                    // Add assistant message with tool calls
                    self.messages.push(Message {
                        role: "assistant".to_string(),
                        content: response.content.clone(),
                    });

                    for tc in tool_calls {
                        self.state = AgentState::ExecutingTool;

                        if tc.name == "report_finding" {
                            // Handle finding report
                            self.state = AgentState::ReportingFinding;
                            let code_snippet = tc.arguments["code_snippet"]
                                .as_str()
                                .unwrap_or("")
                                .trim()
                                .to_string();
                            let suggested_patch = tc.arguments["suggested_patch"]
                                .as_str()
                                .unwrap_or("")
                                .trim()
                                .to_string();
                            let fix_summary = tc.arguments["fix_summary"]
                                .as_str()
                                .unwrap_or("")
                                .trim()
                                .to_string();

                            if code_snippet.is_empty()
                                || suggested_patch.is_empty()
                                || fix_summary.is_empty()
                            {
                                self.messages.push(Message {
                                    role: "user".to_string(),
                                    content: "report_finding rejected: include `code_snippet`, `suggested_patch`, and `fix_summary` with concrete evidence and remediation.".to_string(),
                                });
                                continue;
                            }

                            let finding = AgentFinding {
                                title: tc.arguments["title"]
                                    .as_str()
                                    .unwrap_or("Untitled finding")
                                    .to_string(),
                                severity: tc.arguments["severity"]
                                    .as_str()
                                    .unwrap_or("medium")
                                    .to_string(),
                                cwe_id: tc.arguments["cwe_id"].as_str().map(|s| s.to_string()),
                                file_path: tc.arguments["file_path"]
                                    .as_str()
                                    .unwrap_or("")
                                    .to_string(),
                                line_start: crate::util::sat_i32_i64(
                                    tc.arguments["line_start"].as_i64().unwrap_or(1),
                                ),
                                line_end: tc.arguments["line_end"]
                                    .as_i64()
                                    .map(crate::util::sat_i32_i64),
                                description: tc.arguments["description"]
                                    .as_str()
                                    .unwrap_or("")
                                    .to_string(),
                                code_snippet,
                                suggested_patch,
                                fix_summary,
                                fix_type: parse_fix_type(
                                    tc.arguments["fix_type"].as_str().unwrap_or("code_change"),
                                ),
                                references: tc.arguments["references"]
                                    .as_array()
                                    .map(|values| {
                                        values
                                            .iter()
                                            .filter_map(|value| value.as_str().map(str::to_string))
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                                reasoning: tc.arguments["reasoning"]
                                    .as_str()
                                    .map(|s| s.to_string()),
                            };

                            info!(
                                "[{}] Hunt agent reported finding: {} ({}) at {}:{}",
                                self.scan_id,
                                finding.title,
                                finding.severity,
                                finding.file_path,
                                finding.line_start,
                            );

                            // Save to DB
                            let fingerprint = make_fingerprint(
                                &finding.title,
                                &finding.file_path,
                                finding.line_start,
                            );
                            let _ = self
                                .db
                                .create_finding_full(
                                    self.scan_id,
                                    self.repo_id,
                                    "ai",
                                    &finding.severity,
                                    "medium", // AI findings start at medium confidence until validated
                                    &finding.title,
                                    Some(&finding.description),
                                    finding.cwe_id.as_deref(),
                                    &finding.file_path,
                                    finding.line_start,
                                    finding.line_end,
                                    &fingerprint,
                                    finding.reasoning.as_deref(),
                                    &FindingEvidence {
                                        code_snippet: Some(finding.code_snippet.clone()),
                                        suggested_patch: Some(finding.suggested_patch.clone()),
                                        fix_type: finding.fix_type,
                                        fix_summary: Some(finding.fix_summary.clone()),
                                        references: finding.references.clone(),
                                        manifest_coordinates: None,
                                    },
                                )
                                .await;
                            self.record_event(
                                Some(&surface_key),
                                "completed",
                                format!("Finding reported on {}", surface.name).as_str(),
                                Some(&format!(
                                    "{} at {}:{}",
                                    finding.title, finding.file_path, finding.line_start
                                )),
                                Some(&serde_json::json!({
                                    "severity": finding.severity,
                                    "file_path": finding.file_path,
                                    "line_start": finding.line_start,
                                })),
                            )
                            .await;

                            self.findings.push(finding);

                            // Add tool result
                            self.messages.push(Message {
                                role: "user".to_string(),
                                content: format!(
                                    "Finding recorded. Continue investigating for more vulnerabilities, \
                                     or say \"INVESTIGATION COMPLETE\" if done."
                                ),
                            });
                        } else {
                            // Execute code analysis tool
                            let tool_task_key =
                                format!("{surface_key}:{}:{}", tc.name, self.iteration);
                            self.record_event(
                                Some(&tool_task_key),
                                "running",
                                format!("{} for {}", humanize_tool_name(&tc.name), surface.name)
                                    .as_str(),
                                Some(&tool_detail(&tc.name, &tc.arguments)),
                                Some(&serde_json::json!({
                                    "surface": surface.name,
                                    "tool": tc.name,
                                    "arguments": tc.arguments,
                                    "iteration": self.iteration,
                                })),
                            )
                            .await;
                            let start = std::time::Instant::now();
                            let result = tools::execute_tool(&tc.name, &tc.arguments, index);
                            let tool_duration = start.elapsed();

                            // Log tool call
                            let _ = self
                                .db
                                .create_agent_tool_call(
                                    self.scan_id,
                                    "hunt",
                                    &tc.name,
                                    None,
                                    None,
                                    Some(&tc.arguments),
                                    Some(&serde_json::json!({"output": result.output, "success": result.success})),
                                    None,
                                    None,
                                    None,
                                    Some(sat_i32_u128(duration.as_millis())),
                                    if result.success { None } else { Some(&result.output) },
                                )
                                .await;
                            let tool_title =
                                format!("{} for {}", humanize_tool_name(&tc.name), surface.name);
                            let tool_detail_text = if result.success {
                                format!(
                                    "{} completed in {} ms.",
                                    humanize_tool_name(&tc.name),
                                    tool_duration.as_millis()
                                )
                            } else {
                                result.output.clone()
                            };
                            self.record_event(
                                Some(&tool_task_key),
                                if result.success {
                                    "completed"
                                } else {
                                    "failed"
                                },
                                &tool_title,
                                Some(&tool_detail_text),
                                Some(&serde_json::json!({
                                    "surface": surface.name,
                                    "tool": tc.name,
                                    "duration_ms": sat_i32_u128(duration.as_millis()),
                                })),
                            )
                            .await;

                            // Feed result back as user message (tool_result role)
                            self.messages.push(Message {
                                role: "user".to_string(),
                                content: format!("[Tool Result: {}]\n{}", tc.name, result.output),
                            });
                        }
                    }
                    self.state = AgentState::AwaitingLlm;
                }
            } else {
                // Text-only response — add to conversation and continue
                self.messages.push(Message {
                    role: "assistant".to_string(),
                    content: response.content.clone(),
                });

                if response.stop_reason == StopReason::EndTurn {
                    // LLM ended its turn without tool use — might be done
                    self.state = AgentState::Completed;
                }
            }
        }

        if self.iteration >= MAX_ITERATIONS {
            warn!(
                "[{}] Hunt agent hit iteration limit for surface: {}",
                self.scan_id, surface.name
            );
        }

        self.record_event(
            Some(&surface_key),
            "completed",
            format!("Investigation finished for {}", surface.name).as_str(),
            Some(&format!(
                "{} findings recorded after {} iterations.",
                self.findings.len(),
                self.iteration
            )),
            Some(&serde_json::json!({
                "findings": self.findings.len(),
                "iterations": self.iteration,
            })),
        )
        .await;

        info!(
            "[{}] Hunt agent completed: {} findings in {} iterations",
            self.scan_id,
            self.findings.len(),
            self.iteration,
        );

        Ok(self.findings.clone())
    }

    async fn record_event(
        &self,
        task_key: Option<&str>,
        status: &str,
        title: &str,
        detail: Option<&str>,
        metadata_json: Option<&serde_json::Value>,
    ) {
        let _ = self
            .db
            .create_scan_event(
                self.scan_id,
                Some("hunt"),
                task_key,
                "task",
                Some(status),
                title,
                detail,
                None,
                metadata_json,
            )
            .await;
    }
}

fn make_fingerprint(title: &str, file: &str, line: i32) -> String {
    let input = format!("hunt:{title}:{file}:{line}");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn slugify(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn humanize_tool_name(tool_name: &str) -> &'static str {
    match tool_name {
        "read_file" => "Reading file",
        "search_code" => "Searching code",
        "ast_search" => "AST pattern search",
        "get_callers" => "Tracing callers",
        "get_dependencies" => "Tracing dependencies",
        "report_finding" => "Reporting finding",
        "list_files" => "Listing files",
        "get_symbol" => "Looking up symbol",
        "find_data_flows" => "Tracing data flows",
        _ => "Running tool",
    }
}

fn tool_detail(tool_name: &str, arguments: &serde_json::Value) -> String {
    match tool_name {
        "read_file" => format!(
            "Reading {}.",
            arguments["file_path"]
                .as_str()
                .unwrap_or("the requested file")
        ),
        "search_code" => format!(
            "Searching for `{}`{}.",
            arguments["query"]
                .as_str()
                .unwrap_or("the requested pattern"),
            arguments["file_glob"]
                .as_str()
                .map(|glob| format!(" within {glob}"))
                .unwrap_or_default()
        ),
        "ast_search" => format!(
            "AST search for `{}` in {} files{}.",
            arguments["pattern"]
                .as_str()
                .unwrap_or("the requested pattern"),
            arguments["language"].as_str().unwrap_or("the specified"),
            arguments["file_glob"]
                .as_str()
                .map(|glob| format!(" within {glob}"))
                .unwrap_or_default()
        ),
        "get_callers" => format!(
            "Tracing call sites for {}.",
            arguments["symbol"]
                .as_str()
                .unwrap_or("the requested symbol")
        ),
        "get_dependencies" => format!(
            "Inspecting dependency edges for {}.",
            arguments["file_path"]
                .as_str()
                .unwrap_or("the requested file")
        ),
        "list_files" => format!(
            "Browsing files{}{}.",
            arguments["directory"]
                .as_str()
                .map(|d| format!(" under {d}"))
                .unwrap_or_default(),
            arguments["extension"]
                .as_str()
                .map(|e| format!(" (*.{e})"))
                .unwrap_or_default()
        ),
        "get_symbol" => format!(
            "Looking up symbol `{}`{}.",
            arguments["name"].as_str().unwrap_or("the requested symbol"),
            arguments["file_path"]
                .as_str()
                .map(|f| format!(" in {f}"))
                .unwrap_or_default()
        ),
        "find_data_flows" => format!(
            "Tracing data flows for pattern `{}`{}.",
            arguments["source_pattern"]
                .as_str()
                .unwrap_or("the requested pattern"),
            arguments["file_path"]
                .as_str()
                .map(|f| format!(" in {f}"))
                .unwrap_or_default()
        ),
        _ => "Running investigation tool.".to_string(),
    }
}

const HUNT_SYSTEM_PROMPT: &str = "\
You are a Hunt agent — part of Heimdall, an agentic security scanner. \
Your job is to investigate potential vulnerabilities and logic flaws in a codebase \
by reasoning like a senior security researcher and code auditor.

**Your workflow:**
1. Read the attack surface description and formulate an investigation plan
2. Use tools to read files, search code, trace callers, and examine dependencies
3. Investigate both **security vulnerabilities** and **logic flaws**
4. When you find an issue with sufficient evidence, report it using the `report_finding` tool
5. Continue investigating — there may be multiple issues in the same area
6. When done, respond with the exact text: INVESTIGATION COMPLETE

**Security vulnerabilities to hunt:**
- Injection: SQL, command, path traversal, LDAP, XSS, SSTI, header injection
- Auth: authentication bypasses, authorization flaws, IDOR, privilege escalation, session issues
- Data: SSRF, insecure deserialization, hardcoded credentials, cryptographic misuse
- Config: security misconfigurations, overly permissive CORS, missing security headers

**Logic flaws to hunt:**
- Race conditions and TOCTOU bugs (e.g., check-then-act without locks)
- Off-by-one errors in loops, array indexing, pagination, or boundary checks
- State machine violations (e.g., actions allowed in wrong state, missing state transitions)
- Business logic bypasses (e.g., price manipulation, skipping workflow steps, \
  discount stacking, negative quantity)
- Missing edge case handling (empty inputs, zero values, MAX_INT, Unicode, null bytes)
- Incorrect error handling (swallowed errors, wrong fallback behavior, partial rollbacks)
- Resource leaks (unclosed connections, file handles, goroutines/tasks never cancelled)
- Inconsistent validation (validated in one path but not another, client-side only)
- Concurrency bugs (shared mutable state without synchronization, deadlock potential)

**Rules:**
- Only report findings you have strong evidence for — not theoretical concerns
- Trace data flow from user input to dangerous sinks
- Check for missing authentication, authorization, and input validation
        - Each finding needs: title, severity, file, line, description, code_snippet, fix_summary, and suggested_patch
        - Choose the right `fix_type`: code_change, config_change, dependency_upgrade, or manual_review
        - Even for manual review findings, provide a concrete next-step remediation block in `suggested_patch`
        - For logic flaws, explain the concrete scenario that triggers the bug
        - Do NOT report findings that are clearly covered by existing static analysis
        - Be thorough but efficient — you have a limited iteration budget";

fn parse_fix_type(value: &str) -> FindingFixType {
    match value {
        "dependency_upgrade" => FindingFixType::DependencyUpgrade,
        "config_change" => FindingFixType::ConfigChange,
        "manual_review" => FindingFixType::ManualReview,
        _ => FindingFixType::CodeChange,
    }
}
