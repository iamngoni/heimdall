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
use crate::models::HeimdallResult;
use crate::pipeline::hunt::tools;
use crate::pipeline::tyr::AttackSurface;

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
    pub code_snippet: Option<String>,
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
                        surface
                            .line
                            .map(|l| format!(":{l}"))
                            .unwrap_or_default()
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
                    None,
                    None,
                    Some(response.usage.prompt_tokens as i32),
                    Some(response.usage.completion_tokens as i32),
                    Some(response.usage.total_tokens as i32),
                    Some(duration.as_millis() as i32),
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
                            let finding = AgentFinding {
                                title: tc.arguments["title"]
                                    .as_str()
                                    .unwrap_or("Untitled finding")
                                    .to_string(),
                                severity: tc.arguments["severity"]
                                    .as_str()
                                    .unwrap_or("medium")
                                    .to_string(),
                                cwe_id: tc.arguments["cwe_id"]
                                    .as_str()
                                    .map(|s| s.to_string()),
                                file_path: tc.arguments["file_path"]
                                    .as_str()
                                    .unwrap_or("")
                                    .to_string(),
                                line_start: tc.arguments["line_start"]
                                    .as_i64()
                                    .unwrap_or(1) as i32,
                                line_end: tc.arguments["line_end"]
                                    .as_i64()
                                    .map(|v| v as i32),
                                description: tc.arguments["description"]
                                    .as_str()
                                    .unwrap_or("")
                                    .to_string(),
                                code_snippet: tc.arguments["code_snippet"]
                                    .as_str()
                                    .map(|s| s.to_string()),
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
                                    finding.code_snippet.as_deref(),
                                    &fingerprint,
                                    finding.reasoning.as_deref(),
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
                            let start = std::time::Instant::now();
                            let result =
                                tools::execute_tool(&tc.name, &tc.arguments, index);
                            let tool_duration = start.elapsed();

                            // Log tool call
                            let _ = self
                                .db
                                .create_agent_tool_call(
                                    self.scan_id,
                                    "hunt",
                                    &tc.name,
                                    Some(&tc.arguments),
                                    Some(&serde_json::json!({"output": result.output, "success": result.success})),
                                    None,
                                    None,
                                    None,
                                    Some(tool_duration.as_millis() as i32),
                                    if result.success { None } else { Some(&result.output) },
                                )
                                .await;

                            // Feed result back as user message (tool_result role)
                            self.messages.push(Message {
                                role: "user".to_string(),
                                content: format!(
                                    "[Tool Result: {}]\n{}",
                                    tc.name, result.output
                                ),
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

        info!(
            "[{}] Hunt agent completed: {} findings in {} iterations",
            self.scan_id,
            self.findings.len(),
            self.iteration,
        );

        Ok(self.findings.clone())
    }
}

fn make_fingerprint(title: &str, file: &str, line: i32) -> String {
    let input = format!("hunt:{title}:{file}:{line}");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

const HUNT_SYSTEM_PROMPT: &str = "\
You are a Hunt agent — part of Heimdall, an agentic security scanner. \
Your job is to investigate potential vulnerabilities in a codebase by reasoning like a security researcher.

**Your workflow:**
1. Read the attack surface description and formulate an investigation plan
2. Use tools to read files, search code, trace callers, and examine dependencies
3. Look for real vulnerabilities: SQL injection, command injection, path traversal, \
   authentication bypasses, authorization flaws, SSRF, IDOR, XSS, \
   insecure deserialization, hardcoded credentials, cryptographic misuse, etc.
4. When you find a vulnerability with sufficient evidence, report it using the `report_finding` tool
5. Continue investigating — there may be multiple vulnerabilities in the same area
6. When done, respond with the exact text: INVESTIGATION COMPLETE

**Rules:**
- Only report findings you have strong evidence for — not theoretical concerns
- Trace data flow from user input to dangerous sinks
- Check for missing authentication, authorization, and input validation
- Look for logic flaws, not just pattern matches
- Each finding needs: title, severity, file, line, description, and ideally a code snippet
- Do NOT report findings that are clearly covered by existing static analysis
- Be thorough but efficient — you have a limited iteration budget";
