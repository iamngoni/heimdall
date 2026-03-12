//
//  heimdall
//  src/pipeline/vidarr/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/12.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use log::{info, warn};

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, Message};
use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::HeimdallResult;
use crate::models::db_models::Finding;

/// Víðarr — the adversarial verification stage.
/// For each finding, it asks an AI agent to *try to disprove* it by examining
/// the actual code context. Findings that survive the challenge keep or gain
/// confidence; those that don't are downgraded or dismissed.
pub struct VidarrStage {
    pub scan_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
    pub ai: Arc<dyn ModelProvider>,
    pub default_model: String,
}

/// Víðarr's verdict for a single finding.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub finding_id: uuid::Uuid,
    pub outcome: VerdictOutcome,
    pub reasoning: String,
    pub adjusted_severity: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VerdictOutcome {
    /// Finding is real and exploitable
    Confirmed,
    /// Finding is plausible but cannot be confirmed or denied
    Plausible,
    /// Finding is likely a false positive
    FalsePositive,
}

/// Summary returned to the pipeline orchestrator.
pub struct VidarrContext {
    pub total: usize,
    pub confirmed: usize,
    pub plausible: usize,
    pub dismissed: usize,
}

impl VidarrStage {
    pub fn new(
        scan_id: uuid::Uuid,
        db: Arc<DatabaseOperations>,
        ai: Arc<dyn ModelProvider>,
        default_model: String,
    ) -> Self {
        Self {
            scan_id,
            db,
            ai,
            default_model,
        }
    }

    pub async fn run(
        &self,
        findings: &[Finding],
        index: &CodeIndex,
    ) -> HeimdallResult<VidarrContext> {
        if findings.is_empty() {
            return Ok(VidarrContext {
                total: 0,
                confirmed: 0,
                plausible: 0,
                dismissed: 0,
            });
        }

        info!(
            "[{}] Vidarr: challenging {} findings",
            self.scan_id,
            findings.len()
        );

        let mut confirmed = 0usize;
        let mut plausible = 0usize;
        let mut dismissed = 0usize;

        for finding in findings {
            match self.challenge_finding(finding, index).await {
                Ok(verdict) => {
                    match verdict.outcome {
                        VerdictOutcome::Confirmed => {
                            confirmed += 1;
                            // Bump confidence to high — the adversary couldn't disprove it
                            self.db
                                .update_finding_confidence(finding.id, "high")
                                .await
                                .ok();
                            // If the vidarr suggests a severity adjustment, apply it
                            if let Some(ref sev) = verdict.adjusted_severity {
                                if sev != &finding.severity {
                                    self.db
                                        .update_finding_severity(finding.id, sev)
                                        .await
                                        .ok();
                                }
                            }
                            info!(
                                "[{}] Vidarr CONFIRMED finding {}: {}",
                                self.scan_id, finding.id, finding.title
                            );
                        }
                        VerdictOutcome::Plausible => {
                            plausible += 1;
                            // Keep existing confidence (medium for AI, high for static)
                            info!(
                                "[{}] Vidarr PLAUSIBLE finding {}: {}",
                                self.scan_id, finding.id, finding.title
                            );
                        }
                        VerdictOutcome::FalsePositive => {
                            dismissed += 1;
                            // Mark as false_positive so it's filtered from default views
                            self.db
                                .update_finding_status(finding.id, "false_positive")
                                .await
                                .ok();
                            self.db
                                .update_finding_confidence(finding.id, "low")
                                .await
                                .ok();
                            info!(
                                "[{}] Vidarr DISMISSED finding {}: {} — {}",
                                self.scan_id, finding.id, finding.title, verdict.reasoning
                            );
                        }
                    }
                    // Store the vidarr's reasoning on the finding
                    self.db
                        .append_finding_vidarr_reasoning(finding.id, &verdict.reasoning)
                        .await
                        .ok();
                }
                Err(e) => {
                    warn!(
                        "[{}] Vidarr failed to challenge finding {}: {e:#}",
                        self.scan_id, finding.id
                    );
                    // On error, leave the finding as-is (fail open — don't dismiss findings
                    // just because the vidarr errored)
                    plausible += 1;
                }
            }
        }

        let total = findings.len();
        info!(
            "[{}] Vidarr complete: {confirmed} confirmed, {plausible} plausible, {dismissed} dismissed out of {total}",
            self.scan_id
        );

        Ok(VidarrContext {
            total,
            confirmed,
            plausible,
            dismissed,
        })
    }

    /// Challenge a single finding by asking an adversarial AI agent to disprove it.
    async fn challenge_finding(
        &self,
        finding: &Finding,
        index: &CodeIndex,
    ) -> HeimdallResult<Verdict> {
        // Gather code context around the finding
        let code_context = self.gather_code_context(finding, index);

        let prompt = format!(
            "## Finding Under Review\n\
             **Title:** {title}\n\
             **Severity:** {severity}\n\
             **File:** {file}:{line}\n\
             **CWE:** {cwe}\n\
             **Description:** {description}\n\
             {snippet_section}\
             {reasoning_section}\
             \n## Code Context\n\
             {code_context}\n\
             \n## Your Task\n\
             Analyze this finding adversarially. Try to DISPROVE it by looking for:\n\
             1. **Input validation/sanitization** that prevents exploitation (e.g., parameterized queries, \
                escaping, allowlists)\n\
             2. **Authentication/authorization guards** that restrict access to the vulnerable path\n\
             3. **Framework protections** that automatically mitigate the issue (e.g., ORM parameterization, \
                template auto-escaping, CSRF middleware)\n\
             4. **Dead code** — is this code actually reachable from user input?\n\
             5. **Context errors** — is the finding based on a misreading of the code?\n\
             6. **Severity accuracy** — even if real, is the severity overstated?\n\
             \nRespond with EXACTLY this JSON format (no markdown fences):\n\
             {{\n\
               \"verdict\": \"confirmed\" | \"plausible\" | \"false_positive\",\n\
               \"reasoning\": \"Your detailed reasoning for the verdict\",\n\
               \"adjusted_severity\": \"critical\" | \"high\" | \"medium\" | \"low\" | null\n\
             }}",
            title = finding.title,
            severity = finding.severity,
            file = finding.file_path,
            line = finding.line_start,
            cwe = finding.cwe_id.as_deref().unwrap_or("N/A"),
            description = finding.description.as_deref().unwrap_or("No description"),
            snippet_section = finding
                .code_snippet
                .as_ref()
                .map(|s| format!("\n**Vulnerable Code:**\n```\n{s}\n```\n"))
                .unwrap_or_default(),
            reasoning_section = finding
                .agent_reasoning
                .as_ref()
                .map(|r| format!("\n**Original Agent Reasoning:** {r}\n"))
                .unwrap_or_default(),
            code_context = code_context,
        );

        let request = CompletionRequest {
            model: self.default_model.clone(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: SKEPTIC_SYSTEM_PROMPT.to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: prompt,
                },
            ],
            tools: None,
            max_tokens: Some(2048),
            temperature: Some(0.2),
        };

        let response = self.ai.complete(request).await?;

        // Record the LLM call
        let input_json = serde_json::json!({ "finding_id": finding.id, "title": finding.title });
        let output_json = serde_json::json!({ "raw_response": &response.content });
        self.db
            .create_agent_tool_call(
                self.scan_id,
                "vidarr",
                "challenge_finding",
                Some(&response.provider),
                Some(&response.model),
                Some(&input_json),
                Some(&output_json),
                Some(response.usage.prompt_tokens as i32),
                Some(response.usage.completion_tokens as i32),
                Some(response.usage.total_tokens as i32),
                None,
                None,
            )
            .await
            .ok();

        // Parse the verdict
        self.parse_verdict(finding.id, &response.content)
    }

    /// Parse the LLM response into a Verdict.
    fn parse_verdict(
        &self,
        finding_id: uuid::Uuid,
        raw: &str,
    ) -> HeimdallResult<Verdict> {
        // Try to extract JSON from the response (handle markdown fences)
        let json_str = raw
            .trim()
            .strip_prefix("```json")
            .or_else(|| raw.trim().strip_prefix("```"))
            .unwrap_or(raw.trim())
            .strip_suffix("```")
            .unwrap_or(raw.trim())
            .trim();

        let parsed: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| anyhow::anyhow!("Vidarr returned invalid JSON: {e}\nRaw: {raw}"))?;

        let verdict_str = parsed["verdict"]
            .as_str()
            .unwrap_or("plausible");

        let outcome = match verdict_str {
            "confirmed" => VerdictOutcome::Confirmed,
            "false_positive" => VerdictOutcome::FalsePositive,
            _ => VerdictOutcome::Plausible,
        };

        let reasoning = parsed["reasoning"]
            .as_str()
            .unwrap_or("No reasoning provided")
            .to_string();

        let adjusted_severity = parsed["adjusted_severity"]
            .as_str()
            .filter(|s| ["critical", "high", "medium", "low"].contains(s))
            .map(|s| s.to_string());

        Ok(Verdict {
            finding_id,
            outcome,
            reasoning,
            adjusted_severity,
        })
    }

    /// Gather surrounding code context for the finding.
    fn gather_code_context(&self, finding: &Finding, index: &CodeIndex) -> String {
        // Try to read the file from the index
        let file_content = index
            .files
            .get(&finding.file_path)
            .map(|f| &f.content);

        let Some(content) = file_content else {
            return format!("(File {} not found in code index)", finding.file_path);
        };

        let lines: Vec<&str> = content.lines().collect();
        let start = (finding.line_start as usize).saturating_sub(16);
        let end_line = finding
            .line_end
            .map(|e| e as usize)
            .unwrap_or(finding.line_start as usize);
        let end = (end_line + 16).min(lines.len());

        let mut context = String::new();
        for (i, line) in lines[start..end].iter().enumerate() {
            let line_num = start + i + 1;
            context.push_str(&format!("{line_num:>5} | {line}\n"));
        }

        // Also check if there are callers of functions in the finding area
        // to understand reachability
        let callers_info = self.gather_caller_info(finding, index);

        if callers_info.is_empty() {
            context
        } else {
            format!(
                "{context}\n## Call Sites (reachability evidence)\n{callers_info}"
            )
        }
    }

    /// Find callers of symbols near the finding location to assess reachability.
    fn gather_caller_info(&self, finding: &Finding, index: &CodeIndex) -> String {
        let mut info = String::new();

        // Find symbols defined in the finding file near the finding line
        let symbols = index.symbols.symbols_in_file(&finding.file_path);
        for symbol in symbols {
            let sym_line = symbol.line as i32;
            let finding_end = finding.line_end.unwrap_or(finding.line_start);
            // Symbol is near the finding
            if sym_line >= finding.line_start - 5 && sym_line <= finding_end + 5 {
                let callers = index.callgraph.get_callers(&symbol.name);
                if !callers.is_empty() {
                    info.push_str(&format!(
                        "- `{}` is called from:\n",
                        symbol.name
                    ));
                    for caller in callers.iter().take(5) {
                        info.push_str(&format!(
                            "  - {}:{}\n",
                            caller.file, caller.line
                        ));
                    }
                }
            }
        }

        info
    }
}

const SKEPTIC_SYSTEM_PROMPT: &str = "\
You are Víðarr — the silent judge of Heimdall's security scanner. \
Named after the Norse god of vengeance and silence, your sole purpose is to \
challenge findings and try to DISPROVE them.

**Your mindset:**
- Assume every finding might be a false positive until proven otherwise
- Look for mitigating controls the original agent may have missed
- Check if framework-level protections already handle the threat
- Verify the vulnerable code path is actually reachable from user input
- Consider whether the severity accurately reflects the real-world impact

**Verdict criteria:**
- **confirmed**: You tried to disprove it but could NOT. The vulnerability is real, \
  the code path is reachable, and no mitigating controls prevent exploitation.
- **plausible**: You found partial mitigations or couldn't fully determine reachability, \
  but the finding has enough merit to keep investigating.
- **false_positive**: You found clear evidence that the finding is wrong — either the code \
  is unreachable, framework protections prevent exploitation, input validation blocks \
  the attack vector, or the finding is based on a misreading of the code.

**Rules:**
- Be rigorous but fair — don't dismiss findings without concrete evidence
- If in doubt, verdict should be \"plausible\" — err on the side of caution
- Always provide detailed reasoning explaining your analysis
- If the severity is wrong (too high or too low), suggest an adjustment
- Consider the FULL code context, not just the snippet";
