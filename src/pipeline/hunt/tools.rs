//
//  heimdall
//  src/pipeline/hunt/tools.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use crate::ai::types::ToolDefinition;
use crate::index::CodeIndex;
use serde::{Deserialize, Serialize};

/// Tools available to the hunt agent for code investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTool {
    ReadFile,
    SearchCode,
    GetCallers,
    GetDependencies,
    ReportFinding,
}

/// Result of executing an agent tool.
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub tool_name: String,
    pub output: String,
    pub success: bool,
}

/// Execute a tool call against the code index.
pub fn execute_tool(
    tool_name: &str,
    arguments: &serde_json::Value,
    index: &CodeIndex,
) -> ToolResult {
    match tool_name {
        "read_file" => execute_read_file(arguments, index),
        "search_code" => execute_search_code(arguments, index),
        "get_callers" => execute_get_callers(arguments, index),
        "get_dependencies" => execute_get_dependencies(arguments, index),
        _ => ToolResult {
            tool_name: tool_name.to_string(),
            output: format!("Unknown tool: {tool_name}"),
            success: false,
        },
    }
}

fn execute_read_file(args: &serde_json::Value, index: &CodeIndex) -> ToolResult {
    let file_path = args["file_path"].as_str().unwrap_or("");

    match index.read_file(file_path) {
        Some(content) => {
            // Truncate very large files for LLM context
            let truncated = if content.len() > 15000 {
                format!(
                    "{}\n\n... [truncated — file is {} bytes total]",
                    &content[..15000],
                    content.len()
                )
            } else {
                content.to_string()
            };

            ToolResult {
                tool_name: "read_file".to_string(),
                output: truncated,
                success: true,
            }
        }
        None => ToolResult {
            tool_name: "read_file".to_string(),
            output: format!("File not found: {file_path}"),
            success: false,
        },
    }
}

fn execute_search_code(args: &serde_json::Value, index: &CodeIndex) -> ToolResult {
    let query = args["query"].as_str().unwrap_or("");
    let file_glob = args["file_glob"].as_str();

    let matches = index.search.search(query, file_glob);

    if matches.is_empty() {
        return ToolResult {
            tool_name: "search_code".to_string(),
            output: format!("No matches found for: {query}"),
            success: true,
        };
    }

    let mut output = format!("Found {} matches for `{query}`:\n\n", matches.len());
    for (i, m) in matches.iter().enumerate().take(30) {
        output.push_str(&format!("{}. {}:{}\n", i + 1, m.file, m.line));
        for ctx in &m.context_before {
            output.push_str(&format!("   {ctx}\n"));
        }
        output.push_str(&format!(">> {}\n", m.content));
        for ctx in &m.context_after {
            output.push_str(&format!("   {ctx}\n"));
        }
        output.push('\n');
    }

    if matches.len() > 30 {
        output.push_str(&format!("... and {} more matches\n", matches.len() - 30));
    }

    ToolResult {
        tool_name: "search_code".to_string(),
        output,
        success: true,
    }
}

fn execute_get_callers(args: &serde_json::Value, index: &CodeIndex) -> ToolResult {
    let symbol = args["symbol"].as_str().unwrap_or("");
    let output = index.callgraph.callers_summary(symbol);

    ToolResult {
        tool_name: "get_callers".to_string(),
        output,
        success: true,
    }
}

fn execute_get_dependencies(args: &serde_json::Value, index: &CodeIndex) -> ToolResult {
    let file_path = args["file_path"].as_str().unwrap_or("");
    let output = index.deps.deps_summary(file_path);

    ToolResult {
        tool_name: "get_dependencies".to_string(),
        output,
        success: true,
    }
}

/// Tool definitions for the LLM (used in CompletionRequest.tools).
pub fn hunt_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "read_file".to_string(),
            description: "Read the contents of a specific file in the codebase".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path to the file to read"
                    }
                },
                "required": ["file_path"]
            }),
        },
        ToolDefinition {
            name: "search_code".to_string(),
            description: "Search across the codebase using text or regex patterns".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search pattern (text or regex)"
                    },
                    "file_glob": {
                        "type": "string",
                        "description": "Optional glob pattern to filter files (e.g., '*.py', 'src/**/*.rs')"
                    }
                },
                "required": ["query"]
            }),
        },
        ToolDefinition {
            name: "get_callers".to_string(),
            description: "Find all call sites of a given function or method".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "description": "Name of the function or method to find callers for"
                    }
                },
                "required": ["symbol"]
            }),
        },
        ToolDefinition {
            name: "get_dependencies".to_string(),
            description: "Get the dependency graph for a file — what it imports and what depends on it".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path to the file"
                    }
                },
                "required": ["file_path"]
            }),
        },
        ToolDefinition {
            name: "report_finding".to_string(),
            description: "Report a vulnerability finding with evidence".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short title of the vulnerability"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "Severity level"
                    },
                    "cwe_id": {
                        "type": "string",
                        "description": "CWE identifier (e.g., CWE-89)"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "File where the vulnerability exists"
                    },
                    "line_start": {
                        "type": "integer",
                        "description": "Starting line number"
                    },
                    "line_end": {
                        "type": "integer",
                        "description": "Ending line number (optional)"
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description of the vulnerability and how to exploit it"
                    },
                    "code_snippet": {
                        "type": "string",
                        "description": "The vulnerable code snippet"
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Step-by-step reasoning that led to this finding"
                    }
                },
                "required": ["title", "severity", "file_path", "line_start", "description"]
            }),
        },
    ]
}
