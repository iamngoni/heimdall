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
    ListFiles,
    GetSymbol,
    FindDataFlows,
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
        "list_files" => execute_list_files(arguments, index),
        "get_symbol" => execute_get_symbol(arguments, index),
        "find_data_flows" => execute_find_data_flows(arguments, index),
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

/// Browse the file/directory structure of the codebase.
/// Optionally filter by directory prefix and/or file extension.
fn execute_list_files(args: &serde_json::Value, index: &CodeIndex) -> ToolResult {
    let directory = args["directory"].as_str().unwrap_or("");
    let extension = args["extension"].as_str();

    let mut matching: Vec<(&str, usize)> = index
        .files
        .iter()
        .filter(|(path, _)| {
            if !directory.is_empty() && !path.starts_with(directory) {
                return false;
            }
            if let Some(ext) = extension {
                let dot_ext = format!(".{ext}");
                if !path.ends_with(&dot_ext) {
                    return false;
                }
            }
            true
        })
        .map(|(path, file)| (path.as_str(), file.line_count))
        .collect();

    matching.sort_by_key(|(path, _)| path.to_string());

    if matching.is_empty() {
        let filter_desc = match (directory.is_empty(), extension) {
            (true, None) => "the codebase".to_string(),
            (false, None) => format!("directory `{directory}`"),
            (true, Some(ext)) => format!("extension `.{ext}`"),
            (false, Some(ext)) => format!("directory `{directory}` with extension `.{ext}`"),
        };
        return ToolResult {
            tool_name: "list_files".to_string(),
            output: format!("No files found in {filter_desc}"),
            success: true,
        };
    }

    let mut output = format!("Found {} files:\n\n", matching.len());
    for (path, line_count) in &matching {
        output.push_str(&format!("  {path}  ({line_count} lines)\n"));
    }

    ToolResult {
        tool_name: "list_files".to_string(),
        output,
        success: true,
    }
}

/// Look up the full definition of a specific function, class, struct, or method.
fn execute_get_symbol(args: &serde_json::Value, index: &CodeIndex) -> ToolResult {
    let name = args["name"].as_str().unwrap_or("");
    let file_path = args["file_path"].as_str();

    if name.is_empty() {
        return ToolResult {
            tool_name: "get_symbol".to_string(),
            output: "Missing required parameter: name".to_string(),
            success: false,
        };
    }

    let symbols = index.symbols.find(name);
    let symbols: Vec<_> = if let Some(fp) = file_path {
        symbols.into_iter().filter(|s| s.file == fp).collect()
    } else {
        symbols
    };

    if symbols.is_empty() {
        let qualifier = file_path
            .map(|f| format!(" in {f}"))
            .unwrap_or_default();
        return ToolResult {
            tool_name: "get_symbol".to_string(),
            output: format!("Symbol `{name}` not found{qualifier}"),
            success: false,
        };
    }

    let mut output = format!("Found {} definition(s) for `{name}`:\n\n", symbols.len());
    for sym in &symbols {
        output.push_str(&format!(
            "### {} `{}` at {}:{}\n",
            sym.kind, sym.name, sym.file, sym.line
        ));
        output.push_str(&format!("- Public: {}\n", sym.is_public));
        if !sym.calls.is_empty() {
            output.push_str(&format!("- Calls: {}\n", sym.calls.join(", ")));
        }

        // Read the source around this symbol from the indexed file
        if let Some(content) = index.read_file(&sym.file) {
            let lines: Vec<&str> = content.lines().collect();
            let start = sym.line.saturating_sub(1); // 1-based to 0-based
            // Heuristic: read up to 60 lines from the symbol start for its body
            let end = (start + 60).min(lines.len());
            if start >= lines.len() || start >= end {
                // Avoid panicking if the symbol line is beyond the current file length
                output.push_str(&format!(
                    "\n```text\n\
Unable to display source for `{}` at {}:{}: recorded line {} is beyond the indexed file length ({} lines).\n\
```\n\n",
                    sym.name,
                    sym.file,
                    sym.line,
                    sym.line,
                    lines.len()
                ));
            } else {
                let snippet: String = lines[start..end]
                    .iter()
                    .enumerate()
                    .map(|(i, l)| format!("{:>4} | {l}", start + i + 1))
                    .collect::<Vec<_>>()
                    .join("\n");

                output.push_str(&format!("\n```\n{snippet}\n```\n\n"));
            }
        }
    }

    ToolResult {
        tool_name: "get_symbol".to_string(),
        output,
        success: true,
    }
}

/// Trace where a pattern (source/taint) flows through the codebase via
/// search matches and call graph edges — a rough data-flow / taint trace.
fn execute_find_data_flows(args: &serde_json::Value, index: &CodeIndex) -> ToolResult {
    let source_pattern = args["source_pattern"].as_str().unwrap_or("");
    let file_path = args["file_path"].as_str();
    const MAX_DEPTH_LIMIT: usize = 10;
    const MAX_CALLERS_PER_FUNC: usize = 20;
    const MAX_TOTAL_EDGES: usize = 200;
    let max_depth = (args["max_depth"].as_u64().unwrap_or(2) as usize).min(MAX_DEPTH_LIMIT);

    if source_pattern.is_empty() {
        return ToolResult {
            tool_name: "find_data_flows".to_string(),
            output: "Missing required parameter: source_pattern".to_string(),
            success: false,
        };
    }

    let file_glob = file_path.map(|f| {
        // Convert exact path to a glob that matches just that file
        f.to_string()
    });

    // Step 1: find all locations matching the source pattern
    let initial_matches = index.search.search(source_pattern, file_glob.as_deref());

    if initial_matches.is_empty() {
        return ToolResult {
            tool_name: "find_data_flows".to_string(),
            output: format!("No matches found for pattern: `{source_pattern}`"),
            success: true,
        };
    }

    let mut output = format!(
        "Data flow trace for `{source_pattern}` (max depth {max_depth}):\n\n"
    );

    // Show initial source locations
    output.push_str(&format!(
        "## Sources ({} matches)\n\n",
        initial_matches.len()
    ));
    for (i, m) in initial_matches.iter().enumerate().take(20) {
        output.push_str(&format!("{}. {}:{} — {}\n", i + 1, m.file, m.line, m.content.trim()));
    }
    if initial_matches.len() > 20 {
        output.push_str(&format!("... and {} more\n", initial_matches.len() - 20));
    }

    // Step 2: identify which functions contain these matches, then trace callers
    // up to max_depth hops
    let mut seen_functions: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut current_functions: Vec<String> = Vec::new();

    // Find functions that contain the matched lines
    for m in &initial_matches {
        let syms = index.symbols.symbols_in_file(&m.file);
        for sym in syms {
            if (sym.kind == "function" || sym.kind == "method")
                && sym.line <= m.line
                && !seen_functions.contains(&sym.name)
            {
                seen_functions.insert(sym.name.clone());
                current_functions.push(sym.name.clone());
            }
        }
    }

    if current_functions.is_empty() {
        output.push_str("\nNo containing functions identified for caller tracing.\n");
        return ToolResult {
            tool_name: "find_data_flows".to_string(),
            output,
            success: true,
        };
    }

    // Trace callers breadth-first up to max_depth
    let mut total_edges: usize = 0;
    'outer: for depth in 1..=max_depth {
        if current_functions.is_empty() {
            break;
        }

        output.push_str(&format!("\n## Depth {} — callers\n\n", depth));
        let mut next_functions: Vec<String> = Vec::new();

        for func in &current_functions {
            let callers = index.callgraph.get_callers(func);
            if callers.is_empty() {
                output.push_str(&format!("- `{func}` — no callers found\n"));
            } else {
                let mut shown = 0usize;
                for edge in &callers {
                    if total_edges >= MAX_TOTAL_EDGES {
                        output.push_str(
                            "\n_(output truncated: total edge limit reached)_\n",
                        );
                        break 'outer;
                    }
                    if shown >= MAX_CALLERS_PER_FUNC {
                        output.push_str(&format!(
                            "- _(...{} more callers of `{func}` not shown)_\n",
                            callers.len() - shown
                        ));
                        break;
                    }
                    output.push_str(&format!(
                        "- `{}` calls `{func}` at {}:{}\n",
                        edge.caller, edge.file, edge.line
                    ));
                    total_edges += 1;
                    shown += 1;
                    if !seen_functions.contains(&edge.caller) {
                        seen_functions.insert(edge.caller.clone());
                        next_functions.push(edge.caller.clone());
                    }
                }
            }
        }

        current_functions = next_functions;
    }

    ToolResult {
        tool_name: "find_data_flows".to_string(),
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
            description:
                "Get the dependency graph for a file — what it imports and what depends on it"
                    .to_string(),
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
            name: "list_files".to_string(),
            description: "Browse the file and directory structure of the codebase. \
                          Returns matching file paths with line counts."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Optional path prefix to filter (e.g. 'src/auth/'). If omitted, lists all files."
                    },
                    "extension": {
                        "type": "string",
                        "description": "Optional file extension filter without the dot (e.g. 'rs', 'py')"
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_symbol".to_string(),
            description: "Look up the full definition of a specific function, class, struct, or \
                          method. Returns file, line, kind, and source code."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "The symbol name to look up (e.g. 'authenticate_user', 'UserController')"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Optional — narrow to a specific file if the same name exists in multiple files"
                    }
                },
                "required": ["name"]
            }),
        },
        ToolDefinition {
            name: "find_data_flows".to_string(),
            description: "Trace where a variable or value flows through the codebase — useful \
                          for taint analysis. Finds pattern matches then traces callers through \
                          the call graph."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "source_pattern": {
                        "type": "string",
                        "description": "Regex pattern identifying the source (e.g. 'request\\.get|request\\.body|params\\[')"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Optional — limit search to a specific file"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "How many call-graph hops to trace (default 2, max 10). Values above 10 are clamped to 10."
                    }
                },
                "required": ["source_pattern"]
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
