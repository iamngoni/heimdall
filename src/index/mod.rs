//
//  heimdall
//  src/index/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod ast_search;
pub mod callgraph;
pub mod deps;
pub mod search;
pub mod symbols;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A parsed file in the code index.
#[derive(Debug, Clone)]
pub struct IndexedFile {
    pub path: PathBuf,
    pub relative_path: String,
    pub content: String,
    pub language: Option<String>,
    pub line_count: usize,
    pub byte_size: usize,
    pub content_hash: String,
}

/// Combined code index providing symbol lookup, call graph traversal,
/// dependency resolution, and full-text search across the scanned codebase.
pub struct CodeIndex {
    pub root: PathBuf,
    pub files: HashMap<String, IndexedFile>,
    pub symbols: symbols::SymbolIndex,
    pub callgraph: callgraph::CallGraph,
    pub deps: deps::DependencyGraph,
    pub search: search::SearchIndex,
    pub ast_search: ast_search::AstSearchIndex,
}

impl CodeIndex {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            files: HashMap::new(),
            symbols: symbols::SymbolIndex::new(),
            callgraph: callgraph::CallGraph::new(),
            deps: deps::DependencyGraph::new(),
            search: search::SearchIndex::new(),
            ast_search: ast_search::AstSearchIndex::new(),
        }
    }

    /// Add a file to the index. Extracts symbols and builds search data.
    pub fn add_file(&mut self, file: IndexedFile) {
        let rel = file.relative_path.clone();

        // Extract symbols from this file
        if let Some(ref lang) = file.language {
            let syms = symbols::extract_symbols(&file.content, lang, &rel);
            for sym in &syms {
                self.symbols.add(sym.clone());
                // Build call graph edges from function calls in the body
                for callee in &sym.calls {
                    self.callgraph.add_edge(&sym.name, callee, &rel, sym.line);
                }
            }
        }

        // Index for text search
        self.search.index_file(&rel, &file.content);

        // Index for AST-based structural search
        if let Some(ref lang) = file.language {
            self.ast_search.index_file(&rel, &file.content, lang);
        }

        // Extract dependencies (imports)
        if let Some(ref lang) = file.language {
            let imports = deps::extract_imports(&file.content, lang);
            for imp in imports {
                self.deps.add_dependency(&rel, &imp);
            }
        }

        self.files.insert(rel, file);
    }

    /// Read a file from the indexed codebase by relative path.
    pub fn read_file(&self, relative_path: &str) -> Option<&str> {
        self.files.get(relative_path).map(|f| f.content.as_str())
    }

    /// Get the file tree as a sorted list of relative paths.
    pub fn file_tree(&self) -> Vec<&str> {
        let mut paths: Vec<&str> = self.files.keys().map(|s| s.as_str()).collect();
        paths.sort();
        paths
    }

    /// Detect language from file extension.
    pub fn detect_language(path: &Path) -> Option<String> {
        let ext = path.extension()?.to_str()?;
        let lang = match ext {
            "rs" => "rust",
            "py" => "python",
            "js" | "mjs" | "cjs" => "javascript",
            "ts" | "mts" | "cts" => "typescript",
            "jsx" => "javascript",
            "tsx" => "typescript",
            "go" => "go",
            "java" => "java",
            "rb" => "ruby",
            "php" => "php",
            "c" | "h" => "c",
            "cpp" | "cc" | "cxx" | "hpp" => "cpp",
            "cs" => "csharp",
            "swift" => "swift",
            "kt" | "kts" => "kotlin",
            "scala" => "scala",
            "sol" => "solidity",
            "sh" | "bash" => "shell",
            "sql" => "sql",
            "yaml" | "yml" => "yaml",
            "toml" => "toml",
            "json" => "json",
            "xml" => "xml",
            "html" | "htm" => "html",
            "css" => "css",
            "scss" | "sass" => "scss",
            "md" | "markdown" => "markdown",
            "dockerfile" => "dockerfile",
            _ => return None,
        };
        Some(lang.to_string())
    }

    /// Summary for LLM context: file tree + entry points + key symbols.
    pub fn summary_for_llm(&self, max_chars: usize) -> String {
        let mut out = String::new();
        out.push_str("## File Tree\n");
        for path in self.file_tree() {
            out.push_str(&format!("- {path}\n"));
            if out.len() > max_chars / 3 {
                out.push_str("- ... (truncated)\n");
                break;
            }
        }

        out.push_str("\n## Key Symbols\n");
        let entry_points = self.symbols.entry_points();
        if !entry_points.is_empty() {
            out.push_str("\n### Entry Points\n");
            for sym in &entry_points {
                out.push_str(&format!(
                    "- `{}` ({}) at {}:{}\n",
                    sym.name, sym.kind, sym.file, sym.line
                ));
            }
        }

        let exports = self.symbols.exports();
        if !exports.is_empty() {
            out.push_str("\n### Public API / Exports\n");
            for sym in exports.iter().take(50) {
                out.push_str(&format!(
                    "- `{}` ({}) at {}:{}\n",
                    sym.name, sym.kind, sym.file, sym.line
                ));
            }
        }

        if out.len() > max_chars {
            out.truncate(max_chars);
            out.push_str("\n... (truncated)");
        }
        out
    }
}
