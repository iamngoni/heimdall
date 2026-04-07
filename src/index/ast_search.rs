//
//  heimdall
//  src/index/ast_search.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/22.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::collections::HashMap;
use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator};

/// A match returned by an AST structural query.
#[derive(Debug, Clone)]
pub struct AstSearchMatch {
    /// Relative file path where the match was found.
    pub file: String,
    /// Starting line number (1-indexed).
    pub line_start: usize,
    /// Ending line number (1-indexed).
    pub line_end: usize,
    /// The tree-sitter node kind (e.g. "call_expression", "function_item").
    pub node_kind: String,
    /// The matched source code snippet.
    pub code_snippet: String,
}

/// Entry for a single indexed file: its source text and detected language.
struct IndexedAstFile {
    content: String,
    language: String,
}

/// Semantic/structural code search index powered by tree-sitter S-expression queries.
///
/// Unlike the regex-based `SearchIndex`, this index understands the syntax tree
/// of each file and can match structural patterns such as "find all call
/// expressions whose function name matches `exec|eval`".
pub struct AstSearchIndex {
    /// Indexed files keyed by relative path.
    files: HashMap<String, IndexedAstFile>,
}

impl AstSearchIndex {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
        }
    }

    /// Index a file for AST search.
    pub fn index_file(&mut self, relative_path: &str, content: &str, language: &str) {
        self.files.insert(
            relative_path.to_string(),
            IndexedAstFile {
                content: content.to_string(),
                language: language.to_string(),
            },
        );
    }

    /// Search indexed files using a tree-sitter S-expression query pattern.
    ///
    /// # Arguments
    /// * `pattern` — Tree-sitter query in S-expression syntax, e.g.
    ///   `(call_expression function: (identifier) @fn (#match? @fn "exec|eval"))`
    /// * `language` — Language to restrict the search to (e.g. "rust", "python").
    /// * `file_glob` — Optional glob pattern to filter files.
    pub fn search(
        &self,
        pattern: &str,
        language: &str,
        file_glob: Option<&str>,
    ) -> Result<Vec<AstSearchMatch>, String> {
        let ts_lang = get_language(language)
            .ok_or_else(|| format!("Unsupported language for AST search: {language}"))?;

        let query =
            Query::new(&ts_lang, pattern).map_err(|e| format!("Invalid tree-sitter query: {e}"))?;

        // Require at least one capture so that every match produces a concrete node.
        // Patterns like `(function_item)` with no `@capture` would otherwise silently
        // skip all matches because `m.captures` is always empty.
        if query.capture_names().is_empty() {
            return Err("Query must contain at least one capture (e.g. `@name`). \
                 Capture-less patterns like `(function_item)` are not supported — \
                 add a capture to identify the node of interest, e.g. \
                 `(function_item name: (identifier) @name)`."
                .to_string());
        }

        let glob_pattern = file_glob.and_then(|g| glob::Pattern::new(g).ok());

        let mut parser = Parser::new();
        parser
            .set_language(&ts_lang)
            .map_err(|e| format!("Failed to set parser language: {e}"))?;

        let mut results = Vec::new();

        for (path, entry) in &self.files {
            // Filter by language
            if entry.language != language {
                continue;
            }

            // Filter by glob
            if let Some(ref pat) = glob_pattern {
                if !pat.matches(path) {
                    continue;
                }
            }

            let source = entry.content.as_bytes();
            let tree = match parser.parse(source, None) {
                Some(t) => t,
                None => continue,
            };

            let mut cursor = QueryCursor::new();
            let mut matches = cursor.matches(&query, tree.root_node(), source);

            while let Some(m) = matches.next() {
                // At least one capture is guaranteed by the earlier `capture_names` check.
                let node = m.captures[0].node;

                let start_line = node.start_position().row;
                let end_line = node.end_position().row;
                let snippet = node.utf8_text(source).unwrap_or("").to_string();

                results.push(AstSearchMatch {
                    file: path.clone(),
                    line_start: start_line + 1,
                    line_end: end_line + 1,
                    node_kind: node.kind().to_string(),
                    code_snippet: snippet,
                });
            }
        }

        results.sort_by(|a, b| a.file.cmp(&b.file).then(a.line_start.cmp(&b.line_start)));
        Ok(results)
    }
}

/// Resolve a language name to its tree-sitter `Language` grammar.
fn get_language(name: &str) -> Option<Language> {
    match name {
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "typescript" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        _ => None,
    }
}

/// Returns `true` if the given language name is supported by the AST search index.
pub fn is_language_supported(name: &str) -> bool {
    get_language(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_function_search() {
        let mut index = AstSearchIndex::new();
        index.index_file(
            "src/main.rs",
            "fn main() {\n    println!(\"hello\");\n}\n\nfn helper() {\n    let x = 1;\n}",
            "rust",
        );

        let results = index
            .search("(function_item name: (identifier) @name)", "rust", None)
            .unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].file, "src/main.rs");
    }

    #[test]
    fn test_python_call_search() {
        let mut index = AstSearchIndex::new();
        index.index_file(
            "app.py",
            "import os\nresult = os.system('ls')\neval(user_input)",
            "python",
        );

        let results = index
            .search(
                "(call function: (identifier) @fn (#match? @fn \"eval\"))",
                "python",
                None,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].code_snippet.contains("eval"));
    }

    #[test]
    fn test_invalid_query() {
        let index = AstSearchIndex::new();
        let result = index.search("(not_a_valid_query @@@)", "rust", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_language() {
        let index = AstSearchIndex::new();
        let result = index.search("(identifier)", "brainfuck", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_capture_less_query_returns_error() {
        let index = AstSearchIndex::new();
        // A syntactically valid query with no captures should return a clear error
        // rather than silently returning empty results.
        let result = index.search("(function_item)", "rust", None);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("capture"),
            "error should mention 'capture': {msg}"
        );
    }

    #[test]
    fn test_glob_filter() {
        let mut index = AstSearchIndex::new();
        index.index_file("src/main.rs", "fn main() {}", "rust");
        index.index_file("tests/test.rs", "fn test_it() {}", "rust");

        let results = index
            .search(
                "(function_item name: (identifier) @name)",
                "rust",
                Some("src/**"),
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file, "src/main.rs");
    }

    #[test]
    fn test_language_filter() {
        let mut index = AstSearchIndex::new();
        index.index_file("main.rs", "fn main() {}", "rust");
        index.index_file("app.py", "def main(): pass", "python");

        let results = index
            .search("(function_item name: (identifier) @name)", "rust", None)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file, "main.rs");
    }

    #[test]
    fn test_empty_index() {
        let index = AstSearchIndex::new();
        let results = index.search("(identifier) @id", "rust", None).unwrap();
        assert!(results.is_empty());
    }
}
