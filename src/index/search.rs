//
//  heimdall
//  src/index/search.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::collections::HashMap;

/// A search match with file, line number, and context.
#[derive(Debug, Clone)]
pub struct SearchMatch {
    pub file: String,
    pub line: usize,
    pub content: String,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
}

/// Full-text search index over the scanned codebase.
pub struct SearchIndex {
    /// file path -> lines
    files: HashMap<String, Vec<String>>,
}

impl SearchIndex {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
        }
    }

    /// Index a file's content for searching.
    pub fn index_file(&mut self, relative_path: &str, content: &str) {
        let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        self.files.insert(relative_path.to_string(), lines);
    }

    /// Search for a pattern across all indexed files.
    /// Supports basic text matching and regex via the `regex` crate.
    pub fn search(&self, query: &str, file_glob: Option<&str>) -> Vec<SearchMatch> {
        let re = regex::Regex::new(query).ok();
        let glob_pattern = file_glob.and_then(|g| glob::Pattern::new(g).ok());
        let mut results = Vec::new();

        for (file, lines) in &self.files {
            if let Some(ref pat) = glob_pattern {
                if !pat.matches(file) {
                    continue;
                }
            }

            for (i, line) in lines.iter().enumerate() {
                let matched = if let Some(ref re) = re {
                    re.is_match(line)
                } else {
                    line.contains(query)
                };

                if matched {
                    let context_before: Vec<String> = lines
                        [i.saturating_sub(2)..i]
                        .iter()
                        .cloned()
                        .collect();
                    let context_after: Vec<String> = lines
                        .get(i + 1..std::cmp::min(i + 3, lines.len()))
                        .unwrap_or_default()
                        .to_vec();

                    results.push(SearchMatch {
                        file: file.clone(),
                        line: i + 1,
                        content: line.clone(),
                        context_before,
                        context_after,
                    });
                }
            }
        }

        results.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_text_search() {
        let mut index = SearchIndex::new();
        index.index_file(
            "src/main.rs",
            "fn main() {\n    let password = \"secret\";\n    println!(\"hello\");\n}",
        );
        index.index_file("src/lib.rs", "pub fn helper() {\n    // nothing here\n}");

        let results = index.search("password", None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file, "src/main.rs");
        assert_eq!(results[0].line, 2);
    }

    #[test]
    fn test_regex_search() {
        let mut index = SearchIndex::new();
        index.index_file(
            "app.py",
            "password = 'abc123'\nPASSWORD = 'xyz'\nsecret_key = 'key'",
        );

        // Case-insensitive regex for password =
        let results = index.search(r"(?i)password\s*=", None);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_with_glob_filter() {
        let mut index = SearchIndex::new();
        index.index_file("src/main.rs", "let x = 1;");
        index.index_file("tests/test.rs", "let x = 2;");

        let results = index.search("let x", Some("src/**"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file, "src/main.rs");
    }

    #[test]
    fn test_search_no_results() {
        let mut index = SearchIndex::new();
        index.index_file("src/main.rs", "fn main() {}");

        let results = index.search("nonexistent_term", None);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_context_lines() {
        let mut index = SearchIndex::new();
        index.index_file(
            "file.rs",
            "line1\nline2\nline3\nMATCH\nline5\nline6\nline7",
        );

        let results = index.search("MATCH", None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].line, 4);
        // context_before should have up to 2 lines before
        assert_eq!(results[0].context_before.len(), 2);
        assert_eq!(results[0].context_before[0], "line2");
        assert_eq!(results[0].context_before[1], "line3");
        // context_after should have up to 2 lines after
        assert_eq!(results[0].context_after.len(), 2);
        assert_eq!(results[0].context_after[0], "line5");
        assert_eq!(results[0].context_after[1], "line6");
    }

    #[test]
    fn test_search_multiple_matches_in_same_file() {
        let mut index = SearchIndex::new();
        index.index_file("file.py", "TODO: fix this\nsome code\nTODO: refactor");

        let results = index.search("TODO", None);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].line, 1);
        assert_eq!(results[1].line, 3);
    }

    #[test]
    fn test_search_results_sorted_by_file_then_line() {
        let mut index = SearchIndex::new();
        index.index_file("b.rs", "match\nmatch");
        index.index_file("a.rs", "match");

        let results = index.search("match", None);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].file, "a.rs");
        assert_eq!(results[1].file, "b.rs");
        assert_eq!(results[1].line, 1);
        assert_eq!(results[2].file, "b.rs");
        assert_eq!(results[2].line, 2);
    }

    #[test]
    fn test_search_empty_index() {
        let index = SearchIndex::new();
        let results = index.search("anything", None);
        assert!(results.is_empty());
    }
}
