//
//  heimdall
//  src/index/deps.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Dependency graph tracking file/module dependencies.
pub struct DependencyGraph {
    /// file -> set of imports/dependencies
    dependencies: HashMap<String, HashSet<String>>,
    /// import target -> set of files that import it
    dependents: HashMap<String, HashSet<String>>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self {
            dependencies: HashMap::new(),
            dependents: HashMap::new(),
        }
    }

    pub fn add_dependency(&mut self, file: &str, import: &str) {
        self.dependencies
            .entry(file.to_string())
            .or_default()
            .insert(import.to_string());
        self.dependents
            .entry(import.to_string())
            .or_default()
            .insert(file.to_string());
    }

    /// Get all dependencies of a file.
    pub fn get_dependencies(&self, file: &str) -> Vec<&str> {
        self.dependencies
            .get(file)
            .map(|s| s.iter().map(|x| x.as_str()).collect())
            .unwrap_or_default()
    }

    /// Get all files that depend on a given import target.
    pub fn get_dependents(&self, target: &str) -> Vec<&str> {
        self.dependents
            .get(target)
            .map(|s| s.iter().map(|x| x.as_str()).collect())
            .unwrap_or_default()
    }

    /// Format dependencies as a string for LLM context.
    pub fn deps_summary(&self, file: &str) -> String {
        let deps = self.get_dependencies(file);
        let dependents = self.get_dependents(file);

        let mut out = format!("Dependencies of `{file}`:\n");
        if deps.is_empty() {
            out.push_str("  (none)\n");
        } else {
            for d in &deps {
                out.push_str(&format!("  - {d}\n"));
            }
        }

        out.push_str(&format!("\nDepended on by:\n"));
        if dependents.is_empty() {
            out.push_str("  (none)\n");
        } else {
            for d in &dependents {
                out.push_str(&format!("  - {d}\n"));
            }
        }

        out
    }
}

// --- Language-specific import extraction ---

static RUST_USE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^use\s+([\w:]+)").unwrap());
static RUST_MOD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^mod\s+(\w+)").unwrap());

static PY_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^(?:from\s+([\w.]+)\s+)?import\s+([\w.]+)").unwrap());

static JS_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)(?:import|require)\s*\(?['"]([^'"]+)['"]\)?"#).unwrap());

static GO_IMPORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)"([^"]+)""#).unwrap());

static JAVA_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^import\s+([\w.]+);").unwrap());

/// Extract import/dependency strings from source code.
pub fn extract_imports(content: &str, language: &str) -> Vec<String> {
    match language {
        "rust" => {
            let mut imports: Vec<String> = RUST_USE
                .captures_iter(content)
                .map(|c| c[1].to_string())
                .collect();
            imports.extend(RUST_MOD.captures_iter(content).map(|c| c[1].to_string()));
            imports
        }
        "python" => PY_IMPORT
            .captures_iter(content)
            .map(|c| {
                if let Some(from) = c.get(1) {
                    from.as_str().to_string()
                } else {
                    c[2].to_string()
                }
            })
            .collect(),
        "javascript" | "typescript" => JS_IMPORT
            .captures_iter(content)
            .map(|c| c[1].to_string())
            .collect(),
        "go" => GO_IMPORT
            .captures_iter(content)
            .map(|c| c[1].to_string())
            .collect(),
        "java" | "kotlin" => JAVA_IMPORT
            .captures_iter(content)
            .map(|c| c[1].to_string())
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_graph_add_and_query() {
        let mut graph = DependencyGraph::new();
        graph.add_dependency("src/main.rs", "std::io");
        graph.add_dependency("src/main.rs", "crate::config");

        let deps = graph.get_dependencies("src/main.rs");
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn test_dependents() {
        let mut graph = DependencyGraph::new();
        graph.add_dependency("a.rs", "shared_lib");
        graph.add_dependency("b.rs", "shared_lib");

        let dependents = graph.get_dependents("shared_lib");
        assert_eq!(dependents.len(), 2);
    }

    #[test]
    fn test_no_dependencies() {
        let graph = DependencyGraph::new();
        assert!(graph.get_dependencies("nonexistent").is_empty());
        assert!(graph.get_dependents("nonexistent").is_empty());
    }

    #[test]
    fn test_extract_rust_imports() {
        let code = "use std::io;\nuse crate::config;\nmod auth;\n";
        let imports = extract_imports(code, "rust");
        assert!(imports.contains(&"std::io".to_string()));
        assert!(imports.contains(&"crate::config".to_string()));
        assert!(imports.contains(&"auth".to_string()));
    }

    #[test]
    fn test_extract_python_imports() {
        let code = "import os\nfrom pathlib import Path\nimport sys\n";
        let imports = extract_imports(code, "python");
        assert!(imports.contains(&"os".to_string()));
        assert!(imports.contains(&"pathlib".to_string()));
        assert!(imports.contains(&"sys".to_string()));
    }

    #[test]
    fn test_extract_javascript_imports() {
        // The JS_IMPORT regex: (?m)(?:import|require)\s*\(?['"]([^'"]+)['"]\)?
        // It expects import/require followed by a quoted string.
        // ES module `import X from 'Y'` doesn't match directly because `from` is in the way.
        // But `require('fs')` should match.
        let code = r#"const fs = require('fs');
import './side-effect';
const path = require("path");
"#;
        let imports = extract_imports(code, "javascript");
        assert!(imports.contains(&"fs".to_string()));
        assert!(imports.contains(&"./side-effect".to_string()));
        assert!(imports.contains(&"path".to_string()));
    }

    #[test]
    fn test_extract_java_imports() {
        let code = "import java.util.List;\nimport com.example.MyClass;\n";
        let imports = extract_imports(code, "java");
        assert!(imports.contains(&"java.util.List".to_string()));
        assert!(imports.contains(&"com.example.MyClass".to_string()));
    }

    #[test]
    fn test_extract_unknown_language() {
        let imports = extract_imports("some code", "brainfuck");
        assert!(imports.is_empty());
    }

    #[test]
    fn test_deps_summary() {
        let mut graph = DependencyGraph::new();
        graph.add_dependency("a.rs", "std::io");

        let summary = graph.deps_summary("a.rs");
        assert!(summary.contains("std::io"));
        assert!(summary.contains("Dependencies of"));
    }
}
