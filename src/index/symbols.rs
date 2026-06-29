//
//  heimdall
//  src/index/symbols.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::collections::HashMap;
use tree_sitter::{Language, Node, Parser};

/// A symbol extracted from source code.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub file: String,
    pub line: usize,
    pub is_public: bool,
    pub is_entry_point: bool,
    /// Functions/methods this symbol calls (approximate).
    pub calls: Vec<String>,
}

/// Index of symbols (functions, types, variables) extracted from source code.
pub struct SymbolIndex {
    /// name -> list of symbols (can have same name in different files)
    symbols: HashMap<String, Vec<Symbol>>,
}

impl Default for SymbolIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolIndex {
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
        }
    }

    pub fn add(&mut self, sym: Symbol) {
        self.symbols.entry(sym.name.clone()).or_default().push(sym);
    }

    /// Find all symbols with the given name.
    pub fn find(&self, name: &str) -> Vec<&Symbol> {
        self.symbols
            .get(name)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get all entry points (main functions, route handlers, exports).
    pub fn entry_points(&self) -> Vec<&Symbol> {
        self.symbols
            .values()
            .flatten()
            .filter(|s| s.is_entry_point)
            .collect()
    }

    /// Get all public/exported symbols.
    pub fn exports(&self) -> Vec<&Symbol> {
        self.symbols
            .values()
            .flatten()
            .filter(|s| s.is_public)
            .collect()
    }

    /// Total number of symbols indexed.
    pub fn all_count(&self) -> usize {
        self.symbols.values().map(|v| v.len()).sum()
    }

    /// Get all symbols in a given file.
    pub fn symbols_in_file(&self, file: &str) -> Vec<&Symbol> {
        self.symbols
            .values()
            .flatten()
            .filter(|s| s.file == file)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tree-sitter language resolution
// ---------------------------------------------------------------------------

fn get_ts_language(lang: &str) -> Option<Language> {
    match lang {
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "typescript" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        _ => None,
    }
}

/// Extract symbols from source code using tree-sitter AST parsing.
/// Falls back to regex heuristics for unsupported languages.
pub fn extract_symbols(content: &str, language: &str, file: &str) -> Vec<Symbol> {
    if let Some(ts_lang) = get_ts_language(language)
        && let Some(syms) = extract_with_tree_sitter(content, ts_lang, language, file)
    {
        return syms;
    }
    // Fallback: regex extraction for languages without tree-sitter support
    extract_symbols_regex(content, language, file)
}

// ---------------------------------------------------------------------------
// Tree-sitter based extraction
// ---------------------------------------------------------------------------

fn extract_with_tree_sitter(
    content: &str,
    ts_lang: Language,
    language: &str,
    file: &str,
) -> Option<Vec<Symbol>> {
    let mut parser = Parser::new();
    parser.set_language(&ts_lang).ok()?;
    let tree = parser.parse(content, None)?;
    let root = tree.root_node();
    let source = content.as_bytes();

    let mut symbols = match language {
        "rust" => extract_rust_ts(root, source, file),
        "python" => extract_python_ts(root, source, file),
        "javascript" | "typescript" => extract_js_ts(root, source, file),
        "go" => extract_go_ts(root, source, file),
        "java" => extract_java_ts(root, source, file),
        _ => return None,
    };

    // Extract call edges for functions
    let call_names = extract_call_identifiers(root, source, language);
    let fn_names: Vec<String> = symbols
        .iter()
        .filter(|s| s.kind == "function" || s.kind == "method")
        .map(|s| s.name.clone())
        .collect();
    for sym in &mut symbols {
        if sym.kind == "function" || sym.kind == "method" {
            sym.calls = call_names
                .iter()
                .filter(|c| fn_names.contains(c) && **c != sym.name)
                .cloned()
                .collect();
        }
    }

    Some(symbols)
}

/// Get the text of a named child field from a node.
fn child_text<'a>(node: Node<'a>, field: &str, source: &'a [u8]) -> Option<&'a str> {
    let child = node.child_by_field_name(field)?;
    child.utf8_text(source).ok()
}

/// Check if a node has a specific child node kind anywhere in its children.
fn has_child_kind(node: Node, kind: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == kind {
            return true;
        }
    }
    false
}

/// Recursively collect nodes of specified kinds.
fn collect_nodes<'a>(node: Node<'a>, kinds: &[&str], results: &mut Vec<Node<'a>>) {
    if kinds.contains(&node.kind()) {
        results.push(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_nodes(child, kinds, results);
    }
}

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

fn extract_rust_ts(root: Node, source: &[u8], file: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut nodes = Vec::new();
    collect_nodes(
        root,
        &[
            "function_item",
            "struct_item",
            "trait_item",
            "enum_item",
            "impl_item",
        ],
        &mut nodes,
    );

    for node in nodes {
        match node.kind() {
            "function_item" => {
                if let Some(name) = child_text(node, "name", source) {
                    let is_public = has_child_kind(node, "visibility_modifier");
                    let line = node.start_position().row + 1;
                    let is_entry = name == "main"
                        || (is_public && file.contains("routes"))
                        || name.starts_with("handle_");
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "function".to_string(),
                        file: file.to_string(),
                        line,
                        is_public,
                        is_entry_point: is_entry,
                        calls: Vec::new(),
                    });
                }
            }
            "struct_item" => {
                if let Some(name) = child_text(node, "name", source) {
                    let is_public = has_child_kind(node, "visibility_modifier");
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "struct".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public,
                        is_entry_point: false,
                        calls: Vec::new(),
                    });
                }
            }
            "trait_item" => {
                if let Some(name) = child_text(node, "name", source) {
                    let is_public = has_child_kind(node, "visibility_modifier");
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "trait".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public,
                        is_entry_point: false,
                        calls: Vec::new(),
                    });
                }
            }
            "enum_item" => {
                if let Some(name) = child_text(node, "name", source) {
                    let is_public = has_child_kind(node, "visibility_modifier");
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "enum".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public,
                        is_entry_point: false,
                        calls: Vec::new(),
                    });
                }
            }
            "impl_item" => {
                // Extract methods from impl blocks
                let mut methods = Vec::new();
                collect_nodes(node, &["function_item"], &mut methods);
                for method_node in methods {
                    if let Some(name) = child_text(method_node, "name", source) {
                        let is_public = has_child_kind(method_node, "visibility_modifier");
                        let line = method_node.start_position().row + 1;
                        let is_entry =
                            (is_public && file.contains("routes")) || name.starts_with("handle_");
                        symbols.push(Symbol {
                            name: name.to_string(),
                            kind: "method".to_string(),
                            file: file.to_string(),
                            line,
                            is_public,
                            is_entry_point: is_entry,
                            calls: Vec::new(),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    symbols
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

fn extract_python_ts(root: Node, source: &[u8], file: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut nodes = Vec::new();
    collect_nodes(
        root,
        &["function_definition", "class_definition"],
        &mut nodes,
    );

    for node in nodes {
        match node.kind() {
            "function_definition" => {
                if let Some(name) = child_text(node, "name", source) {
                    // If parent is class body, it's a method
                    let is_method = node
                        .parent()
                        .and_then(|p| p.parent())
                        .map(|gp| gp.kind() == "class_definition")
                        .unwrap_or(false);
                    let is_public = !name.starts_with('_');
                    let is_entry =
                        name == "main" || file.contains("views") || file.contains("routes");
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: if is_method { "method" } else { "function" }.to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public,
                        is_entry_point: is_entry && !is_method,
                        calls: Vec::new(),
                    });
                }
            }
            "class_definition" => {
                if let Some(name) = child_text(node, "name", source) {
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "class".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public: true,
                        is_entry_point: false,
                        calls: Vec::new(),
                    });
                }
            }
            _ => {}
        }
    }

    symbols
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript
// ---------------------------------------------------------------------------

fn extract_js_ts(root: Node, source: &[u8], file: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut nodes = Vec::new();
    collect_nodes(
        root,
        &[
            "function_declaration",
            "class_declaration",
            "lexical_declaration",
            "export_statement",
            "method_definition",
        ],
        &mut nodes,
    );

    for node in nodes {
        match node.kind() {
            "function_declaration" => {
                if let Some(name) = child_text(node, "name", source) {
                    let is_exported = node
                        .parent()
                        .map(|p| p.kind() == "export_statement")
                        .unwrap_or(false);
                    let is_entry =
                        file.contains("route") || file.contains("handler") || file.contains("api");
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "function".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public: is_exported,
                        is_entry_point: is_entry,
                        calls: Vec::new(),
                    });
                }
            }
            "class_declaration" => {
                if let Some(name) = child_text(node, "name", source) {
                    let is_exported = node
                        .parent()
                        .map(|p| p.kind() == "export_statement")
                        .unwrap_or(false);
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "class".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public: is_exported,
                        is_entry_point: false,
                        calls: Vec::new(),
                    });
                }
            }
            "export_statement" => {
                // Handled via parent check in function_declaration/class_declaration
            }
            "lexical_declaration" => {
                // Match `const foo = (...) => ...` arrow functions
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "variable_declarator" {
                        let has_arrow = child
                            .child_by_field_name("value")
                            .map(|v| v.kind() == "arrow_function")
                            .unwrap_or(false);
                        if has_arrow && let Some(name) = child_text(child, "name", source) {
                            let is_exported = node
                                .parent()
                                .map(|p| p.kind() == "export_statement")
                                .unwrap_or(false);
                            symbols.push(Symbol {
                                name: name.to_string(),
                                kind: "function".to_string(),
                                file: file.to_string(),
                                line: node.start_position().row + 1,
                                is_public: is_exported,
                                is_entry_point: false,
                                calls: Vec::new(),
                            });
                        }
                    }
                }
            }
            "method_definition" => {
                if let Some(name) = child_text(node, "name", source) {
                    let is_public = name != "constructor" && !name.starts_with('#');
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "method".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public,
                        is_entry_point: false,
                        calls: Vec::new(),
                    });
                }
            }
            _ => {}
        }
    }

    symbols
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

fn extract_go_ts(root: Node, source: &[u8], file: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut nodes = Vec::new();
    collect_nodes(
        root,
        &[
            "function_declaration",
            "method_declaration",
            "type_declaration",
        ],
        &mut nodes,
    );

    for node in nodes {
        match node.kind() {
            "function_declaration" => {
                if let Some(name) = child_text(node, "name", source) {
                    let is_public = name.starts_with(char::is_uppercase);
                    let is_entry = name == "main"
                        || (is_public && (file.contains("handler") || file.contains("api")));
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "function".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public,
                        is_entry_point: is_entry,
                        calls: Vec::new(),
                    });
                }
            }
            "method_declaration" => {
                if let Some(name) = child_text(node, "name", source) {
                    let is_public = name.starts_with(char::is_uppercase);
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "method".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public,
                        is_entry_point: is_public
                            && (file.contains("handler") || file.contains("api")),
                        calls: Vec::new(),
                    });
                }
            }
            "type_declaration" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "type_spec"
                        && let Some(name) = child_text(child, "name", source)
                    {
                        let type_node = child.child_by_field_name("type");
                        let kind = match type_node.map(|n| n.kind()) {
                            Some("struct_type") => "struct",
                            Some("interface_type") => "interface",
                            _ => "type",
                        };
                        let is_public = name.starts_with(char::is_uppercase);
                        symbols.push(Symbol {
                            name: name.to_string(),
                            kind: kind.to_string(),
                            file: file.to_string(),
                            line: child.start_position().row + 1,
                            is_public,
                            is_entry_point: false,
                            calls: Vec::new(),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    symbols
}

// ---------------------------------------------------------------------------
// Java
// ---------------------------------------------------------------------------

fn extract_java_ts(root: Node, source: &[u8], file: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut nodes = Vec::new();
    collect_nodes(
        root,
        &[
            "class_declaration",
            "interface_declaration",
            "method_declaration",
            "constructor_declaration",
        ],
        &mut nodes,
    );

    for node in nodes {
        match node.kind() {
            "class_declaration" => {
                if let Some(name) = child_text(node, "name", source) {
                    let is_public = has_modifier(node, source, "public");
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "class".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public,
                        is_entry_point: false,
                        calls: Vec::new(),
                    });
                }
            }
            "interface_declaration" => {
                if let Some(name) = child_text(node, "name", source) {
                    let is_public = has_modifier(node, source, "public");
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "interface".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public,
                        is_entry_point: false,
                        calls: Vec::new(),
                    });
                }
            }
            "method_declaration" => {
                if let Some(name) = child_text(node, "name", source) {
                    let is_public = has_modifier(node, source, "public");
                    let is_entry = name == "main"
                        || (is_public && (file.contains("Controller") || file.contains("Handler")));
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "method".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public,
                        is_entry_point: is_entry,
                        calls: Vec::new(),
                    });
                }
            }
            "constructor_declaration" => {
                if let Some(name) = child_text(node, "name", source) {
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "constructor".to_string(),
                        file: file.to_string(),
                        line: node.start_position().row + 1,
                        is_public: has_modifier(node, source, "public"),
                        is_entry_point: false,
                        calls: Vec::new(),
                    });
                }
            }
            _ => {}
        }
    }

    symbols
}

/// Check if a Java node has a specific modifier (public, private, etc.).
fn has_modifier(node: Node, source: &[u8], modifier: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let mut mod_cursor = child.walk();
            for mod_child in child.children(&mut mod_cursor) {
                if let Ok(text) = mod_child.utf8_text(source)
                    && text == modifier
                {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Call identifier extraction (language-agnostic via tree-sitter)
// ---------------------------------------------------------------------------

fn extract_call_identifiers(root: Node, source: &[u8], language: &str) -> Vec<String> {
    let mut calls = Vec::new();
    let mut call_nodes = Vec::new();

    let call_kind = match language {
        "rust" => "call_expression",
        "python" => "call",
        "javascript" | "typescript" => "call_expression",
        "go" => "call_expression",
        "java" => "method_invocation",
        _ => return calls,
    };

    collect_nodes(root, &[call_kind], &mut call_nodes);

    for node in call_nodes {
        let func_node = node.child_by_field_name("function");
        let name = match func_node {
            Some(f) if f.kind() == "identifier" || f.kind() == "field_identifier" => {
                f.utf8_text(source).ok().map(|s| s.to_string())
            }
            Some(f) if f.kind() == "field_expression" || f.kind() == "member_expression" => f
                .child_by_field_name("field")
                .or_else(|| f.child_by_field_name("property"))
                .and_then(|n| n.utf8_text(source).ok())
                .map(|s| s.to_string()),
            _ => {
                // For Java method_invocation, the name field is different
                node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .map(|s| s.to_string())
            }
        };

        if let Some(name) = name
            && !is_builtin_call(&name, language)
        {
            calls.push(name);
        }
    }

    calls.sort();
    calls.dedup();
    calls
}

fn is_builtin_call(name: &str, language: &str) -> bool {
    match language {
        "rust" => matches!(
            name,
            "if" | "for"
                | "while"
                | "match"
                | "return"
                | "let"
                | "mut"
                | "Some"
                | "None"
                | "Ok"
                | "Err"
                | "vec"
                | "format"
                | "println"
                | "eprintln"
                | "print"
                | "write"
                | "writeln"
        ),
        "python" => matches!(
            name,
            "print"
                | "len"
                | "range"
                | "str"
                | "int"
                | "float"
                | "list"
                | "dict"
                | "set"
                | "type"
                | "isinstance"
                | "super"
        ),
        "javascript" | "typescript" => matches!(
            name,
            "console"
                | "require"
                | "parseInt"
                | "parseFloat"
                | "setTimeout"
                | "setInterval"
                | "Promise"
                | "Array"
                | "Object"
        ),
        "go" => matches!(
            name,
            "make"
                | "len"
                | "cap"
                | "append"
                | "copy"
                | "delete"
                | "new"
                | "panic"
                | "recover"
                | "close"
        ),
        "java" => matches!(
            name,
            "toString" | "equals" | "hashCode" | "getClass" | "println" | "print"
        ),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Regex fallback (for languages without tree-sitter grammars)
// ---------------------------------------------------------------------------

use regex::Regex;
use std::sync::LazyLock;

static RUBY_DEF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*def\s+(\w+[!?=]?)").unwrap());
static RUBY_CLASS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*class\s+(\w+)").unwrap());
static RUBY_MODULE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*module\s+(\w+)").unwrap());

static PHP_FUNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(public\s+|private\s+|protected\s+)?function\s+(\w+)").unwrap()
});
static PHP_CLASS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^\s*class\s+(\w+)").unwrap());

// C
static C_FUNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(?:static\s+)?(?:inline\s+)?(?:const\s+)?(?:unsigned\s+)?(?:void|int|char|float|double|long|short|size_t|bool|\w+_t|\w+\s*\*)\s+(\w+)\s*\(").unwrap()
});
static C_STRUCT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*(?:typedef\s+)?struct\s+(\w+)").unwrap());
static C_TYPEDEF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*typedef\s+.*\s+(\w+)\s*;").unwrap());
static C_DEFINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*#define\s+(\w+)").unwrap());

// C++
static CPP_CLASS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*(?:template\s*<[^>]*>\s*)?class\s+(\w+)").unwrap());
static CPP_NAMESPACE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*namespace\s+(\w+)").unwrap());
static CPP_METHOD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^(?:[\w:*&<>]+\s+)+(\w+)::(\w+)\s*\(").unwrap());

// C#
static CS_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:public|private|protected|internal)?\s*(?:static\s+)?(?:abstract\s+)?(?:sealed\s+)?(?:partial\s+)?(?:class|interface|enum|struct|record)\s+(\w+)").unwrap()
});
static CS_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(public|private|protected|internal)\s+(?:static\s+)?(?:async\s+)?(?:override\s+)?(?:virtual\s+)?[\w<>\[\]?]+\s+(\w+)\s*\(").unwrap()
});
static CS_PROP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^\s*(public|private|protected|internal)\s+(?:static\s+)?[\w<>\[\]?]+\s+(\w+)\s*\{",
    )
    .unwrap()
});

// Swift
static SWIFT_FUNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:public\s+|private\s+|internal\s+|fileprivate\s+|open\s+)?(?:static\s+)?(?:class\s+)?func\s+(\w+)").unwrap()
});
static SWIFT_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:public\s+|private\s+|internal\s+|fileprivate\s+|open\s+)?(?:final\s+)?(?:class|struct|enum|protocol|actor)\s+(\w+)").unwrap()
});

// Kotlin
static KT_FUN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:public\s+|private\s+|protected\s+|internal\s+)?(?:suspend\s+)?(?:inline\s+)?fun\s+(?:<[^>]*>\s*)?(\w+)").unwrap()
});
static KT_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:public\s+|private\s+|protected\s+|internal\s+)?(?:data\s+|sealed\s+|abstract\s+|open\s+|inner\s+)?(?:class|object|interface|enum\s+class)\s+(\w+)").unwrap()
});

// Scala
static SCALA_DEF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:private\s+|protected\s+)?(?:override\s+)?def\s+(\w+)").unwrap()
});
static SCALA_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:case\s+)?(?:abstract\s+)?(?:sealed\s+)?(?:class|object|trait)\s+(\w+)")
        .unwrap()
});

// Shell/Bash
static SH_FUNC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*(?:function\s+(\w+)|(\w+)\s*\(\s*\)\s*\{)").unwrap());
static SH_EXPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*export\s+(\w+)=").unwrap());
static SH_ALIAS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^\s*alias\s+(\w+)=").unwrap());

fn extract_symbols_regex(content: &str, language: &str, file: &str) -> Vec<Symbol> {
    match language {
        "ruby" => extract_ruby_symbols(content, file),
        "php" => extract_php_symbols(content, file),
        "c" => extract_c_symbols(content, file),
        "cpp" => extract_cpp_symbols(content, file),
        "csharp" => extract_csharp_symbols(content, file),
        "swift" => extract_swift_symbols(content, file),
        "kotlin" => extract_kotlin_symbols(content, file),
        "scala" => extract_scala_symbols(content, file),
        "shell" | "bash" => extract_shell_symbols(content, file),
        _ => Vec::new(),
    }
}

fn regex_line_number(content: &str, byte_offset: usize) -> usize {
    content[..byte_offset].matches('\n').count() + 1
}

fn extract_ruby_symbols(content: &str, file: &str) -> Vec<Symbol> {
    let mut syms = Vec::new();

    for cap in RUBY_DEF.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "method".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    for cap in RUBY_CLASS.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "class".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    for cap in RUBY_MODULE.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "module".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    syms
}

fn extract_php_symbols(content: &str, file: &str) -> Vec<Symbol> {
    let mut syms = Vec::new();

    for cap in PHP_FUNC.captures_iter(content) {
        let name = cap[2].to_string();
        let visibility = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("public");
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "function".to_string(),
            file: file.to_string(),
            line,
            is_public: visibility == "public",
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    for cap in PHP_CLASS.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "class".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    syms
}

fn extract_c_symbols(content: &str, file: &str) -> Vec<Symbol> {
    let mut syms = Vec::new();

    for cap in C_FUNC.captures_iter(content) {
        let name = cap[1].to_string();
        // Skip common C keywords/types that may be false positives
        if matches!(
            name.as_str(),
            "if" | "for" | "while" | "switch" | "return" | "sizeof" | "typeof"
        ) {
            continue;
        }
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "function".to_string(),
            file: file.to_string(),
            line,
            is_public: !content[..cap.get(0).unwrap().start()].ends_with("static "),
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    for cap in C_STRUCT.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "struct".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    for cap in C_TYPEDEF.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "typedef".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    for cap in C_DEFINE.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "macro".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    syms
}

fn extract_cpp_symbols(content: &str, file: &str) -> Vec<Symbol> {
    let mut syms = extract_c_symbols(content, file);

    for cap in CPP_CLASS.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "class".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    for cap in CPP_NAMESPACE.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "namespace".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    for cap in CPP_METHOD.captures_iter(content) {
        let name = cap[2].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "method".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    syms
}

fn extract_csharp_symbols(content: &str, file: &str) -> Vec<Symbol> {
    let mut syms = Vec::new();

    for cap in CS_TYPE.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        let full_match = cap.get(0).unwrap().as_str();
        let is_public = full_match.contains("public") || full_match.contains("internal");
        let kind = if full_match.contains("interface") {
            "interface"
        } else if full_match.contains("enum") {
            "enum"
        } else if full_match.contains("struct") {
            "struct"
        } else if full_match.contains("record") {
            "record"
        } else {
            "class"
        };
        syms.push(Symbol {
            name,
            kind: kind.to_string(),
            file: file.to_string(),
            line,
            is_public,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    for cap in CS_METHOD.captures_iter(content) {
        let visibility = cap[1].to_string();
        let name = cap[2].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name: name.clone(),
            kind: "method".to_string(),
            file: file.to_string(),
            line,
            is_public: visibility == "public",
            is_entry_point: name == "Main",
            calls: Vec::new(),
        });
    }

    for cap in CS_PROP.captures_iter(content) {
        let visibility = cap[1].to_string();
        let name = cap[2].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "property".to_string(),
            file: file.to_string(),
            line,
            is_public: visibility == "public",
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    syms
}

fn extract_swift_symbols(content: &str, file: &str) -> Vec<Symbol> {
    let mut syms = Vec::new();

    for cap in SWIFT_FUNC.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        let full_match = cap.get(0).unwrap().as_str();
        let is_public = full_match.contains("public") || full_match.contains("open");
        syms.push(Symbol {
            name,
            kind: "function".to_string(),
            file: file.to_string(),
            line,
            is_public,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    for cap in SWIFT_TYPE.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        let full_match = cap.get(0).unwrap().as_str();
        let is_public = full_match.contains("public") || full_match.contains("open");
        let kind = if full_match.contains("protocol") {
            "protocol"
        } else if full_match.contains("struct") {
            "struct"
        } else if full_match.contains("enum") {
            "enum"
        } else if full_match.contains("actor") {
            "actor"
        } else {
            "class"
        };
        syms.push(Symbol {
            name,
            kind: kind.to_string(),
            file: file.to_string(),
            line,
            is_public,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    syms
}

fn extract_kotlin_symbols(content: &str, file: &str) -> Vec<Symbol> {
    let mut syms = Vec::new();

    for cap in KT_FUN.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        let full_match = cap.get(0).unwrap().as_str();
        let is_public = !full_match.contains("private")
            && !full_match.contains("protected")
            && !full_match.contains("internal");
        syms.push(Symbol {
            name: name.clone(),
            kind: "function".to_string(),
            file: file.to_string(),
            line,
            is_public,
            is_entry_point: name == "main",
            calls: Vec::new(),
        });
    }

    for cap in KT_TYPE.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        let full_match = cap.get(0).unwrap().as_str();
        let is_public = !full_match.contains("private")
            && !full_match.contains("protected")
            && !full_match.contains("internal");
        let kind = if full_match.contains("object") {
            "object"
        } else if full_match.contains("interface") {
            "interface"
        } else if full_match.contains("enum") {
            "enum"
        } else {
            "class"
        };
        syms.push(Symbol {
            name,
            kind: kind.to_string(),
            file: file.to_string(),
            line,
            is_public,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    syms
}

fn extract_scala_symbols(content: &str, file: &str) -> Vec<Symbol> {
    let mut syms = Vec::new();

    for cap in SCALA_DEF.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        let full_match = cap.get(0).unwrap().as_str();
        let is_public = !full_match.contains("private") && !full_match.contains("protected");
        syms.push(Symbol {
            name: name.clone(),
            kind: "function".to_string(),
            file: file.to_string(),
            line,
            is_public,
            is_entry_point: name == "main",
            calls: Vec::new(),
        });
    }

    for cap in SCALA_TYPE.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        let full_match = cap.get(0).unwrap().as_str();
        let kind = if full_match.contains("object") {
            "object"
        } else if full_match.contains("trait") {
            "trait"
        } else {
            "class"
        };
        syms.push(Symbol {
            name,
            kind: kind.to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    syms
}

fn extract_shell_symbols(content: &str, file: &str) -> Vec<Symbol> {
    let mut syms = Vec::new();

    for cap in SH_FUNC.captures_iter(content) {
        let name = cap
            .get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "function".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    for cap in SH_EXPORT.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "variable".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    for cap in SH_ALIAS.captures_iter(content) {
        let name = cap[1].to_string();
        let line = regex_line_number(content, cap.get(0).unwrap().start());
        syms.push(Symbol {
            name,
            kind: "alias".to_string(),
            file: file.to_string(),
            line,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
    }

    syms
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Rust — tree-sitter
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_rust_functions() {
        let code = r#"
pub fn main() {
    println!("hello");
}

fn helper() {
    // private
}

pub async fn handle_request() {}
"#;
        let syms = extract_symbols(code, "rust", "src/main.rs");
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"main"), "Expected main, got: {names:?}");
        assert!(names.contains(&"helper"), "Expected helper, got: {names:?}");
        assert!(
            names.contains(&"handle_request"),
            "Expected handle_request, got: {names:?}"
        );
    }

    #[test]
    fn test_extract_rust_structs_and_traits() {
        let code = r#"
pub struct Config {
    name: String,
}

struct Private;

pub trait Provider {
    fn name(&self) -> &str;
}
"#;
        let syms = extract_symbols(code, "rust", "src/lib.rs");
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"Config"));
        assert!(names.contains(&"Private"));
        assert!(names.contains(&"Provider"));

        let config = syms.iter().find(|s| s.name == "Config").unwrap();
        assert_eq!(config.kind, "struct");
        assert!(config.is_public);

        let private = syms.iter().find(|s| s.name == "Private").unwrap();
        assert!(!private.is_public);

        let provider = syms.iter().find(|s| s.name == "Provider").unwrap();
        assert_eq!(provider.kind, "trait");
        assert!(provider.is_public);
    }

    #[test]
    fn test_rust_entry_points() {
        let code = "pub fn main() {}\nfn helper() {}";
        let syms = extract_symbols(code, "rust", "src/main.rs");
        let main_sym = syms.iter().find(|s| s.name == "main").unwrap();
        assert!(main_sym.is_entry_point);

        let helper = syms.iter().find(|s| s.name == "helper").unwrap();
        assert!(!helper.is_entry_point);
    }

    #[test]
    fn test_rust_route_functions_are_entry_points() {
        let code = "pub fn list_repos() {}\npub fn create_repo() {}";
        let syms = extract_symbols(code, "rust", "src/routes/repos.rs");
        for sym in &syms {
            assert!(
                sym.is_entry_point,
                "Expected {} to be an entry point",
                sym.name
            );
        }
    }

    #[test]
    fn test_rust_public_visibility() {
        let code = "pub fn public_fn() {}\nfn private_fn() {}";
        let syms = extract_symbols(code, "rust", "test.rs");
        let public = syms.iter().find(|s| s.name == "public_fn").unwrap();
        assert!(public.is_public);
        let private = syms.iter().find(|s| s.name == "private_fn").unwrap();
        assert!(!private.is_public);
    }

    #[test]
    fn test_rust_enum_extraction() {
        let code = "pub enum Color { Red, Green, Blue }";
        let syms = extract_symbols(code, "rust", "src/lib.rs");
        let color = syms.iter().find(|s| s.name == "Color").unwrap();
        assert_eq!(color.kind, "enum");
        assert!(color.is_public);
    }

    #[test]
    fn test_rust_impl_methods() {
        let code = r#"
struct Foo;
impl Foo {
    pub fn new() -> Self { Foo }
    fn private_method(&self) {}
}
"#;
        let syms = extract_symbols(code, "rust", "src/foo.rs");
        let new_fn = syms.iter().find(|s| s.name == "new").unwrap();
        assert_eq!(new_fn.kind, "method");
        assert!(new_fn.is_public);

        let private = syms.iter().find(|s| s.name == "private_method").unwrap();
        assert!(!private.is_public);
    }

    // -----------------------------------------------------------------------
    // Python — tree-sitter
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_python_symbols() {
        let code = r#"
def hello():
    pass

class MyClass:
    def method(self):
        pass

async def async_handler():
    pass
"#;
        let syms = extract_symbols(code, "python", "app.py");
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"hello"));
        assert!(names.contains(&"MyClass"));
        assert!(names.contains(&"method"));
        assert!(names.contains(&"async_handler"));

        let cls = syms.iter().find(|s| s.name == "MyClass").unwrap();
        assert_eq!(cls.kind, "class");

        let hello = syms.iter().find(|s| s.name == "hello").unwrap();
        assert_eq!(hello.kind, "function");

        let method = syms.iter().find(|s| s.name == "method").unwrap();
        assert_eq!(method.kind, "method");

        let async_handler = syms.iter().find(|s| s.name == "async_handler").unwrap();
        assert_eq!(async_handler.kind, "function");
    }

    #[test]
    fn test_python_private_function() {
        let code = "def _private():\n    pass\ndef public():\n    pass";
        let syms = extract_symbols(code, "python", "mod.py");
        let private = syms.iter().find(|s| s.name == "_private").unwrap();
        assert!(!private.is_public);
        let public = syms.iter().find(|s| s.name == "public").unwrap();
        assert!(public.is_public);
    }

    // -----------------------------------------------------------------------
    // JavaScript — tree-sitter
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_javascript_symbols() {
        let code = r#"
function doSomething() {}
const handler = () => {};
class UserService {}
"#;
        let syms = extract_symbols(code, "javascript", "app.js");
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"doSomething"),
            "Expected doSomething, got: {names:?}"
        );
        assert!(
            names.contains(&"handler"),
            "Expected handler, got: {names:?}"
        );
        assert!(
            names.contains(&"UserService"),
            "Expected UserService, got: {names:?}"
        );
    }

    #[test]
    fn test_extract_typescript_uses_ts_parser() {
        let code = "function hello() {}\nclass Greeter {}";
        let syms = extract_symbols(code, "typescript", "app.ts");
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"hello"));
        assert!(names.contains(&"Greeter"));
    }

    // -----------------------------------------------------------------------
    // Go — tree-sitter
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_go_symbols() {
        let code = r#"package main

func main() {
}

func HandleRequest() {
}

type Config struct {
    Name string
}
"#;
        let syms = extract_symbols(code, "go", "main.go");
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"main"), "Expected main, got: {names:?}");
        assert!(
            names.contains(&"HandleRequest"),
            "Expected HandleRequest, got: {names:?}"
        );
        assert!(names.contains(&"Config"), "Expected Config, got: {names:?}");

        let config = syms.iter().find(|s| s.name == "Config").unwrap();
        assert!(config.is_public);
    }

    // -----------------------------------------------------------------------
    // Java — tree-sitter
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_java_symbols() {
        let code = r#"
public class UserController {
    public void getUser() {}
    private void validateInput() {}
}
"#;
        let syms = extract_symbols(code, "java", "UserController.java");
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"UserController"));
        assert!(names.contains(&"getUser"));
        assert!(names.contains(&"validateInput"));

        let validate = syms.iter().find(|s| s.name == "validateInput").unwrap();
        assert!(!validate.is_public);
    }

    // -----------------------------------------------------------------------
    // Regex fallback tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ruby_symbols() {
        let code = "class MyClass\n  def my_method\n  end\nend\nmodule MyModule\nend";
        let syms = extract_symbols(code, "ruby", "app.rb");
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"MyClass"));
        assert!(names.contains(&"my_method"));
        assert!(names.contains(&"MyModule"));
    }

    #[test]
    fn test_php_symbols() {
        let code = "<?php\nclass UserController {\n    public function index() {}\n    private function validate() {}\n}";
        let syms = extract_symbols(code, "php", "UserController.php");
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"UserController"));
        assert!(names.contains(&"index"));
        assert!(names.contains(&"validate"));

        let validate = syms.iter().find(|s| s.name == "validate").unwrap();
        assert!(!validate.is_public);
    }

    // -----------------------------------------------------------------------
    // SymbolIndex tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_symbol_index_find() {
        let mut index = SymbolIndex::new();
        index.add(Symbol {
            name: "main".to_string(),
            kind: "function".to_string(),
            file: "src/main.rs".to_string(),
            line: 1,
            is_public: true,
            is_entry_point: true,
            calls: Vec::new(),
        });

        let found = index.find("main");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file, "src/main.rs");

        let not_found = index.find("nonexistent");
        assert!(not_found.is_empty());
    }

    #[test]
    fn test_symbol_index_symbols_in_file() {
        let mut index = SymbolIndex::new();
        index.add(Symbol {
            name: "foo".to_string(),
            kind: "function".to_string(),
            file: "a.rs".to_string(),
            line: 1,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
        index.add(Symbol {
            name: "bar".to_string(),
            kind: "function".to_string(),
            file: "b.rs".to_string(),
            line: 1,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });

        let a_syms = index.symbols_in_file("a.rs");
        assert_eq!(a_syms.len(), 1);
        assert_eq!(a_syms[0].name, "foo");
    }

    #[test]
    fn test_symbol_index_entry_points() {
        let mut index = SymbolIndex::new();
        index.add(Symbol {
            name: "main".to_string(),
            kind: "function".to_string(),
            file: "main.rs".to_string(),
            line: 1,
            is_public: true,
            is_entry_point: true,
            calls: Vec::new(),
        });
        index.add(Symbol {
            name: "helper".to_string(),
            kind: "function".to_string(),
            file: "main.rs".to_string(),
            line: 5,
            is_public: false,
            is_entry_point: false,
            calls: Vec::new(),
        });

        let entries = index.entry_points();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "main");
    }

    #[test]
    fn test_symbol_index_exports() {
        let mut index = SymbolIndex::new();
        index.add(Symbol {
            name: "public_fn".to_string(),
            kind: "function".to_string(),
            file: "lib.rs".to_string(),
            line: 1,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
        index.add(Symbol {
            name: "private_fn".to_string(),
            kind: "function".to_string(),
            file: "lib.rs".to_string(),
            line: 5,
            is_public: false,
            is_entry_point: false,
            calls: Vec::new(),
        });

        let exports = index.exports();
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name, "public_fn");
    }

    #[test]
    fn test_symbol_index_all_count() {
        let mut index = SymbolIndex::new();
        assert_eq!(index.all_count(), 0);

        index.add(Symbol {
            name: "a".to_string(),
            kind: "function".to_string(),
            file: "a.rs".to_string(),
            line: 1,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
        index.add(Symbol {
            name: "b".to_string(),
            kind: "function".to_string(),
            file: "b.rs".to_string(),
            line: 1,
            is_public: true,
            is_entry_point: false,
            calls: Vec::new(),
        });
        assert_eq!(index.all_count(), 2);
    }

    #[test]
    fn test_unknown_language_returns_empty() {
        let syms = extract_symbols("some code", "brainfuck", "file.bf");
        assert!(syms.is_empty());
    }
}
