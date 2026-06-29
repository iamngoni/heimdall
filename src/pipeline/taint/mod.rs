//
//  heimdall
//  src/pipeline/taint/mod.rs
//

use log::info;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::{FindingEvidence, HeimdallResult};
use crate::util::sat_i32_usize;

// ---- Types ----

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceCategory {
    UserInput,
    Environment,
    File,
    Network,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SinkCategory {
    Sql,
    Command,
    FileAccess,
    Xss,
    Deserialization,
}

#[derive(Debug, Clone)]
pub struct TaintSource {
    pub pattern: &'static str,
    pub category: SourceCategory,
    pub languages: &'static [&'static str],
}

#[derive(Debug, Clone)]
pub struct TaintSink {
    pub pattern: &'static str,
    pub category: SinkCategory,
    pub languages: &'static [&'static str],
}

#[derive(Debug, Clone)]
pub struct TaintFlow {
    pub file_path: String,
    pub source_line: usize,
    pub source_text: String,
    pub source_category: SourceCategory,
    pub sink_line: usize,
    pub sink_text: String,
    pub sink_category: SinkCategory,
    pub variable_chain: Vec<String>,
    pub severity: String,
}

// ---- Source/Sink Definitions ----

const SOURCES: &[TaintSource] = &[
    // Python
    TaintSource {
        pattern: "request.args",
        category: SourceCategory::UserInput,
        languages: &["python"],
    },
    TaintSource {
        pattern: "request.form",
        category: SourceCategory::UserInput,
        languages: &["python"],
    },
    TaintSource {
        pattern: "request.json",
        category: SourceCategory::UserInput,
        languages: &["python"],
    },
    TaintSource {
        pattern: "request.data",
        category: SourceCategory::UserInput,
        languages: &["python"],
    },
    TaintSource {
        pattern: "request.get_json",
        category: SourceCategory::UserInput,
        languages: &["python"],
    },
    TaintSource {
        pattern: "input(",
        category: SourceCategory::UserInput,
        languages: &["python"],
    },
    TaintSource {
        pattern: "sys.argv",
        category: SourceCategory::UserInput,
        languages: &["python"],
    },
    TaintSource {
        pattern: "os.environ",
        category: SourceCategory::Environment,
        languages: &["python"],
    },
    // JavaScript
    TaintSource {
        pattern: "req.body",
        category: SourceCategory::UserInput,
        languages: &["javascript", "typescript"],
    },
    TaintSource {
        pattern: "req.query",
        category: SourceCategory::UserInput,
        languages: &["javascript", "typescript"],
    },
    TaintSource {
        pattern: "req.params",
        category: SourceCategory::UserInput,
        languages: &["javascript", "typescript"],
    },
    TaintSource {
        pattern: "document.location",
        category: SourceCategory::UserInput,
        languages: &["javascript", "typescript"],
    },
    TaintSource {
        pattern: "window.location",
        category: SourceCategory::UserInput,
        languages: &["javascript", "typescript"],
    },
    TaintSource {
        pattern: "process.argv",
        category: SourceCategory::UserInput,
        languages: &["javascript", "typescript"],
    },
    TaintSource {
        pattern: "process.env",
        category: SourceCategory::Environment,
        languages: &["javascript", "typescript"],
    },
    // Go
    TaintSource {
        pattern: "r.URL.Query",
        category: SourceCategory::UserInput,
        languages: &["go"],
    },
    TaintSource {
        pattern: "r.FormValue",
        category: SourceCategory::UserInput,
        languages: &["go"],
    },
    TaintSource {
        pattern: "r.Body",
        category: SourceCategory::UserInput,
        languages: &["go"],
    },
    // Java
    TaintSource {
        pattern: "request.getParameter",
        category: SourceCategory::UserInput,
        languages: &["java"],
    },
    TaintSource {
        pattern: "request.getAttribute",
        category: SourceCategory::UserInput,
        languages: &["java"],
    },
    TaintSource {
        pattern: "request.getHeader",
        category: SourceCategory::UserInput,
        languages: &["java"],
    },
    TaintSource {
        pattern: "getInputStream",
        category: SourceCategory::UserInput,
        languages: &["java"],
    },
    // Rust
    TaintSource {
        pattern: "web::Json",
        category: SourceCategory::UserInput,
        languages: &["rust"],
    },
    TaintSource {
        pattern: "web::Query",
        category: SourceCategory::UserInput,
        languages: &["rust"],
    },
    TaintSource {
        pattern: "web::Path",
        category: SourceCategory::UserInput,
        languages: &["rust"],
    },
];

const SINKS: &[TaintSink] = &[
    // SQL injection
    TaintSink {
        pattern: "execute(",
        category: SinkCategory::Sql,
        languages: &["python", "javascript", "java"],
    },
    TaintSink {
        pattern: "cursor.execute",
        category: SinkCategory::Sql,
        languages: &["python"],
    },
    TaintSink {
        pattern: "db.query",
        category: SinkCategory::Sql,
        languages: &["javascript", "typescript"],
    },
    TaintSink {
        pattern: "f\"SELECT",
        category: SinkCategory::Sql,
        languages: &["python"],
    },
    TaintSink {
        pattern: "f\"INSERT",
        category: SinkCategory::Sql,
        languages: &["python"],
    },
    TaintSink {
        pattern: "f\"UPDATE",
        category: SinkCategory::Sql,
        languages: &["python"],
    },
    TaintSink {
        pattern: "f\"DELETE",
        category: SinkCategory::Sql,
        languages: &["python"],
    },
    TaintSink {
        pattern: "\"SELECT \" +",
        category: SinkCategory::Sql,
        languages: &["javascript", "typescript", "java"],
    },
    TaintSink {
        pattern: "\"INSERT \" +",
        category: SinkCategory::Sql,
        languages: &["javascript", "typescript", "java"],
    },
    // Command injection
    TaintSink {
        pattern: "os.system(",
        category: SinkCategory::Command,
        languages: &["python"],
    },
    TaintSink {
        pattern: "subprocess.call(",
        category: SinkCategory::Command,
        languages: &["python"],
    },
    TaintSink {
        pattern: "subprocess.Popen(",
        category: SinkCategory::Command,
        languages: &["python"],
    },
    TaintSink {
        pattern: "subprocess.run(",
        category: SinkCategory::Command,
        languages: &["python"],
    },
    TaintSink {
        pattern: "exec(",
        category: SinkCategory::Command,
        languages: &["javascript", "typescript", "python"],
    },
    TaintSink {
        pattern: "child_process.exec(",
        category: SinkCategory::Command,
        languages: &["javascript", "typescript"],
    },
    TaintSink {
        pattern: "child_process.spawn(",
        category: SinkCategory::Command,
        languages: &["javascript", "typescript"],
    },
    TaintSink {
        pattern: "Runtime.exec(",
        category: SinkCategory::Command,
        languages: &["java"],
    },
    TaintSink {
        pattern: "ProcessBuilder(",
        category: SinkCategory::Command,
        languages: &["java"],
    },
    // XSS
    TaintSink {
        pattern: ".innerHTML",
        category: SinkCategory::Xss,
        languages: &["javascript", "typescript"],
    },
    TaintSink {
        pattern: "document.write(",
        category: SinkCategory::Xss,
        languages: &["javascript", "typescript"],
    },
    TaintSink {
        pattern: "|safe",
        category: SinkCategory::Xss,
        languages: &["python"],
    },
    // Deserialization
    TaintSink {
        pattern: "pickle.loads(",
        category: SinkCategory::Deserialization,
        languages: &["python"],
    },
    TaintSink {
        pattern: "yaml.load(",
        category: SinkCategory::Deserialization,
        languages: &["python"],
    },
    TaintSink {
        pattern: "eval(",
        category: SinkCategory::Deserialization,
        languages: &["javascript", "typescript", "python"],
    },
];

// ---- Analyzer ----

pub struct TaintAnalyzer;

impl Default for TaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyze a single file for taint flows.
    pub fn analyze_file(&self, file_path: &str, content: &str, language: &str) -> Vec<TaintFlow> {
        let lines: Vec<&str> = content.lines().collect();
        if lines.is_empty() {
            return vec![];
        }

        // Step 1: Find all source lines and track tainted variables
        let mut tainted_vars: HashMap<String, (usize, SourceCategory)> = HashMap::new();

        for (line_idx, line) in lines.iter().enumerate() {
            for source in SOURCES {
                if !source.languages.contains(&language) {
                    continue;
                }
                if line.contains(source.pattern) {
                    // Try to extract the variable being assigned
                    if let Some(var) = extract_assigned_var(line) {
                        tainted_vars.insert(var, (line_idx + 1, source.category.clone()));
                    }
                }
            }
        }

        // Step 2: Propagate taint through variable assignments (fixed-point)
        let mut changed = true;
        let mut iterations = 0;
        while changed && iterations < 10 {
            changed = false;
            iterations += 1;
            let current_tainted: HashSet<String> = tainted_vars.keys().cloned().collect();

            for (line_idx, line) in lines.iter().enumerate() {
                if let Some(assigned) = extract_assigned_var(line) {
                    if tainted_vars.contains_key(&assigned) {
                        continue;
                    }
                    // Check if any tainted var appears on the RHS
                    for tainted in &current_tainted {
                        if line.contains(tainted.as_str()) {
                            let (_, ref cat) = tainted_vars[tainted];
                            tainted_vars.insert(assigned.clone(), (line_idx + 1, cat.clone()));
                            changed = true;
                            break;
                        }
                    }
                }
            }
        }

        // Step 3: Check if any tainted variable reaches a sink
        let mut flows = Vec::new();
        for (line_idx, line) in lines.iter().enumerate() {
            for sink in SINKS {
                if !sink.languages.contains(&language) {
                    continue;
                }
                if !line.contains(sink.pattern) {
                    continue;
                }

                // Check if any tainted variable appears in this sink line
                for (var, (source_line, source_cat)) in &tainted_vars {
                    if line.contains(var.as_str()) {
                        let severity = match sink.category {
                            SinkCategory::Sql | SinkCategory::Command => "critical".to_string(),
                            SinkCategory::Xss | SinkCategory::Deserialization => "high".to_string(),
                            SinkCategory::FileAccess => "medium".to_string(),
                        };

                        flows.push(TaintFlow {
                            file_path: file_path.to_string(),
                            source_line: *source_line,
                            source_text: lines.get(source_line - 1).unwrap_or(&"").to_string(),
                            source_category: source_cat.clone(),
                            sink_line: line_idx + 1,
                            sink_text: line.to_string(),
                            sink_category: sink.category.clone(),
                            variable_chain: vec![var.clone()],
                            severity,
                        });
                        break; // One flow per sink line
                    }
                }
            }
        }

        flows
    }

    /// Analyze multiple files.
    pub fn analyze_files(&self, files: &[(String, String, String)]) -> Vec<TaintFlow> {
        files
            .iter()
            .flat_map(|(path, content, lang)| self.analyze_file(path, content, lang))
            .collect()
    }
}

/// Extract the variable being assigned on the LHS of an assignment.
fn extract_assigned_var(line: &str) -> Option<String> {
    let trimmed = line.trim();

    // Python/JS: var = ..., let var = ..., const var = ..., var var = ...
    // Go: var := ...
    // Strip leading let/const/var keywords
    let stripped = trimmed
        .strip_prefix("let ")
        .or_else(|| trimmed.strip_prefix("const "))
        .or_else(|| trimmed.strip_prefix("var "))
        .unwrap_or(trimmed);

    // Look for = (but not ==, !=, <=, >=)
    if let Some(eq_idx) = stripped.find('=') {
        if eq_idx == 0 {
            return None;
        }
        let before_eq = stripped[..eq_idx].trim();
        let after_eq_start = &stripped[eq_idx..];

        // Skip ==, !=, <=, >=
        if after_eq_start.starts_with("==")
            || before_eq.ends_with('!')
            || before_eq.ends_with('<')
            || before_eq.ends_with('>')
        {
            return None;
        }

        // Handle := (Go)
        let var_name = before_eq.trim_end_matches(':').trim();

        // Extract just the variable name (no type annotations, destructuring etc.)
        let var_name = var_name.split(':').next()?.trim(); // Strip TS type annotations
        let var_name = var_name.split_whitespace().last()?; // Take last token

        if var_name.is_empty()
            || var_name.contains('(')
            || var_name.contains(')')
            || var_name.contains('[')
        {
            return None;
        }

        Some(var_name.to_string())
    } else {
        None
    }
}

/// Detect language from file extension.
pub fn detect_language(path: &str) -> Option<&'static str> {
    let ext = std::path::Path::new(path).extension()?.to_str()?;
    match ext {
        "py" => Some("python"),
        "js" | "jsx" | "mjs" => Some("javascript"),
        "ts" | "tsx" => Some("typescript"),
        "rs" => Some("rust"),
        "go" => Some("go"),
        "java" => Some("java"),
        _ => None,
    }
}

// ---- Pipeline Stage ----

pub struct TaintAnalysisStage {
    pub scan_id: Uuid,
    pub repo_id: Uuid,
    pub db: Arc<DatabaseOperations>,
}

impl TaintAnalysisStage {
    pub fn new(scan_id: Uuid, repo_id: Uuid, db: Arc<DatabaseOperations>) -> Self {
        Self {
            scan_id,
            repo_id,
            db,
        }
    }

    pub async fn run(&self, code_index: &CodeIndex) -> HeimdallResult<Vec<TaintFlow>> {
        info!("[{}] Starting taint analysis", self.scan_id);

        let analyzer = TaintAnalyzer::new();
        let mut all_flows = Vec::new();

        for file in code_index.files.values() {
            let language = match file.language.as_deref() {
                Some(lang) => lang,
                None => continue,
            };

            let flows = analyzer.analyze_file(&file.relative_path, &file.content, language);
            all_flows.extend(flows);
        }

        info!(
            "[{}] Taint analysis found {} flows",
            self.scan_id,
            all_flows.len()
        );

        // Persist findings
        for flow in &all_flows {
            let cwe = match flow.sink_category {
                SinkCategory::Sql => "CWE-89",
                SinkCategory::Command => "CWE-78",
                SinkCategory::Xss => "CWE-79",
                SinkCategory::Deserialization => "CWE-502",
                SinkCategory::FileAccess => "CWE-22",
            };

            let title = format!(
                "Taint flow: {:?} → {:?} in {}",
                flow.source_category, flow.sink_category, flow.file_path
            );
            let description = format!(
                "Data flows from untrusted source (line {}) to dangerous sink (line {}).\n\nSource: {}\nSink: {}\nVariable chain: {}",
                flow.source_line,
                flow.sink_line,
                flow.source_text.trim(),
                flow.sink_text.trim(),
                flow.variable_chain.join(" → ")
            );
            let snippet = format!(
                "{:>5} | {}\n{:>5} | {}\n\nVariable chain: {}",
                flow.source_line,
                flow.source_text.trim(),
                flow.sink_line,
                flow.sink_text.trim(),
                flow.variable_chain.join(" → ")
            );
            let evidence = FindingEvidence::code_change(
                snippet,
                taint_fix_guidance(&flow.sink_category),
                taint_fix_summary(&flow.sink_category),
            )
            .with_references([
                cwe_reference(cwe),
                taint_reference(&flow.sink_category).to_string(),
            ]);

            let _ = self
                .db
                .create_finding_full(
                    self.scan_id,
                    self.repo_id,
                    "static",
                    &flow.severity,
                    "medium",
                    &title,
                    Some(&description),
                    Some(cwe),
                    &flow.file_path,
                    sat_i32_usize(flow.source_line),
                    Some(sat_i32_usize(flow.sink_line)),
                    &format!(
                        "taint-{}-{}-{}",
                        flow.file_path, flow.source_line, flow.sink_line
                    ),
                    None,
                    &evidence,
                )
                .await;
        }

        Ok(all_flows)
    }
}

fn taint_fix_summary(category: &SinkCategory) -> &'static str {
    match category {
        SinkCategory::Sql => "Break the tainted flow by switching to parameterized queries.",
        SinkCategory::Command => {
            "Break the tainted flow by passing arguments as an argv list, not a shell string."
        }
        SinkCategory::Xss => {
            "Break the tainted flow by encoding output or sanitizing HTML before rendering."
        }
        SinkCategory::Deserialization => {
            "Break the tainted flow by rejecting untrusted serialized data or switching to a safe format."
        }
        SinkCategory::FileAccess => {
            "Break the tainted flow by canonicalizing paths and enforcing an allow-listed root."
        }
    }
}

fn taint_fix_guidance(category: &SinkCategory) -> &'static str {
    match category {
        SinkCategory::Sql => {
            "// Replace string-built SQL with parameter binding.\n// Example:\n//   sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(user_id)"
        }
        SinkCategory::Command => {
            "// Replace shell-string execution with argv-based process spawning.\n// Example:\n//   Command::new(\"git\").arg(\"status\").arg(repo_path)"
        }
        SinkCategory::Xss => {
            "// Treat the source value as untrusted output.\n// Render it as text (`textContent`) or sanitize it with a trusted HTML sanitizer before injecting it."
        }
        SinkCategory::Deserialization => {
            "// Do not deserialize attacker-controlled bytes with an unsafe format.\n// Prefer JSON / schema-validated input and reject untrusted pickle / Java serialization payloads."
        }
        SinkCategory::FileAccess => {
            "// Canonicalize the user-controlled path, reject `..` / absolute paths, and enforce that the resolved path stays under an allow-listed root directory."
        }
    }
}

fn taint_reference(category: &SinkCategory) -> &'static str {
    match category {
        SinkCategory::Sql => "https://owasp.org/www-community/attacks/SQL_Injection",
        SinkCategory::Command => "https://owasp.org/www-community/attacks/Command_Injection",
        SinkCategory::Xss => "https://owasp.org/www-community/attacks/xss/",
        SinkCategory::Deserialization => {
            "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"
        }
        SinkCategory::FileAccess => "https://owasp.org/www-community/attacks/Path_Traversal",
    }
}

fn cwe_reference(cwe_id: &str) -> String {
    let numeric = cwe_id.trim_start_matches("CWE-");
    format!("https://cwe.mitre.org/data/definitions/{numeric}.html")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyzer() -> TaintAnalyzer {
        TaintAnalyzer::new()
    }

    #[test]
    fn test_python_sqli_fstring() {
        let code = r#"
user_input = request.args.get("name")
query = f"SELECT * FROM users WHERE name = '{user_input}'"
cursor.execute(query)
"#;
        let flows = analyzer().analyze_file("app.py", code, "python");
        assert!(!flows.is_empty());
        assert!(
            flows
                .iter()
                .any(|f| matches!(f.sink_category, SinkCategory::Sql))
        );
    }

    #[test]
    fn test_python_command_injection() {
        let code = r#"
cmd = request.form.get("cmd")
os.system(cmd)
"#;
        let flows = analyzer().analyze_file("app.py", code, "python");
        assert!(!flows.is_empty());
        assert!(
            flows
                .iter()
                .any(|f| matches!(f.sink_category, SinkCategory::Command))
        );
    }

    #[test]
    fn test_js_sqli_concat() {
        let code = r#"
const name = req.query.name;
const sql = "SELECT * FROM users WHERE name = '" + name + "'";
db.query(sql);
"#;
        let flows = analyzer().analyze_file("app.js", code, "javascript");
        assert!(!flows.is_empty());
    }

    #[test]
    fn test_js_xss_innerhtml() {
        let code = r#"
const input = req.body.comment;
element.innerHTML = input;
"#;
        let flows = analyzer().analyze_file("app.js", code, "javascript");
        assert!(!flows.is_empty());
        assert!(
            flows
                .iter()
                .any(|f| matches!(f.sink_category, SinkCategory::Xss))
        );
    }

    #[test]
    fn test_variable_propagation() {
        let code = r#"
user_data = request.args.get("x")
processed = user_data.strip()
clean = processed.lower()
os.system(clean)
"#;
        let flows = analyzer().analyze_file("app.py", code, "python");
        assert!(
            !flows.is_empty(),
            "Should detect taint through variable chain"
        );
    }

    #[test]
    fn test_no_source_no_flow() {
        let code = r#"
safe_val = "hardcoded"
os.system(safe_val)
"#;
        let flows = analyzer().analyze_file("app.py", code, "python");
        assert!(flows.is_empty(), "No taint source means no flows");
    }

    #[test]
    fn test_no_sink_no_flow() {
        let code = r#"
user_input = request.args.get("name")
print(user_input)
"#;
        let flows = analyzer().analyze_file("app.py", code, "python");
        assert!(flows.is_empty(), "No sink means no flows");
    }

    #[test]
    fn test_detect_language() {
        assert_eq!(detect_language("app.py"), Some("python"));
        assert_eq!(detect_language("app.js"), Some("javascript"));
        assert_eq!(detect_language("app.ts"), Some("typescript"));
        assert_eq!(detect_language("main.rs"), Some("rust"));
        assert_eq!(detect_language("main.go"), Some("go"));
        assert_eq!(detect_language("App.java"), Some("java"));
        assert_eq!(detect_language("style.css"), None);
    }

    #[test]
    fn test_extract_assigned_var() {
        assert_eq!(extract_assigned_var("x = 1"), Some("x".to_string()));
        assert_eq!(
            extract_assigned_var("let name = req.body"),
            Some("name".to_string())
        );
        assert_eq!(
            extract_assigned_var("const val = foo"),
            Some("val".to_string())
        );
        assert_eq!(extract_assigned_var("if x == 1:"), None);
        assert_eq!(extract_assigned_var("  return foo"), None);
    }
}
