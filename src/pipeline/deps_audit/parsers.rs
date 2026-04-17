//
//  heimdall
//  src/pipeline/deps_audit/parsers.rs
//

use super::Dependency;

/// Parse a manifest file and extract dependencies.
pub fn parse_manifest(ecosystem: &str, filename: &str, content: &str) -> Vec<Dependency> {
    match (ecosystem, filename) {
        ("crates.io", "Cargo.lock") => parse_cargo_lock(content),
        ("crates.io", _) => parse_cargo_toml(content),
        ("npm", "package-lock.json") => parse_package_lock_json(content),
        ("npm", _) => parse_package_json(content),
        ("PyPI", _) => parse_requirements_txt(content),
        ("Go", _) => parse_go_mod(content),
        ("Maven", _) => parse_pom_xml(content),
        _ => vec![],
    }
}

fn make_dependency(
    name: impl Into<String>,
    version: impl Into<String>,
    declared_version: impl Into<String>,
    ecosystem: &str,
    content: &str,
    line_start: usize,
    line_end: usize,
) -> Dependency {
    Dependency {
        name: name.into(),
        version: version.into(),
        declared_version: declared_version.into(),
        ecosystem: ecosystem.to_string(),
        line_start: line_start as i32,
        line_end: Some(line_end as i32),
        code_snippet: snippet_for_range(content, line_start, line_end),
    }
}

fn snippet_for_range(content: &str, line_start: usize, line_end: usize) -> String {
    let lines = content.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return String::new();
    }

    let start = line_start.max(1).min(lines.len());
    let end = line_end.max(start).min(lines.len());
    lines[start - 1..end].join("\n")
}

fn find_line_number(content: &str, needle: &str) -> usize {
    content
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains(needle))
        .map(|(idx, _)| idx + 1)
        .unwrap_or(1)
}

/// Parse Cargo.toml [dependencies] section.
fn parse_cargo_toml(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut in_deps = false;

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with('[') {
            in_deps = trimmed == "[dependencies]"
                || trimmed == "[dev-dependencies]"
                || trimmed == "[build-dependencies]";
            continue;
        }

        if !in_deps {
            continue;
        }

        if let Some((name, rest)) = trimmed.split_once('=') {
            let name = name.trim();
            let rest = rest.trim();

            let declared_version = if rest.starts_with('"') {
                rest.trim_matches('"').to_string()
            } else if rest.starts_with('{') {
                extract_inline_version(rest)
            } else {
                continue;
            };

            if !declared_version.is_empty() {
                deps.push(make_dependency(
                    name,
                    declared_version.clone(),
                    declared_version,
                    "crates.io",
                    content,
                    line_idx + 1,
                    line_idx + 1,
                ));
            }
        }
    }

    deps
}

/// Parse Cargo.lock [[package]] blocks for exact resolved versions.
fn parse_cargo_lock(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut version_line = 1usize;
    let mut in_package = false;

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            if in_package && !name.is_empty() && !version.is_empty() {
                deps.push(make_dependency(
                    std::mem::take(&mut name),
                    version.clone(),
                    std::mem::take(&mut version),
                    "crates.io",
                    content,
                    version_line,
                    version_line,
                ));
            }
            in_package = true;
            name.clear();
            version.clear();
            version_line = line_idx + 1;
            continue;
        }

        if !in_package {
            continue;
        }

        if let Some((key, val)) = trimmed.split_once('=') {
            let key = key.trim();
            let val = val.trim().trim_matches('"');
            match key {
                "name" => name = val.to_string(),
                "version" => {
                    version = val.to_string();
                    version_line = line_idx + 1;
                }
                _ => {}
            }
        }
    }

    if in_package && !name.is_empty() && !version.is_empty() {
        deps.push(make_dependency(
            name,
            version.clone(),
            version,
            "crates.io",
            content,
            version_line,
            version_line,
        ));
    }

    deps
}

/// Parse package-lock.json for exact resolved versions.
fn parse_package_lock_json(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();

    let json: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return deps,
    };

    if let Some(packages) = json.get("packages").and_then(|v| v.as_object()) {
        for (path, info) in packages {
            if path.is_empty() {
                continue;
            }

            let name = path.rsplit("node_modules/").next().unwrap_or(path);
            let version = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
            if !name.is_empty() && !version.is_empty() {
                let line_number = find_line_number(content, &format!("\"{path}\""));
                deps.push(make_dependency(
                    name,
                    version,
                    version,
                    "npm",
                    content,
                    line_number,
                    line_number,
                ));
            }
        }
    } else if let Some(dependencies) = json.get("dependencies").and_then(|v| v.as_object()) {
        fn walk_v1_deps(
            obj: &serde_json::Map<String, serde_json::Value>,
            content: &str,
            deps: &mut Vec<Dependency>,
        ) {
            for (name, info) in obj {
                if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                    let line_number = find_line_number(content, &format!("\"{name}\""));
                    deps.push(make_dependency(
                        name,
                        version,
                        version,
                        "npm",
                        content,
                        line_number,
                        line_number,
                    ));
                }

                if let Some(nested) = info.get("dependencies").and_then(|v| v.as_object()) {
                    walk_v1_deps(nested, content, deps);
                }
            }
        }

        walk_v1_deps(dependencies, content, &mut deps);
    }

    deps
}

fn extract_inline_version(table: &str) -> String {
    for part in table.split(',') {
        let part = part.trim().trim_matches(|c| c == '{' || c == '}');
        if let Some((key, val)) = part.split_once('=') {
            if key.trim() == "version" {
                return val.trim().trim_matches('"').to_string();
            }
        }
    }
    String::new()
}

/// Parse package.json dependencies.
fn parse_package_json(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();

    let json: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return deps,
    };

    for key in &["dependencies", "devDependencies"] {
        if let Some(obj) = json.get(key).and_then(|v| v.as_object()) {
            for (name, version) in obj {
                if let Some(declared_version) = version.as_str() {
                    let clean = declared_version.trim_start_matches(|c: char| !c.is_ascii_digit());
                    if !clean.is_empty() {
                        let line_number = find_line_number(content, &format!("\"{name}\""));
                        deps.push(make_dependency(
                            name,
                            clean,
                            declared_version,
                            "npm",
                            content,
                            line_number,
                            line_number,
                        ));
                    }
                }
            }
        }
    }

    deps
}

/// Parse requirements.txt.
fn parse_requirements_txt(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }

        let line = if let Some(idx) = line.find('#') {
            line[..idx].trim()
        } else {
            line
        };

        let separators = ["==", ">=", "~=", "<=", "!=", ">", "<"];
        let mut found = false;
        for sep in &separators {
            if let Some(idx) = line.find(sep) {
                let name = line[..idx].trim();
                let version_spec = line[idx + sep.len()..].trim();
                let declared_version = version_spec.split(',').next().unwrap_or(version_spec).trim();
                if !name.is_empty() && !declared_version.is_empty() {
                    deps.push(make_dependency(
                        name,
                        declared_version,
                        declared_version,
                        "PyPI",
                        content,
                        line_idx + 1,
                        line_idx + 1,
                    ));
                }
                found = true;
                break;
            }
        }

        if !found && !line.is_empty() {
            deps.push(make_dependency(
                line,
                "",
                "",
                "PyPI",
                content,
                line_idx + 1,
                line_idx + 1,
            ));
        }
    }

    deps
}

/// Parse go.mod.
fn parse_go_mod(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut in_require = false;

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with("require (") || trimmed == "require (" {
            in_require = true;
            continue;
        }

        if in_require && trimmed == ")" {
            in_require = false;
            continue;
        }

        if trimmed.starts_with("require ") && !trimmed.contains('(') {
            let parts: Vec<&str> = trimmed["require ".len()..].split_whitespace().collect();
            if parts.len() >= 2 {
                let declared_version = parts[1];
                deps.push(make_dependency(
                    parts[0],
                    declared_version.trim_start_matches('v'),
                    declared_version,
                    "Go",
                    content,
                    line_idx + 1,
                    line_idx + 1,
                ));
            }
            continue;
        }

        if in_require {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 && !parts[0].starts_with("//") {
                let declared_version = parts[1];
                deps.push(make_dependency(
                    parts[0],
                    declared_version.trim_start_matches('v'),
                    declared_version,
                    "Go",
                    content,
                    line_idx + 1,
                    line_idx + 1,
                ));
            }
        }
    }

    deps
}

/// Parse pom.xml dependencies (simple string matching).
fn parse_pom_xml(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut in_dependency = false;
    let mut group_id = String::new();
    let mut artifact_id = String::new();
    let mut version = String::new();
    let mut dependency_start_line = 1usize;

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed == "<dependency>" {
            in_dependency = true;
            group_id.clear();
            artifact_id.clear();
            version.clear();
            dependency_start_line = line_idx + 1;
            continue;
        }

        if trimmed == "</dependency>" {
            if in_dependency
                && !artifact_id.is_empty()
                && !version.is_empty()
                && !version.contains("${")
            {
                deps.push(make_dependency(
                    format!("{}:{}", group_id, artifact_id),
                    version.clone(),
                    version.clone(),
                    "Maven",
                    content,
                    dependency_start_line,
                    line_idx + 1,
                ));
            }
            in_dependency = false;
            continue;
        }

        if in_dependency {
            if let Some(v) = extract_xml_value(trimmed, "groupId") {
                group_id = v;
            } else if let Some(v) = extract_xml_value(trimmed, "artifactId") {
                artifact_id = v;
            } else if let Some(v) = extract_xml_value(trimmed, "version") {
                version = v;
            }
        }
    }

    deps
}

fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    if let Some(start) = line.find(&open) {
        if let Some(end) = line.find(&close) {
            let val = &line[start + open.len()..end];
            return Some(val.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cargo_toml() {
        let content = r#"
[dependencies]
serde = "1.0"
tokio = { version = "1.28", features = ["full"] }
rand = { git = "https://github.com/rust-random/rand" }

[dev-dependencies]
tempfile = "3.5"
"#;
        let deps = parse_cargo_toml(content);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, "1.0");
        assert_eq!(deps[1].name, "tokio");
        assert_eq!(deps[1].version, "1.28");
        assert_eq!(deps[2].name, "tempfile");
    }

    #[test]
    fn test_parse_package_json() {
        let content = r#"{
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "~4.17.21"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}"#;
        let deps = parse_package_json(content);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "express");
        assert_eq!(deps[0].version, "4.18.2");
        assert_eq!(deps[0].declared_version, "^4.18.2");
    }

    #[test]
    fn test_parse_requirements_txt() {
        let content = "flask==2.3.0\nrequests>=2.28.0\nnumpy  # math lib\n";
        let deps = parse_requirements_txt(content);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "flask");
        assert_eq!(deps[0].version, "2.3.0");
        assert_eq!(deps[1].name, "requests");
        assert_eq!(deps[1].version, "2.28.0");
        assert_eq!(deps[2].name, "numpy");
    }

    #[test]
    fn test_parse_go_mod() {
        let content = r#"
module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.14.0
)
"#;
        let deps = parse_go_mod(content);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        assert_eq!(deps[0].version, "1.9.1");
        assert_eq!(deps[0].declared_version, "v1.9.1");
    }

    #[test]
    fn test_parse_pom_xml() {
        let content = r#"
<dependencies>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>5.3.30</version>
    </dependency>
    <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>${junit.version}</version>
    </dependency>
</dependencies>
"#;
        let deps = parse_pom_xml(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "org.springframework:spring-core");
        assert_eq!(deps[0].version, "5.3.30");
    }
}
