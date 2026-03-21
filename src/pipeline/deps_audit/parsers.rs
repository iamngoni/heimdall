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

/// Parse Cargo.toml [dependencies] section.
fn parse_cargo_toml(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut in_deps = false;

    for line in content.lines() {
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

        // name = "version" or name = { version = "..." }
        if let Some((name, rest)) = trimmed.split_once('=') {
            let name = name.trim();
            let rest = rest.trim();

            let version = if rest.starts_with('"') {
                rest.trim_matches('"').to_string()
            } else if rest.starts_with('{') {
                // Inline table: extract version field
                extract_inline_version(rest)
            } else {
                continue;
            };

            if !version.is_empty() {
                deps.push(Dependency {
                    name: name.to_string(),
                    version,
                    ecosystem: "crates.io".to_string(),
                });
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
    let mut in_package = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            // Emit previous package if complete
            if in_package && !name.is_empty() && !version.is_empty() {
                deps.push(Dependency {
                    name: std::mem::take(&mut name),
                    version: std::mem::take(&mut version),
                    ecosystem: "crates.io".to_string(),
                });
            }
            in_package = true;
            name.clear();
            version.clear();
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
                "version" => version = val.to_string(),
                _ => {}
            }
        }
    }

    // Emit last package
    if in_package && !name.is_empty() && !version.is_empty() {
        deps.push(Dependency {
            name,
            version,
            ecosystem: "crates.io".to_string(),
        });
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

    // package-lock.json v2/v3 uses "packages" with "" as root
    if let Some(packages) = json.get("packages").and_then(|v| v.as_object()) {
        for (path, info) in packages {
            // Skip the root package (empty path)
            if path.is_empty() {
                continue;
            }
            // Extract name from the path (e.g., "node_modules/express")
            let name = path.rsplit("node_modules/").next().unwrap_or(path);
            let version = info.get("version").and_then(|v| v.as_str()).unwrap_or("");

            if !name.is_empty() && !version.is_empty() {
                deps.push(Dependency {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem: "npm".to_string(),
                });
            }
        }
    }
    // Fallback: package-lock.json v1 uses "dependencies"
    else if let Some(dependencies) = json.get("dependencies").and_then(|v| v.as_object()) {
        fn walk_v1_deps(
            obj: &serde_json::Map<String, serde_json::Value>,
            deps: &mut Vec<Dependency>,
        ) {
            for (name, info) in obj {
                if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                    deps.push(Dependency {
                        name: name.clone(),
                        version: version.to_string(),
                        ecosystem: "npm".to_string(),
                    });
                }
                // Recurse into nested dependencies
                if let Some(nested) = info.get("dependencies").and_then(|v| v.as_object()) {
                    walk_v1_deps(nested, deps);
                }
            }
        }
        walk_v1_deps(dependencies, &mut deps);
    }

    deps
}

fn extract_inline_version(table: &str) -> String {
    // Simple extraction: find version = "..."
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
                if let Some(v) = version.as_str() {
                    // Strip leading ^, ~, >=, etc.
                    let clean = v.trim_start_matches(|c: char| !c.is_ascii_digit());
                    if !clean.is_empty() {
                        deps.push(Dependency {
                            name: name.clone(),
                            version: clean.to_string(),
                            ecosystem: "npm".to_string(),
                        });
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

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }

        // Strip inline comments
        let line = if let Some(idx) = line.find('#') {
            line[..idx].trim()
        } else {
            line
        };

        // Handle ==, >=, ~=, <=, !=
        let separators = ["==", ">=", "~=", "<=", "!=", ">", "<"];
        let mut found = false;
        for sep in &separators {
            if let Some(idx) = line.find(sep) {
                let name = line[..idx].trim();
                let version = line[idx + sep.len()..].trim();
                // Take first version in compound specifiers (e.g., ">=1.0,<2.0")
                let version = version.split(',').next().unwrap_or(version).trim();
                if !name.is_empty() && !version.is_empty() {
                    deps.push(Dependency {
                        name: name.to_string(),
                        version: version.to_string(),
                        ecosystem: "PyPI".to_string(),
                    });
                }
                found = true;
                break;
            }
        }

        if !found && !line.is_empty() {
            // Package name without version
            deps.push(Dependency {
                name: line.to_string(),
                version: String::new(),
                ecosystem: "PyPI".to_string(),
            });
        }
    }

    deps
}

/// Parse go.mod.
fn parse_go_mod(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut in_require = false;

    for line in content.lines() {
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
            // Single-line require
            let parts: Vec<&str> = trimmed["require ".len()..].split_whitespace().collect();
            if parts.len() >= 2 {
                deps.push(Dependency {
                    name: parts[0].to_string(),
                    version: parts[1].trim_start_matches('v').to_string(),
                    ecosystem: "Go".to_string(),
                });
            }
            continue;
        }

        if in_require {
            // Lines inside require block: "module/path v1.2.3"
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 && !parts[0].starts_with("//") {
                deps.push(Dependency {
                    name: parts[0].to_string(),
                    version: parts[1].trim_start_matches('v').to_string(),
                    ecosystem: "Go".to_string(),
                });
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

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "<dependency>" {
            in_dependency = true;
            group_id.clear();
            artifact_id.clear();
            version.clear();
            continue;
        }

        if trimmed == "</dependency>" {
            if in_dependency
                && !artifact_id.is_empty()
                && !version.is_empty()
                && !version.contains("${")
            {
                deps.push(Dependency {
                    name: format!("{}:{}", group_id, artifact_id),
                    version: version.clone(),
                    ecosystem: "Maven".to_string(),
                });
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
        assert_eq!(deps.len(), 1); // junit skipped due to ${...}
        assert_eq!(deps[0].name, "org.springframework:spring-core");
        assert_eq!(deps[0].version, "5.3.30");
    }
}
