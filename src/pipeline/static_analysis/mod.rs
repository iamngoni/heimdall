//
//  heimdall
//  src/pipeline/static_analysis/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::collections::HashSet;
use std::sync::Arc;

use log::info;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use crate::config::SemgrepConfig;
use crate::db::DatabaseOperations;
use crate::index::CodeIndex;
use crate::models::{FindingEvidence, FindingFixType, HeimdallResult};
use crate::pipeline::deps_audit::DepsAuditStage;
use crate::util::sat_i32_usize;

pub mod semgrep;

/// Static analysis stage using pattern matching for deterministic vulnerability detection.
/// Catches low-hanging fruit before the AI Hunt agent.
pub struct StaticAnalysisStage {
    pub scan_id: uuid::Uuid,
    pub repo_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
    pub work_dir: Option<std::path::PathBuf>,
    pub semgrep_config: SemgrepConfig,
}

/// Context passed to the Hunt agent about what static analysis found.
pub struct StaticAnalysisContext {
    pub findings_count: usize,
    pub summary: String,
}

/// A pattern rule for static analysis.
///
/// Every rule carries both a detection regex AND remediation guidance. The
/// `fix_summary` and `fix_template` fields are required — a rule that detects
/// a problem without telling operators how to fix it is not acceptable.
/// `fix_type` classifies the remediation shape so the UI and downstream
/// automation can render/act appropriately.
struct Rule {
    name: &'static str,
    pattern: &'static str,
    severity: &'static str,
    cwe: &'static str,
    description: &'static str,
    languages: &'static [&'static str],
    /// One-liner plain-English summary of the remediation shown in triage
    /// queues and finding headers.
    fix_summary: &'static str,
    /// Concrete replacement guidance — a code snippet, shell command, or
    /// description of the safer API. Rendered as the suggested_patch when no
    /// line-level diff can be generated.
    fix_template: &'static str,
    /// Classification of the fix (code edit vs config change vs manual review).
    fix_type: FindingFixType,
    /// Authoritative references — OWASP entries, CWE pages, RFC links.
    /// Populated into `FindingEvidence::references` for every match.
    references: &'static [&'static str],
}

const RULES: &[Rule] = &[
    // SQL injection
    Rule {
        name: "sql-injection-string-concat",
        pattern: r#"(?i)(?:execute|query|raw)\s*\(.*(?:format!|%s|\+\s*\w+|\$\{)"#,
        severity: "high",
        cwe: "CWE-89",
        description: "Potential SQL injection via string concatenation/interpolation",
        languages: &["rust", "python", "javascript", "typescript", "go", "java"],
        fix_summary: "Use parameterized queries — never interpolate user input into SQL strings.",
        fix_template: "// Replace string interpolation with parameter binding:\n// Before: db.query(format!(\"SELECT * FROM users WHERE id = {}\", user_id))\n// After:  sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(user_id)\n//\n// Each database driver exposes a parameterized API:\n//   Rust:        sqlx::query(\"... WHERE id = $1\").bind(value)\n//   Python:      cursor.execute(\"... WHERE id = %s\", (value,))\n//   JavaScript:  db.query(\"... WHERE id = $1\", [value])\n//   Go:          db.Query(\"... WHERE id = $1\", value)\n//   Java (JDBC): pstmt.setString(1, value)",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
    Rule {
        name: "sql-injection-fstring",
        pattern: r#"(?i)(?:execute|query|cursor\.)\s*\(\s*f["'].*(?:SELECT|INSERT|UPDATE|DELETE)"#,
        severity: "high",
        cwe: "CWE-89",
        description: "SQL query built with f-string interpolation",
        languages: &["python"],
        fix_summary: "Replace f-string SQL with parameterized queries using %s placeholders.",
        fix_template: "# Before:\n# cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n#\n# After (psycopg2 / sqlite3 / mysql-connector):\n# cursor.execute(\"SELECT * FROM users WHERE name = %s\", (name,))\n#\n# After (SQLAlchemy Core):\n# conn.execute(text(\"SELECT * FROM users WHERE name = :name\"), {\"name\": name})",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://bobby-tables.com/python",
        ],
    },
    // Command injection
    Rule {
        name: "command-injection",
        pattern: r#"(?i)(?:system|exec|popen|subprocess\.(?:call|run|Popen)|child_process\.exec)\s*\(.*(?:format!|\+\s*\w+|\$\{|%s)"#,
        severity: "critical",
        cwe: "CWE-78",
        description: "Potential command injection via string interpolation in shell command",
        languages: &["rust", "python", "javascript", "typescript", "go", "java"],
        fix_summary: "Pass arguments as a list/array — never concatenate user input into shell strings.",
        fix_template: "// Before: subprocess.call(\"ls \" + user_input, shell=True)\n// After:  subprocess.run([\"ls\", user_input], shell=False, check=True)\n//\n// Language-specific safe APIs:\n//   Python:     subprocess.run([prog, arg1, arg2], shell=False)\n//   Node.js:    require('child_process').execFile(prog, [arg1, arg2])\n//   Rust:       Command::new(prog).arg(arg1).arg(arg2).output()\n//   Go:         exec.Command(prog, arg1, arg2).Output()\n//\n// shell=True / bash -c is a code smell when the command includes user input.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },
    // Hardcoded secrets
    Rule {
        name: "hardcoded-api-key",
        pattern: r#"(?i)(?:api_?key|secret_?key|password|token)\s*[:=]\s*["'][A-Za-z0-9+/=_-]{16,}["']"#,
        severity: "high",
        cwe: "CWE-798",
        description: "Potential hardcoded secret or API key",
        languages: &[],
        fix_summary: "Move the secret to an environment variable or a secrets manager and rotate the exposed value.",
        fix_template: "// 1. Remove the literal from source.\n// 2. Read from env at runtime:\n//    Rust:   std::env::var(\"API_KEY\")\n//    Python: os.environ[\"API_KEY\"]\n//    Node:   process.env.API_KEY\n// 3. Rotate the credential — assume it is already compromised if committed.\n// 4. Add the name (NOT the value) to .env.example and document in README.\n// 5. Ensure .env is listed in .gitignore.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
    },
    Rule {
        name: "aws-access-key",
        pattern: r#"AKIA[0-9A-Z]{16}"#,
        severity: "critical",
        cwe: "CWE-798",
        description: "AWS access key ID detected",
        languages: &[],
        fix_summary: "Rotate the AWS key immediately and switch to IAM roles or env-var credentials.",
        fix_template: "// URGENT:\n// 1. Rotate the key: AWS Console -> IAM -> Users -> Security credentials -> Make inactive, then Delete.\n// 2. Audit CloudTrail for unauthorized use over the key's lifetime.\n// 3. Remove the literal from source AND git history (use `git filter-repo`).\n// 4. Replace with one of:\n//    - IAM role (preferred for EC2/ECS/Lambda)\n//    - AWS SSO / Identity Center for local development\n//    - Environment variables loaded from a secrets manager (AWS Secrets Manager, Vault)",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys_rotate.html",
        ],
    },
    Rule {
        name: "private-key",
        pattern: r#"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"#,
        severity: "critical",
        cwe: "CWE-321",
        description: "Private key embedded in source code",
        languages: &[],
        fix_summary: "Rotate the key, remove it from source AND git history, load from a secret store at runtime.",
        fix_template: "// 1. Treat the key as compromised — regenerate a new keypair.\n// 2. Revoke any certificates issued against the old key.\n// 3. Remove from git history: `git filter-repo --path <file> --invert-paths`\n//    (or use BFG Repo-Cleaner for larger repos).\n// 4. Load the new key at runtime:\n//    - Kubernetes: Secret mounted as a file\n//    - Vault / AWS Secrets Manager\n//    - Env var with base64-encoded PEM (dev only)\n// 5. Audit any systems that accepted signatures from the old key.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/321.html",
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
        ],
    },
    // Path traversal
    Rule {
        name: "path-traversal",
        pattern: r#"(?i)(?:open|read_file|fs\.read|Path\.new)\s*\(.*(?:params|request|req\.|query|input)"#,
        severity: "high",
        cwe: "CWE-22",
        description: "Potential path traversal — file operation with user-controlled input",
        languages: &[],
        fix_summary: "Validate path is inside an allowed root AFTER canonicalization; reject `..` and absolute paths from user input.",
        fix_template: "// Safe pattern:\n// 1. Define an allow-list root: let root = PathBuf::from(\"/var/app/uploads\").canonicalize()?\n// 2. Join + canonicalize the user-supplied path.\n// 3. Verify the resolved path starts with the root.\n//\n// Rust example:\n//   let candidate = root.join(user_path).canonicalize()?;\n//   if !candidate.starts_with(&root) { return Err(\"path traversal\".into()); }\n//\n// Python:\n//   full = os.path.realpath(os.path.join(root, user_path))\n//   if not full.startswith(root + os.sep): raise SecurityError\n//\n// Never just strip `..` — attackers use encoding tricks (`..%2f`, `....//`).",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    },
    // XSS
    Rule {
        name: "xss-innerhtml",
        pattern: r#"\.innerHTML\s*="#,
        severity: "medium",
        cwe: "CWE-79",
        description: "Potential XSS via innerHTML assignment",
        languages: &["javascript", "typescript"],
        fix_summary: "Use `textContent` for plain text, or sanitize HTML with DOMPurify before assignment.",
        fix_template: "// If you just need text:\n//   element.textContent = userInput;   // safe — no HTML parsing\n//\n// If you genuinely need HTML (rare):\n//   import DOMPurify from 'dompurify';\n//   element.innerHTML = DOMPurify.sanitize(userInput, { USE_PROFILES: { html: true } });\n//\n// In frameworks, prefer the framework's escaping:\n//   React:  {userInput}          // auto-escapes\n//   Vue:    {{ userInput }}      // auto-escapes\n//   Svelte: {userInput}          // auto-escapes",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://owasp.org/www-community/attacks/xss/",
            "https://github.com/cure53/DOMPurify",
        ],
    },
    Rule {
        name: "xss-dangerously-set",
        pattern: r#"dangerouslySetInnerHTML"#,
        severity: "medium",
        cwe: "CWE-79",
        description: "React dangerouslySetInnerHTML usage — ensure input is sanitized",
        languages: &["javascript", "typescript"],
        fix_summary: "Render as text with `{value}` if possible; otherwise sanitize with DOMPurify before passing to __html.",
        fix_template: "// Prefer plain rendering (React auto-escapes):\n//   <div>{userContent}</div>\n//\n// If HTML is truly required:\n//   import DOMPurify from 'isomorphic-dompurify';\n//   <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />\n//\n// Document WHY raw HTML is needed in a comment — this API is called\n// `dangerous` for a reason. Review any data that reaches it as untrusted.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html",
        ],
    },
    // Deserialization
    Rule {
        name: "unsafe-deserialization-python",
        pattern: r#"(?:pickle\.loads?|yaml\.(?:load|unsafe_load))\s*\("#,
        severity: "high",
        cwe: "CWE-502",
        description: "Unsafe deserialization detected",
        languages: &["python"],
        fix_summary: "Never `pickle.loads` untrusted data; use JSON or `yaml.safe_load`.",
        fix_template: "# For JSON-compatible data:\n#   json.loads(data)\n#\n# For YAML:\n#   yaml.safe_load(data)          # safe\n#   yaml.load(data)                # UNSAFE — arbitrary code execution\n#\n# If you must use pickle for trusted internal data:\n# - Sign the payload with HMAC and verify signature before unpickling.\n# - Document the trust boundary.\n#\n# pickle is arbitrary-code-execution by design. Treat any pickled blob\n# from outside the process as RCE.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://docs.python.org/3/library/pickle.html#restricting-globals",
        ],
    },
    Rule {
        name: "unsafe-deserialization-java",
        pattern: r#"ObjectInputStream\s*\("#,
        severity: "high",
        cwe: "CWE-502",
        description: "Java deserialization of untrusted data",
        languages: &["java"],
        fix_summary: "Avoid Java serialization for untrusted data; use JSON (Jackson/Gson) or add an ObjectInputFilter.",
        fix_template: "// Preferred: switch to JSON:\n//   ObjectMapper mapper = new ObjectMapper();\n//   MyType value = mapper.readValue(data, MyType.class);\n//\n// If you must use ObjectInputStream, install a serialization filter:\n//   ObjectInputStream ois = new ObjectInputStream(in);\n//   ois.setObjectInputFilter(filter ->\n//       filter.serialClass() == MyType.class\n//           ? ObjectInputFilter.Status.ALLOWED\n//           : ObjectInputFilter.Status.REJECTED);\n//\n// See JEP 290 (Java 9+).",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            "https://openjdk.org/jeps/290",
        ],
    },
    // Weak crypto
    Rule {
        name: "weak-hash-md5",
        pattern: r#"(?i)(?:md5|MD5)\s*[\(.]"#,
        severity: "medium",
        cwe: "CWE-328",
        description: "Use of weak MD5 hash — consider SHA-256 or better",
        languages: &[],
        fix_summary: "Replace MD5 with SHA-256 for integrity or bcrypt/argon2 for passwords.",
        fix_template: "// For data integrity / fingerprinting:\n//   Rust:    use sha2::{Sha256, Digest}; Sha256::digest(data)\n//   Python:  hashlib.sha256(data).hexdigest()\n//   Node:    crypto.createHash('sha256').update(data).digest('hex')\n//\n// For password hashing (NEVER use MD5/SHA-256 directly):\n//   Rust:    argon2 crate\n//   Python:  passlib.hash.argon2 or bcrypt\n//   Node:    bcrypt or argon2\n//\n// MD5 is acceptable ONLY for non-security uses (checksumming large files,\n// cache keys) — and even then, SHA-256 has comparable performance now.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/328.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
        ],
    },
    Rule {
        name: "weak-hash-sha1",
        pattern: r#"(?i)(?:sha1|SHA1)\s*[\(.]"#,
        severity: "low",
        cwe: "CWE-328",
        description: "Use of SHA-1 hash — consider SHA-256 for security-sensitive contexts",
        languages: &[],
        fix_summary: "Use SHA-256 (or SHA-3) anywhere collision resistance matters.",
        fix_template: "// Replace SHA-1 with SHA-256 in:\n// - Certificate pinning\n// - Signature algorithms\n// - Content-addressable storage where collisions are exploitable\n//\n// SHA-1 remains acceptable for non-security uses (git object IDs, older\n// HMAC constructions where key strength carries security) but should not\n// be introduced into new code.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/328.html",
            "https://shattered.io",
        ],
    },
    // CSRF
    Rule {
        name: "missing-csrf-check",
        pattern: r#"(?i)@(?:app\.route|post)\s*\([^)]*methods\s*=\s*\[.*POST"#,
        severity: "medium",
        cwe: "CWE-352",
        description: "POST endpoint without apparent CSRF protection",
        languages: &["python"],
        fix_summary: "Add CSRF token validation via Flask-WTF or a same-origin check.",
        fix_template: "# Flask with Flask-WTF:\n#   from flask_wtf.csrf import CSRFProtect\n#   csrf = CSRFProtect(app)\n#\n# For API endpoints consumed by SPAs, prefer:\n# - SameSite=Lax|Strict cookies (prevents cross-origin POST)\n# - Double-submit cookie pattern\n# - Origin / Referer header validation\n#\n# If the endpoint is truly public (no session), document it and add rate\n# limiting instead.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://flask-wtf.readthedocs.io/en/stable/csrf/",
        ],
    },
    // Open redirect
    Rule {
        name: "open-redirect",
        pattern: r#"(?i)(?:redirect|location\.href|window\.location)\s*=?\s*(?:params|request|req\.|query)"#,
        severity: "medium",
        cwe: "CWE-601",
        description: "Potential open redirect using user-controlled URL",
        languages: &[],
        fix_summary: "Validate redirect targets against an allow-list of known-safe URLs/hosts.",
        fix_template: "// Never redirect to an arbitrary user-supplied URL.\n// Instead:\n// 1. Maintain an allow-list of safe destinations (e.g., relative paths within your app).\n// 2. For external redirects, whitelist by hostname:\n//\n//   let target = parsed_url.host_str().ok_or(\"missing host\")?;\n//   let allowed = [\"example.com\", \"login.example.com\"];\n//   if !allowed.contains(&target) { return reject(); }\n//\n// 3. Prefer redirecting to a key that maps to a known URL server-side:\n//   GET /return?to=account  -> /account\n//   GET /return?to=billing  -> /billing",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/601.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        ],
    },
    // -----------------------------------------------------------------------
    // Injection (extended)
    // -----------------------------------------------------------------------
    Rule {
        name: "ldap-injection",
        pattern: r#"(?i)(?:ldap_search|ldap_bind|ldap\.search|search_s)\s*\(.*(?:format!|\+\s*\w+|\$\{|%s|f["'])"#,
        severity: "high",
        cwe: "CWE-90",
        description: "Potential LDAP injection via string interpolation in LDAP query",
        languages: &["python", "javascript", "typescript", "java"],
        fix_summary: "Escape LDAP filter special characters (`* ( ) \\ NUL`) or use a parameterized LDAP library.",
        fix_template: "// Escape LDAP filter metacharacters before interpolation:\n//   Python:  from ldap.filter import escape_filter_chars\n//            filter = f\"(uid={escape_filter_chars(username)})\"\n//   Java:    org.springframework.ldap.support.LdapEncoder.filterEncode(username)\n//   Node:    ldap-filter-escape package\n//\n// Characters requiring escape in filters: * ( ) \\ NUL\n// Characters requiring escape in DN: , + \" \\ < > ; leading/trailing spaces.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/90.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    Rule {
        name: "xxe-xml-parsing",
        pattern: r#"(?i)(?:XMLParser|etree\.parse|parseString|DocumentBuilder|SAXParser|XMLReader)\s*\("#,
        severity: "high",
        cwe: "CWE-611",
        description: "XML parsing without explicit XXE protection — disable external entities",
        languages: &["python", "java", "javascript", "typescript"],
        fix_summary: "Disable external entity resolution and DTD loading in the XML parser.",
        fix_template: "// Python (defusedxml is the safest choice):\n//   from defusedxml.ElementTree import parse\n//\n// Java:\n//   DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n//   dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n//   dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n//   dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n//\n// Node (libxmljs):\n//   libxml.parseXml(data, { noent: false, dtdload: false });",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "https://pypi.org/project/defusedxml/",
        ],
    },
    Rule {
        name: "xpath-injection",
        pattern: r#"(?i)(?:xpath|evaluate)\s*\(.*(?:format!|\+\s*\w+|\$\{|%s|f["'])"#,
        severity: "high",
        cwe: "CWE-643",
        description: "Potential XPath injection via string interpolation",
        languages: &[],
        fix_summary: "Use parameterized XPath (XPath variables) instead of string concatenation.",
        fix_template: "// Java (javax.xml.xpath with variable resolver):\n//   XPath xpath = XPathFactory.newInstance().newXPath();\n//   xpath.setXPathVariableResolver(v -> v.getLocalPart().equals(\"uid\") ? uid : null);\n//   xpath.evaluate(\"//user[uid=$uid]\", doc);\n//\n// Python (lxml):\n//   tree.xpath(\"//user[uid=$uid]\", uid=user_input)\n//\n// Never build XPath via string concatenation — the expression grammar\n// has its own injection surface analogous to SQL.",
        fix_type: FindingFixType::CodeChange,
        references: &["https://cwe.mitre.org/data/definitions/643.html"],
    },
    Rule {
        name: "ssti-template-injection",
        pattern: r#"(?i)(?:render_template_string|Template\(|Jinja2|Environment\(\s*loader)\s*\(.*(?:request|params|input|\+\s*\w+)"#,
        severity: "critical",
        cwe: "CWE-1336",
        description: "Potential server-side template injection (SSTI)",
        languages: &["python", "javascript", "typescript"],
        fix_summary: "Never pass user input as the template SOURCE — pass it as template VARIABLES instead.",
        fix_template: "# WRONG — user input becomes the template source:\n#   render_template_string(f\"Hello {user_name}\")\n#\n# RIGHT — user input is a variable:\n#   render_template_string(\"Hello {{ name }}\", name=user_name)\n#\n# Jinja2 sandbox (if you MUST execute user templates):\n#   from jinja2.sandbox import SandboxedEnvironment\n#   env = SandboxedEnvironment()\n#\n# SSTI leads to RCE in nearly every template engine. Treat user-supplied\n# template strings with the same care as user-supplied code.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://portswigger.net/research/server-side-template-injection",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
        ],
    },
    Rule {
        name: "nosql-injection",
        pattern: r#"(?i)(?:\.find|\.findOne|\.aggregate|\.update|\.delete)\s*\(\s*\{[^}]*(?:\$where|\$regex|\$ne|\$gt|\$lt)"#,
        severity: "high",
        cwe: "CWE-943",
        description: "Potential NoSQL injection via MongoDB operator in query",
        languages: &["javascript", "typescript", "python"],
        fix_summary: "Cast/validate input types before query; reject objects when a scalar is expected.",
        fix_template: "// Attack: login endpoint accepts { \"password\": { \"$ne\": null } } and matches any user.\n//\n// Defense:\n// 1. Validate input shape — reject objects when you expect a string:\n//    if (typeof req.body.password !== 'string') return 400;\n// 2. Use a schema validator (joi, zod, mongoose schemas with `SchemaType.cast`).\n// 3. Disable `$where` server-side (it evaluates JS): set `$where` in query filters.\n// 4. In Mongoose, call `.lean()` with `sanitizeFilter: true` or use `mongo-sanitize`.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/943.html",
            "https://www.npmjs.com/package/mongo-sanitize",
        ],
    },
    Rule {
        name: "header-injection-crlf",
        pattern: r#"(?i)(?:set_header|setHeader|add_header|header)\s*\(.*(?:request|params|req\.|query|input)"#,
        severity: "medium",
        cwe: "CWE-113",
        description: "HTTP header set with user-controlled value — potential CRLF injection",
        languages: &[],
        fix_summary: "Strip `\\r` and `\\n` from any user-controlled header value, or reject outright.",
        fix_template: "// Most modern frameworks reject CRLF in header values automatically — but\n// defense in depth:\n//\n//   let cleaned = user_value.replace('\\r', \"\").replace('\\n', \"\");\n//   if cleaned != user_value { return Err(\"invalid header\".into()); }\n//   response.headers_mut().insert(name, HeaderValue::from_str(&cleaned)?);\n//\n// Node / Express: the built-in `http` module rejects CRLF since v6+; still\n// validate if writing custom headers via raw sockets.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/113.html",
            "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
        ],
    },
    Rule {
        name: "log-injection",
        pattern: r#"(?i)(?:log\.(?:info|warn|error|debug)|logger\.(?:info|warn|error|debug)|console\.log)\s*\(.*(?:request|req\.|params|query|input)"#,
        severity: "low",
        cwe: "CWE-117",
        description: "User-controlled data in log output — potential log injection/forging",
        languages: &[],
        fix_summary: "Log user input through a sanitizer that escapes/strips newlines, or use structured (JSON) logging.",
        fix_template: "// Unsafe: log.info(\"user=\" + user_input)\n// Attacker submits: user=alice\\n[ERROR] fake log line\n//\n// Safe options:\n// 1. Structured logging (every field is a key=value pair; no injection):\n//    log.info(\"login_attempt\", user: user_input, ip: client_ip);\n// 2. Escape before logging:\n//    let safe = user_input.replace('\\n', \"\\\\n\").replace('\\r', \"\\\\r\");\n// 3. Limit logged length so attackers can't pollute rotating logs.",
        fix_type: FindingFixType::CodeChange,
        references: &["https://cwe.mitre.org/data/definitions/117.html"],
    },
    // -----------------------------------------------------------------------
    // Auth & Session
    // -----------------------------------------------------------------------
    Rule {
        name: "hardcoded-jwt-secret",
        pattern: r#"(?i)(?:jwt\.sign|jwt\.encode|jwt\.decode|JWTManager|SECRET_KEY)\s*[:=\(].*["'][A-Za-z0-9+/=_-]{8,}["']"#,
        severity: "critical",
        cwe: "CWE-798",
        description: "Hardcoded JWT secret — use environment variables for secrets",
        languages: &[],
        fix_summary: "Rotate the secret, move it to environment variables or a secret manager, and regenerate all active tokens.",
        fix_template: "// 1. Generate a new strong secret (>= 256 bits for HS256):\n//    openssl rand -hex 64\n// 2. Load at runtime:\n//    const secret = process.env.JWT_SECRET ?? throw new Error('JWT_SECRET missing');\n// 3. Invalidate all existing tokens (bump a `token_version` claim or short TTLs).\n// 4. Consider switching to RS256 (public/private keypair) so the secret is\n//    not required by services that only verify tokens.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://datatracker.ietf.org/doc/html/rfc7519",
        ],
    },
    Rule {
        name: "permissive-cors",
        pattern: r#"(?i)(?:Access-Control-Allow-Origin|cors\(|CORS\(|allow_origin).*['"]\*['"]"#,
        severity: "medium",
        cwe: "CWE-942",
        description: "Permissive CORS policy allowing all origins",
        languages: &[],
        fix_summary: "Replace `*` with an explicit allow-list of trusted origins.",
        fix_template: "// Express with cors middleware:\n//   app.use(cors({ origin: ['https://app.example.com', 'https://admin.example.com'] }));\n//\n// Actix-web:\n//   Cors::default()\n//       .allowed_origin(\"https://app.example.com\")\n//       .allowed_origin(\"https://admin.example.com\")\n//\n// Rules of thumb:\n// - `*` + credentials is impossible (browsers reject).\n// - Echoing the Origin header back is equivalent to `*` for attackers.\n// - Use an allow-list; keep it in config, not hardcoded.",
        fix_type: FindingFixType::ConfigChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/942.html",
            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
        ],
    },
    Rule {
        name: "insecure-cookie",
        pattern: r#"(?i)(?:set_cookie|Set-Cookie|cookie\s*=).*(?:secure\s*[:=]\s*(?:false|False)|httponly\s*[:=]\s*(?:false|False))"#,
        severity: "medium",
        cwe: "CWE-614",
        description: "Cookie set without Secure or HttpOnly flag",
        languages: &[],
        fix_summary: "Set `Secure`, `HttpOnly`, and `SameSite=Lax` (or `Strict`) on session cookies.",
        fix_template: "// Express:\n//   res.cookie('session', token, {\n//     httpOnly: true,\n//     secure: true,         // HTTPS only\n//     sameSite: 'lax',      // or 'strict' for high-security\n//     maxAge: 3600_000,\n//   });\n//\n// Django: SESSION_COOKIE_SECURE = True, SESSION_COOKIE_HTTPONLY = True\n// Flask:  app.config['SESSION_COOKIE_SECURE'] = True\n//         app.config['SESSION_COOKIE_HTTPONLY'] = True\n//         app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'",
        fix_type: FindingFixType::ConfigChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/614.html",
            "https://owasp.org/www-community/controls/SecureCookieAttribute",
        ],
    },
    Rule {
        name: "session-fixation",
        pattern: r#"(?i)session\s*\[\s*['"]session_id['"]\s*\]\s*=\s*(?:request|params|req\.|query)"#,
        severity: "high",
        cwe: "CWE-384",
        description: "Session ID set from user-controlled input — potential session fixation",
        languages: &["python", "javascript", "typescript"],
        fix_summary: "Regenerate the session ID on every privilege transition (login, role change) and never accept client-supplied IDs.",
        fix_template: "# Flask:\n#   from flask import session\n#   session.clear()\n#   session['user_id'] = user.id\n#   # Flask rotates the session cookie automatically on clear() + assignment.\n#\n# Django:\n#   from django.contrib.auth import login\n#   login(request, user)  # automatically rotates the session key.\n#\n# Express (express-session):\n#   req.session.regenerate(err => {\n#     req.session.userId = user.id;\n#     req.session.save();\n#   });",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/384.html",
            "https://owasp.org/www-community/attacks/Session_fixation",
        ],
    },
    Rule {
        name: "missing-auth-decorator",
        pattern: r#"@app\.route\([^)]*\)\s*\n\s*def\s+\w+\("#,
        severity: "low",
        cwe: "CWE-862",
        description: "Flask route without apparent authentication decorator",
        languages: &["python"],
        fix_summary: "Add `@login_required` (or the project's auth decorator) to non-public routes.",
        fix_template: "# Flask-Login:\n#   from flask_login import login_required\n#\n#   @app.route('/admin')\n#   @login_required\n#   def admin_panel():\n#       ...\n#\n# For API routes with role checks, compose decorators:\n#   @app.route('/admin/users')\n#   @login_required\n#   @require_role('admin')\n#   def list_users():\n#       ...\n#\n# If the route is intentionally public, add a `# @public_endpoint` marker\n# comment so future reviewers know the omission is deliberate.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/862.html",
            "https://flask-login.readthedocs.io/",
        ],
    },
    // -----------------------------------------------------------------------
    // Crypto
    // -----------------------------------------------------------------------
    Rule {
        name: "weak-random",
        pattern: r#"(?i)(?:Math\.random\(\)|rand\(\)|random\.random\(\)|random\.randint|random\.choice)"#,
        severity: "medium",
        cwe: "CWE-338",
        description: "Weak random number generator — use cryptographically secure alternatives for security contexts",
        languages: &[],
        fix_summary: "Use a CSPRNG: `secrets` in Python, `crypto.randomBytes` in Node, `rand::rngs::OsRng` in Rust.",
        fix_template: "// Python:\n//   import secrets\n//   token = secrets.token_urlsafe(32)\n//   choice = secrets.choice(options)\n//\n// Node.js:\n//   const crypto = require('crypto');\n//   const token = crypto.randomBytes(32).toString('hex');\n//\n// Rust:\n//   use rand::rngs::OsRng;\n//   use rand::RngCore;\n//   let mut bytes = [0u8; 32];\n//   OsRng.fill_bytes(&mut bytes);\n//\n// Math.random / rand() / random.random are fine for games, simulations, and\n// non-security randomness. Anywhere an attacker could benefit from predicting\n// the value (tokens, passwords, IDs, IVs, nonces) — use a CSPRNG.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/338.html",
            "https://docs.python.org/3/library/secrets.html",
        ],
    },
    Rule {
        name: "ecb-mode",
        pattern: r#"(?i)(?:ECB|MODE_ECB|AES\.new\([^)]*ECB|Cipher\.getInstance\(\s*["']AES["']\s*\))"#,
        severity: "high",
        cwe: "CWE-327",
        description: "ECB mode detected — use CBC, CTR, or GCM mode instead",
        languages: &[],
        fix_summary: "Switch to AES-GCM (authenticated) or AES-CBC with a random IV and a separate MAC.",
        fix_template: "// AES-GCM (recommended — authenticated encryption):\n//   Python: from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n//   Node:   crypto.createCipheriv('aes-256-gcm', key, iv)\n//   Rust:   aes-gcm crate with Aes256Gcm::new(&key).encrypt(&nonce, plaintext)\n//\n// AES-CBC (if GCM unavailable) — pair with HMAC-SHA256 for integrity:\n//   Use a fresh 16-byte random IV per message.\n//   MAC the ciphertext separately.\n//\n// ECB encrypts identical blocks to identical ciphertext — patterns in the\n// plaintext leak through. See the famous `ECB Tux` image.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/327.html",
            "https://cryptography.io/en/latest/hazmat/primitives/aead/",
        ],
    },
    Rule {
        name: "hardcoded-iv-nonce",
        pattern: r#"(?i)(?:iv|nonce|initialization_vector)\s*[:=]\s*(?:b["']|["'])[A-Za-z0-9+/=]{8,}["']"#,
        severity: "medium",
        cwe: "CWE-329",
        description: "Hardcoded IV/nonce — use a random value for each encryption",
        languages: &[],
        fix_summary: "Generate a fresh random IV/nonce for every encryption; prepend it to the ciphertext.",
        fix_template: "// AES-CBC: 16-byte IV\n// AES-GCM: 12-byte nonce (unique per key/message — never reused)\n// ChaCha20-Poly1305: 12-byte nonce\n//\n// Python:\n//   iv = os.urandom(16)\n// Node:\n//   const iv = crypto.randomBytes(12);\n// Rust:\n//   use rand::RngCore; let mut iv = [0u8; 12]; OsRng.fill_bytes(&mut iv);\n//\n// Store the IV alongside the ciphertext — it is NOT a secret, just unique.",
        fix_type: FindingFixType::CodeChange,
        references: &["https://cwe.mitre.org/data/definitions/329.html"],
    },
    // -----------------------------------------------------------------------
    // Data Exposure
    // -----------------------------------------------------------------------
    Rule {
        name: "stack-trace-exposure",
        pattern: r#"(?i)(?:traceback\.print_exc|e\.printStackTrace|\.backtrace\(\)|print_stacktrace)"#,
        severity: "medium",
        cwe: "CWE-209",
        description: "Stack trace printed — may leak sensitive information to users",
        languages: &[],
        fix_summary: "Log the stack trace server-side; return a generic error message to clients.",
        fix_template: "// Pattern:\n//   try {\n//       risky_thing();\n//   } catch (err) {\n//       logger.error('operation failed', err);      // full trace to logs\n//       res.status(500).json({                       // sanitized to client\n//           error: 'internal_error',\n//           request_id: req.id,                      // helps correlate with logs\n//       });\n//   }\n//\n// NEVER send `err.message` or the stack to the response body in production.\n// Stack traces leak file paths, framework versions, ORM internals, etc.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/209.html",
            "https://owasp.org/www-community/Improper_Error_Handling",
        ],
    },
    Rule {
        name: "debug-mode-production",
        pattern: r#"(?i)(?:DEBUG\s*=\s*True|app\.debug\s*=\s*True|debug:\s*true|FLASK_DEBUG\s*=\s*1)"#,
        severity: "medium",
        cwe: "CWE-489",
        description: "Debug mode enabled — disable in production deployments",
        languages: &[],
        fix_summary: "Read debug flag from environment; default to false in production.",
        fix_template: "# Python (Flask/Django):\n#   DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'\n#\n# Node (Express):\n#   const isDev = process.env.NODE_ENV !== 'production';\n#   app.set('env', isDev ? 'development' : 'production');\n#\n# Debug mode typically exposes interactive consoles (Werkzeug debugger),\n# detailed tracebacks, and profiler data — all of which are RCE surfaces\n# in production.",
        fix_type: FindingFixType::ConfigChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/489.html",
            "https://docs.djangoproject.com/en/stable/ref/settings/#debug",
        ],
    },
    Rule {
        name: "verbose-error-response",
        pattern: r#"(?i)(?:res\.send|res\.json|response\.write|render)\s*\(.*(?:err\.message|error\.stack|e\.getMessage)"#,
        severity: "medium",
        cwe: "CWE-209",
        description: "Error details sent in response — may expose sensitive internal information",
        languages: &["javascript", "typescript", "java"],
        fix_summary: "Map internal errors to generic client-safe codes; log the details server-side.",
        fix_template: "// Centralized error handler (Express):\n//   app.use((err, req, res, next) => {\n//       logger.error({ err, req_id: req.id });\n//       res.status(err.status ?? 500).json({\n//           error: err.code ?? 'internal_error',\n//           request_id: req.id,\n//       });\n//   });\n//\n// Define an AppError type with stable, enumerable `.code` values. Map only\n// the code + message (not the stack or cause chain) to the response body.",
        fix_type: FindingFixType::CodeChange,
        references: &["https://cwe.mitre.org/data/definitions/209.html"],
    },
    Rule {
        name: "todo-with-secret",
        pattern: r#"(?i)(?://|#)\s*(?:TODO|FIXME|HACK|XXX).*(?:password|secret|key|token|credential)"#,
        severity: "low",
        cwe: "CWE-615",
        description: "Comment references secrets — ensure no credentials in source comments",
        languages: &[],
        fix_summary: "Remove the comment or ensure no credentials are embedded; rotate anything that may have leaked.",
        fix_template: "// 1. Read the comment carefully — does it reference a real secret?\n// 2. If yes: rotate the credential AND scrub the comment from git history.\n// 3. If it's just a TODO to wire up auth, rewrite without credential keywords.\n//\n// Example rewrites:\n//   Before: // TODO: use real api_key here, not 'test-key-12345'\n//   After:  // TODO(issue-42): load credentials from secrets manager",
        fix_type: FindingFixType::ManualReview,
        references: &["https://cwe.mitre.org/data/definitions/615.html"],
    },
    // -----------------------------------------------------------------------
    // Memory & Resource Safety
    // -----------------------------------------------------------------------
    Rule {
        name: "buffer-overflow-c",
        pattern: r#"(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\("#,
        severity: "critical",
        cwe: "CWE-120",
        description: "Use of unsafe C function prone to buffer overflow — use bounded alternatives",
        languages: &["c", "cpp"],
        fix_summary: "Replace with bounded variants: `strncpy`/`strlcpy`, `snprintf`, `fgets`.",
        fix_template: "// Unsafe -> Safe:\n//   gets(buf)         -> fgets(buf, sizeof(buf), stdin)\n//   strcpy(d, s)      -> strlcpy(d, s, sizeof(d))   // BSD, musl\n//                     -> snprintf(d, sizeof(d), \"%s\", s)\n//   strcat(d, s)      -> strlcat(d, s, sizeof(d))\n//   sprintf(buf, ...) -> snprintf(buf, sizeof(buf), ...)\n//\n// C++ alternative: use std::string and iostream; ditch C-string APIs\n// entirely where possible.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/120.html",
            "https://man.openbsd.org/strlcpy",
        ],
    },
    Rule {
        name: "use-after-free",
        pattern: r#"(?:free|delete|kfree)\s*\(\s*\w+\s*\)"#,
        severity: "critical",
        cwe: "CWE-416",
        description: "Memory deallocation detected — verify no use-after-free of freed pointer",
        languages: &["c", "cpp"],
        fix_summary: "Set the pointer to NULL after free, or redesign with RAII / smart pointers.",
        fix_template: "// Defensive pattern:\n//   free(ptr);\n//   ptr = NULL;  // any subsequent deref is a controlled NULL-deref, not UAF\n//\n// Better: use RAII wrappers and ownership:\n//   C++:  std::unique_ptr<T>, std::shared_ptr<T>\n//   C:    wrap lifecycle in a struct with explicit ownership semantics;\n//         run sanitizers (-fsanitize=address) in CI.\n//\n// Review every aliased pointer to the freed object — a use-after-free\n// usually manifests through a second pointer you forgot about.",
        fix_type: FindingFixType::ManualReview,
        references: &[
            "https://cwe.mitre.org/data/definitions/416.html",
            "https://github.com/google/sanitizers/wiki/AddressSanitizer",
        ],
    },
    Rule {
        name: "integer-overflow",
        pattern: r#"(?i)(?:as\s+(?:u8|u16|i8|i16|u32|i32)|\(\s*(?:int|short|byte)\s*\)\s*\w+)"#,
        severity: "medium",
        cwe: "CWE-190",
        description: "Potential integer overflow from narrowing cast",
        languages: &["rust", "java", "c", "cpp"],
        fix_summary: "Use checked / saturating conversions, or widen the target type.",
        fix_template: "// Rust:\n//   let small: u8 = value.try_into()?;           // returns Err on overflow\n//   let clamped: u8 = u8::try_from(value).unwrap_or(u8::MAX);\n//   let saturating: u8 = value.saturating_as::<u8>(); // with the num_traits crate\n//\n// Java:\n//   Math.toIntExact(longValue);  // throws ArithmeticException on overflow\n//\n// C/C++:\n//   Use fixed-width types (int32_t, uint64_t) and validate range before cast.\n//   Compile with -ftrapv or -fsanitize=signed-integer-overflow.",
        fix_type: FindingFixType::CodeChange,
        references: &["https://cwe.mitre.org/data/definitions/190.html"],
    },
    // -----------------------------------------------------------------------
    // Misc
    // -----------------------------------------------------------------------
    Rule {
        name: "regex-dos",
        pattern: r#"(?:Regex::new|re\.compile|new RegExp)\s*\(.*(?:\.\*\.\*|\(.+\|\.\+\)\*|\(\.\+\)\+)"#,
        severity: "medium",
        cwe: "CWE-1333",
        description: "Potentially catastrophic regex — may cause ReDoS with crafted input",
        languages: &[],
        fix_summary: "Rewrite the regex without nested quantifiers, or use a linear-time engine (RE2, Rust regex).",
        fix_template: "// Catastrophic patterns to avoid:\n//   (.+)+          — nested quantifiers\n//   (a|a)*         — alternation overlapping quantifier\n//   .*.*           — unbounded backtracking corridor\n//\n// Safer alternatives:\n// 1. Use a linear-time regex engine:\n//    - Rust:   `regex` crate (always linear)\n//    - Go:     built-in regexp (RE2)\n//    - Python: `re2` (via the re2 package)\n// 2. Anchor patterns: ^pattern$ with explicit length limits on { }.\n// 3. Reject input longer than your expected max before matching.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/1333.html",
            "https://github.com/google/re2",
        ],
    },
    Rule {
        name: "ssrf",
        pattern: r#"(?i)(?:requests\.get|fetch|http\.get|urllib\.request|HttpClient|curl_exec)\s*\(.*(?:request|params|req\.|query|input|user)"#,
        severity: "high",
        cwe: "CWE-918",
        description: "HTTP request with user-controlled URL — potential SSRF",
        languages: &[],
        fix_summary: "Resolve hostname, reject RFC1918 / link-local / metadata IPs, allow-list permitted destinations.",
        fix_template: "// Defense layers (use all of them):\n// 1. Parse + validate the URL structure (scheme, host).\n// 2. Resolve DNS and check the resolved IP is not:\n//    - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC1918)\n//    - 127.0.0.0/8 (loopback)\n//    - 169.254.0.0/16 (link-local, incl. AWS/GCP metadata 169.254.169.254)\n//    - ::1, fc00::/7, fe80::/10\n// 3. Allow-list schemes: http, https only.\n// 4. Disable redirect-following OR re-validate the final URL after each hop.\n// 5. Isolate the outbound egress — dedicated subnet, proxy, or sidecar.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/918.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    Rule {
        name: "toctou-race",
        pattern: r#"(?i)(?:os\.path\.exists|File\.exists|access)\s*\([^)]+\).*\n.*(?:open|read|write|unlink|remove)\s*\("#,
        severity: "medium",
        cwe: "CWE-367",
        description: "Time-of-check to time-of-use (TOCTOU) race condition on file operation",
        languages: &["python", "java", "c", "cpp"],
        fix_summary: "Open the file once with the correct flags and handle errors — don't check existence separately.",
        fix_template: "# Race-prone:\n#   if os.path.exists(path):\n#       with open(path) as f: ...\n#\n# Race-free (EAFP):\n#   try:\n#       with open(path) as f: ...\n#   except FileNotFoundError:\n#       ...\n#\n# For exclusive creation (prevent symlink attacks):\n#   fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)\n#\n# In C: open(path, O_CREAT | O_EXCL, mode) then operate on the fd.",
        fix_type: FindingFixType::CodeChange,
        references: &["https://cwe.mitre.org/data/definitions/367.html"],
    },
    Rule {
        name: "prototype-pollution",
        pattern: r#"(?:__proto__|constructor\s*\.\s*prototype|Object\.assign\s*\(\s*\{\s*\})"#,
        severity: "high",
        cwe: "CWE-1321",
        description: "Potential prototype pollution via __proto__ or constructor.prototype",
        languages: &["javascript", "typescript"],
        fix_summary: "Use Object.create(null), Map, or a structured-clone merge; reject keys `__proto__`, `constructor`, `prototype`.",
        fix_template: "// Safer merge pattern:\n//   function safeMerge(target, source) {\n//       for (const key of Object.keys(source)) {\n//           if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;\n//           target[key] = source[key];\n//       }\n//   }\n//\n// Prefer Map for user-keyed data:\n//   const store = new Map();\n//   store.set(userKey, userValue);\n//\n// Libraries that mitigate this: lodash/defaultsDeep (patched >= 4.17.20),\n// `merge-options` with { concatArrays: true, ignoreUndefined: true }.",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://cwe.mitre.org/data/definitions/1321.html",
            "https://learn.snyk.io/lesson/prototype-pollution/",
        ],
    },
    // -----------------------------------------------------------------------
    // Additional Secrets
    // -----------------------------------------------------------------------
    Rule {
        name: "github-token",
        pattern: r#"(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})"#,
        severity: "critical",
        cwe: "CWE-798",
        description: "GitHub personal access token or OAuth token detected",
        languages: &[],
        fix_summary: "Revoke the token immediately on GitHub, scrub from git history, replace with a GitHub App or OIDC.",
        fix_template: "// URGENT:\n// 1. GitHub -> Settings -> Developer settings -> Personal access tokens -> Revoke.\n// 2. `git filter-repo --path <file> --invert-paths` to scrub history.\n// 3. Force-push cleaned history (coordinate with collaborators).\n// 4. Replace:\n//    - CI: GitHub Actions with OIDC federation (no token storage required).\n//    - Bots: GitHub App with fine-grained permissions.\n//    - Dev tooling: gh CLI's device flow (no stored PAT).",
        fix_type: FindingFixType::CodeChange,
        references: &[
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
            "https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
        ],
    },
    Rule {
        name: "slack-token",
        pattern: r#"xox[bporas]-[0-9]{10,13}-[A-Za-z0-9-]{20,}"#,
        severity: "critical",
        cwe: "CWE-798",
        description: "Slack API token detected",
        languages: &[],
        fix_summary: "Revoke the token in Slack, remove from history, move to a secret manager.",
        fix_template: "// 1. Slack admin -> Apps -> manage -> revoke the token.\n// 2. If it was a bot token (xoxb-): rotate at the Slack App config page.\n// 3. `git filter-repo` to scrub history; notify collaborators.\n// 4. Store the new token in AWS Secrets Manager / Vault / GitHub Actions secrets.\n// 5. Review Slack audit log for any unauthorized messages/file access.",
        fix_type: FindingFixType::CodeChange,
        references: &["https://api.slack.com/authentication/best-practices"],
    },
    Rule {
        name: "google-api-key",
        pattern: r#"AIza[0-9A-Za-z_-]{35}"#,
        severity: "high",
        cwe: "CWE-798",
        description: "Google API key detected",
        languages: &[],
        fix_summary: "Restrict or rotate the key in Google Cloud Console; replace with OAuth2 or service account JSON.",
        fix_template: "// 1. Google Cloud Console -> APIs & Services -> Credentials -> Restrict or Delete.\n// 2. Scrub from git history.\n// 3. Choose a safer auth mechanism:\n//    - Server-to-server: Service account key (short-lived via Workload Identity).\n//    - User-facing: OAuth2 with consent screen.\n//    - Client-side (browser/mobile): Restrict the API key by HTTP referrer / package name / IP.",
        fix_type: FindingFixType::CodeChange,
        references: &["https://cloud.google.com/docs/authentication/api-keys"],
    },
    Rule {
        name: "connection-string-password",
        pattern: r#"(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^:]+:[^@\s]+@"#,
        severity: "high",
        cwe: "CWE-798",
        description: "Connection string with embedded password detected",
        languages: &[],
        fix_summary: "Move the password to an environment variable / secret manager; rotate the database credential.",
        fix_template: "// Unsafe: const DB = \"postgres://user:hunter2@db.internal/app\";\n//\n// Safe:\n//   const pw = process.env.DB_PASSWORD;\n//   const DB = `postgres://user:${encodeURIComponent(pw)}@db.internal/app`;\n//\n// Better: use a secret manager and short-lived credentials:\n//   - AWS: RDS IAM authentication\n//   - GCP: Cloud SQL Auth Proxy + IAM\n//   - On-prem: HashiCorp Vault dynamic secrets\n//\n// Rotate the exposed password before shipping the fix — assume it is\n// already in someone's git-scraped credential dataset.",
        fix_type: FindingFixType::CodeChange,
        references: &["https://cwe.mitre.org/data/definitions/798.html"],
    },
];

impl StaticAnalysisStage {
    pub fn new(
        scan_id: uuid::Uuid,
        repo_id: uuid::Uuid,
        db: Arc<DatabaseOperations>,
        semgrep_config: SemgrepConfig,
    ) -> Self {
        Self {
            scan_id,
            repo_id,
            db,
            work_dir: None,
            semgrep_config,
        }
    }

    pub fn with_work_dir(mut self, work_dir: std::path::PathBuf) -> Self {
        self.work_dir = Some(work_dir);
        self
    }

    pub async fn run(&self, index: &CodeIndex) -> HeimdallResult<StaticAnalysisContext> {
        info!("[{}] Starting static analysis", self.scan_id);

        let mut total_findings = 0usize;
        let mut summary_parts = Vec::new();
        let mut pattern_findings = 0usize;

        self.record_event(
            Some("pattern-scan"),
            "running",
            "Running deterministic code pattern checks",
            Some("Inspecting the codebase for known vulnerable patterns and dangerous APIs."),
            None,
            None,
        )
        .await;
        for rule in RULES {
            let re = match Regex::new(rule.pattern) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for (file_path, indexed_file) in &index.files {
                // Skip test files, spec files, and lock files — they contain
                // intentional patterns that would cause false positives.
                if is_test_or_generated_file(file_path) {
                    continue;
                }

                // Check language filter
                if !rule.languages.is_empty() {
                    if let Some(ref lang) = indexed_file.language {
                        if !rule.languages.contains(&lang.as_str()) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                for (line_idx, line) in indexed_file.content.lines().enumerate() {
                    // Skip lines inside test blocks (Rust #[cfg(test)] / #[test],
                    // Python def test_, JS describe/it, etc.)
                    if is_test_line_context(&indexed_file.content, line_idx) {
                        continue;
                    }

                    if re.is_match(line) {
                        let line_num = sat_i32_usize(line_idx + 1);
                        let snippet = extract_snippet(&indexed_file.content, line_idx, 2);
                        let fingerprint = make_fingerprint(rule.name, file_path, line_num);

                        let evidence = FindingEvidence {
                            code_snippet: Some(snippet),
                            suggested_patch: Some(rule.fix_template.to_string()),
                            fix_type: rule.fix_type,
                            fix_summary: Some(rule.fix_summary.to_string()),
                            references: rule.references.iter().map(|s| s.to_string()).collect(),
                            manifest_coordinates: None,
                        };

                        let _ = self
                            .db
                            .create_finding_full(
                                self.scan_id,
                                self.repo_id,
                                "static",
                                rule.severity,
                                "high", // static rules are deterministic = high confidence
                                &format!("[{}] {}", rule.cwe, rule.description),
                                Some(rule.description),
                                Some(rule.cwe),
                                file_path,
                                line_num,
                                Some(line_num),
                                &fingerprint,
                                None,
                                &evidence,
                            )
                            .await;

                        total_findings += 1;
                        pattern_findings += 1;
                    }
                }
            }
        }
        self.record_event(
            Some("pattern-scan"),
            "completed",
            "Deterministic pattern checks finished",
            Some(&format!(
                "{pattern_findings} findings recorded from regex and rule-based checks."
            )),
            Some(45),
            Some(&serde_json::json!({
                "findings": pattern_findings,
            })),
        )
        .await;

        // Secret detection via entropy analysis
        self.record_event(
            Some("secret-scan"),
            "running",
            "Scanning for embedded secrets",
            Some("Checking source files for high-entropy tokens and secret-like literals."),
            None,
            None,
        )
        .await;
        let secret_count = self.detect_secrets(index).await?;
        total_findings += secret_count;
        self.record_event(
            Some("secret-scan"),
            "completed",
            "Secret scan finished",
            Some(&format!(
                "{secret_count} potential secret findings recorded."
            )),
            Some(70),
            Some(&serde_json::json!({
                "findings": secret_count,
            })),
        )
        .await;

        self.record_event(
            Some("dependency-audit"),
            "running",
            "Auditing dependencies",
            Some("Reviewing manifest files against OSV for known vulnerable packages."),
            None,
            None,
        )
        .await;
        let deps_count = match DepsAuditStage::new(self.scan_id, self.repo_id, Arc::clone(&self.db))
            .run(index)
            .await
        {
            Ok(vulns) => {
                let count = vulns.len();
                self.record_event(
                    Some("dependency-audit"),
                    "completed",
                    "Dependency audit finished",
                    Some(&format!("{count} vulnerable dependency findings recorded.")),
                    Some(100),
                    Some(&serde_json::json!({
                        "findings": count,
                    })),
                )
                .await;
                count
            }
            Err(error) => {
                self.record_event(
                    Some("dependency-audit"),
                    "failed",
                    "Dependency audit failed",
                    Some(&error.to_string()),
                    None,
                    None,
                )
                .await;
                0
            }
        };
        total_findings += deps_count;

        // Semgrep integration (optional — runs if semgrep is installed)
        if let Some(ref work_dir) = self.work_dir {
            self.record_event(
                Some("semgrep-scan"),
                "running",
                "Running Semgrep analysis",
                Some("Executing Semgrep with auto-config rules for enhanced vulnerability detection."),
                None,
                None,
            )
            .await;

            // Collect existing fingerprints for deduplication
            let existing_fingerprints: HashSet<String> = if let Ok(findings) = self
                .db
                .list_findings_by_scan(self.scan_id, None, None)
                .await
            {
                findings.iter().map(|f| f.fingerprint.clone()).collect()
            } else {
                HashSet::new()
            };

            let semgrep_stage = semgrep::SemgrepStage::new(
                self.scan_id,
                self.repo_id,
                Arc::clone(&self.db),
                self.semgrep_config.clone(),
            );
            match semgrep_stage.run(work_dir, &existing_fingerprints).await {
                Ok(semgrep_count) => {
                    total_findings += semgrep_count;
                    self.record_event(
                        Some("semgrep-scan"),
                        "completed",
                        "Semgrep analysis finished",
                        Some(&format!(
                            "{semgrep_count} additional findings from Semgrep."
                        )),
                        Some(100),
                        Some(&serde_json::json!({
                            "findings": semgrep_count,
                        })),
                    )
                    .await;
                }
                Err(error) => {
                    self.record_event(
                        Some("semgrep-scan"),
                        "failed",
                        "Semgrep analysis failed",
                        Some(&error.to_string()),
                        None,
                        None,
                    )
                    .await;
                }
            }
        }

        if total_findings > 0 {
            summary_parts.push(format!("{total_findings} static analysis findings"));
        }

        let summary = if summary_parts.is_empty() {
            "No static analysis findings.".to_string()
        } else {
            summary_parts.join("; ")
        };

        info!(
            "[{}] Static analysis complete: {total_findings} findings",
            self.scan_id
        );

        Ok(StaticAnalysisContext {
            findings_count: total_findings,
            summary,
        })
    }

    async fn record_event(
        &self,
        task_key: Option<&str>,
        status: &str,
        title: &str,
        detail: Option<&str>,
        progress_pct: Option<i32>,
        metadata_json: Option<&serde_json::Value>,
    ) {
        let _ = self
            .db
            .create_scan_event(
                self.scan_id,
                Some("static_analysis"),
                task_key,
                "task",
                Some(status),
                title,
                detail,
                progress_pct,
                metadata_json,
            )
            .await;
    }

    /// Detect high-entropy strings that might be secrets.
    async fn detect_secrets(&self, index: &CodeIndex) -> HeimdallResult<usize> {
        let mut count = 0usize;

        for (file_path, file) in &index.files {
            // Skip non-code files for entropy analysis
            if file.language.is_none() {
                continue;
            }

            for (line_idx, line) in file.content.lines().enumerate() {
                if let Some(secret_literal) = find_secret_candidate(line) {
                    let line_num = sat_i32_usize(line_idx + 1);
                    let fingerprint = make_fingerprint("high-entropy-secret", file_path, line_num);
                    let detail = format!(
                        "Potential hardcoded secret-like literal detected: `{secret_literal}`"
                    );
                    let snippet = extract_snippet(&file.content, line_idx, 2);
                    let evidence = FindingEvidence::code_change(
                        snippet,
                        format!(
                            "// 1. Remove the credential literal `{secret_literal}` from source.\n\
                             // 2. Load it from a secret manager or environment variable at runtime.\n\
                             // 3. Rotate the exposed credential immediately — treat it as compromised.\n\
                             // 4. Scrub it from git history if it was committed."
                        ),
                        "Move the secret out of source control and rotate the exposed value.",
                    )
                    .with_references([
                        "https://cwe.mitre.org/data/definitions/798.html",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                    ]);

                    let _ = self
                        .db
                        .create_finding_full(
                            self.scan_id,
                            self.repo_id,
                            "static",
                            "high",
                            "medium",
                            "[CWE-798] Potential secret or credential in source code",
                            Some("High-entropy string found near secret-related keywords"),
                            Some("CWE-798"),
                            file_path,
                            line_num,
                            Some(line_num),
                            &fingerprint,
                            Some(detail.as_str()),
                            &evidence,
                        )
                        .await;

                    count += 1;
                }
            }
        }

        Ok(count)
    }
}

fn find_secret_candidate(line: &str) -> Option<String> {
    static QUOTED_LITERAL_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"["']([^"'\\\n]{20,})["']"#).unwrap());
    static SECRET_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?ix)
                (?:api(?:_|-)?key|secret|secret(?:_|-)?key|token|access(?:_|-)?token|
                   refresh(?:_|-)?token|password|passwd|private(?:_|-)?key|
                   access(?:_|-)?key|client(?:_|-)?secret|encryption(?:_|-)?(?:key|iv)|
                   credential|bearer|session(?:_|-)?secret)
                \s*[:=]
            "#,
        )
        .unwrap()
    });

    if !SECRET_CONTEXT.is_match(line) {
        return None;
    }

    QUOTED_LITERAL_RE
        .captures_iter(line)
        .filter_map(|captures| captures.get(1).map(|matched| matched.as_str()))
        .find(|literal| looks_like_secret_literal(literal))
        .map(ToString::to_string)
}

fn looks_like_secret_literal(literal: &str) -> bool {
    if literal.len() < 24 || looks_like_structured_path(literal) || looks_like_uuid(literal) {
        return false;
    }

    let classes = char_classes(literal);
    let entropy = shannon_entropy(literal);

    (classes >= 3 || (is_hex_like(literal) && literal.len() >= 32)) && entropy >= 3.5
}

fn looks_like_structured_path(literal: &str) -> bool {
    let slash_count = literal.matches('/').count();

    literal.starts_with('/')
        || literal.starts_with("./")
        || literal.starts_with("../")
        || literal.contains("://")
        || literal.contains('?')
        || literal.contains('&')
        || literal.contains('\\')
        || literal.contains(' ')
        || literal.contains('\t')
        || slash_count >= 2
}

fn looks_like_uuid(literal: &str) -> bool {
    static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            .unwrap()
    });

    UUID_RE.is_match(literal)
}

fn is_hex_like(literal: &str) -> bool {
    literal
        .chars()
        .all(|character| character.is_ascii_hexdigit())
}

fn char_classes(literal: &str) -> usize {
    let mut classes = HashSet::new();

    for character in literal.chars() {
        if character.is_ascii_lowercase() {
            classes.insert("lower");
        } else if character.is_ascii_uppercase() {
            classes.insert("upper");
        } else if character.is_ascii_digit() {
            classes.insert("digit");
        } else if matches!(character, '+' | '/' | '=' | '_' | '-') {
            classes.insert("symbol");
        }
    }

    classes.len()
}

fn shannon_entropy(literal: &str) -> f64 {
    let mut frequencies = std::collections::HashMap::new();
    let total = literal.chars().count() as f64;

    for character in literal.chars() {
        *frequencies.entry(character).or_insert(0usize) += 1;
    }

    frequencies
        .values()
        .map(|count| {
            let probability = *count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
}

/// Check if a file path is a test, spec, fixture, or generated file
/// that should be excluded from static analysis pattern matching.
fn is_test_or_generated_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();

    // Lock files contain crate/package names that match vulnerability patterns
    if lower.ends_with(".lock") || lower.ends_with("-lock.json") {
        return true;
    }

    // Test/spec directories
    let test_dirs = [
        "/test/",
        "/tests/",
        "/__tests__/",
        "/spec/",
        "/specs/",
        "/fixtures/",
        "/testdata/",
        "/test_data/",
        "/mock/",
        "/mocks/",
    ];
    if test_dirs.iter().any(|d| lower.contains(d)) {
        return true;
    }

    // Test file naming conventions
    let filename = lower.rsplit('/').next().unwrap_or(&lower);
    if filename.starts_with("test_")
        || filename.ends_with("_test.rs")
        || filename.ends_with("_test.go")
        || filename.ends_with("_test.py")
        || filename.ends_with(".test.js")
        || filename.ends_with(".test.ts")
        || filename.ends_with(".test.tsx")
        || filename.ends_with(".spec.js")
        || filename.ends_with(".spec.ts")
        || filename.ends_with(".spec.tsx")
    {
        return true;
    }

    false
}

/// Check if a line is inside a test block (e.g., Rust #[cfg(test)] module,
/// or preceded by #[test]). This catches inline tests in the same file.
fn is_test_line_context(content: &str, line_idx: usize) -> bool {
    let lines: Vec<&str> = content.lines().collect();

    // Look backwards from this line for test markers
    let start = line_idx.saturating_sub(30);
    let mut in_cfg_test = false;
    let mut cfg_test_brace_depth: i32 = 0;

    for i in start..=line_idx {
        if i >= lines.len() {
            break;
        }
        let trimmed = lines[i].trim();

        if trimmed.contains("#[cfg(test)]") {
            in_cfg_test = true;
            cfg_test_brace_depth = 0;
        }

        if in_cfg_test {
            cfg_test_brace_depth += sat_i32_usize(trimmed.matches('{').count());
            cfg_test_brace_depth -= sat_i32_usize(trimmed.matches('}').count());
        }
    }

    // If we're inside a #[cfg(test)] block that hasn't closed, this is test code
    if in_cfg_test && cfg_test_brace_depth > 0 {
        return true;
    }

    // Check for #[test] attribute on nearby function
    let check_start = line_idx.saturating_sub(5);
    for i in check_start..line_idx {
        if i < lines.len() {
            let trimmed = lines[i].trim();
            if trimmed == "#[test]" || trimmed.starts_with("#[test]") {
                return true;
            }
        }
    }

    false
}

fn extract_snippet(content: &str, center_line: usize, context: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = center_line.saturating_sub(context);
    let end = std::cmp::min(center_line + context + 1, lines.len());
    lines[start..end].join("\n")
}

fn make_fingerprint(rule: &str, file: &str, line: i32) -> String {
    let input = format!("{rule}:{file}:{line}");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: compile a rule's pattern and check if it matches the given code line.
    fn rule_matches(rule_name: &str, line: &str) -> bool {
        let rule = RULES.iter().find(|r| r.name == rule_name).unwrap();
        let re = Regex::new(rule.pattern).unwrap();
        re.is_match(line)
    }

    // -----------------------------------------------------------------------
    // SQL injection rules
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_sql_injection_format() {
        assert!(rule_matches(
            "sql-injection-string-concat",
            r#"let q = query(format!("SELECT * FROM users WHERE id = {}", user_input));"#,
        ));
    }

    #[test]
    fn test_sql_injection_no_false_positive_parameterized() {
        // Parameterized queries should not match
        assert!(!rule_matches(
            "sql-injection-string-concat",
            r#"sqlx::query("SELECT * FROM users WHERE id = $1").bind(id)"#,
        ));
    }

    #[test]
    fn test_detect_sql_injection_fstring() {
        assert!(rule_matches(
            "sql-injection-fstring",
            r#"cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")"#,
        ));
    }

    // -----------------------------------------------------------------------
    // Command injection
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_command_injection() {
        // The command-injection rule looks for: system/exec/popen/subprocess.call etc.
        // followed by format!/+\s*\w+/${}/%s
        assert!(rule_matches(
            "command-injection",
            r#"subprocess.call("ls " + user_input, shell=True)"#,
        ));
    }

    // -----------------------------------------------------------------------
    // Hardcoded secrets
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_hardcoded_api_key() {
        assert!(rule_matches(
            "hardcoded-api-key",
            r#"api_key = "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx""#,
        ));
    }

    #[test]
    fn test_detect_aws_access_key() {
        assert!(rule_matches(
            "aws-access-key",
            r#"AWS_KEY = "AKIAIOSFODNN7EXAMPLE""#,
        ));
    }

    #[test]
    fn test_detect_private_key() {
        assert!(rule_matches(
            "private-key",
            r#"-----BEGIN RSA PRIVATE KEY-----"#,
        ));
        assert!(rule_matches(
            "private-key",
            r#"-----BEGIN PRIVATE KEY-----"#,
        ));
    }

    #[test]
    fn test_find_secret_candidate_detects_encryption_key_literal() {
        let line =
            r#"private static readonly ENCRYPTION_KEY = "6uRGxB8V6kshhuXI2BedlQqkW8WGCcgg";"#;
        assert_eq!(
            find_secret_candidate(line).as_deref(),
            Some("6uRGxB8V6kshhuXI2BedlQqkW8WGCcgg")
        );
    }

    #[test]
    fn test_find_secret_candidate_ignores_api_route_string() {
        let line = r#"app.get("/api/applications/failed-authorization", async (req, res) => {"#;
        assert!(find_secret_candidate(line).is_none());
    }

    #[test]
    fn test_find_secret_candidate_ignores_fetch_endpoint() {
        let line = r#"const response = await fetch("/api/automations/available-tables");"#;
        assert!(find_secret_candidate(line).is_none());
    }

    // -----------------------------------------------------------------------
    // XSS
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_xss_innerhtml() {
        assert!(rule_matches(
            "xss-innerhtml",
            r#"element.innerHTML = userInput;"#,
        ));
    }

    #[test]
    fn test_detect_dangerously_set_inner_html() {
        assert!(rule_matches(
            "xss-dangerously-set",
            r#"<div dangerouslySetInnerHTML={{__html: data}} />"#,
        ));
    }

    // -----------------------------------------------------------------------
    // Unsafe deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_python_pickle() {
        assert!(rule_matches(
            "unsafe-deserialization-python",
            r#"data = pickle.loads(raw_bytes)"#,
        ));
    }

    #[test]
    fn test_detect_python_yaml_unsafe() {
        assert!(rule_matches(
            "unsafe-deserialization-python",
            r#"config = yaml.load(open("config.yml"))"#,
        ));
    }

    #[test]
    fn test_detect_java_deserialization() {
        assert!(rule_matches(
            "unsafe-deserialization-java",
            r#"ObjectInputStream ois = new ObjectInputStream(inputStream);"#,
        ));
    }

    // -----------------------------------------------------------------------
    // Weak hashing
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_md5_usage() {
        assert!(rule_matches("weak-hash-md5", r#"let hash = md5(data);"#));
    }

    #[test]
    fn test_detect_sha1_usage() {
        assert!(rule_matches("weak-hash-sha1", r#"let hash = sha1(data);"#));
    }

    // -----------------------------------------------------------------------
    // Helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_snippet_center() {
        let content = "line0\nline1\nline2\nline3\nline4";
        let snippet = extract_snippet(content, 2, 1);
        assert_eq!(snippet, "line1\nline2\nline3");
    }

    #[test]
    fn test_extract_snippet_at_start() {
        let content = "line0\nline1\nline2";
        let snippet = extract_snippet(content, 0, 2);
        // Start clamped to 0, end is min(0+2+1, 3) = 3
        assert_eq!(snippet, "line0\nline1\nline2");
    }

    #[test]
    fn test_extract_snippet_at_end() {
        let content = "line0\nline1\nline2";
        let snippet = extract_snippet(content, 2, 2);
        // Start = 2-2 = 0, end = min(2+2+1, 3) = 3
        assert_eq!(snippet, "line0\nline1\nline2");
    }

    #[test]
    fn test_make_fingerprint_deterministic() {
        let fp1 = make_fingerprint("rule-name", "file.rs", 10);
        let fp2 = make_fingerprint("rule-name", "file.rs", 10);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_make_fingerprint_differs_for_different_inputs() {
        let fp1 = make_fingerprint("rule-a", "file.rs", 10);
        let fp2 = make_fingerprint("rule-b", "file.rs", 10);
        assert_ne!(fp1, fp2);

        let fp3 = make_fingerprint("rule-a", "file.rs", 11);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn test_fingerprint_is_hex_sha256() {
        let fp = make_fingerprint("test", "file.rs", 1);
        assert_eq!(fp.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // Rule structure validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_rule_patterns_compile() {
        for rule in RULES {
            let result = Regex::new(rule.pattern);
            assert!(
                result.is_ok(),
                "Rule '{}' has invalid regex pattern: {}",
                rule.name,
                rule.pattern,
            );
        }
    }

    #[test]
    fn test_all_rules_have_cwe() {
        for rule in RULES {
            assert!(
                rule.cwe.starts_with("CWE-"),
                "Rule '{}' has invalid CWE: {}",
                rule.name,
                rule.cwe
            );
        }
    }

    #[test]
    fn test_all_rules_have_valid_severity() {
        let valid_severities = ["critical", "high", "medium", "low"];
        for rule in RULES {
            assert!(
                valid_severities.contains(&rule.severity),
                "Rule '{}' has invalid severity: {}",
                rule.name,
                rule.severity
            );
        }
    }
}
