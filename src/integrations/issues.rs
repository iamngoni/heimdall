use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow};
use log::{info, warn};
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::crypto;
use crate::db::DatabaseOperations;
use crate::models::db_models::{Finding, OauthConnection, Repo, RepoIssue};

pub fn issue_provider(repo: &Repo) -> Option<&'static str> {
    match repo.source_type.as_str() {
        "github" => Some("github"),
        "gitlab" => Some("gitlab"),
        "bitbucket" => Some("bitbucket"),
        _ => None,
    }
}

pub fn supports_issue_creation(repo: &Repo) -> bool {
    issue_provider(repo).is_some()
        && repo.oauth_connection_id.is_some()
        && repo.remote_url.is_some()
}

/// Check whether a Bitbucket repository has its issue tracker enabled.
/// Returns `Ok(true)` if enabled, `Ok(false)` if disabled, `Err` on network/auth errors.
pub async fn check_bitbucket_issue_tracker(
    remote_url: &str,
    token: &str,
    connection: &OauthConnection,
) -> Result<bool> {
    let (_, path) = split_remote(remote_url)?;
    if path.len() < 2 {
        return Err(anyhow!(
            "Unable to determine Bitbucket workspace/repository from remote URL"
        ));
    }
    let workspace = &path[0];
    let repo_slug = &path[1];
    let url = format!(
        "https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/issues?pagelen=1"
    );

    let client = Client::new();
    let mut req = client.get(&url).header("User-Agent", "Heimdall");
    if connection.token_source == "pat" {
        req = req.basic_auth(&connection.provider_user_id, Some(token));
    } else {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req
        .send()
        .await
        .context("Failed to reach Bitbucket issues API")?;
    let status = resp.status();

    if status.is_success() {
        info!("[bitbucket] issue tracker is enabled for {workspace}/{repo_slug}");
        return Ok(true);
    }

    let body = resp.text().await.unwrap_or_default();
    if status.as_u16() == 404 && body.contains("no issue tracker") {
        info!("[bitbucket] issue tracker is disabled for {workspace}/{repo_slug}");
        return Ok(false);
    }

    if status.as_u16() == 401 || status.as_u16() == 403 {
        warn!("[bitbucket] auth error checking issue tracker for {workspace}/{repo_slug}: {body}");
        return Err(anyhow!(
            "Authentication failed checking Bitbucket issue tracker"
        ));
    }

    warn!("[bitbucket] unexpected response checking issue tracker ({status}): {body}");
    Ok(false)
}

pub fn severity_meets_threshold(severity: &str, minimum: &str) -> bool {
    severity_rank(severity) >= severity_rank(minimum)
}

pub fn finding_qualifies_for_auto_issue(finding: &Finding, minimum_severity: &str) -> bool {
    severity_meets_threshold(&finding.severity, minimum_severity)
        && (finding.poc_validated || confidence_rank(&finding.confidence) >= 3)
}

pub async fn create_or_link_issue(
    db: &DatabaseOperations,
    encryption_key: Option<&[u8; 32]>,
    repo: &Repo,
    finding: &Finding,
    auto_created: bool,
) -> Result<(RepoIssue, bool)> {
    let provider = issue_provider(repo)
        .ok_or_else(|| anyhow!("Issue creation is not supported for this repository"))?;

    if let Some(existing) = db
        .get_repo_issue_by_fingerprint(repo.id, provider, &finding.fingerprint)
        .await?
    {
        return Ok((existing, false));
    }

    let connection_id = repo
        .oauth_connection_id
        .ok_or_else(|| anyhow!("This repository does not have a connected provider account"))?;
    let connection = db
        .get_oauth_connection_by_id(connection_id)
        .await?
        .ok_or_else(|| anyhow!("Provider connection for repository could not be found"))?;

    let encoded = connection
        .access_token_enc
        .as_deref()
        .ok_or_else(|| anyhow!("Connected provider is missing an access token"))?;
    let token = crypto::decode_stored_secret(encoded, encryption_key)?;

    let remote_url = repo
        .remote_url
        .as_deref()
        .ok_or_else(|| anyhow!("Repository has no remote URL"))?;
    let created_issue = match provider {
        "github" => create_github_issue(remote_url, &token, finding).await?,
        "gitlab" => create_gitlab_issue(remote_url, &token, finding).await?,
        "bitbucket" => create_bitbucket_issue(remote_url, &token, &connection, finding).await?,
        _ => unreachable!(),
    };

    let repo_issue = db
        .upsert_repo_issue(
            repo.id,
            Some(finding.id),
            provider,
            &created_issue.external_issue_id,
            created_issue.external_issue_number.as_deref(),
            &created_issue.issue_url,
            &created_issue.title,
            &finding.fingerprint,
            &finding.severity,
            "open",
            auto_created,
        )
        .await?;

    Ok((repo_issue, true))
}

#[derive(Debug)]
struct CreatedIssue {
    external_issue_id: String,
    external_issue_number: Option<String>,
    issue_url: String,
    title: String,
}

#[derive(Debug, Deserialize)]
struct GitHubIssueResponse {
    id: u64,
    number: u64,
    html_url: String,
    title: String,
}

#[derive(Debug, Deserialize)]
struct GitLabIssueResponse {
    id: u64,
    iid: u64,
    web_url: String,
    title: String,
}

async fn create_github_issue(
    remote_url: &str,
    token: &str,
    finding: &Finding,
) -> Result<CreatedIssue> {
    let (_, path) = split_remote(remote_url)?;
    if path.len() < 2 {
        return Err(anyhow!(
            "Unable to determine GitHub owner/repository from remote URL"
        ));
    }
    let owner = &path[0];
    let repo = &path[1];
    let client = Client::new();
    let response = client
        .post(format!(
            "https://api.github.com/repos/{owner}/{repo}/issues"
        ))
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "Heimdall")
        .header("Accept", "application/vnd.github+json")
        .json(&serde_json::json!({
            "title": issue_title(finding),
            "body": issue_body(finding),
            "labels": ["heimdall", "security", finding.severity.to_lowercase()],
        }))
        .send()
        .await
        .context("Failed to reach GitHub issues API")?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("GitHub issue creation failed: {body}"));
    }

    let issue = response
        .json::<GitHubIssueResponse>()
        .await
        .context("Failed to parse GitHub issue response")?;

    Ok(CreatedIssue {
        external_issue_id: issue.id.to_string(),
        external_issue_number: Some(issue.number.to_string()),
        issue_url: issue.html_url,
        title: issue.title,
    })
}

async fn create_gitlab_issue(
    remote_url: &str,
    token: &str,
    finding: &Finding,
) -> Result<CreatedIssue> {
    let (host, path) = split_remote(remote_url)?;
    if path.len() < 2 {
        return Err(anyhow!(
            "Unable to determine GitLab project path from remote URL"
        ));
    }

    let client = Client::new();
    let project_path = path.join("/");
    let encoded_project = encode_path_component(&project_path);
    let response = client
        .post(format!(
            "https://{host}/api/v4/projects/{encoded_project}/issues"
        ))
        .header("Authorization", format!("Bearer {token}"))
        .form(&[
            ("title", issue_title(finding)),
            ("description", issue_body(finding)),
            (
                "labels",
                format!("heimdall,security,{}", finding.severity.to_lowercase()),
            ),
        ])
        .send()
        .await
        .context("Failed to reach GitLab issues API")?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("GitLab issue creation failed: {body}"));
    }

    let issue = response
        .json::<GitLabIssueResponse>()
        .await
        .context("Failed to parse GitLab issue response")?;

    Ok(CreatedIssue {
        external_issue_id: issue.id.to_string(),
        external_issue_number: Some(issue.iid.to_string()),
        issue_url: issue.web_url,
        title: issue.title,
    })
}

#[derive(Debug, Deserialize)]
struct BitbucketIssueResponse {
    id: u64,
    title: String,
    links: BitbucketIssueLinks,
}

#[derive(Debug, Deserialize)]
struct BitbucketIssueLinks {
    html: BitbucketHref,
}

#[derive(Debug, Deserialize)]
struct BitbucketHref {
    href: String,
}

async fn create_bitbucket_issue(
    remote_url: &str,
    token: &str,
    connection: &OauthConnection,
    finding: &Finding,
) -> Result<CreatedIssue> {
    let (_, path) = split_remote(remote_url)?;
    if path.len() < 2 {
        return Err(anyhow!(
            "Unable to determine Bitbucket workspace/repository from remote URL"
        ));
    }
    let workspace = &path[0];
    let repo_slug = &path[1];
    let client = Client::new();
    let mut req = client
        .post(format!(
            "https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/issues"
        ))
        .header("User-Agent", "Heimdall");
    if connection.token_source == "pat" {
        req = req.basic_auth(&connection.provider_user_id, Some(token));
    } else {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let response = req
        .json(&serde_json::json!({
            "title": issue_title(finding),
            "content": {
                "raw": issue_body(finding),
                "markup": "markdown"
            },
            "kind": "bug",
            "priority": match finding.severity.to_lowercase().as_str() {
                "critical" => "critical",
                "high" => "major",
                "medium" => "minor",
                "low" => "trivial",
                _ => "minor",
            },
        }))
        .send()
        .await
        .context("Failed to reach Bitbucket issues API")?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("Bitbucket issue creation failed: {body}"));
    }

    let issue = response
        .json::<BitbucketIssueResponse>()
        .await
        .context("Failed to parse Bitbucket issue response")?;

    Ok(CreatedIssue {
        external_issue_id: issue.id.to_string(),
        external_issue_number: Some(issue.id.to_string()),
        issue_url: issue.links.html.href,
        title: issue.title,
    })
}

fn split_remote(remote_url: &str) -> Result<(String, Vec<String>)> {
    let trimmed = remote_url.trim().trim_end_matches(".git");
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let without_auth = without_scheme
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(without_scheme);
    let normalized = without_auth.replacen(':', "/", 1);
    let mut parts = normalized.split('/').filter(|segment| !segment.is_empty());
    let host = parts
        .next()
        .ok_or_else(|| anyhow!("Unable to determine remote host"))?
        .to_string();
    let path = parts.map(ToString::to_string).collect::<Vec<_>>();
    Ok((host, path))
}

fn encode_path_component(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn issue_title(finding: &Finding) -> String {
    format!("[{}] {}", finding.severity.to_uppercase(), finding.title)
}

fn issue_body(finding: &Finding) -> String {
    let mut body = String::new();
    body.push_str("## Heimdall Finding\n\n");
    body.push_str(&format!("- Severity: `{}`\n", finding.severity));
    body.push_str(&format!("- Confidence: `{}`\n", finding.confidence));
    body.push_str(&format!("- Fingerprint: `{}`\n", finding.fingerprint));
    body.push_str(&format!(
        "- Location: `{}`:{}",
        finding.file_path, finding.line_start
    ));
    if let Some(line_end) = finding.line_end {
        body.push_str(&format!("-{line_end}"));
    }
    body.push('\n');
    if let Some(cwe) = &finding.cwe_id {
        body.push_str(&format!("- CWE: `{cwe}`\n"));
    }
    if let Some(cve) = &finding.cve_id {
        body.push_str(&format!("- CVE: `{cve}`\n"));
    }
    body.push('\n');

    if let Some(description) = &finding.description {
        body.push_str("### Summary\n\n");
        body.push_str(description.trim());
        body.push_str("\n\n");
    }

    if let Some(snippet) = &finding.code_snippet {
        body.push_str("### Evidence\n\n```text\n");
        let snippet = if snippet.len() > 1200 {
            format!("{}...", &snippet[..1200])
        } else {
            snippet.clone()
        };
        body.push_str(snippet.trim());
        body.push_str("\n```\n\n");
    }

    if let Some(patch) = &finding.suggested_patch {
        body.push_str("### Suggested Patch\n\n```diff\n");
        let patch = if patch.len() > 1600 {
            format!("{}...", &patch[..1600])
        } else {
            patch.clone()
        };
        body.push_str(patch.trim());
        body.push_str("\n```\n");
    }

    body
}

/// Group findings by their title (rule name) for bulk issue creation.
/// Returns a map of title → list of findings, preserving the highest severity per group.
pub fn group_findings_by_rule(findings: &[Finding]) -> BTreeMap<String, Vec<&Finding>> {
    let mut groups: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        groups.entry(finding.title.clone()).or_default().push(finding);
    }
    groups
}

/// Compute a stable group fingerprint from the rule title.
fn group_fingerprint(title: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"heimdall-group:");
    hasher.update(title.as_bytes());
    format!("group:{:x}", hasher.finalize())
}

/// Determine the highest severity among a group of findings.
fn max_severity(findings: &[&Finding]) -> String {
    findings
        .iter()
        .max_by_key(|f| severity_rank(&f.severity))
        .map(|f| f.severity.clone())
        .unwrap_or_else(|| "medium".to_string())
}

fn grouped_issue_title(title: &str, severity: &str, count: usize) -> String {
    format!(
        "[{}] {} ({} location{})",
        severity.to_uppercase(),
        title,
        count,
        if count == 1 { "" } else { "s" }
    )
}

fn grouped_issue_body(title: &str, findings: &[&Finding]) -> String {
    let mut body = String::new();
    body.push_str("## Heimdall Grouped Finding\n\n");

    let severity = max_severity(findings);
    body.push_str(&format!("- Rule: **{}**\n", title));
    body.push_str(&format!("- Severity: `{}`\n", severity));
    body.push_str(&format!("- Locations: **{}**\n", findings.len()));

    if let Some(cwe) = findings.iter().find_map(|f| f.cwe_id.as_ref()) {
        body.push_str(&format!("- CWE: `{cwe}`\n"));
    }
    body.push('\n');

    if let Some(description) = findings.iter().find_map(|f| f.description.as_ref()) {
        body.push_str("### Summary\n\n");
        body.push_str(description.trim());
        body.push_str("\n\n");
    }

    body.push_str("### Affected Locations\n\n");
    body.push_str("| File | Line | Confidence |\n");
    body.push_str("|------|------|------------|\n");
    for f in findings {
        let line = if let Some(end) = f.line_end {
            format!("{}-{}", f.line_start, end)
        } else {
            f.line_start.to_string()
        };
        body.push_str(&format!(
            "| `{}` | {} | {} |\n",
            f.file_path, line, f.confidence
        ));
    }
    body.push('\n');

    // Include one representative code snippet
    if let Some(snippet) = findings.iter().find_map(|f| f.code_snippet.as_ref()) {
        body.push_str("### Example Evidence\n\n```text\n");
        let snippet = if snippet.len() > 1200 {
            format!("{}...", &snippet[..1200])
        } else {
            snippet.clone()
        };
        body.push_str(snippet.trim());
        body.push_str("\n```\n\n");
    }

    if let Some(patch) = findings.iter().find_map(|f| f.suggested_patch.as_ref()) {
        body.push_str("### Suggested Patch\n\n```diff\n");
        let patch = if patch.len() > 1600 {
            format!("{}...", &patch[..1600])
        } else {
            patch.clone()
        };
        body.push_str(patch.trim());
        body.push_str("\n```\n");
    }

    body
}

/// Create or link a single issue for a *group* of findings that share the same rule/title.
/// Returns `(RepoIssue, created: bool, linked_finding_count)`.
pub async fn create_or_link_grouped_issue(
    db: &DatabaseOperations,
    encryption_key: Option<&[u8; 32]>,
    repo: &Repo,
    title: &str,
    findings: &[&Finding],
    auto_created: bool,
) -> Result<(RepoIssue, bool, usize)> {
    let provider = issue_provider(repo)
        .ok_or_else(|| anyhow!("Issue creation is not supported for this repository"))?;

    let fp = group_fingerprint(title);

    // Check if a grouped issue already exists for this rule
    if let Some(existing) = db
        .get_repo_issue_by_fingerprint(repo.id, provider, &fp)
        .await?
    {
        return Ok((existing, false, findings.len()));
    }

    let connection_id = repo
        .oauth_connection_id
        .ok_or_else(|| anyhow!("This repository does not have a connected provider account"))?;
    let connection = db
        .get_oauth_connection_by_id(connection_id)
        .await?
        .ok_or_else(|| anyhow!("Provider connection for repository could not be found"))?;

    let encoded = connection
        .access_token_enc
        .as_deref()
        .ok_or_else(|| anyhow!("Connected provider is missing an access token"))?;
    let token = crypto::decode_stored_secret(encoded, encryption_key)?;

    let remote_url = repo
        .remote_url
        .as_deref()
        .ok_or_else(|| anyhow!("Repository has no remote URL"))?;

    let severity = max_severity(findings);
    let issue_title_str = grouped_issue_title(title, &severity, findings.len());
    let issue_body_str = grouped_issue_body(title, findings);

    // Build a temporary Finding-like struct for the provider functions isn't needed;
    // we'll call the provider APIs directly with our grouped title/body.
    let created_issue = match provider {
        "github" => {
            create_github_grouped_issue(remote_url, &token, &issue_title_str, &issue_body_str, &severity)
                .await?
        }
        "gitlab" => {
            create_gitlab_grouped_issue(remote_url, &token, &issue_title_str, &issue_body_str, &severity)
                .await?
        }
        "bitbucket" => {
            create_bitbucket_grouped_issue(
                remote_url,
                &token,
                &connection,
                &issue_title_str,
                &issue_body_str,
                &severity,
            )
            .await?
        }
        _ => unreachable!(),
    };

    let repo_issue = db
        .upsert_repo_issue(
            repo.id,
            None, // no single finding_id for a group
            provider,
            &created_issue.external_issue_id,
            created_issue.external_issue_number.as_deref(),
            &created_issue.issue_url,
            &created_issue.title,
            &fp,
            &severity,
            "open",
            auto_created,
        )
        .await?;

    Ok((repo_issue, true, findings.len()))
}

async fn create_github_grouped_issue(
    remote_url: &str,
    token: &str,
    title: &str,
    body: &str,
    severity: &str,
) -> Result<CreatedIssue> {
    let (_, path) = split_remote(remote_url)?;
    if path.len() < 2 {
        return Err(anyhow!(
            "Unable to determine GitHub owner/repository from remote URL"
        ));
    }
    let owner = &path[0];
    let repo = &path[1];
    let client = Client::new();
    let response = client
        .post(format!(
            "https://api.github.com/repos/{owner}/{repo}/issues"
        ))
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "Heimdall")
        .header("Accept", "application/vnd.github+json")
        .json(&serde_json::json!({
            "title": title,
            "body": body,
            "labels": ["heimdall", "security", severity.to_lowercase()],
        }))
        .send()
        .await
        .context("Failed to reach GitHub issues API")?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("GitHub issue creation failed: {body}"));
    }

    let issue = response
        .json::<GitHubIssueResponse>()
        .await
        .context("Failed to parse GitHub issue response")?;

    Ok(CreatedIssue {
        external_issue_id: issue.id.to_string(),
        external_issue_number: Some(issue.number.to_string()),
        issue_url: issue.html_url,
        title: issue.title,
    })
}

async fn create_gitlab_grouped_issue(
    remote_url: &str,
    token: &str,
    title: &str,
    body: &str,
    severity: &str,
) -> Result<CreatedIssue> {
    let (host, path) = split_remote(remote_url)?;
    if path.len() < 2 {
        return Err(anyhow!(
            "Unable to determine GitLab project path from remote URL"
        ));
    }

    let client = Client::new();
    let project_path = path.join("/");
    let encoded_project = encode_path_component(&project_path);
    let response = client
        .post(format!(
            "https://{host}/api/v4/projects/{encoded_project}/issues"
        ))
        .header("Authorization", format!("Bearer {token}"))
        .form(&[
            ("title", title.to_string()),
            ("description", body.to_string()),
            (
                "labels",
                format!("heimdall,security,{}", severity.to_lowercase()),
            ),
        ])
        .send()
        .await
        .context("Failed to reach GitLab issues API")?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("GitLab issue creation failed: {body}"));
    }

    let issue = response
        .json::<GitLabIssueResponse>()
        .await
        .context("Failed to parse GitLab issue response")?;

    Ok(CreatedIssue {
        external_issue_id: issue.id.to_string(),
        external_issue_number: Some(issue.iid.to_string()),
        issue_url: issue.web_url,
        title: issue.title,
    })
}

async fn create_bitbucket_grouped_issue(
    remote_url: &str,
    token: &str,
    connection: &OauthConnection,
    title: &str,
    body: &str,
    severity: &str,
) -> Result<CreatedIssue> {
    let (_, path) = split_remote(remote_url)?;
    if path.len() < 2 {
        return Err(anyhow!(
            "Unable to determine Bitbucket workspace/repository from remote URL"
        ));
    }
    let workspace = &path[0];
    let repo_slug = &path[1];
    let client = Client::new();
    let mut req = client
        .post(format!(
            "https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/issues"
        ))
        .header("User-Agent", "Heimdall");
    if connection.token_source == "pat" {
        req = req.basic_auth(&connection.provider_user_id, Some(token));
    } else {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let response = req
        .json(&serde_json::json!({
            "title": title,
            "content": {
                "raw": body,
                "markup": "markdown"
            },
            "kind": "bug",
            "priority": match severity.to_lowercase().as_str() {
                "critical" => "critical",
                "high" => "major",
                "medium" => "minor",
                "low" => "trivial",
                _ => "minor",
            },
        }))
        .send()
        .await
        .context("Failed to reach Bitbucket issues API")?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("Bitbucket issue creation failed: {body}"));
    }

    let issue = response
        .json::<BitbucketIssueResponse>()
        .await
        .context("Failed to parse Bitbucket issue response")?;

    Ok(CreatedIssue {
        external_issue_id: issue.id.to_string(),
        external_issue_number: Some(issue.id.to_string()),
        issue_url: issue.links.html.href,
        title: issue.title,
    })
}

fn severity_rank(severity: &str) -> i32 {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn confidence_rank(confidence: &str) -> i32 {
    match confidence.trim().to_ascii_lowercase().as_str() {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    fn sample_finding() -> Finding {
        Finding {
            id: Uuid::nil(),
            scan_id: Uuid::nil(),
            repo_id: Uuid::nil(),
            source: "static".to_string(),
            status: "open".to_string(),
            severity: "high".to_string(),
            confidence: "medium".to_string(),
            title: "Sample finding".to_string(),
            description: None,
            cwe_id: None,
            cve_id: None,
            file_path: "server.js".to_string(),
            line_start: 1,
            line_end: Some(1),
            code_snippet: None,
            suggested_patch: None,
            poc_exploit_json: None,
            poc_validated: false,
            fingerprint: "fp".to_string(),
            agent_reasoning: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_auto_issue_requires_high_confidence_or_validation() {
        let finding = sample_finding();
        assert!(!finding_qualifies_for_auto_issue(&finding, "high"));
    }

    #[test]
    fn test_auto_issue_allows_validated_medium_confidence_finding() {
        let mut finding = sample_finding();
        finding.poc_validated = true;
        assert!(finding_qualifies_for_auto_issue(&finding, "high"));
    }
}
