use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use uuid::Uuid;

use crate::ai::ModelProvider;
use crate::ai::types::{CompletionRequest, Message};
use crate::crypto;
use crate::db::DatabaseOperations;
use crate::models::db_models::{Finding, Patch, RemediationRun, Repo};

const MAX_PROMPT_CHARS: usize = 18_000;
const MAX_STORED_OUTPUT_CHARS: usize = 8_000;
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const GITHUB_API_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct RemediationJob {
    pub db: Arc<DatabaseOperations>,
    pub ai_provider: Arc<dyn ModelProvider>,
    pub ai_model: String,
    pub ai_provider_name: String,
    pub encryption_key: Option<[u8; 32]>,
    pub data_dir: String,
    pub repo: Repo,
    pub finding: Finding,
    pub patch: Option<Patch>,
    pub run: RemediationRun,
    pub user_id: Uuid,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentPatchResponse {
    pub summary: String,
    pub unified_diff: String,
    #[serde(default)]
    pub validation_notes: Option<String>,
}

#[derive(Debug)]
struct CommandResult {
    stdout: String,
    stderr: String,
}

impl CommandResult {
    fn combined(&self) -> String {
        [self.stdout.trim(), self.stderr.trim()]
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Debug)]
struct GitHubRepo {
    host: String,
    owner: String,
    name: String,
}

#[derive(Debug)]
struct CreatedPullRequest {
    id: String,
    number: String,
    url: String,
    title: String,
}

#[derive(Debug, Deserialize)]
struct GitHubPullResponse {
    id: u64,
    number: u64,
    html_url: String,
    title: String,
}

pub async fn run_fix_pr(job: RemediationJob) -> Result<()> {
    let mut validation_log = String::new();
    match run_fix_pr_inner(&job, &mut validation_log).await {
        Ok(()) => Ok(()),
        Err(error) => {
            let error_message = truncate_chars(&format!("{error:#}"), MAX_STORED_OUTPUT_CHARS);
            let validation_output = if validation_log.trim().is_empty() {
                None
            } else {
                Some(truncate_chars(&validation_log, MAX_STORED_OUTPUT_CHARS))
            };
            let _ = job
                .db
                .fail_remediation_run(job.run.id, &error_message, validation_output.as_deref())
                .await;
            let metadata = serde_json::json!({
                "run_id": job.run.id,
                "status": "failed",
                "error": error_message,
                "validation_output": validation_output,
            });
            let _ = job
                .db
                .create_finding_event_with_metadata(
                    job.finding.id,
                    Some(job.user_id),
                    "remediation_failed",
                    None,
                    Some(&job.run.id.to_string()),
                    Some("Fix PR agent failed before opening a pull request."),
                    Some(&metadata),
                )
                .await;
            Err(error)
        }
    }
}

async fn run_fix_pr_inner(job: &RemediationJob, validation_log: &mut String) -> Result<()> {
    if job.repo.source_type != "github" {
        bail!("Fix PR automation currently supports provider-connected GitHub repositories only");
    }

    job.db
        .mark_remediation_run_running(job.run.id)
        .await?
        .ok_or_else(|| anyhow!("Remediation run was not found"))?;

    let branch_name = job
        .run
        .branch_name
        .as_deref()
        .ok_or_else(|| anyhow!("Remediation run is missing a branch name"))?;
    let base_branch = job
        .run
        .base_branch
        .as_deref()
        .or(job.repo.default_branch.as_deref())
        .unwrap_or("main");
    let remote_url = job
        .repo
        .remote_url
        .as_deref()
        .ok_or_else(|| anyhow!("Repository has no remote URL"))?;
    let github_repo = parse_github_remote(remote_url)?;

    let connection_id = job
        .repo
        .oauth_connection_id
        .ok_or_else(|| anyhow!("Repository is not connected to a GitHub OAuth account"))?;
    let connection = job
        .db
        .get_oauth_connection_by_id(connection_id)
        .await?
        .ok_or_else(|| anyhow!("GitHub connection for repository could not be found"))?;
    if connection.provider != "github" {
        bail!(
            "Repository connection is for {}, not GitHub",
            connection.provider
        );
    }
    let encoded = connection
        .access_token_enc
        .as_deref()
        .ok_or_else(|| anyhow!("GitHub connection is missing an access token"))?;
    let token = crypto::decode_stored_secret(encoded, job.encryption_key.as_ref())?;

    let metadata = serde_json::json!({
        "run_id": job.run.id,
        "status": "running",
        "provider": job.ai_provider_name,
        "model": job.ai_model,
        "branch": branch_name,
        "base": base_branch,
    });
    job.db
        .create_finding_event_with_metadata(
            job.finding.id,
            Some(job.user_id),
            "remediation_started",
            None,
            Some(&job.run.id.to_string()),
            Some("Fix PR agent started generating and validating a repository change."),
            Some(&metadata),
        )
        .await?;

    let run_dir = PathBuf::from(&job.data_dir)
        .join("remediations")
        .join(job.run.id.to_string());
    let work_dir = run_dir.join("repo");
    if run_dir.exists() {
        tokio::fs::remove_dir_all(&run_dir)
            .await
            .with_context(|| format!("Failed to remove stale remediation directory {run_dir:?}"))?;
    }
    tokio::fs::create_dir_all(&run_dir)
        .await
        .with_context(|| format!("Failed to create remediation directory {run_dir:?}"))?;

    clone_repository(&github_repo, base_branch, &work_dir, &token, validation_log).await?;
    git(&work_dir, ["checkout", "-B", branch_name], Some(&token)).await?;
    git(
        &work_dir,
        ["config", "user.name", "Heimdall Fix Agent"],
        Some(&token),
    )
    .await?;
    git(
        &work_dir,
        ["config", "user.email", "heimdall@localhost"],
        Some(&token),
    )
    .await?;

    let relative_file = safe_relative_path(&job.finding.file_path)?;
    let target_file = work_dir.join(&relative_file);
    let file_content = tokio::fs::read_to_string(&target_file)
        .await
        .with_context(|| format!("Failed to read target file {}", job.finding.file_path))?;
    let source_context = source_context_for_prompt(&file_content, &job.finding);

    let initial_prompt = build_agent_prompt(job, &source_context, None);
    let mut agent_response = request_agent_patch(job, "generate_patch", initial_prompt).await?;
    let mut diff = clean_diff(agent_response.unified_diff.as_str());
    if diff.trim().is_empty() {
        bail!("Fix agent returned an empty unified diff");
    }

    let diff_path = run_dir.join("agent.diff");
    let check_result = check_patch(&work_dir, &diff_path, &diff, &token).await;
    if let Err(error) = check_result {
        append_log(
            validation_log,
            "Initial patch did not apply",
            &format!("{error:#}"),
        );
        let repair_prompt =
            build_agent_prompt(job, &source_context, Some((&diff, &format!("{error:#}"))));
        agent_response = request_agent_patch(job, "repair_patch", repair_prompt).await?;
        diff = clean_diff(agent_response.unified_diff.as_str());
        if diff.trim().is_empty() {
            bail!("Fix agent repair returned an empty unified diff");
        }
        check_patch(&work_dir, &diff_path, &diff, &token).await?;
    }

    tokio::fs::write(&diff_path, &diff)
        .await
        .context("Failed to write agent patch")?;
    git_path(&work_dir, ["apply"], &diff_path, Some(&token)).await?;
    let _ = tokio::fs::remove_file(&diff_path).await;
    append_log(validation_log, "Patch applied", "git apply succeeded");

    let diff_check = git(&work_dir, ["diff", "--check"], Some(&token)).await?;
    append_log(
        validation_log,
        "Whitespace validation",
        &diff_check.combined_if_empty("git diff --check passed"),
    );

    let status = git(&work_dir, ["status", "--porcelain"], Some(&token)).await?;
    if status.stdout.trim().is_empty() {
        bail!("Fix agent patch applied cleanly but produced no working-tree changes");
    }
    append_log(validation_log, "Changed files", status.stdout.trim());

    git(&work_dir, ["add", "-A"], Some(&token)).await?;
    let commit_message = commit_message(&job.finding);
    git(&work_dir, ["commit", "-m", &commit_message], Some(&token)).await?;
    let commit_sha = git(&work_dir, ["rev-parse", "HEAD"], Some(&token))
        .await?
        .stdout
        .trim()
        .to_string();
    append_log(validation_log, "Commit", &commit_sha);

    git_with_header(
        &work_dir,
        ["push", "-u", "origin", branch_name],
        Some(&token),
    )
    .await?;
    append_log(validation_log, "Branch pushed", branch_name);

    let pr_title = pr_title(&job.finding);
    let pr_body = pr_body(job, &agent_response, validation_log);
    let pr = create_github_pull_request(
        &github_repo,
        &token,
        &pr_title,
        branch_name,
        base_branch,
        &pr_body,
    )
    .await?;

    let completion_metadata = serde_json::json!({
        "run_id": job.run.id,
        "provider": job.ai_provider_name,
        "model": job.ai_model,
        "branch": branch_name,
        "base": base_branch,
        "commit_sha": commit_sha,
        "pr_url": pr.url,
        "external_pr_number": pr.number,
    });
    job.db
        .complete_remediation_run_pr(
            job.run.id,
            Some(&commit_sha),
            Some(&pr.url),
            Some(&pr.id),
            Some(&pr.number),
            Some(&pr.title),
            Some(&agent_response.summary),
            Some(&truncate_chars(validation_log, MAX_STORED_OUTPUT_CHARS)),
            Some(&completion_metadata),
        )
        .await?
        .ok_or_else(|| anyhow!("Remediation run disappeared before completion"))?;

    job.db
        .create_finding_event_with_metadata(
            job.finding.id,
            Some(job.user_id),
            "remediation_pr_opened",
            None,
            Some(&pr.url),
            Some("Fix PR agent opened a draft pull request."),
            Some(&completion_metadata),
        )
        .await?;

    Ok(())
}

async fn request_agent_patch(
    job: &RemediationJob,
    tool_name: &str,
    prompt: String,
) -> Result<AgentPatchResponse> {
    let request = CompletionRequest {
        model: job.ai_model.clone(),
        messages: vec![
            Message {
                role: "system".to_string(),
                content: "You are Heimdall's security fix agent. Generate a minimal, reviewable code change for the finding. Return ONLY JSON with keys summary, unified_diff, validation_notes. unified_diff must be a git-style unified diff rooted at the repository root. Do not include markdown outside the JSON. Do not invent unrelated files or broad refactors.".to_string(),
            },
            Message {
                role: "user".to_string(),
                content: prompt,
            },
        ],
        tools: None,
        max_tokens: Some(6000),
        temperature: Some(0.1),
    };

    let started = Instant::now();
    let input = serde_json::json!({
        "finding_id": job.finding.id,
        "repo_id": job.repo.id,
        "run_id": job.run.id,
        "tool_name": tool_name,
        "file_path": job.finding.file_path,
    });
    let response = match job.ai_provider.complete(request).await {
        Ok(response) => response,
        Err(error) => {
            let _ = job
                .db
                .create_agent_tool_call(
                    job.finding.scan_id,
                    "remediation",
                    tool_name,
                    Some(&job.ai_provider_name),
                    Some(&job.ai_model),
                    Some(&input),
                    None,
                    None,
                    None,
                    None,
                    Some(started.elapsed().as_millis().min(i32::MAX as u128) as i32),
                    Some(&truncate_chars(
                        &format!("{error:#}"),
                        MAX_STORED_OUTPUT_CHARS,
                    )),
                )
                .await;
            return Err(error).context("Fix agent completion failed");
        }
    };

    let output = serde_json::json!({
        "provider": response.provider,
        "model": response.model,
        "stop_reason": response.stop_reason,
        "content_preview": truncate_chars(&response.content, 2000),
    });
    let _ = job
        .db
        .create_agent_tool_call(
            job.finding.scan_id,
            "remediation",
            tool_name,
            Some(&job.ai_provider_name),
            Some(&job.ai_model),
            Some(&input),
            Some(&output),
            Some(response.usage.prompt_tokens.min(i32::MAX as u32) as i32),
            Some(response.usage.completion_tokens.min(i32::MAX as u32) as i32),
            Some(response.usage.total_tokens.min(i32::MAX as u32) as i32),
            Some(started.elapsed().as_millis().min(i32::MAX as u128) as i32),
            None,
        )
        .await;

    extract_agent_fix_response(&response.content)
}

async fn clone_repository(
    repo: &GitHubRepo,
    branch: &str,
    work_dir: &Path,
    token: &str,
    validation_log: &mut String,
) -> Result<()> {
    let mut command = Command::new("git");
    command
        .arg("-c")
        .arg(format!(
            "http.extraheader={}",
            github_basic_auth_header(token)
        ))
        .args(["clone", "--depth", "1", "--branch", branch, "--progress"])
        .arg(repo.clone_url())
        .arg(work_dir);
    let output = run_command(command, Some(token))
        .await
        .context("Failed to clone repository")?;
    append_log(
        validation_log,
        "Repository cloned",
        &output.combined_if_empty("clone completed"),
    );
    Ok(())
}

async fn check_patch(
    work_dir: &Path,
    diff_path: &Path,
    diff: &str,
    token: &str,
) -> Result<CommandResult> {
    tokio::fs::write(diff_path, diff)
        .await
        .context("Failed to write agent patch for validation")?;
    let result = git_path(work_dir, ["apply", "--check"], diff_path, Some(token)).await;
    let _ = tokio::fs::remove_file(diff_path).await;
    result
}

async fn git<const N: usize>(
    work_dir: &Path,
    args: [&str; N],
    secret: Option<&str>,
) -> Result<CommandResult> {
    let mut command = Command::new("git");
    command.arg("-C").arg(work_dir).args(args);
    run_command(command, secret).await
}

async fn git_path<const N: usize>(
    work_dir: &Path,
    args: [&str; N],
    path_arg: &Path,
    secret: Option<&str>,
) -> Result<CommandResult> {
    let mut command = Command::new("git");
    command.arg("-C").arg(work_dir).args(args).arg(path_arg);
    run_command(command, secret).await
}

async fn git_with_header<const N: usize>(
    work_dir: &Path,
    args: [&str; N],
    token: Option<&str>,
) -> Result<CommandResult> {
    let mut command = Command::new("git");
    command.arg("-C").arg(work_dir);
    if let Some(token) = token {
        command.arg("-c").arg(format!(
            "http.extraheader={}",
            github_basic_auth_header(token)
        ));
    }
    command.args(args);
    run_command(command, token).await
}

async fn run_command(mut command: Command, secret: Option<&str>) -> Result<CommandResult> {
    let output = tokio::time::timeout(GIT_COMMAND_TIMEOUT, command.output())
        .await
        .context("Git command timed out")?
        .context("Failed to start command")?;
    let stdout = redact_secret(&String::from_utf8_lossy(&output.stdout), secret);
    let stderr = redact_secret(&String::from_utf8_lossy(&output.stderr), secret);
    if output.status.success() {
        Ok(CommandResult { stdout, stderr })
    } else {
        bail!(
            "command exited with {}: {}",
            output.status,
            [stdout.trim(), stderr.trim()]
                .into_iter()
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}

async fn create_github_pull_request(
    repo: &GitHubRepo,
    token: &str,
    title: &str,
    head: &str,
    base: &str,
    body: &str,
) -> Result<CreatedPullRequest> {
    if repo.host != "github.com" {
        bail!(
            "GitHub Enterprise pull requests are not yet supported for host {}",
            repo.host
        );
    }

    let client = Client::builder()
        .timeout(GITHUB_API_TIMEOUT)
        .build()
        .context("Failed to build GitHub API client")?;
    let response = client
        .post(format!(
            "https://api.github.com/repos/{}/{}/pulls",
            repo.owner, repo.name
        ))
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "Heimdall")
        .header("Accept", "application/vnd.github+json")
        .json(&serde_json::json!({
            "title": title,
            "head": head,
            "base": base,
            "body": body,
            "draft": true,
        }))
        .send()
        .await
        .context("Failed to reach GitHub pull request API")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("GitHub pull request creation failed ({status}): {body}");
    }

    let pr = response
        .json::<GitHubPullResponse>()
        .await
        .context("Failed to parse GitHub pull request response")?;

    Ok(CreatedPullRequest {
        id: pr.id.to_string(),
        number: pr.number.to_string(),
        url: pr.html_url,
        title: pr.title,
    })
}

fn build_agent_prompt(
    job: &RemediationJob,
    source_context: &str,
    repair: Option<(&str, &str)>,
) -> String {
    let mut prompt = String::new();
    prompt.push_str("Create a minimal security fix for this Heimdall finding.\n\n");
    prompt.push_str("Finding:\n");
    prompt.push_str(&format!("- Title: {}\n", job.finding.title));
    prompt.push_str(&format!("- Severity: {}\n", job.finding.severity));
    prompt.push_str(&format!("- Confidence: {}\n", job.finding.confidence));
    prompt.push_str(&format!(
        "- Location: {}:{}",
        job.finding.file_path, job.finding.line_start
    ));
    if let Some(line_end) = job.finding.line_end {
        prompt.push_str(&format!("-{line_end}"));
    }
    prompt.push('\n');
    if let Some(cwe) = &job.finding.cwe_id {
        prompt.push_str(&format!("- CWE: {cwe}\n"));
    }
    if let Some(cve) = &job.finding.cve_id {
        prompt.push_str(&format!("- CVE: {cve}\n"));
    }
    if let Some(description) = &job.finding.description {
        prompt.push_str("\nDescription:\n");
        prompt.push_str(&truncate_chars(description.trim(), 3000));
        prompt.push('\n');
    }
    if let Some(summary) = &job.finding.fix_summary {
        prompt.push_str("\nRemediation summary from scan:\n");
        prompt.push_str(&truncate_chars(summary.trim(), 2000));
        prompt.push('\n');
    }
    if let Some(snippet) = &job.finding.code_snippet {
        prompt.push_str("\nVulnerable snippet from scan:\n```text\n");
        prompt.push_str(&truncate_chars(snippet.trim(), 4000));
        prompt.push_str("\n```\n");
    }
    if let Some(patch) = &job.patch {
        prompt.push_str("\nStored suggested diff, for context only. It may be stale, incomplete, or wrong:\n```diff\n");
        prompt.push_str(&truncate_chars(patch.diff_content.trim(), 5000));
        prompt.push_str("\n```\n");
    } else if let Some(patch) = &job.finding.suggested_patch {
        prompt.push_str("\nSuggested patch text from finding, for context only. It may be stale, incomplete, or wrong:\n```diff\n");
        prompt.push_str(&truncate_chars(patch.trim(), 5000));
        prompt.push_str("\n```\n");
    }
    prompt.push_str(
        "\nCurrent repository source context. Line numbers are not part of the file:\n```text\n",
    );
    prompt.push_str(&truncate_chars(source_context, MAX_PROMPT_CHARS));
    prompt.push_str("\n```\n");

    if let Some((previous_diff, error)) = repair {
        prompt.push_str("\nThe previous diff failed git apply --check. Repair it against the current source context.\n");
        prompt.push_str("\nPrevious diff:\n```diff\n");
        prompt.push_str(&truncate_chars(previous_diff.trim(), 5000));
        prompt.push_str("\n```\n");
        prompt.push_str("\nApply error:\n```text\n");
        prompt.push_str(&truncate_chars(error.trim(), 4000));
        prompt.push_str("\n```\n");
    }

    prompt.push_str(
        "\nReturn only JSON: {\"summary\":\"...\",\"unified_diff\":\"diff --git ...\",\"validation_notes\":\"...\"}.",
    );
    prompt
}

pub fn extract_agent_fix_response(content: &str) -> Result<AgentPatchResponse> {
    let cleaned = strip_fenced_code(content);
    let parsed = if let Ok(parsed) = serde_json::from_str::<AgentPatchResponse>(&cleaned) {
        parsed
    } else {
        let start = cleaned
            .find('{')
            .ok_or_else(|| anyhow!("agent response did not contain JSON"))?;
        let end = cleaned
            .rfind('}')
            .ok_or_else(|| anyhow!("agent response did not contain a complete JSON object"))?;
        serde_json::from_str::<AgentPatchResponse>(&cleaned[start..=end])
            .context("agent response JSON did not match the expected fix schema")?
    };
    if parsed.summary.trim().is_empty() {
        bail!("agent response summary was empty");
    }
    if clean_diff(&parsed.unified_diff).trim().is_empty() {
        bail!("agent response unified_diff was empty");
    }
    Ok(parsed)
}

fn source_context_for_prompt(content: &str, finding: &Finding) -> String {
    let total_chars = content.chars().count();
    if total_chars <= MAX_PROMPT_CHARS {
        return content
            .lines()
            .enumerate()
            .map(|(idx, line)| format!("{:>5} | {line}", idx + 1))
            .collect::<Vec<_>>()
            .join("\n");
    }

    let lines = content.lines().collect::<Vec<_>>();
    let start_line = finding.line_start.max(1) as usize;
    let end_line = finding
        .line_end
        .unwrap_or(finding.line_start)
        .max(finding.line_start) as usize;
    let excerpt_start = start_line.saturating_sub(40).max(1);
    let excerpt_end = (end_line + 40).min(lines.len());

    (excerpt_start..=excerpt_end)
        .filter_map(|line_number| {
            lines
                .get(line_number - 1)
                .map(|line| format!("{line_number:>5} | {line}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn branch_name_for_finding(finding: &Finding) -> String {
    branch_name_for_finding_with_suffix(finding, "")
}

pub fn branch_name_for_finding_with_suffix(finding: &Finding, suffix: &str) -> String {
    let slug = slugify(&finding.title);
    let short_id = finding.id.to_string();
    let short_id = short_id.split('-').next().unwrap_or(&short_id);
    let mut branch = format!("heimdall/fix/{short_id}");
    if !slug.is_empty() {
        branch.push('-');
        branch.push_str(&slug);
    }
    let suffix = slugify(suffix);
    if !suffix.is_empty() {
        branch.push('-');
        branch.push_str(&suffix);
    }
    truncate_branch(&branch, 96)
}

pub fn supports_fix_pr(repo: &Repo) -> bool {
    repo.source_type == "github" && repo.oauth_connection_id.is_some() && repo.remote_url.is_some()
}

fn commit_message(finding: &Finding) -> String {
    let title = truncate_chars(&finding.title.replace('\n', " "), 64);
    format!("fix: {title}")
}

fn pr_title(finding: &Finding) -> String {
    format!("[Heimdall] Fix {}", finding.title.replace('\n', " "))
}

fn pr_body(job: &RemediationJob, response: &AgentPatchResponse, validation_log: &str) -> String {
    let mut body = String::new();
    body.push_str("## Heimdall Fix PR\n\n");
    body.push_str(&format!("- Finding: `{}`\n", job.finding.id));
    body.push_str(&format!("- Severity: `{}`\n", job.finding.severity));
    body.push_str(&format!("- Confidence: `{}`\n", job.finding.confidence));
    body.push_str(&format!(
        "- Location: `{}`:{}",
        job.finding.file_path, job.finding.line_start
    ));
    if let Some(line_end) = job.finding.line_end {
        body.push_str(&format!("-{line_end}"));
    }
    body.push('\n');
    if let Some(cwe) = &job.finding.cwe_id {
        body.push_str(&format!("- CWE: `{cwe}`\n"));
    }
    if let Some(cve) = &job.finding.cve_id {
        body.push_str(&format!("- CVE: `{cve}`\n"));
    }
    body.push_str(&format!(
        "- Agent: `{}` / `{}`\n\n",
        job.ai_provider_name, job.ai_model
    ));
    body.push_str("### Agent Summary\n\n");
    body.push_str(response.summary.trim());
    body.push_str("\n\n");
    if let Some(notes) = response
        .validation_notes
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        body.push_str("### Agent Notes\n\n");
        body.push_str(notes.trim());
        body.push_str("\n\n");
    }
    if let Some(description) = &job.finding.description {
        body.push_str("### Finding Context\n\n");
        body.push_str(&truncate_chars(description.trim(), 2000));
        body.push_str("\n\n");
    }
    body.push_str("### Heimdall Validation\n\n```text\n");
    body.push_str(&truncate_chars(validation_log.trim(), 4000));
    body.push_str("\n```\n");
    body
}

fn parse_github_remote(remote_url: &str) -> Result<GitHubRepo> {
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
        .ok_or_else(|| anyhow!("Unable to determine GitHub remote host"))?
        .to_string();
    let owner = parts
        .next()
        .ok_or_else(|| anyhow!("Unable to determine GitHub owner from remote URL"))?
        .to_string();
    let name = parts
        .next()
        .ok_or_else(|| anyhow!("Unable to determine GitHub repository from remote URL"))?
        .trim_end_matches(".git")
        .to_string();
    Ok(GitHubRepo { host, owner, name })
}

impl GitHubRepo {
    fn clone_url(&self) -> String {
        format!("https://{}/{}/{}.git", self.host, self.owner, self.name)
    }
}

fn github_basic_auth_header(token: &str) -> String {
    format!(
        "Authorization: Basic {}",
        github_basic_auth_credential(token)
    )
}

fn github_basic_auth_credential(token: &str) -> String {
    BASE64.encode(format!("x-access-token:{token}"))
}

fn safe_relative_path(file_path: &str) -> Result<PathBuf> {
    let path = Path::new(file_path);
    if path.is_absolute() {
        bail!("Finding file path must be relative to the repository root");
    }
    let mut safe = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => safe.push(segment),
            Component::CurDir => {}
            _ => bail!("Finding file path contains unsafe path components"),
        }
    }
    if safe.as_os_str().is_empty() {
        bail!("Finding file path is empty");
    }
    Ok(safe)
}

fn clean_diff(diff: &str) -> String {
    strip_fenced_code(diff)
}

fn strip_fenced_code(content: &str) -> String {
    let trimmed = content.trim();
    if !trimmed.starts_with("```") {
        return trimmed.to_string();
    }
    let lines = trimmed.lines().collect::<Vec<_>>();
    if lines.len() >= 2 && lines.last().is_some_and(|line| line.trim() == "```") {
        return lines[1..lines.len() - 1].join("\n").trim().to_string();
    }
    trimmed
        .trim_start_matches("```json")
        .trim_start_matches("```diff")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim()
        .to_string()
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

fn truncate_branch(value: &str, max_chars: usize) -> String {
    let trimmed = truncate_chars(value, max_chars);
    trimmed.trim_end_matches(['-', '/', '.']).to_string()
}

fn slugify(value: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = false;
    for ch in value.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            last_dash = false;
        } else if !last_dash && !slug.is_empty() {
            slug.push('-');
            last_dash = true;
        }
        if slug.len() >= 56 {
            break;
        }
    }
    slug.trim_matches('-').to_string()
}

fn append_log(log: &mut String, title: &str, detail: &str) {
    if !log.is_empty() {
        log.push_str("\n\n");
    }
    log.push_str(title);
    log.push('\n');
    log.push_str(detail.trim());
}

fn redact_secret(value: &str, secret: Option<&str>) -> String {
    let mut value = value.to_string();
    if let Some(secret) = secret.filter(|secret| !secret.is_empty()) {
        value = value.replace(secret, "[redacted]");
        value = value.replace(&github_basic_auth_credential(secret), "[redacted]");
    }
    value
}

trait CombinedIfEmpty {
    fn combined_if_empty(&self, fallback: &str) -> String;
}

impl CombinedIfEmpty for CommandResult {
    fn combined_if_empty(&self, fallback: &str) -> String {
        let combined = self.combined();
        if combined.trim().is_empty() {
            fallback.to_string()
        } else {
            combined
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_inside_fence() {
        let parsed = extract_agent_fix_response(
            "```json\n{\"summary\":\"Fixes hashing\",\"unified_diff\":\"diff --git a/a b/a\\n--- a/a\\n+++ b/a\",\"validation_notes\":\"ok\"}\n```",
        )
        .expect("response should parse");

        assert_eq!(parsed.summary, "Fixes hashing");
        assert!(parsed.unified_diff.contains("diff --git"));
    }

    #[test]
    fn parses_json_from_noisy_response() {
        let parsed = extract_agent_fix_response(
            "Here is the patch: {\"summary\":\"Tighten auth\",\"unified_diff\":\"```diff\\ndiff --git a/a b/a\\n--- a/a\\n+++ b/a\\n```\"}",
        )
        .expect("response should parse");

        assert_eq!(
            clean_diff(&parsed.unified_diff),
            "diff --git a/a b/a\n--- a/a\n+++ b/a"
        );
    }

    #[test]
    fn builds_stable_branch_name() {
        let finding = Finding {
            id: Uuid::parse_str("12345678-1234-1234-1234-123456789012").unwrap(),
            scan_id: Uuid::nil(),
            repo_id: Uuid::nil(),
            source: "ai".to_string(),
            status: "open".to_string(),
            severity: "high".to_string(),
            confidence: "high".to_string(),
            title: "SQL Injection: unsafe query construction!".to_string(),
            description: None,
            cwe_id: None,
            cve_id: None,
            file_path: "src/main.rs".to_string(),
            line_start: 1,
            line_end: None,
            code_snippet: None,
            suggested_patch: None,
            fix_type: None,
            fix_summary: None,
            references_json: None,
            manifest_coordinates_json: None,
            poc_exploit_json: None,
            poc_validated: false,
            fingerprint: "fp".to_string(),
            agent_reasoning: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        assert_eq!(
            branch_name_for_finding(&finding),
            "heimdall/fix/12345678-sql-injection-unsafe-query-construction"
        );
    }

    #[test]
    fn builds_github_basic_auth_header_for_git_https() {
        assert_eq!(
            github_basic_auth_header("token"),
            "Authorization: Basic eC1hY2Nlc3MtdG9rZW46dG9rZW4="
        );
    }

    #[test]
    fn redacts_github_basic_auth_credential() {
        let output = "remote: Authorization: Basic eC1hY2Nlc3MtdG9rZW46dG9rZW4= failed for GitHub";

        assert_eq!(
            redact_secret(output, Some("token")),
            "remote: Authorization: Basic [redacted] failed for GitHub"
        );
    }
}
