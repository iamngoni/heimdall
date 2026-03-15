//
//  heimdall
//  src/pipeline/ingest/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use log::{debug, info};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use walkdir::WalkDir;

use crate::crypto;
use crate::db::DatabaseOperations;
use crate::index::{CodeIndex, IndexedFile};
use crate::models::HeimdallResult;
use crate::models::db_models::Repo;
use crate::sse::ScanBroadcaster;
use crate::util::sat_i32_usize;

/// Handles repository ingestion: clone/download, file enumeration, language detection,
/// symbol extraction, and building the in-memory CodeIndex.
pub struct IngestStage {
    pub scan_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
    pub sse: Arc<ScanBroadcaster>,
    pub encryption_key: Option<[u8; 32]>,
    pub data_dir: String,
}

/// Output of the ingest stage.
pub struct IngestOutput {
    pub code_index: CodeIndex,
    pub commit_sha: Option<String>,
    pub work_dir: PathBuf,
}

/// Files/directories to skip during ingestion.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    "vendor",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".cargo",
];

const MAX_FILE_SIZE: u64 = 1_048_576; // 1 MB — skip very large files

impl IngestStage {
    pub fn new(
        scan_id: uuid::Uuid,
        db: Arc<DatabaseOperations>,
        sse: Arc<ScanBroadcaster>,
        encryption_key: Option<[u8; 32]>,
        data_dir: String,
    ) -> Self {
        Self {
            scan_id,
            db,
            sse,
            encryption_key,
            data_dir,
        }
    }

    /// Run the ingest stage for a given repo.
    pub async fn run(&self, repo: &Repo) -> HeimdallResult<IngestOutput> {
        info!("[{}] Starting ingest for repo {}", self.scan_id, repo.name);
        self.record_event(
            Some("source-acquisition"),
            "running",
            "Fetching repository source",
            Some("Preparing a clean working directory and acquiring the repository contents."),
            None,
            None,
        )
        .await;

        // Step 1: Acquire the source code
        let work_dir = self.acquire_source(repo).await?;
        self.record_event(
            Some("source-acquisition"),
            "completed",
            "Repository source ready",
            Some("Working copy is ready for commit detection and indexing."),
            Some(20),
            Some(&serde_json::json!({
                "source_type": repo.source_type,
                "work_dir": work_dir,
            })),
        )
        .await;

        // Step 2: Detect commit SHA
        self.record_event(
            Some("commit-detection"),
            "running",
            "Detecting repository commit",
            Some("Resolving the current commit SHA from the working copy."),
            None,
            None,
        )
        .await;
        let commit_sha = detect_commit_sha(&work_dir);
        if let Some(ref sha) = commit_sha {
            info!("[{}] Detected commit SHA: {}", self.scan_id, sha);
            self.db.update_scan_commit_sha(self.scan_id, sha).await?;
        }
        self.record_event(
            Some("commit-detection"),
            "completed",
            "Commit resolved",
            Some(
                commit_sha
                    .as_deref()
                    .unwrap_or("Commit SHA could not be resolved from the working copy."),
            ),
            Some(35),
            Some(&serde_json::json!({
                "commit_sha": commit_sha,
            })),
        )
        .await;

        // Step 3: Walk files and build code index
        self.record_event(
            Some("index-build"),
            "running",
            "Indexing repository contents",
            Some("Enumerating files, extracting symbols, and building the code index."),
            None,
            None,
        )
        .await;
        let code_index = self.build_index(&work_dir, repo).await?;
        self.record_event(
            Some("index-build"),
            "completed",
            "Repository index built",
            Some(&format!(
                "{} files indexed and {} symbols extracted.",
                code_index.files.len(),
                code_index.symbols.all_count()
            )),
            Some(100),
            Some(&serde_json::json!({
                "files_indexed": code_index.files.len(),
                "symbols": code_index.symbols.all_count(),
            })),
        )
        .await;

        info!(
            "[{}] Ingest complete: {} files indexed, {} symbols",
            self.scan_id,
            code_index.files.len(),
            code_index.symbols.all_count(),
        );

        Ok(IngestOutput {
            code_index,
            commit_sha,
            work_dir,
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
                Some("ingest"),
                task_key,
                "task",
                Some(status),
                title,
                detail,
                progress_pct,
                metadata_json,
            )
            .await;
        self.sse
            .emit_stage_update(self.scan_id, "ingest", "running", None);
    }

    /// Clone or locate the repo source.
    async fn acquire_source(&self, repo: &Repo) -> HeimdallResult<PathBuf> {
        let work_base = PathBuf::from(&self.data_dir).join("scans");
        std::fs::create_dir_all(&work_base)?;
        let work_dir = work_base.join(self.scan_id.to_string());

        match repo.source_type.as_str() {
            "github" | "gitlab" | "bitbucket" | "git_url" => {
                if work_dir.exists() {
                    info!(
                        "[{}] Removing stale scan work directory {:?} before clone",
                        self.scan_id, work_dir
                    );
                    std::fs::remove_dir_all(&work_dir)?;
                }

                let url = repo
                    .remote_url
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("Repo has no remote URL"))?;

                let clone_url = self.resolve_clone_url(repo, url).await?;

                info!(
                    "[{}] Cloning {} into {:?}",
                    self.scan_id,
                    repo.remote_url.as_deref().unwrap_or(url),
                    work_dir
                );

                let mut cmd = tokio::process::Command::new("git");
                cmd.args(["clone", "--depth", "1", "--progress"]);
                if let Some(ref branch) = repo.default_branch {
                    cmd.args(["--branch", branch]);
                }
                cmd.arg(&clone_url)
                    .arg(&work_dir)
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped());

                self.stream_clone_progress(cmd).await?;
            }
            "zip" => {
                // remote_url holds the path to the uploaded .zip file
                let zip_path = repo
                    .remote_url
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("Zip repo has no file path stored"))?;

                let zip_file = std::path::Path::new(zip_path);
                if !zip_file.exists() {
                    anyhow::bail!("Uploaded zip file not found at {:?}", zip_path);
                }

                if work_dir.exists() {
                    std::fs::remove_dir_all(&work_dir)?;
                }
                std::fs::create_dir_all(&work_dir)?;

                info!(
                    "[{}] Extracting zip {:?} into {:?}",
                    self.scan_id, zip_path, work_dir
                );

                // Extract zip into work_dir
                let file = std::fs::File::open(zip_file)?;
                let mut archive = zip::ZipArchive::new(file)
                    .map_err(|e| anyhow::anyhow!("Failed to open zip archive: {e}"))?;

                for i in 0..archive.len() {
                    let mut entry = archive
                        .by_index(i)
                        .map_err(|e| anyhow::anyhow!("Failed to read zip entry: {e}"))?;

                    let entry_path = match entry.enclosed_name() {
                        Some(p) => p.to_owned(),
                        None => continue, // skip unsafe paths
                    };

                    let dest = work_dir.join(&entry_path);

                    if entry.is_dir() {
                        std::fs::create_dir_all(&dest)?;
                    } else {
                        if let Some(parent) = dest.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        let mut out = std::fs::File::create(&dest)?;
                        std::io::copy(&mut entry, &mut out)?;
                    }
                }

                // If the zip contained a single top-level directory, move its
                // contents up so the work_dir is the repo root.
                let entries: Vec<_> = std::fs::read_dir(&work_dir)?
                    .filter_map(|e| e.ok())
                    .collect();
                if entries.len() == 1 && entries[0].file_type().map(|t| t.is_dir()).unwrap_or(false)
                {
                    let inner = entries[0].path();
                    let tmp_name = work_dir.with_file_name(format!("{}-inner", self.scan_id));
                    std::fs::rename(&inner, &tmp_name)?;
                    std::fs::remove_dir_all(&work_dir)?;
                    std::fs::rename(&tmp_name, &work_dir)?;
                }

                info!(
                    "[{}] Zip extracted ({} entries)",
                    self.scan_id,
                    archive.len()
                );
            }
            other => {
                anyhow::bail!("Unknown source type: {other}");
            }
        }

        Ok(work_dir)
    }

    async fn stream_clone_progress(&self, mut cmd: tokio::process::Command) -> HeimdallResult<()> {
        let mut child = cmd.spawn()?;
        let mut stderr = child.stderr.take().ok_or_else(|| {
            anyhow::anyhow!("git clone did not expose stderr for progress capture")
        })?;

        let mut buffer = [0u8; 4096];
        let mut pending = String::new();
        let mut last_progress: Option<CloneProgressUpdate> = None;

        loop {
            let bytes_read = stderr.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }

            pending.push_str(&String::from_utf8_lossy(&buffer[..bytes_read]));

            while let Some(idx) = pending.find(['\r', '\n']) {
                let segment = pending[..idx].trim().to_string();
                pending.drain(..=idx);
                self.handle_clone_progress_segment(&segment, &mut last_progress)
                    .await;
            }
        }

        if !pending.trim().is_empty() {
            self.handle_clone_progress_segment(pending.trim(), &mut last_progress)
                .await;
        }

        let status = child.wait().await?;
        if !status.success() {
            let stderr_summary = last_progress
                .as_ref()
                .map(|update| update.detail.clone())
                .filter(|detail| !detail.is_empty())
                .unwrap_or_else(|| {
                    "git clone failed without additional progress output.".to_string()
                });
            anyhow::bail!("git clone failed: {stderr_summary}");
        }

        Ok(())
    }

    async fn handle_clone_progress_segment(
        &self,
        segment: &str,
        last_progress: &mut Option<CloneProgressUpdate>,
    ) {
        let Some(update) = parse_clone_progress(segment) else {
            return;
        };

        let should_emit = match last_progress {
            Some(previous) => previous.phase != update.phase || previous.bucket != update.bucket,
            None => true,
        };

        if !should_emit {
            return;
        }

        *last_progress = Some(update.clone());
        self.record_event(
            Some("source-acquisition"),
            "running",
            update.title.as_str(),
            Some(update.detail.as_str()),
            Some(update.progress_pct),
            Some(&serde_json::json!({
                "phase": update.phase,
                "progress_bucket": update.bucket,
                "raw": update.raw,
            })),
        )
        .await;
    }

    async fn resolve_clone_url(&self, repo: &Repo, remote_url: &str) -> HeimdallResult<String> {
        match repo.source_type.as_str() {
            "github" | "gitlab" | "bitbucket" => {
                let Some(connection_id) = repo.oauth_connection_id else {
                    return Ok(remote_url.to_string());
                };

                let connection = self
                    .db
                    .get_oauth_connection_by_id(connection_id)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("OAuth connection not found for repository"))?;

                let token = connection.access_token_enc.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("OAuth connection is missing an access token")
                })?;
                let token = crypto::decode_stored_secret(token, self.encryption_key.as_ref())?;

                Ok(embed_token_in_clone_url(
                    &repo.source_type,
                    remote_url,
                    &token,
                    &connection.token_source,
                    &connection.provider_user_id,
                ))
            }
            _ => Ok(remote_url.to_string()),
        }
    }

    /// Walk all files in the working directory and build the CodeIndex.
    async fn build_index(&self, work_dir: &Path, repo: &Repo) -> HeimdallResult<CodeIndex> {
        let mut index = CodeIndex::new(work_dir.to_path_buf());
        let mut file_count = 0u32;

        for entry in WalkDir::new(work_dir)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !should_skip(e))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            let metadata = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.len() > MAX_FILE_SIZE {
                debug!("Skipping large file: {:?} ({} bytes)", path, metadata.len());
                continue;
            }

            let relative = path
                .strip_prefix(work_dir)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue, // skip binary files
            };

            let language = CodeIndex::detect_language(path);
            let content_hash = sha256_hex(&content);
            let line_count = content.lines().count();
            let byte_size = content.len();

            // Record file snapshot in DB
            let _ = self
                .db
                .create_file_snapshot(
                    repo.id,
                    self.scan_id,
                    &relative,
                    &content_hash,
                    &content,
                    language.as_deref(),
                    sat_i32_usize(line_count),
                    sat_i32_usize(byte_size),
                )
                .await;

            let indexed = IndexedFile {
                path: path.to_path_buf(),
                relative_path: relative,
                content,
                language,
                line_count,
                byte_size,
                content_hash,
            };

            index.add_file(indexed);
            file_count += 1;
        }

        info!("[{}] Indexed {file_count} files", self.scan_id);
        Ok(index)
    }
}

#[derive(Clone)]
struct CloneProgressUpdate {
    phase: &'static str,
    title: String,
    detail: String,
    progress_pct: i32,
    bucket: i32,
    raw: String,
}

fn parse_clone_progress(segment: &str) -> Option<CloneProgressUpdate> {
    let normalized = segment.trim().trim_start_matches("remote: ").trim();
    if normalized.is_empty() {
        return None;
    }

    let phase = if normalized.starts_with("Cloning into") {
        "connect"
    } else if normalized.starts_with("Enumerating objects") {
        "enumerating"
    } else if normalized.starts_with("Counting objects") {
        "counting"
    } else if normalized.starts_with("Compressing objects") {
        "compressing"
    } else if normalized.starts_with("Receiving objects") {
        "receiving"
    } else if normalized.starts_with("Resolving deltas") {
        "resolving"
    } else if normalized.starts_with("Updating files")
        || normalized.starts_with("Checking out files")
    {
        "checkout"
    } else {
        return None;
    };

    let percentage = extract_percentage(normalized);
    let progress_pct = match phase {
        "connect" => 3,
        "enumerating" => 6,
        "counting" => interpolate_progress(8, 12, percentage.unwrap_or(100)),
        "compressing" => interpolate_progress(12, 16, percentage.unwrap_or(100)),
        "receiving" => interpolate_progress(16, 62, percentage.unwrap_or(100)),
        "resolving" => interpolate_progress(62, 86, percentage.unwrap_or(100)),
        "checkout" => interpolate_progress(86, 99, percentage.unwrap_or(100)),
        _ => 5,
    };
    let bucket = (percentage.unwrap_or(progress_pct).max(0) / 5) * 5;

    Some(CloneProgressUpdate {
        phase,
        title: clone_progress_title(phase, normalized),
        detail: normalized.to_string(),
        progress_pct,
        bucket,
        raw: segment.to_string(),
    })
}

fn clone_progress_title(phase: &str, normalized: &str) -> String {
    match phase {
        "connect" => "Connecting to remote".to_string(),
        "enumerating" => "Enumerating repository objects".to_string(),
        "counting" => "Counting objects".to_string(),
        "compressing" => "Compressing objects".to_string(),
        "receiving" => "Receiving objects".to_string(),
        "resolving" => "Resolving deltas".to_string(),
        "checkout" => {
            if normalized.starts_with("Checking out files") {
                "Checking out files".to_string()
            } else {
                "Updating working tree".to_string()
            }
        }
        _ => "Cloning repository".to_string(),
    }
}

fn extract_percentage(line: &str) -> Option<i32> {
    let percent_index = line.find('%')?;
    let digits: String = line[..percent_index]
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_whitespace() || ch.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .filter(|ch| ch.is_ascii_digit())
        .collect();
    digits.parse::<i32>().ok()
}

fn interpolate_progress(start: i32, end: i32, percentage: i32) -> i32 {
    let clamped = percentage.clamp(0, 100);
    start + (((end - start) as f32) * (clamped as f32 / 100.0)).round() as i32
}

fn embed_token_in_clone_url(
    provider: &str,
    url: &str,
    token: &str,
    token_source: &str,
    provider_user_id: &str,
) -> String {
    let Some(rest) = url.strip_prefix("https://") else {
        return url.to_string();
    };

    // Strip any existing username@ from the URL (Bitbucket clone URLs include it)
    // and capture the embedded username for Bitbucket App Password auth.
    let (embedded_user, rest) = match rest.find('@') {
        Some(at) if rest[..at].find('/').is_none() => (Some(&rest[..at]), &rest[at + 1..]),
        _ => (None, rest),
    };

    let username: std::borrow::Cow<'_, str> = match provider {
        "github" => "x-access-token".into(),
        "gitlab" => "oauth2".into(),
        // Bitbucket App Passwords use the Bitbucket username (not email) for Basic auth.
        // The clone URL from the API already contains it (e.g. https://username@bitbucket.org/...).
        "bitbucket" if token_source == "pat" => embedded_user.unwrap_or(provider_user_id).into(),
        "bitbucket" => "x-token-auth".into(),
        _ => return url.to_string(),
    };

    format!("https://{username}:{token}@{rest}")
}

fn should_skip(entry: &walkdir::DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();
    if entry.file_type().is_dir() {
        return SKIP_DIRS.contains(&name.as_ref());
    }
    // Skip hidden files and lock files
    if name.starts_with('.') {
        return true;
    }
    false
}

fn detect_commit_sha(work_dir: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(work_dir)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::{extract_percentage, parse_clone_progress};

    #[test]
    fn parses_receiving_objects_progress() {
        let update =
            parse_clone_progress("Receiving objects:  42% (420/1000), 1.23 MiB | 2.10 MiB/s")
                .expect("expected clone progress update");

        assert_eq!(update.phase, "receiving");
        assert_eq!(update.title, "Receiving objects");
        assert_eq!(update.bucket, 40);
        assert!(update.progress_pct >= 16);
    }

    #[test]
    fn parses_checkout_phase_progress() {
        let update =
            parse_clone_progress("Updating files:  80% (800/1000)").expect("expected update");

        assert_eq!(update.phase, "checkout");
        assert_eq!(update.title, "Updating working tree");
        assert_eq!(extract_percentage(&update.detail), Some(80));
    }

    #[test]
    fn ignores_irrelevant_clone_output() {
        assert!(parse_clone_progress("done.").is_none());
        assert!(parse_clone_progress("").is_none());
    }
}
