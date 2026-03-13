//
//  heimdall
//  src/pipeline/ingest/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::path::{Path, PathBuf};
use std::sync::Arc;

use log::{debug, info};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::crypto;
use crate::db::DatabaseOperations;
use crate::index::{CodeIndex, IndexedFile};
use crate::models::HeimdallResult;
use crate::models::db_models::Repo;

/// Handles repository ingestion: clone/download, file enumeration, language detection,
/// symbol extraction, and building the in-memory CodeIndex.
pub struct IngestStage {
    pub scan_id: uuid::Uuid,
    pub db: Arc<DatabaseOperations>,
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
        encryption_key: Option<[u8; 32]>,
        data_dir: String,
    ) -> Self {
        Self {
            scan_id,
            db,
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
    }

    /// Clone or locate the repo source.
    async fn acquire_source(&self, repo: &Repo) -> HeimdallResult<PathBuf> {
        let work_base = PathBuf::from(&self.data_dir).join("scans");
        std::fs::create_dir_all(&work_base)?;
        let work_dir = work_base.join(self.scan_id.to_string());

        match repo.source_type.as_str() {
            "github" | "gitlab" | "git_url" => {
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

                let output = tokio::process::Command::new("git")
                    .args(["clone", "--depth", "1", &clone_url])
                    .arg(&work_dir)
                    .output()
                    .await?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!("git clone failed: {stderr}");
                }
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
                    let tmp_name = work_dir.with_file_name(format!(
                        "{}-inner",
                        self.scan_id
                    ));
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
                    line_count as i32,
                    byte_size as i32,
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

    let username = match provider {
        "github" => "x-access-token",
        "gitlab" => "oauth2",
        // Bitbucket App Passwords use the actual username, not x-token-auth.
        "bitbucket" if token_source == "pat" => provider_user_id,
        "bitbucket" => "x-token-auth",
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
