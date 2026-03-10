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
    ) -> Self {
        Self {
            scan_id,
            db,
            encryption_key,
        }
    }

    /// Run the ingest stage for a given repo.
    pub async fn run(&self, repo: &Repo) -> HeimdallResult<IngestOutput> {
        info!("[{}] Starting ingest for repo {}", self.scan_id, repo.name);

        // Step 1: Acquire the source code
        let work_dir = self.acquire_source(repo).await?;

        // Step 2: Detect commit SHA
        let commit_sha = detect_commit_sha(&work_dir);
        if let Some(ref sha) = commit_sha {
            info!("[{}] Detected commit SHA: {}", self.scan_id, sha);
            self.db.update_scan_commit_sha(self.scan_id, sha).await?;
        }

        // Step 3: Walk files and build code index
        let code_index = self.build_index(&work_dir, repo).await?;

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

    /// Clone or locate the repo source.
    async fn acquire_source(&self, repo: &Repo) -> HeimdallResult<PathBuf> {
        let work_base = std::env::temp_dir().join("heimdall").join("scans");
        std::fs::create_dir_all(&work_base)?;
        let work_dir = work_base.join(self.scan_id.to_string());

        match repo.source_type.as_str() {
            "github" | "gitlab" | "git_url" => {
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
                // For zip uploads, the file would already be extracted to a temp dir
                // For now, we expect work_dir to exist
                if !work_dir.exists() {
                    anyhow::bail!("Zip source directory not found at {:?}", work_dir);
                }
            }
            other => {
                anyhow::bail!("Unknown source type: {other}");
            }
        }

        Ok(work_dir)
    }

    async fn resolve_clone_url(&self, repo: &Repo, remote_url: &str) -> HeimdallResult<String> {
        match repo.source_type.as_str() {
            "github" | "gitlab" => {
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

fn embed_token_in_clone_url(provider: &str, url: &str, token: &str) -> String {
    let Some(rest) = url.strip_prefix("https://") else {
        return url.to_string();
    };

    let username = match provider {
        "github" => "x-access-token",
        "gitlab" => "oauth2",
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
