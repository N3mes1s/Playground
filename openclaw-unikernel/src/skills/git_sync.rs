//! # Skills Git Sync
//!
//! Synchronizes skills from remote git repositories via HTTP.
//! In the unikernel environment, we can't use actual `git` so
//! we fetch raw files from GitHub/GitLab APIs.
//!
//! Supports:
//! - open-skills community repo (default)
//! - Custom skill repos via URL
//! - Periodic sync on a configurable interval

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// Default open-skills repository.
const DEFAULT_SKILLS_REPO: &str = "github.com/theonlyhennygod/zeroclaw";
const DEFAULT_SKILLS_PATH: &str = "skills";
const DEFAULT_SKILLS_BRANCH: &str = "main";

/// Configuration for git sync.
#[derive(Debug, Clone)]
pub struct GitSyncConfig {
    pub repo_host: String,
    pub repo_owner: String,
    pub repo_name: String,
    pub branch: String,
    pub skills_path: String,
    pub sync_interval_ticks: u64,
    pub last_sync: u64,
}

impl Default for GitSyncConfig {
    fn default() -> Self {
        GitSyncConfig {
            repo_host: String::from("api.github.com"),
            repo_owner: String::from("theonlyhennygod"),
            repo_name: String::from("zeroclaw"),
            branch: String::from(DEFAULT_SKILLS_BRANCH),
            skills_path: String::from(DEFAULT_SKILLS_PATH),
            sync_interval_ticks: 3_600_000_000_000, // ~30 min at 2GHz
            last_sync: 0,
        }
    }
}

/// Result of a sync operation.
#[derive(Debug)]
pub struct SyncResult {
    pub skills_added: usize,
    pub skills_updated: usize,
    pub errors: Vec<String>,
}

/// Sync skills from the configured repository.
pub fn sync(config: &GitSyncConfig) -> SyncResult {
    crate::kprintln!(
        "[git-sync] syncing skills from {}/{}/{}",
        config.repo_owner, config.repo_name, config.skills_path
    );

    let mut result = SyncResult {
        skills_added: 0,
        skills_updated: 0,
        errors: Vec::new(),
    };

    // Step 1: List files in the skills directory via GitHub API
    let api_path = format!(
        "/repos/{}/{}/contents/{}?ref={}",
        config.repo_owner, config.repo_name,
        config.skills_path, config.branch
    );

    let file_list = match fetch_github_directory(&config.repo_host, &api_path) {
        Ok(files) => files,
        Err(e) => {
            result.errors.push(format!("failed to list skills: {}", e));
            return result;
        }
    };

    // Step 2: Fetch each skill file
    for file_info in &file_list {
        if !file_info.name.ends_with(".md") && !file_info.name.ends_with(".toml") {
            continue;
        }

        match fetch_skill_file(&config.repo_host, &file_info.download_url) {
            Ok(content) => {
                let ramfs_path = format!("/workspace/skills/{}", file_info.name);
                let existed = crate::config::ramfs_read(&ramfs_path).is_some();
                crate::config::ramfs_write(&ramfs_path, &content);

                if existed {
                    result.skills_updated += 1;
                } else {
                    result.skills_added += 1;
                }
            }
            Err(e) => {
                result.errors.push(format!("{}: {}", file_info.name, e));
            }
        }
    }

    crate::kprintln!(
        "[git-sync] sync complete: {} added, {} updated, {} errors",
        result.skills_added, result.skills_updated, result.errors.len()
    );

    result
}

/// Sync from a custom URL (raw directory listing or single file).
pub fn sync_from_url(url: &str) -> SyncResult {
    let mut result = SyncResult {
        skills_added: 0,
        skills_updated: 0,
        errors: Vec::new(),
    };

    let host = match url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .and_then(|s| s.split('/').next())
    {
        Some(h) => h,
        None => {
            result.errors.push(String::from("invalid URL"));
            return result;
        }
    };

    let path = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .and_then(|s| s.find('/').map(|i| &s[i..]))
        .unwrap_or("/");

    match crate::net::http::get(host, path, None) {
        Ok(response) => {
            if response.is_success() {
                if let Ok(body) = response.body_str() {
                    // Determine filename from URL
                    let name = path.rsplit('/').next().unwrap_or("skill.md");
                    let ramfs_path = format!("/workspace/skills/{}", name);
                    let existed = crate::config::ramfs_read(&ramfs_path).is_some();
                    crate::config::ramfs_write(&ramfs_path, body);

                    if existed {
                        result.skills_updated += 1;
                    } else {
                        result.skills_added += 1;
                    }
                }
            } else {
                result.errors.push(format!("HTTP {}", response.status_code));
            }
        }
        Err(e) => {
            result.errors.push(String::from(e));
        }
    }

    result
}

/// Check if it's time to sync (based on TSC tick interval).
pub fn should_sync(config: &GitSyncConfig) -> bool {
    let now = crate::kernel::rdtsc();
    now.saturating_sub(config.last_sync) >= config.sync_interval_ticks
}

// ── GitHub API Helpers ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct FileInfo {
    name: String,
    download_url: String,
}

/// Fetch a directory listing from the GitHub Contents API.
fn fetch_github_directory(host: &str, path: &str) -> Result<Vec<FileInfo>, &'static str> {
    let response = crate::net::http::get(host, path, None)
        .map_err(|_| "HTTP request failed")?;

    if !response.is_success() {
        return Err("GitHub API returned non-200");
    }

    let body = response.body_str().map_err(|_| "invalid response body")?;

    // Parse the JSON array of file objects
    // Each object has "name" and "download_url" fields
    parse_github_contents_response(body)
}

/// Parse GitHub Contents API response JSON.
fn parse_github_contents_response(json: &str) -> Result<Vec<FileInfo>, &'static str> {
    let mut files = Vec::new();
    let json = json.trim();

    if !json.starts_with('[') {
        return Err("expected JSON array");
    }

    // Split the array into individual objects
    let mut depth = 0;
    let mut obj_start = None;

    for (i, ch) in json.char_indices() {
        match ch {
            '{' => {
                if depth == 1 && obj_start.is_none() {
                    obj_start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 1 {
                    if let Some(start) = obj_start {
                        let obj = &json[start..=i];
                        if let Some(info) = parse_file_object(obj) {
                            files.push(info);
                        }
                        obj_start = None;
                    }
                }
            }
            '[' if depth == 0 => depth += 1,
            ']' if depth == 1 => break,
            _ => {}
        }
    }

    Ok(files)
}

fn parse_file_object(json: &str) -> Option<FileInfo> {
    let name = extract_simple_str(json, "name")?;
    let download_url = extract_simple_str(json, "download_url")?;

    Some(FileInfo {
        name: String::from(name),
        download_url: String::from(download_url),
    })
}

fn extract_simple_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let search = format!("\"{}\":\"", key);
    let alt_search = format!("\"{}\" : \"", key);

    let start = json.find(&search)
        .map(|p| p + search.len())
        .or_else(|| json.find(&alt_search).map(|p| p + alt_search.len()))?;

    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Fetch a single skill file from its download URL.
fn fetch_skill_file(host: &str, url: &str) -> Result<String, &'static str> {
    let path = if url.starts_with("https://") || url.starts_with("http://") {
        url.strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .and_then(|s| s.find('/').map(|i| &s[i..]))
            .unwrap_or(url)
    } else {
        url
    };

    // Extract host from the download URL if different from API host
    let file_host = if url.starts_with("https://") || url.starts_with("http://") {
        url.strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .and_then(|s| s.split('/').next())
            .unwrap_or(host)
    } else {
        host
    };

    let response = crate::net::http::get(file_host, path, None)
        .map_err(|_| "HTTP request failed")?;

    if !response.is_success() {
        return Err("download failed");
    }

    response.body_str().map(String::from).map_err(|_| "invalid body")
}
