//! Minimal GitHub REST API client. We only implement the endpoints the
//! one-shot `Action` flow needs: fetch the default branch SHA, create a
//! branch, commit a patch file by file, and open a pull request. Uses
//! `reqwest + rustls` - no `octocrab` to keep deps slim.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const API_ROOT: &str = "https://api.github.com";

#[derive(Debug, Clone)]
pub struct GitHubClient {
    pub http: Client,
    pub token: String,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchRef {
    pub sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    pub number: u64,
    pub html_url: String,
    pub head: BranchHead,
    pub base: BranchHead,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchHead {
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub sha: String,
}

#[derive(Debug, Deserialize)]
struct RefObject {
    object: RefObjectSha,
}

#[derive(Debug, Deserialize)]
struct RefObjectSha {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct RepoInfo {
    default_branch: String,
}

impl GitHubClient {
    pub fn new(token: impl Into<String>) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("build github http client")?;
        Ok(Self {
            http,
            token: token.into(),
            user_agent: "ods/0.1 (optimization-discovery-system)".into(),
        })
    }

    pub async fn default_branch(&self, owner: &str, repo: &str) -> Result<String> {
        let url = format!("{API_ROOT}/repos/{owner}/{repo}");
        let resp = self.get(&url).await?.error_for_status()?;
        let info: RepoInfo = resp.json().await?;
        Ok(info.default_branch)
    }

    pub async fn branch_sha(&self, owner: &str, repo: &str, branch: &str) -> Result<String> {
        let url = format!("{API_ROOT}/repos/{owner}/{repo}/git/ref/heads/{branch}");
        let resp = self.get(&url).await?.error_for_status()?;
        let r: RefObject = resp.json().await?;
        Ok(r.object.sha)
    }

    pub async fn create_branch(
        &self,
        owner: &str,
        repo: &str,
        new_branch: &str,
        from_sha: &str,
    ) -> Result<()> {
        let url = format!("{API_ROOT}/repos/{owner}/{repo}/git/refs");
        self.post_json(
            &url,
            &serde_json::json!({
                "ref": format!("refs/heads/{new_branch}"),
                "sha": from_sha,
            }),
        )
        .await?;
        Ok(())
    }

    /// Create or update a file on `branch`. Fetches the current file SHA when
    /// updating an existing file (GitHub's Contents API requires it).
    pub async fn put_file(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        path: &str,
        contents_b64: &str,
        commit_message: &str,
    ) -> Result<()> {
        let get_url =
            format!("{API_ROOT}/repos/{owner}/{repo}/contents/{path}?ref={branch}");
        let existing_sha = match self.http
            .get(&get_url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("User-Agent", &self.user_agent)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                let v: serde_json::Value = r.json().await.unwrap_or_default();
                v.get("sha").and_then(|s| s.as_str()).map(|s| s.to_string())
            }
            _ => None,
        };

        let put_url = format!("{API_ROOT}/repos/{owner}/{repo}/contents/{path}");
        let mut body = serde_json::json!({
            "message": commit_message,
            "content": contents_b64,
            "branch": branch,
        });
        if let Some(sha) = existing_sha {
            body["sha"] = serde_json::Value::String(sha);
        }
        self.http
            .put(&put_url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("User-Agent", &self.user_agent)
            .header("Accept", "application/vnd.github+json")
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn open_pr(
        &self,
        owner: &str,
        repo: &str,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
        draft: bool,
    ) -> Result<PullRequest> {
        let url = format!("{API_ROOT}/repos/{owner}/{repo}/pulls");
        let resp = self
            .post_json(
                &url,
                &serde_json::json!({
                    "title": title,
                    "head": head,
                    "base": base,
                    "body": body,
                    "draft": draft,
                }),
            )
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    async fn get(&self, url: &str) -> Result<reqwest::Response> {
        Ok(self
            .http
            .get(url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("User-Agent", &self.user_agent)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await?)
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response> {
        Ok(self
            .http
            .post(url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("User-Agent", &self.user_agent)
            .header("Accept", "application/vnd.github+json")
            .json(body)
            .send()
            .await?)
    }
}

/// Very small base64 encoder sufficient for PUT contents bodies. Pulling the
/// base64 crate is avoidable since the encode path is bounded by patch size.
pub fn b64_encode(bytes: &[u8]) -> String {
    const ALPH: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | bytes[i + 2] as u32;
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPH[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_matches_known_values() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }
}
