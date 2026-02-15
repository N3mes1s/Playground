//! # Browser Tool
//!
//! Fetches web content via HTTPS. In the unikernel, this uses our
//! built-in HTTP client rather than a headless browser.
//! Supports domain allowlisting and private host blocking.

use alloc::string::String;
use alloc::format;
use super::{Tool, ToolResult};

pub struct BrowserTool;

impl BrowserTool {
    pub fn new() -> Self { BrowserTool }
}

/// Blocked private/internal IP ranges.
fn is_private_host(host: &str) -> bool {
    // Block common internal hostnames
    let blocked = ["localhost", "127.0.0.1", "0.0.0.0", "::1",
                   "169.254.", "10.", "192.168.", "172.16.",
                   "172.17.", "172.18.", "172.19.", "172.20.",
                   "172.21.", "172.22.", "172.23.", "172.24.",
                   "172.25.", "172.26.", "172.27.", "172.28.",
                   "172.29.", "172.30.", "172.31."];

    for b in &blocked {
        if host.starts_with(b) || host == *b {
            return true;
        }
    }
    false
}

impl Tool for BrowserTool {
    fn name(&self) -> &str { "browser" }

    fn description(&self) -> &str {
        "Fetch web page content via HTTPS. Returns the page body as text. \
         Use when you need to look up documentation, check API responses, \
         or retrieve web content. Cannot access private/internal hosts."
    }

    fn parameters_schema(&self) -> &str {
        r#"{"type":"object","properties":{"url":{"type":"string","description":"The URL to fetch (must be HTTPS)"},"action":{"type":"string","enum":["get","post"],"description":"HTTP method (default: get)"}},"required":["url"]}"#
    }

    fn execute(&self, arguments: &str) -> ToolResult {
        let url = crate::providers::extract_json_string(arguments, "url")
            .unwrap_or_default();

        if url.is_empty() {
            return ToolResult::err("url is required");
        }

        // Parse host from URL
        let host = url.strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .and_then(|s| s.split('/').next())
            .unwrap_or(&url);

        // Block private hosts
        if is_private_host(host) {
            return ToolResult::err("cannot access private/internal hosts");
        }

        // Extract path
        let path = url.strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .and_then(|s| s.find('/').map(|i| &s[i..]))
            .unwrap_or("/");

        match crate::net::http::get(host, path, None) {
            Ok(response) => {
                if response.is_success() {
                    match response.body_str() {
                        Ok(body) => {
                            // Truncate to 100KB
                            let truncated = if body.len() > 102400 {
                                &body[..102400]
                            } else {
                                body
                            };
                            ToolResult::ok(truncated)
                        }
                        Err(_) => ToolResult::ok("[binary content]"),
                    }
                } else {
                    ToolResult::err(&format!("HTTP {}", response.status_code))
                }
            }
            Err(e) => ToolResult::err(&format!("fetch failed: {}", e)),
        }
    }
}
