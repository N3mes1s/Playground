//! # File Operations Tools
//!
//! Read and write files in the unikernel's RAM filesystem.
//! All paths are validated against the security policy.

use alloc::string::String;
use alloc::format;
use super::{Tool, ToolResult};

// ── File Read ──────────────────────────────────────────────────────────────

pub struct FileReadTool;

impl FileReadTool {
    pub fn new() -> Self { FileReadTool }
}

impl Tool for FileReadTool {
    fn name(&self) -> &str { "file_read" }

    fn description(&self) -> &str {
        "Read the contents of a file. Use when you need to examine file contents. \
         The path must be within the workspace."
    }

    fn parameters_schema(&self) -> &str {
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the file to read"}},"required":["path"]}"#
    }

    fn execute(&self, arguments: &str) -> ToolResult {
        let path = crate::providers::extract_json_string(arguments, "path")
            .unwrap_or_default();

        if path.is_empty() {
            return ToolResult::err("no path specified");
        }

        // Security check
        if let Err(e) = crate::security::validate_path(&path) {
            return ToolResult::err(&format!("security: {}", e));
        }

        match crate::config::ramfs_read(&path) {
            Some(content) => ToolResult::ok(&content),
            None => ToolResult::err(&format!("file not found: {}", path)),
        }
    }
}

// ── File Write ─────────────────────────────────────────────────────────────

pub struct FileWriteTool;

impl FileWriteTool {
    pub fn new() -> Self { FileWriteTool }
}

impl Tool for FileWriteTool {
    fn name(&self) -> &str { "file_write" }

    fn description(&self) -> &str {
        "Write content to a file. Creates the file if it doesn't exist, \
         overwrites if it does. The path must be within the workspace."
    }

    fn parameters_schema(&self) -> &str {
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to write to"},"content":{"type":"string","description":"Content to write"}},"required":["path","content"]}"#
    }

    fn execute(&self, arguments: &str) -> ToolResult {
        let path = crate::providers::extract_json_string(arguments, "path")
            .unwrap_or_default();
        let content = crate::providers::extract_json_string(arguments, "content")
            .unwrap_or_default();

        if path.is_empty() {
            return ToolResult::err("no path specified");
        }

        // Security check
        if let Err(e) = crate::security::validate_path(&path) {
            return ToolResult::err(&format!("security: {}", e));
        }

        // Check autonomy level
        let policy = crate::security::policy();
        if policy.autonomy == crate::security::AutonomyLevel::ReadOnly {
            return ToolResult::err("file_write is disabled in read-only mode");
        }

        crate::config::ramfs_write(&path, &content);
        ToolResult::ok(&format!("wrote {} bytes to {}", content.len(), path))
    }
}
