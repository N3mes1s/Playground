//! # Shell Tool
//!
//! Executes commands in a sandboxed environment.
//! In the unikernel, "shell commands" are limited to built-in utilities
//! since there's no actual shell. The security policy is enforced.

use alloc::string::String;
use alloc::format;
use super::{Tool, ToolResult};

pub struct ShellTool;

impl ShellTool {
    pub fn new() -> Self {
        ShellTool
    }

    /// Execute a built-in command (no real shell in the unikernel).
    fn execute_builtin(&self, command: &str) -> ToolResult {
        let parts: alloc::vec::Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return ToolResult::err("empty command");
        }

        match parts[0] {
            "echo" => {
                let output = parts[1..].join(" ");
                ToolResult::ok(&output)
            }
            "pwd" => {
                ToolResult::ok("/workspace")
            }
            "ls" => {
                // List ramfs entries
                let output = crate::config::ramfs_list(parts.get(1).copied().unwrap_or("/"));
                ToolResult::ok(&output)
            }
            "cat" => {
                if let Some(path) = parts.get(1) {
                    match crate::config::ramfs_read(path) {
                        Some(content) => ToolResult::ok(&content),
                        None => ToolResult::err(&format!("file not found: {}", path)),
                    }
                } else {
                    ToolResult::err("usage: cat <file>")
                }
            }
            "wc" => {
                if let Some(path) = parts.get(1) {
                    match crate::config::ramfs_read(path) {
                        Some(content) => {
                            let lines = content.lines().count();
                            let words = content.split_whitespace().count();
                            let bytes = content.len();
                            ToolResult::ok(&format!("{} {} {} {}", lines, words, bytes, path))
                        }
                        None => ToolResult::err(&format!("file not found: {}", path)),
                    }
                } else {
                    ToolResult::err("usage: wc <file>")
                }
            }
            "head" => {
                if let Some(path) = parts.last() {
                    let n = if parts.len() > 2 && parts[1] == "-n" {
                        parts[2].parse().unwrap_or(10)
                    } else {
                        10
                    };
                    match crate::config::ramfs_read(path) {
                        Some(content) => {
                            let output: String = content.lines()
                                .take(n)
                                .collect::<alloc::vec::Vec<_>>()
                                .join("\n");
                            ToolResult::ok(&output)
                        }
                        None => ToolResult::err(&format!("file not found: {}", path)),
                    }
                } else {
                    ToolResult::err("usage: head [-n N] <file>")
                }
            }
            "tail" => {
                if let Some(path) = parts.last() {
                    let n: usize = if parts.len() > 2 && parts[1] == "-n" {
                        parts[2].parse().unwrap_or(10)
                    } else {
                        10
                    };
                    match crate::config::ramfs_read(path) {
                        Some(content) => {
                            let lines: alloc::vec::Vec<&str> = content.lines().collect();
                            let start = lines.len().saturating_sub(n);
                            let output = lines[start..].join("\n");
                            ToolResult::ok(&output)
                        }
                        None => ToolResult::err(&format!("file not found: {}", path)),
                    }
                } else {
                    ToolResult::err("usage: tail [-n N] <file>")
                }
            }
            "grep" => {
                if parts.len() < 3 {
                    return ToolResult::err("usage: grep <pattern> <file>");
                }
                let pattern = parts[1];
                let path = parts[2];
                match crate::config::ramfs_read(path) {
                    Some(content) => {
                        let matches: String = content.lines()
                            .filter(|line| line.contains(pattern))
                            .collect::<alloc::vec::Vec<_>>()
                            .join("\n");
                        ToolResult::ok(&matches)
                    }
                    None => ToolResult::err(&format!("file not found: {}", path)),
                }
            }
            _ => ToolResult::err(&format!(
                "command '{}' not available in unikernel mode",
                parts[0]
            )),
        }
    }
}

impl Tool for ShellTool {
    fn name(&self) -> &str { "shell" }

    fn description(&self) -> &str {
        "Execute a shell command within the unikernel sandbox. \
         Available commands: echo, pwd, ls, cat, wc, head, tail, grep. \
         Use when you need to inspect files, search content, or run utilities."
    }

    fn parameters_schema(&self) -> &str {
        r#"{"type":"object","properties":{"command":{"type":"string","description":"The command to execute"}},"required":["command"]}"#
    }

    fn execute(&self, arguments: &str) -> ToolResult {
        // Extract "command" from JSON arguments
        let command = crate::providers::extract_json_string(arguments, "command")
            .unwrap_or_default();

        if command.is_empty() {
            return ToolResult::err("no command specified");
        }

        // Validate against security policy
        if let Err(e) = crate::security::validate_command(&command) {
            return ToolResult::err(&format!("security policy violation: {}", e));
        }

        self.execute_builtin(&command)
    }
}
