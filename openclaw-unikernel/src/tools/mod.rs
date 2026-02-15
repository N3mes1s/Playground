//! # Tool System
//!
//! Tools are capabilities the agent can invoke during conversations.
//! Each tool implements the `Tool` trait and is registered with the
//! tool registry. The security policy is enforced on every tool call.
//!
//! Built-in tools:
//! - shell: Execute sandboxed commands
//! - file_read: Read files (from ramfs in unikernel)
//! - file_write: Write files (to ramfs)
//! - memory_store: Save to agent memory
//! - memory_recall: Search agent memory
//! - memory_forget: Delete from agent memory
//! - browser: HTTP-based web content fetching

mod shell;
mod file_ops;
mod memory_tools;
mod browser;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use crate::providers::ToolSpec;

/// Result from executing a tool.
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub success: bool,
    pub output: String,
}

impl ToolResult {
    pub fn ok(output: &str) -> Self {
        ToolResult {
            success: true,
            output: String::from(output),
        }
    }

    pub fn err(message: &str) -> Self {
        ToolResult {
            success: false,
            output: String::from(message),
        }
    }
}

/// Tool trait — all tools implement this.
pub trait Tool: Send {
    /// Tool name (used in function calling).
    fn name(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// JSON Schema for the tool's parameters.
    fn parameters_schema(&self) -> &str;

    /// Execute the tool with the given arguments JSON.
    fn execute(&self, arguments: &str) -> ToolResult;

    /// Convert to a ToolSpec for the provider.
    fn to_spec(&self) -> ToolSpec {
        ToolSpec {
            name: String::from(self.name()),
            description: String::from(self.description()),
            parameters_json: String::from(self.parameters_schema()),
        }
    }
}

/// The tool registry — holds all registered tools.
pub struct ToolRegistry {
    tools: Vec<Box<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        ToolRegistry { tools: Vec::new() }
    }

    /// Register a tool.
    pub fn register(&mut self, tool: Box<dyn Tool>) {
        self.tools.push(tool);
    }

    /// Get all tool specs (for the provider).
    pub fn specs(&self) -> Vec<ToolSpec> {
        self.tools.iter().map(|t| t.to_spec()).collect()
    }

    /// Execute a tool by name.
    pub fn execute(&self, name: &str, arguments: &str) -> ToolResult {
        for tool in &self.tools {
            if tool.name() == name {
                return tool.execute(arguments);
            }
        }
        ToolResult::err(&alloc::format!("tool '{}' not found", name))
    }

    /// Get tool count.
    pub fn count(&self) -> usize {
        self.tools.len()
    }
}

/// Create the default tool registry with all built-in tools.
pub fn create_default_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();

    registry.register(Box::new(shell::ShellTool::new()));
    registry.register(Box::new(file_ops::FileReadTool::new()));
    registry.register(Box::new(file_ops::FileWriteTool::new()));
    registry.register(Box::new(memory_tools::MemoryStoreTool::new()));
    registry.register(Box::new(memory_tools::MemoryRecallTool::new()));
    registry.register(Box::new(memory_tools::MemoryForgetTool::new()));
    registry.register(Box::new(browser::BrowserTool::new()));

    registry
}
