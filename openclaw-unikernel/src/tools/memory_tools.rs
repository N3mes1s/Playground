//! # Memory Tools
//!
//! Tools for the agent to interact with its own memory system:
//! - memory_store: Save information for later recall
//! - memory_recall: Search for previously stored information
//! - memory_forget: Remove information from memory

use alloc::string::String;
use alloc::format;
use super::{Tool, ToolResult};
use crate::memory::{MemoryCategory, Memory};

// ── Memory Store ───────────────────────────────────────────────────────────

pub struct MemoryStoreTool;

impl MemoryStoreTool {
    pub fn new() -> Self { MemoryStoreTool }
}

impl Tool for MemoryStoreTool {
    fn name(&self) -> &str { "memory_store" }

    fn description(&self) -> &str {
        "Store information in long-term memory. Use when the user shares important \
         facts, preferences, or context you should remember. Categories: \
         'core' (permanent facts), 'daily' (daily context), 'conversation' (session notes)."
    }

    fn parameters_schema(&self) -> &str {
        r#"{"type":"object","properties":{"key":{"type":"string","description":"A unique key for this memory"},"content":{"type":"string","description":"The information to remember"},"category":{"type":"string","enum":["core","daily","conversation"],"description":"Memory category"}},"required":["key","content"]}"#
    }

    fn execute(&self, arguments: &str) -> ToolResult {
        let key = crate::providers::extract_json_string(arguments, "key")
            .unwrap_or_default();
        let content = crate::providers::extract_json_string(arguments, "content")
            .unwrap_or_default();
        let category_str = crate::providers::extract_json_string(arguments, "category")
            .unwrap_or_else(|| String::from("daily"));

        if key.is_empty() || content.is_empty() {
            return ToolResult::err("key and content are required");
        }

        let category = MemoryCategory::from_str(&category_str);
        let mem = crate::memory::global();
        let mut mem = mem.lock();

        match mem.store(&key, &content, category) {
            Ok(()) => ToolResult::ok(&format!(
                "stored memory '{}' in {} category",
                key, category_str
            )),
            Err(e) => ToolResult::err(&e),
        }
    }
}

// ── Memory Recall ──────────────────────────────────────────────────────────

pub struct MemoryRecallTool;

impl MemoryRecallTool {
    pub fn new() -> Self { MemoryRecallTool }
}

impl Tool for MemoryRecallTool {
    fn name(&self) -> &str { "memory_recall" }

    fn description(&self) -> &str {
        "Search through long-term memory for relevant information. \
         Use when you need to recall previously stored facts, preferences, \
         or context. Returns the most relevant results ranked by score."
    }

    fn parameters_schema(&self) -> &str {
        r#"{"type":"object","properties":{"query":{"type":"string","description":"What to search for"},"limit":{"type":"integer","description":"Max results (default 5)"}},"required":["query"]}"#
    }

    fn execute(&self, arguments: &str) -> ToolResult {
        let query = crate::providers::extract_json_string(arguments, "query")
            .unwrap_or_default();
        let limit = crate::providers::extract_json_number(arguments, "limit")
            .unwrap_or(5) as usize;

        if query.is_empty() {
            return ToolResult::err("query is required");
        }

        let mem = crate::memory::global();
        let mem = mem.lock();
        let results = mem.recall(&query, limit);

        if results.is_empty() {
            return ToolResult::ok("no relevant memories found");
        }

        let mut output = String::new();
        for (i, result) in results.iter().enumerate() {
            output.push_str(&format!(
                "{}. [{}] (score: {:.2}) {}: {}\n",
                i + 1,
                result.entry.category.as_str(),
                result.score,
                result.entry.key,
                result.entry.content
            ));
        }

        ToolResult::ok(&output)
    }
}

// ── Memory Forget ──────────────────────────────────────────────────────────

pub struct MemoryForgetTool;

impl MemoryForgetTool {
    pub fn new() -> Self { MemoryForgetTool }
}

impl Tool for MemoryForgetTool {
    fn name(&self) -> &str { "memory_forget" }

    fn description(&self) -> &str {
        "Remove a specific memory entry by its key. Use when information \
         is outdated, incorrect, or the user asks you to forget something."
    }

    fn parameters_schema(&self) -> &str {
        r#"{"type":"object","properties":{"key":{"type":"string","description":"The key of the memory to forget"}},"required":["key"]}"#
    }

    fn execute(&self, arguments: &str) -> ToolResult {
        let key = crate::providers::extract_json_string(arguments, "key")
            .unwrap_or_default();

        if key.is_empty() {
            return ToolResult::err("key is required");
        }

        let mem = crate::memory::global();
        let mut mem = mem.lock();

        if mem.forget(&key) {
            ToolResult::ok(&format!("forgot memory '{}'", key))
        } else {
            ToolResult::err(&format!("memory '{}' not found", key))
        }
    }
}
