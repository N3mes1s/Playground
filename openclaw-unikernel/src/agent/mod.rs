//! # Agent Loop
//!
//! The core agent runtime — manages conversation flow between
//! channels, providers, and tools. This is the heart of OpenClaw.
//!
//! Flow:
//! 1. Receive message from a channel
//! 2. Build context (system prompt + memory + conversation history)
//! 3. Send to LLM provider
//! 4. If tool calls: execute tools, loop back to step 3
//! 5. Send response back to channel
//! 6. Store conversation in memory

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use crate::providers::{self, Message, Role};
use crate::channels::ChannelMessage;
use crate::tools::ToolRegistry;
use crate::memory::{self, MemoryCategory, Memory};

/// Maximum number of tool-call rounds before stopping.
const MAX_TOOL_ROUNDS: usize = 3;

/// Maximum memory context entries per turn.
const MAX_MEMORY_CONTEXT: usize = 3;

/// The agent state.
pub struct Agent {
    /// The LLM provider
    provider: alloc::boxed::Box<dyn providers::Provider>,
    /// Registered tools
    tools: ToolRegistry,
    /// Conversation history
    history: Vec<Message>,
    /// System prompt
    system_prompt: String,
    /// Maximum conversation history length
    max_history: usize,
}

impl Agent {
    pub fn new(
        provider: alloc::boxed::Box<dyn providers::Provider>,
        tools: ToolRegistry,
        system_prompt: String,
    ) -> Self {
        Agent {
            provider,
            tools,
            history: Vec::new(),
            system_prompt,
            max_history: 10, // Keep lean for long autonomous runs
        }
    }

    /// Process a single message and return the response.
    pub fn process_message(&mut self, msg: &ChannelMessage) -> String {
        crate::kprintln!("[agent] processing message from {}: {}",
            msg.sender,
            crate::util::truncate(&msg.content, 80)
        );

        // Store user message in memory
        {
            let mem = memory::global();
            let mut mem = mem.lock();
            let key = format!("user-{}", msg.timestamp);
            let _ = mem.store(&key, &msg.content, MemoryCategory::Daily);
        }

        // Build context with memory
        let context = self.build_context(&msg.content);

        // Add user message to history
        self.history.push(Message::new(Role::User, &msg.content));

        // Send to LLM with tool loop
        let response = self.completion_loop(&context);

        // Store assistant response in memory (only if meaningful)
        if response.len() > 30 {
            let mem = memory::global();
            let mut mem = mem.lock();
            let key = format!("assistant-{}", crate::kernel::rdtsc());
            let summary = crate::util::truncate(&response, 100);
            let _ = mem.store(&key, &summary, MemoryCategory::Conversation);
        }

        // Add to conversation history
        self.history.push(Message::new(Role::Assistant, &response));

        // Trim history if too long
        while self.history.len() > self.max_history {
            self.history.remove(0);
        }

        response
    }

    /// Build the full context for an LLM request.
    fn build_context(&self, user_message: &str) -> Vec<Message> {
        let mut messages = Vec::new();

        // System prompt
        messages.push(Message::new(Role::System, &self.system_prompt));

        // Memory context
        let mem = memory::global();
        let mem = mem.lock();
        let memories = mem.recall(user_message, MAX_MEMORY_CONTEXT);

        if !memories.is_empty() {
            let mut memory_context = String::from("[Memory context]\n");
            for result in &memories {
                memory_context.push_str(&format!(
                    "- {}: {}\n",
                    result.entry.key,
                    crate::util::truncate(&result.entry.content, 200)
                ));
            }
            memory_context.push_str("[End memory context]\n");

            messages.push(Message::new(Role::System, &memory_context));
        }

        drop(mem); // Release the lock

        // Conversation history
        for msg in &self.history {
            messages.push(msg.clone());
        }

        messages
    }

    /// The main completion loop — handles tool calls iteratively.
    /// Returns either a text response or a summary of tool actions.
    fn completion_loop(&self, initial_context: &[Message]) -> String {
        let mut messages: Vec<Message> = initial_context.to_vec();
        let tool_specs = self.tools.specs();
        let mut tool_log: Vec<String> = Vec::new();

        for round in 0..MAX_TOOL_ROUNDS {
            crate::kprintln!("[agent] LLM request (round {})", round + 1);

            let response = match self.provider.complete(&messages, &tool_specs) {
                Ok(resp) => resp,
                Err(e) => {
                    crate::kprintln!("[agent] provider error: {}", e);
                    return format!("I encountered an error communicating with the AI provider: {}", e);
                }
            };

            crate::kprintln!("[agent] tokens: {} prompt, {} completion",
                response.usage.prompt_tokens,
                response.usage.completion_tokens
            );

            // If no tool calls, return the content
            if response.tool_calls.is_empty() {
                let text = response.content.unwrap_or_else(|| String::from("(no response)"));
                // If we have tool results and text, combine them
                if !tool_log.is_empty() && text.len() > 5 {
                    return format!("{}\n\nActions: {}", text, tool_log.join(", "));
                }
                return text;
            }

            // If model returned text AND tool calls, capture it
            let _content_text = response.content.clone().unwrap_or_default();

            // Execute tool calls
            messages.push(Message {
                role: Role::Assistant,
                content: response.content.clone().unwrap_or_default(),
                tool_call_id: None,
                tool_calls: Some(response.tool_calls.clone()),
            });

            for tool_call in &response.tool_calls {
                crate::kprintln!("[agent] tool call: {}({})",
                    tool_call.name,
                    crate::util::truncate(&tool_call.arguments, 50)
                );

                let result = self.tools.execute(&tool_call.name, &tool_call.arguments);

                crate::kprintln!("[agent] tool result: {} ({})",
                    if result.success { "ok" } else { "error" },
                    crate::util::truncate(&result.output, 80)
                );

                // Log what was done
                tool_log.push(format!("{}:{}", tool_call.name,
                    if result.success { "ok" } else { "err" }));

                // Add tool result with proper tool_call_id for OpenAI
                let truncated_output = if result.output.len() > 500 {
                    let mut trunc = crate::util::truncate(&result.output, 500);
                    trunc.push_str("\n...(truncated)");
                    trunc
                } else {
                    result.output
                };
                messages.push(Message {
                    role: Role::Tool,
                    content: truncated_output,
                    tool_call_id: Some(tool_call.id.clone()),
                    tool_calls: None,
                });
            }
        }

        // Tool rounds exhausted — return summary of actions taken
        crate::kprintln!("[agent] tool rounds exhausted, {} actions taken", tool_log.len());
        format!("Actions completed: {}", tool_log.join(", "))
    }

    /// Get conversation history length.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Clear conversation history.
    pub fn clear_history(&mut self) {
        self.history.clear()
    }
}
