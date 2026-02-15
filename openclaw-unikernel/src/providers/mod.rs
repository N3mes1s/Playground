//! # LLM Provider System
//!
//! Trait-based abstraction over LLM APIs. Each provider implements the
//! `Provider` trait for chat completion. The factory creates the right
//! provider from configuration.
//!
//! Supported providers (30+):
//! - OpenAI (GPT-4o, o1, etc.)
//! - Anthropic (Claude 3.5/4)
//! - OpenRouter (aggregator)
//! - Ollama (local)
//! - Google Gemini
//! - 25+ OpenAI-compatible (Groq, Mistral, DeepSeek, Together, etc.)

mod openai;
mod anthropic;
mod openrouter;
mod ollama;
mod gemini;
pub mod resilient;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// A message in a conversation.
#[derive(Debug, Clone)]
pub struct Message {
    pub role: Role,
    pub content: String,
    /// For role=tool: the ID of the tool call this is a result for
    pub tool_call_id: Option<String>,
    /// For role=assistant: tool calls the model requested
    pub tool_calls: Option<Vec<ToolCall>>,
}

impl Message {
    pub fn new(role: Role, content: &str) -> Self {
        Message {
            role,
            content: String::from(content),
            tool_call_id: None,
            tool_calls: None,
        }
    }
}

/// Message roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        }
    }
}

/// A tool call requested by the model.
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

/// Response from an LLM provider.
#[derive(Debug, Clone)]
pub struct CompletionResponse {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub finish_reason: FinishReason,
    pub usage: TokenUsage,
}

/// Why the model stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishReason {
    Stop,
    ToolUse,
    Length,
    ContentFilter,
    Unknown,
}

/// Token usage statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Tool specification for function calling.
#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters_json: String,
}

/// Configuration for a provider.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub provider_name: String,
    pub api_key: String,
    pub model: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub api_base_url: Option<String>,
    pub timeout_ms: u64,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        ProviderConfig {
            provider_name: String::from("openai"),
            api_key: String::new(),
            model: String::from("gpt-4o"),
            temperature: 0.7,
            max_tokens: 4096,
            api_base_url: None,
            timeout_ms: 120_000,
        }
    }
}

/// The core provider trait — all LLM backends implement this.
pub trait Provider: Send {
    /// Get the provider name.
    fn name(&self) -> &str;

    /// Send a chat completion request.
    fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<CompletionResponse, String>;

    /// Check if the provider is healthy and reachable.
    fn health_check(&self) -> Result<(), String>;
}

// ── OpenAI-Compatible Base ─────────────────────────────────────────────────

/// Base client for OpenAI-compatible APIs (used by 25+ providers).
pub struct OpenAiCompatibleClient {
    pub config: ProviderConfig,
    pub host: String,
    pub path: String,
}

impl OpenAiCompatibleClient {
    pub fn new(config: ProviderConfig, host: &str, path: &str) -> Self {
        OpenAiCompatibleClient {
            config,
            host: String::from(host),
            path: String::from(path),
        }
    }

    /// Build the JSON request body for chat completions.
    pub fn build_request_json(&self, messages: &[Message], tools: &[ToolSpec]) -> String {
        let mut json = String::from("{");

        // Model — read live config to support runtime model switching
        let live_model = crate::config::get().model.clone();
        let model = if live_model.is_empty() { &self.config.model } else { &live_model };
        json.push_str(&format!("\"model\":\"{}\",", model));

        // Messages
        json.push_str("\"messages\":[");
        for (i, msg) in messages.iter().enumerate() {
            if i > 0 { json.push(','); }
            json.push('{');
            json.push_str(&format!("\"role\":\"{}\"", msg.role.as_str()));

            // For assistant messages with tool_calls, content may be null
            if msg.role == Role::Assistant && msg.tool_calls.is_some() {
                if msg.content.is_empty() {
                    json.push_str(",\"content\":null");
                } else {
                    json.push_str(&format!(",\"content\":{}", json_string_escape(&msg.content)));
                }
                // Serialize tool_calls array
                if let Some(ref calls) = msg.tool_calls {
                    json.push_str(",\"tool_calls\":[");
                    for (j, tc) in calls.iter().enumerate() {
                        if j > 0 { json.push(','); }
                        json.push_str(&format!(
                            "{{\"id\":\"{}\",\"type\":\"function\",\"function\":{{\"name\":\"{}\",\"arguments\":{}}}}}",
                            tc.id, tc.name, json_string_escape(&tc.arguments)
                        ));
                    }
                    json.push(']');
                }
            } else if msg.role == Role::Tool {
                json.push_str(&format!(",\"content\":{}", json_string_escape(&msg.content)));
                if let Some(ref tc_id) = msg.tool_call_id {
                    json.push_str(&format!(",\"tool_call_id\":\"{}\"", tc_id));
                }
            } else {
                json.push_str(&format!(",\"content\":{}", json_string_escape(&msg.content)));
            }

            json.push('}');
        }
        json.push_str("],");

        // Temperature
        // Format f32 manually for no_std
        let temp_int = (self.config.temperature * 10.0) as u32;
        json.push_str(&format!("\"temperature\":0.{},", temp_int));

        // Max tokens — use max_completion_tokens for newer models (gpt-4o+, gpt-5+)
        let uses_new_param = model.contains("gpt-4o") || model.contains("gpt-4.1")
            || model.contains("gpt-5") || model.contains("o1") || model.contains("o3");
        if uses_new_param {
            json.push_str(&format!("\"max_completion_tokens\":{}", self.config.max_tokens));
        } else {
            json.push_str(&format!("\"max_tokens\":{}", self.config.max_tokens));
        }

        // Tools (if any)
        if !tools.is_empty() {
            json.push_str(",\"tools\":[");
            for (i, tool) in tools.iter().enumerate() {
                if i > 0 { json.push(','); }
                json.push_str(&format!(
                    "{{\"type\":\"function\",\"function\":{{\"name\":\"{}\",\"description\":{},\"parameters\":{}}}}}",
                    tool.name,
                    json_string_escape(&tool.description),
                    tool.parameters_json
                ));
            }
            json.push(']');
        }

        json.push('}');
        json
    }

    /// Send a request and parse the response.
    pub fn send_completion(
        &self,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<CompletionResponse, String> {
        let body = self.build_request_json(messages, tools);

        // Read live API key from global config (supports runtime updates via POST /config)
        let live_key = crate::config::get().api_key.clone();
        let api_key = if live_key.is_empty() || live_key == "OPENAI_API_KEY" {
            &self.config.api_key
        } else {
            &live_key
        };

        let response = crate::net::http::post_json(
            &self.host,
            &self.path,
            &body,
            Some(api_key),
        )
        .map_err(|e| String::from(e))?;

        if !response.is_success() {
            return Err(format!(
                "API error {}: {}",
                response.status_code,
                response.body_str().unwrap_or("(binary response)")
            ));
        }

        parse_openai_response(&response.body)
    }
}

/// Parse an OpenAI-format JSON response (minimal JSON parser).
fn parse_openai_response(body: &[u8]) -> Result<CompletionResponse, String> {
    let text = core::str::from_utf8(body)
        .map_err(|_| String::from("invalid UTF-8 in API response"))?;

    // Extract content from "content":"..." field
    let content = extract_json_string(text, "content");

    // Extract finish_reason
    let finish_reason = match extract_json_string(text, "finish_reason").as_deref() {
        Some("stop") => FinishReason::Stop,
        Some("tool_calls") => FinishReason::ToolUse,
        Some("length") => FinishReason::Length,
        Some("content_filter") => FinishReason::ContentFilter,
        _ => FinishReason::Unknown,
    };

    // Extract token usage
    let usage = TokenUsage {
        prompt_tokens: extract_json_number(text, "prompt_tokens").unwrap_or(0) as u32,
        completion_tokens: extract_json_number(text, "completion_tokens").unwrap_or(0) as u32,
        total_tokens: extract_json_number(text, "total_tokens").unwrap_or(0) as u32,
    };

    // Extract tool calls (simplified)
    let tool_calls = extract_tool_calls(text);

    Ok(CompletionResponse {
        content,
        tool_calls,
        finish_reason,
        usage,
    })
}

/// Extract tool calls from the response JSON.
fn extract_tool_calls(json: &str) -> Vec<ToolCall> {
    let mut calls = Vec::new();

    // Look for "tool_calls" array
    if let Some(start) = json.find("\"tool_calls\"") {
        let rest = &json[start..];
        if let Some(arr_start) = rest.find('[') {
            let arr_rest = &rest[arr_start..];
            // Parse each tool call object in the array
            // depth starts at 1 because we're inside the [ bracket
            let mut depth: i32 = 1;
            let mut obj_start = None;
            for (i, c) in arr_rest.char_indices().skip(1) {
                match c {
                    '[' => { depth += 1; }
                    ']' => {
                        depth -= 1;
                        if depth <= 0 { break; }
                    }
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
                                let obj = &arr_rest[start..=i];
                                if let Some(call) = parse_tool_call(obj) {
                                    calls.push(call);
                                }
                                obj_start = None;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    calls
}

fn parse_tool_call(json: &str) -> Option<ToolCall> {
    let id = extract_json_string(json, "id")?;
    // Look for "function" object
    let name = extract_json_string(json, "name")?;
    let arguments = extract_json_string(json, "arguments").unwrap_or_default();

    Some(ToolCall {
        id,
        name,
        arguments,
    })
}

// ── Minimal JSON Helpers ───────────────────────────────────────────────────

/// Extract a string value for a given key from JSON.
pub fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let start = json.find(&pattern)?;
    let rest = &json[start + pattern.len()..];

    // Skip whitespace and colon
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?;
    let rest = rest.trim_start();

    if rest.starts_with("null") {
        return None;
    }

    if !rest.starts_with('"') {
        return None;
    }

    // Find the end of the string, handling escapes
    let rest = &rest[1..]; // Skip opening quote
    let mut result = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(escaped) = chars.next() {
                    match escaped {
                        '"' => result.push('"'),
                        '\\' => result.push('\\'),
                        'n' => result.push('\n'),
                        'r' => result.push('\r'),
                        't' => result.push('\t'),
                        _ => {
                            result.push('\\');
                            result.push(escaped);
                        }
                    }
                }
            }
            '"' => return Some(result),
            _ => result.push(c),
        }
    }

    None
}

/// Extract a numeric value for a given key from JSON.
pub fn extract_json_number(json: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\"", key);
    let start = json.find(&pattern)?;
    let rest = &json[start + pattern.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();

    let mut num_str = String::new();
    for c in rest.chars() {
        if c.is_ascii_digit() {
            num_str.push(c);
        } else {
            break;
        }
    }

    if num_str.is_empty() {
        return None;
    }

    let mut result: u64 = 0;
    for c in num_str.chars() {
        result = result.checked_mul(10)?;
        result = result.checked_add((c as u64) - (b'0' as u64))?;
    }
    Some(result)
}

/// Escape a string for JSON output.
pub fn json_string_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            _ => result.push(c),
        }
    }
    result.push('"');
    result
}

// ── Provider Factory ───────────────────────────────────────────────────────

/// All supported provider names.
pub const PROVIDER_NAMES: &[&str] = &[
    "openai", "anthropic", "openrouter", "ollama", "gemini",
    "groq", "mistral", "deepseek", "cohere", "perplexity",
    "together", "fireworks", "huggingface", "lmstudio", "venice",
    "xai", "cloudflare", "moonshot", "synthetic", "glm",
    "minimax", "bedrock", "qianfan", "opencode", "zai",
    "vercel", "custom",
];

/// Create a provider from configuration.
pub fn create(config: ProviderConfig) -> Box<dyn Provider> {
    match config.provider_name.as_str() {
        "openai" => Box::new(openai::OpenAiProvider::new(config)),
        "anthropic" => Box::new(anthropic::AnthropicProvider::new(config)),
        "openrouter" => Box::new(openrouter::OpenRouterProvider::new(config)),
        "ollama" => Box::new(ollama::OllamaProvider::new(config)),
        "gemini" => Box::new(gemini::GeminiProvider::new(config)),
        // All OpenAI-compatible providers
        "groq" => Box::new(openai::OpenAiProvider::with_base(
            config, "api.groq.com", "/openai/v1/chat/completions"
        )),
        "mistral" => Box::new(openai::OpenAiProvider::with_base(
            config, "api.mistral.ai", "/v1/chat/completions"
        )),
        "deepseek" => Box::new(openai::OpenAiProvider::with_base(
            config, "api.deepseek.com", "/chat/completions"
        )),
        "together" => Box::new(openai::OpenAiProvider::with_base(
            config, "api.together.xyz", "/v1/chat/completions"
        )),
        "fireworks" => Box::new(openai::OpenAiProvider::with_base(
            config, "api.fireworks.ai", "/inference/v1/chat/completions"
        )),
        "xai" => Box::new(openai::OpenAiProvider::with_base(
            config, "api.x.ai", "/v1/chat/completions"
        )),
        "perplexity" => Box::new(openai::OpenAiProvider::with_base(
            config, "api.perplexity.ai", "/chat/completions"
        )),
        "cohere" => Box::new(openai::OpenAiProvider::with_base(
            config, "api.cohere.ai", "/v1/chat/completions"
        )),
        _ => {
            // Default to OpenAI-compatible with custom base URL
            let base_url_clone = config.api_base_url.clone();
            if let Some(ref base_url) = base_url_clone {
                let host = extract_host(base_url).unwrap_or("localhost");
                let path = extract_path(base_url).unwrap_or("/v1/chat/completions");
                Box::new(openai::OpenAiProvider::with_base(config, host, path))
            } else {
                Box::new(openai::OpenAiProvider::new(config))
            }
        }
    }
}

fn extract_host(url: &str) -> Option<&str> {
    let s = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    Some(s.split('/').next().unwrap_or(s))
}

fn extract_path(url: &str) -> Option<&str> {
    let s = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    s.find('/').map(|i| &s[i..])
}
