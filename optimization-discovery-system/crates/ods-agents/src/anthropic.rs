//! Minimal typed Anthropic Messages API client with a tool-use loop.
//!
//! Dependency posture: `reqwest` with `rustls-tls` only. No OpenSSL, no
//! native-tls, no CLI shell-out - everything stays inside the static binary.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub const DEFAULT_MODEL: &str = "claude-opus-4-7";
const API_URL: &str = "https://api.anthropic.com/v1/messages";
const API_VERSION: &str = "2023-06-01";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub call_id: String,
    pub content: String,
    pub is_error: bool,
}

/// Transport-only client. Higher-level orchestration lives in [`ToolUseLoop`].
pub struct AnthropicClient {
    http: reqwest::Client,
    api_key: String,
    model: String,
}

impl AnthropicClient {
    pub fn new(api_key: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            http,
            api_key: api_key.into(),
            model: DEFAULT_MODEL.into(),
        })
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub async fn send_messages(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolSpec],
        max_tokens: u32,
    ) -> Result<ResponseEnvelope> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
            "tools": tools,
        });
        let resp = self
            .http
            .post(API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("anthropic request failed")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("anthropic {status}: {text}");
        }
        let envelope: ResponseEnvelope =
            serde_json::from_str(&text).context("parse anthropic response")?;
        Ok(envelope)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(default)]
        is_error: bool,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseEnvelope {
    pub id: String,
    pub model: String,
    pub stop_reason: Option<String>,
    pub content: Vec<ContentBlock>,
    #[serde(default)]
    pub usage: Usage,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub input_tokens: u32,
    #[serde(default)]
    pub output_tokens: u32,
    #[serde(default)]
    pub cache_creation_input_tokens: u32,
    #[serde(default)]
    pub cache_read_input_tokens: u32,
}

/// Dispatches tool calls to typed Rust functions. Callers register handlers
/// keyed by tool name; the loop feeds the model's tool_use blocks through the
/// registry and appends the tool_result back into the conversation until the
/// assistant returns `stop_reason == "end_turn"`.
pub struct ToolUseLoop {
    pub max_iters: u32,
    pub max_tokens: u32,
    handlers: HashMap<String, Box<dyn ToolHandler>>,
}

pub trait ToolHandler: Send + Sync {
    fn call(&self, input: &serde_json::Value) -> Result<String>;
}

impl Default for ToolUseLoop {
    fn default() -> Self {
        Self {
            max_iters: 24,
            max_tokens: 4096,
            handlers: HashMap::new(),
        }
    }
}

impl ToolUseLoop {
    pub fn register(&mut self, name: impl Into<String>, handler: Box<dyn ToolHandler>) {
        self.handlers.insert(name.into(), handler);
    }

    pub fn dispatch(&self, call: &ToolCall) -> ToolResult {
        match self.handlers.get(&call.name) {
            Some(h) => match h.call(&call.input) {
                Ok(content) => ToolResult {
                    call_id: call.id.clone(),
                    content,
                    is_error: false,
                },
                Err(e) => ToolResult {
                    call_id: call.id.clone(),
                    content: e.to_string(),
                    is_error: true,
                },
            },
            None => ToolResult {
                call_id: call.id.clone(),
                content: format!("no handler registered for tool {}", call.name),
                is_error: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;
    impl ToolHandler for Echo {
        fn call(&self, input: &serde_json::Value) -> Result<String> {
            Ok(input.to_string())
        }
    }

    #[test]
    fn unknown_tool_yields_error_result() {
        let loop_ = ToolUseLoop::default();
        let r = loop_.dispatch(&ToolCall {
            id: "c1".into(),
            name: "nope".into(),
            input: serde_json::json!({}),
        });
        assert!(r.is_error);
    }

    #[test]
    fn registered_handler_is_dispatched() {
        let mut loop_ = ToolUseLoop::default();
        loop_.register("echo", Box::new(Echo));
        let r = loop_.dispatch(&ToolCall {
            id: "c2".into(),
            name: "echo".into(),
            input: serde_json::json!({"hi": 1}),
        });
        assert!(!r.is_error);
        assert!(r.content.contains("hi"));
    }
}
