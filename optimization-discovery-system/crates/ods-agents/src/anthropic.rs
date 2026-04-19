//! Typed Anthropic Messages API client with a tool-use loop.
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

/// Accumulated token usage across iterations of a single [`ToolUseLoop::run`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LoopStats {
    pub iterations: u32,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_read_tokens: u32,
    pub cache_creation_tokens: u32,
}

impl LoopStats {
    /// Rough cost estimate assuming Opus-class pricing (tunable via
    /// `ODS_INPUT_PRICE_PER_MTOK` / `ODS_OUTPUT_PRICE_PER_MTOK` env vars).
    pub fn estimated_cost_usd(&self) -> f64 {
        let input_per_mtok: f64 = std::env::var("ODS_INPUT_PRICE_PER_MTOK")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15.0);
        let output_per_mtok: f64 = std::env::var("ODS_OUTPUT_PRICE_PER_MTOK")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(75.0);
        (self.input_tokens as f64 / 1_000_000.0) * input_per_mtok
            + (self.output_tokens as f64 / 1_000_000.0) * output_per_mtok
    }
}

/// Dispatches tool calls to typed Rust functions. Callers register handlers
/// keyed by tool name; the loop feeds the model's tool_use blocks through the
/// registry and appends the tool_result back into the conversation until the
/// assistant returns `stop_reason == "end_turn"`.
pub struct ToolUseLoop {
    pub max_iters: u32,
    pub max_tokens: u32,
    pub tool_specs: Vec<ToolSpec>,
    handlers: HashMap<String, Box<dyn ToolHandler>>,
}

#[async_trait::async_trait]
pub trait ToolHandler: Send + Sync {
    async fn call(&self, input: &serde_json::Value) -> Result<String>;
}

impl Default for ToolUseLoop {
    fn default() -> Self {
        Self {
            max_iters: 24,
            max_tokens: 4096,
            tool_specs: Vec::new(),
            handlers: HashMap::new(),
        }
    }
}

impl ToolUseLoop {
    pub fn register(
        &mut self,
        spec: ToolSpec,
        handler: Box<dyn ToolHandler>,
    ) {
        self.handlers.insert(spec.name.clone(), handler);
        self.tool_specs.push(spec);
    }

    pub async fn dispatch(&self, call: &ToolCall) -> ToolResult {
        match self.handlers.get(&call.name) {
            Some(h) => match h.call(&call.input).await {
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

    /// Run the tool-use conversation until `stop_reason == "end_turn"` or the
    /// iteration cap is hit. Returns the accumulated stats plus the final
    /// assistant text (concatenation of any text blocks in the last turn).
    ///
    /// Observability: when `observer` is `Some`, structured events are
    /// emitted for each turn, each tool call, and each assistant reasoning
    /// block, with previews capped at a bounded length to keep logs readable.
    pub async fn run(
        &self,
        client: &AnthropicClient,
        system: &str,
        initial_user_msg: &str,
    ) -> Result<(LoopStats, String, Conversation)> {
        self.run_observed(client, system, initial_user_msg, None).await
    }

    pub async fn run_observed(
        &self,
        client: &AnthropicClient,
        system: &str,
        initial_user_msg: &str,
        observer: Option<&ConversationObserver<'_>>,
    ) -> Result<(LoopStats, String, Conversation)> {
        let mut stats = LoopStats::default();
        let mut convo = Conversation::new();
        convo.push_user_text(initial_user_msg);

        for iter in 0..self.max_iters {
            stats.iterations += 1;
            let envelope = client
                .send_messages(system, &convo.messages, &self.tool_specs, self.max_tokens)
                .await?;
            stats.input_tokens += envelope.usage.input_tokens;
            stats.output_tokens += envelope.usage.output_tokens;
            stats.cache_read_tokens += envelope.usage.cache_read_input_tokens;
            stats.cache_creation_tokens += envelope.usage.cache_creation_input_tokens;

            // Observe the turn itself + any reasoning / tool-use blocks.
            if let Some(obs) = observer {
                obs.on_turn(
                    iter + 1,
                    envelope.stop_reason.clone(),
                    envelope.usage.input_tokens,
                    envelope.usage.output_tokens,
                    envelope.usage.cache_read_input_tokens,
                    envelope.usage.cache_creation_input_tokens,
                );
                for block in &envelope.content {
                    match block {
                        ContentBlock::Text { text } => obs.on_reasoning(iter + 1, text),
                        ContentBlock::ToolUse { name, input, .. } => {
                            obs.on_tool_call(iter + 1, name, input)
                        }
                        _ => {}
                    }
                }
            }

            // Append assistant turn.
            convo.push_assistant(envelope.content.clone());

            // Dispatch any tool_use blocks; collect their results.
            let calls: Vec<ToolCall> = envelope
                .content
                .iter()
                .filter_map(|b| match b {
                    ContentBlock::ToolUse { id, name, input } => Some(ToolCall {
                        id: id.clone(),
                        name: name.clone(),
                        input: input.clone(),
                    }),
                    _ => None,
                })
                .collect();

            if calls.is_empty() {
                let text = extract_text(&envelope.content);
                return Ok((stats, text, convo));
            }

            let mut tool_results = Vec::with_capacity(calls.len());
            for call in &calls {
                let r = self.dispatch(call).await;
                if let Some(obs) = observer {
                    obs.on_tool_result(iter + 1, &call.name, !r.is_error, &r.content);
                }
                tool_results.push(ContentBlock::ToolResult {
                    tool_use_id: r.call_id,
                    content: r.content,
                    is_error: r.is_error,
                });
            }
            convo.push_user(tool_results);

            if matches!(
                envelope.stop_reason.as_deref(),
                Some("end_turn") | Some("stop_sequence")
            ) && calls.is_empty()
            {
                let text = extract_text(&envelope.content);
                return Ok((stats, text, convo));
            }
        }

        let text = convo
            .last_assistant_text()
            .unwrap_or_else(|| "max_iters reached".into());
        Ok((stats, text, convo))
    }
}

fn extract_text(blocks: &[ContentBlock]) -> String {
    blocks
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text { text } => Some(text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Callback surface for observing a [`ToolUseLoop::run_observed`] conversation.
/// Implemented by `race.rs` to fan events out to the agent event sink.
pub struct ConversationObserver<'a> {
    #[allow(clippy::type_complexity)]
    pub on_turn: Box<dyn Fn(u32, Option<String>, u32, u32, u32, u32) + Send + Sync + 'a>,
    pub on_reasoning: Box<dyn Fn(u32, &str) + Send + Sync + 'a>,
    pub on_tool_call: Box<dyn Fn(u32, &str, &serde_json::Value) + Send + Sync + 'a>,
    pub on_tool_result: Box<dyn Fn(u32, &str, bool, &str) + Send + Sync + 'a>,
}

impl<'a> ConversationObserver<'a> {
    fn on_turn(
        &self,
        iter: u32,
        stop: Option<String>,
        tin: u32,
        tout: u32,
        cr: u32,
        cc: u32,
    ) {
        (self.on_turn)(iter, stop, tin, tout, cr, cc);
    }
    fn on_reasoning(&self, iter: u32, text: &str) {
        (self.on_reasoning)(iter, text);
    }
    fn on_tool_call(&self, iter: u32, tool: &str, input: &serde_json::Value) {
        (self.on_tool_call)(iter, tool, input);
    }
    fn on_tool_result(&self, iter: u32, tool: &str, ok: bool, result: &str) {
        (self.on_tool_result)(iter, tool, ok, result);
    }
}

#[derive(Debug, Clone, Default)]
pub struct Conversation {
    pub messages: Vec<Message>,
}

impl Conversation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_user_text(&mut self, text: &str) {
        self.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: text.to_string(),
            }],
        });
    }

    pub fn push_user(&mut self, content: Vec<ContentBlock>) {
        self.messages.push(Message {
            role: Role::User,
            content,
        });
    }

    pub fn push_assistant(&mut self, content: Vec<ContentBlock>) {
        self.messages.push(Message {
            role: Role::Assistant,
            content,
        });
    }

    pub fn last_assistant_text(&self) -> Option<String> {
        for m in self.messages.iter().rev() {
            if matches!(m.role, Role::Assistant) {
                return Some(extract_text(&m.content));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;
    #[async_trait::async_trait]
    impl ToolHandler for Echo {
        async fn call(&self, input: &serde_json::Value) -> Result<String> {
            Ok(input.to_string())
        }
    }

    #[tokio::test]
    async fn unknown_tool_yields_error_result() {
        let loop_ = ToolUseLoop::default();
        let r = loop_
            .dispatch(&ToolCall {
                id: "c1".into(),
                name: "nope".into(),
                input: serde_json::json!({}),
            })
            .await;
        assert!(r.is_error);
    }

    #[tokio::test]
    async fn registered_handler_is_dispatched() {
        let mut loop_ = ToolUseLoop::default();
        loop_.register(
            ToolSpec {
                name: "echo".into(),
                description: "echo".into(),
                input_schema: serde_json::json!({"type":"object"}),
            },
            Box::new(Echo),
        );
        let r = loop_
            .dispatch(&ToolCall {
                id: "c2".into(),
                name: "echo".into(),
                input: serde_json::json!({"hi": 1}),
            })
            .await;
        assert!(!r.is_error);
        assert!(r.content.contains("hi"));
    }

    #[test]
    fn stats_cost_is_reasonable() {
        let s = LoopStats {
            iterations: 2,
            input_tokens: 1_000_000,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
        };
        // Default Opus pricing: $15/M input
        assert!((s.estimated_cost_usd() - 15.0).abs() < 0.01);
    }
}
