//! Typed Anthropic Messages API client with a tool-use loop.
//!
//! Dependency posture: `reqwest` with `rustls-tls` only. No OpenSSL, no
//! native-tls, no CLI shell-out - everything stays inside the static binary.

use anyhow::{Context, Result};
use ods_core::{BudgetTracker, LoopError};
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
        self.send_messages_with_schema(system, messages, tools, max_tokens, None)
            .await
    }

    /// Variant of [`send_messages`] that sets the `output_config.format`
    /// field so Claude's grammar-constrained decoder guarantees the final
    /// text block is schema-valid JSON.
    ///
    /// See https://platform.claude.com/docs/en/build-with-claude/structured-outputs.
    /// Generally available on Claude Opus 4.7 / 4.6, Sonnet 4.6 / 4.5,
    /// Haiku 4.5. No beta header required. Works even when tools are in
    /// play - the model uses tools freely during intermediate turns and
    /// the FINAL text block is what gets constrained.
    pub async fn send_messages_with_schema(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolSpec],
        max_tokens: u32,
        output_schema: Option<&serde_json::Value>,
    ) -> Result<ResponseEnvelope> {
        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
            "tools": tools,
        });
        if let Some(schema) = output_schema {
            body["output_config"] = serde_json::json!({
                "format": {
                    "type": "json_schema",
                    "schema": schema,
                },
            });
        }
        tracing::debug!(
            target: "ods::anthropic",
            has_schema = output_schema.is_some(),
            body_bytes = serde_json::to_string(&body).map(|s| s.len()).unwrap_or(0),
            body_keys = ?body.as_object().map(|m| m.keys().cloned().collect::<Vec<_>>()),
            "POST /v1/messages"
        );
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
        call_cost_usd(self.input_tokens, self.output_tokens)
    }
}

fn input_rate_per_mtok() -> f64 {
    std::env::var("ODS_INPUT_PRICE_PER_MTOK")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15.0)
}

fn output_rate_per_mtok() -> f64 {
    std::env::var("ODS_OUTPUT_PRICE_PER_MTOK")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(75.0)
}

/// Price one specific API call's usage numbers (this call only, not the
/// running total).
pub fn call_cost_usd(input_tokens: u32, output_tokens: u32) -> f64 {
    (input_tokens as f64 / 1_000_000.0) * input_rate_per_mtok()
        + (output_tokens as f64 / 1_000_000.0) * output_rate_per_mtok()
}

/// Upper bound on the next call's cost. Input tokens: reuse last observed
/// value (it already includes the growing conversation), or estimate from
/// system+messages char count on the first iteration. Output tokens: always
/// assume the full `max_tokens` budget.
fn project_next_call_cost(
    max_tokens: u32,
    last_input_tokens: Option<u32>,
    system: &str,
    messages: &[Message],
) -> f64 {
    let input_tokens = last_input_tokens.unwrap_or_else(|| estimate_input_tokens(system, messages));
    call_cost_usd(input_tokens, max_tokens)
}

/// Very rough char-to-token estimate for the first call before we've seen
/// Claude's own tokenizer output. 3.5 chars/token is conservative for
/// English+code mixes; we round up to add headroom.
fn estimate_input_tokens(system: &str, messages: &[Message]) -> u32 {
    let mut chars = system.len();
    for m in messages {
        for block in &m.content {
            chars += match block {
                ContentBlock::Text { text } => text.len(),
                ContentBlock::ToolUse { name, input, .. } => name.len() + input.to_string().len(),
                ContentBlock::ToolResult { content, .. } => content.len(),
            };
        }
    }
    // 3.5 chars per token → tokens = chars / 3.5, rounded up.
    ((chars as f64 / 3.5).ceil() as u32).max(500)
}

/// Dispatches tool calls to typed Rust functions. Callers register handlers
/// keyed by tool name; the loop feeds the model's tool_use blocks through the
/// registry and appends the tool_result back into the conversation until the
/// assistant returns `stop_reason == "end_turn"`.
pub struct ToolUseLoop {
    pub max_iters: u32,
    pub max_tokens: u32,
    pub tool_specs: Vec<ToolSpec>,
    /// When `Some`, forwarded as `output_config.format.json_schema.schema`
    /// on every API request. The final `text` content block is grammar-
    /// constrained to match this schema -- no parser-of-last-resort
    /// needed for callers that want structured output.
    pub output_schema: Option<serde_json::Value>,
    /// Shared per-run budget tracker. When `Some`, the loop projects a
    /// conservative upper bound on the next API call's cost and bails with
    /// `LoopError::BudgetWouldExceed` *before* the POST fires if charging
    /// the projection would exceed the cap.
    pub budget_tracker: Option<BudgetTracker>,
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
            output_schema: None,
            budget_tracker: None,
            handlers: HashMap::new(),
        }
    }
}

impl ToolUseLoop {
    pub fn register(&mut self, spec: ToolSpec, handler: Box<dyn ToolHandler>) {
        self.handlers.insert(spec.name.clone(), handler);
        self.tool_specs.push(spec);
    }

    /// Attach a shared [`BudgetTracker`]. All specialists racing in the same
    /// run share one tracker so their accumulated spend is tested against the
    /// cap *globally* before each API call.
    pub fn with_budget_tracker(mut self, tracker: BudgetTracker) -> Self {
        self.budget_tracker = Some(tracker);
        self
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
        self.run_observed(client, system, initial_user_msg, None)
            .await
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

        // Best estimate of the next call's input tokens. First iteration uses
        // a char-to-token ratio over the initial prompt; later iterations
        // reuse the previous envelope's actual input_tokens (which includes
        // the growing conversation history Claude is re-reading each turn).
        let mut last_input_tokens: Option<u32> = None;

        for iter in 0..self.max_iters {
            // Hard per-call budget gate. Projection is an upper bound
            // computed from (a) the last observed input-token count (or a
            // char-based estimate on first call) and (b) the loop's
            // max_tokens output ceiling. If charging this projection to the
            // shared tracker would exceed the cap, bail *before* the POST.
            if let Some(tracker) = &self.budget_tracker {
                let projection = project_next_call_cost(
                    self.max_tokens,
                    last_input_tokens,
                    system,
                    &convo.messages,
                );
                if let Some(reason) = tracker.would_exceed(projection) {
                    return Err(anyhow::Error::new(LoopError::BudgetWouldExceed {
                        current_usd: reason.current_usd,
                        projected_usd: reason.projected_usd,
                        cap_usd: reason.cap_usd,
                    }));
                }
            }

            stats.iterations += 1;
            let envelope = client
                .send_messages_with_schema(
                    system,
                    &convo.messages,
                    &self.tool_specs,
                    self.max_tokens,
                    self.output_schema.as_ref(),
                )
                .await?;
            stats.input_tokens += envelope.usage.input_tokens;
            stats.output_tokens += envelope.usage.output_tokens;
            stats.cache_read_tokens += envelope.usage.cache_read_input_tokens;
            stats.cache_creation_tokens += envelope.usage.cache_creation_input_tokens;
            last_input_tokens = Some(envelope.usage.input_tokens);

            // Charge the real delta (this single call's cost) to the shared
            // tracker so other specialists see our spend immediately.
            if let Some(tracker) = &self.budget_tracker {
                let delta =
                    call_cost_usd(envelope.usage.input_tokens, envelope.usage.output_tokens);
                tracker.add_spent(delta);
            }

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
    fn on_turn(&self, iter: u32, stop: Option<String>, tin: u32, tout: u32, cr: u32, cc: u32) {
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

    #[tokio::test]
    async fn run_observed_bails_before_post_when_budget_would_exceed() {
        // Client points at a black-hole URL we'd never want to hit. The
        // budget gate must reject the call *before* any HTTP attempt.
        let client = AnthropicClient::new("sk-ant-test-key-not-used").expect("build client");
        // 1-cent cap. max_tokens 4096 at $75/Mtok = $0.31 output projection
        // alone, which already exceeds the cap, so the gate must fire on
        // the first iteration.
        let budget = ods_core::Budget {
            wall_cap: std::time::Duration::from_secs(60),
            spend_cap_usd: 0.01,
        };
        let tracker = ods_core::BudgetTracker::new(Some(&budget));
        let loop_ = ToolUseLoop::default().with_budget_tracker(tracker);
        let err = loop_
            .run_observed(&client, "sys", "hello", None)
            .await
            .expect_err("expected budget gate to fire");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("budget would exceed"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn projection_respects_max_tokens() {
        // No observed history yet — projection uses the char-based estimate
        // for input (small) plus the full max_tokens output ceiling.
        let p = project_next_call_cost(4096, None, "sys", &[]);
        // 4096 * 75/1M = $0.307; input is tiny.
        assert!(p > 0.29 && p < 0.40, "projection out of range: ${p}");
    }

    #[test]
    fn tracker_would_exceed_trips_on_cap_breach() {
        let b = ods_core::Budget {
            wall_cap: std::time::Duration::from_secs(60),
            spend_cap_usd: 1.0,
        };
        let t = ods_core::BudgetTracker::new(Some(&b));
        t.add_spent(0.90);
        assert!(t.would_exceed(0.05).is_none(), "0.90 + 0.05 < 1.00");
        assert!(t.would_exceed(0.20).is_some(), "0.90 + 0.20 > 1.00");
    }
}
