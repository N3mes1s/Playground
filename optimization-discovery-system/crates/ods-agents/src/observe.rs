//! Structured agent observability.
//!
//! Every meaningful thing the agent does - an LLM iteration, a tool call,
//! a reasoning text block, a specialist start/finish - is emitted as an
//! [`AgentEvent`]. Events flow through two channels:
//!
//! 1. `tracing::info!` fields on the `ods_agents::observe` target so users
//!    can follow along in real time with `RUST_LOG=info`.
//! 2. An optional [`EventSink`] that persists events to `RunStore::append_event`
//!    for later inspection via `ods explain --timeline`.
//!
//! Keeping the sink as a trait lets tests snapshot events without wiring a
//! real SQLite store.

use ods_core::{LoopStage, RunId, RunStore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::Mutex;

/// One unit of observability. Each variant serialises to JSON so it can
/// land in the `run_events.detail` column and be replayed later.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum AgentEvent {
    /// The orchestrator routed a specialist race.
    RaceStart { specialists: Vec<String> },
    /// A specialist's conversation is beginning.
    SpecialistStart {
        kind: String,
        target: String,
        hypothesis: String,
        seed_recipe_id: Option<String>,
    },
    /// One turn of the tool-use loop completed; we saw assistant content.
    Turn {
        specialist: String,
        iteration: u32,
        stop_reason: Option<String>,
        input_tokens: u32,
        output_tokens: u32,
        cache_read_tokens: u32,
        cache_creation_tokens: u32,
    },
    /// The assistant emitted free-form reasoning text.
    Reasoning {
        specialist: String,
        iteration: u32,
        text_preview: String,
    },
    /// The assistant asked to invoke a tool.
    ToolCall {
        specialist: String,
        iteration: u32,
        tool: String,
        input_preview: String,
    },
    /// The tool dispatcher returned.
    ToolResult {
        specialist: String,
        iteration: u32,
        tool: String,
        ok: bool,
        result_preview: String,
    },
    /// Specialist produced a candidate patch.
    PatchProposed {
        specialist: String,
        diff_bytes: usize,
    },
    /// Specialist's patch was rejected by the zero-diff gate.
    PatchRejected {
        specialist: String,
        reasons: Vec<String>,
    },
    /// Specialist's verdict: final cost + winner candidate status.
    SpecialistFinish {
        kind: String,
        patch_attempted: bool,
        accepted: bool,
        spent_usd: f64,
        tokens_in: u32,
        tokens_out: u32,
    },
    /// Race-level summary after all specialists ran.
    RaceFinish {
        winner: Option<String>,
        total_spent_usd: f64,
        budget_exhausted: bool,
    },
    /// A recipe proposed by an LLM source (Generalizer or Explorer)
    /// was rejected by the pre-upsert validation gate. Tracked so
    /// operators can see the quality signal without grepping logs.
    RecipeRejected {
        /// Where the recipe came from — `"generalizer"` or
        /// `"explorer"`, both string constants.
        source: String,
        recipe_id: String,
        /// The tree-sitter error or "did not match source diff", etc.
        reason: String,
    },
}

/// Persists events into `run_events`.
pub trait EventSink: Send + Sync {
    fn record(&self, run_id: &RunId, stage: LoopStage, event: &AgentEvent);
}

/// Default sink that writes into an [`RunStore`].
pub struct SqliteEventSink {
    pub store: Arc<Mutex<RunStore>>,
}

impl SqliteEventSink {
    pub fn new(store: RunStore) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
        }
    }
    pub fn shared(store: Arc<Mutex<RunStore>>) -> Self {
        Self { store }
    }
}

impl EventSink for SqliteEventSink {
    fn record(&self, run_id: &RunId, stage: LoopStage, event: &AgentEvent) {
        let kind = event_kind(event);
        let detail = serde_json::to_string(event).unwrap_or_default();
        if let Ok(store) = self.store.lock() {
            let _ = store.append_event(run_id, stage, kind, Some(&detail));
        }
    }
}

/// Test sink that captures events in-memory.
pub struct InMemorySink {
    pub events: Arc<Mutex<Vec<(LoopStage, AgentEvent)>>>,
}

impl InMemorySink {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Default for InMemorySink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSink for InMemorySink {
    fn record(&self, _run_id: &RunId, stage: LoopStage, event: &AgentEvent) {
        if let Ok(mut v) = self.events.lock() {
            v.push((stage, event.clone()));
        }
    }
}

/// Emit an event to both tracing and the sink. Keeps call-sites terse.
pub fn emit(
    sink: Option<&Arc<dyn EventSink>>,
    run_id: &RunId,
    stage: LoopStage,
    event: AgentEvent,
) {
    emit_trace(&event);
    if let Some(s) = sink {
        s.record(run_id, stage, &event);
    }
}

fn emit_trace(event: &AgentEvent) {
    match event {
        AgentEvent::RaceStart { specialists } => {
            tracing::info!(target: "ods::agents", specialists = ?specialists, "race start");
        }
        AgentEvent::SpecialistStart {
            kind,
            target,
            hypothesis,
            seed_recipe_id,
        } => {
            tracing::info!(
                target: "ods::agents",
                specialist = %kind,
                target = %target,
                seed = ?seed_recipe_id,
                hypothesis = %hypothesis,
                "specialist start"
            );
        }
        AgentEvent::Turn {
            specialist,
            iteration,
            stop_reason,
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_creation_tokens,
        } => {
            tracing::info!(
                target: "ods::agents",
                specialist = %specialist,
                iter = iteration,
                stop = ?stop_reason,
                tok_in = input_tokens,
                tok_out = output_tokens,
                cache_read = cache_read_tokens,
                cache_new = cache_creation_tokens,
                "turn"
            );
        }
        AgentEvent::Reasoning {
            specialist,
            iteration,
            text_preview,
        } => {
            tracing::info!(
                target: "ods::agents::reasoning",
                specialist = %specialist,
                iter = iteration,
                text = %text_preview,
                "agent reasoning"
            );
        }
        AgentEvent::ToolCall {
            specialist,
            iteration,
            tool,
            input_preview,
        } => {
            tracing::info!(
                target: "ods::agents::tool",
                specialist = %specialist,
                iter = iteration,
                tool = %tool,
                input = %input_preview,
                "tool call"
            );
        }
        AgentEvent::ToolResult {
            specialist,
            iteration,
            tool,
            ok,
            result_preview,
        } => {
            tracing::info!(
                target: "ods::agents::tool",
                specialist = %specialist,
                iter = iteration,
                tool = %tool,
                ok = ok,
                result = %result_preview,
                "tool result"
            );
        }
        AgentEvent::PatchProposed {
            specialist,
            diff_bytes,
        } => {
            tracing::info!(
                target: "ods::agents",
                specialist = %specialist,
                bytes = diff_bytes,
                "patch proposed"
            );
        }
        AgentEvent::PatchRejected {
            specialist,
            reasons,
        } => {
            tracing::info!(
                target: "ods::agents",
                specialist = %specialist,
                reasons = ?reasons,
                "patch rejected by gate"
            );
        }
        AgentEvent::SpecialistFinish {
            kind,
            patch_attempted,
            accepted,
            spent_usd,
            tokens_in,
            tokens_out,
        } => {
            tracing::info!(
                target: "ods::agents",
                specialist = %kind,
                patch = patch_attempted,
                accepted = accepted,
                cost_usd = spent_usd,
                tok_in = tokens_in,
                tok_out = tokens_out,
                "specialist finish"
            );
        }
        AgentEvent::RaceFinish {
            winner,
            total_spent_usd,
            budget_exhausted,
        } => {
            tracing::info!(
                target: "ods::agents",
                winner = ?winner,
                cost_usd = total_spent_usd,
                budget_exhausted = budget_exhausted,
                "race finish"
            );
        }
        AgentEvent::RecipeRejected {
            source,
            recipe_id,
            reason,
        } => {
            tracing::warn!(
                target: "ods::agents",
                source = %source,
                recipe_id = %recipe_id,
                reason = %preview(reason, 200),
                "recipe rejected by validation gate"
            );
        }
    }
}

fn event_kind(e: &AgentEvent) -> &'static str {
    match e {
        AgentEvent::RaceStart { .. } => "race-start",
        AgentEvent::SpecialistStart { .. } => "specialist-start",
        AgentEvent::Turn { .. } => "turn",
        AgentEvent::Reasoning { .. } => "reasoning",
        AgentEvent::ToolCall { .. } => "tool-call",
        AgentEvent::ToolResult { .. } => "tool-result",
        AgentEvent::PatchProposed { .. } => "patch-proposed",
        AgentEvent::PatchRejected { .. } => "patch-rejected",
        AgentEvent::SpecialistFinish { .. } => "specialist-finish",
        AgentEvent::RaceFinish { .. } => "race-finish",
        AgentEvent::RecipeRejected { .. } => "recipe-rejected",
    }
}

/// Bounded string preview helper. LLM outputs can be long; we clip to keep
/// log lines readable. Newlines are collapsed so each event becomes one
/// logical log line.
pub fn preview(s: &str, n: usize) -> String {
    let collapsed: String = s
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    if collapsed.chars().count() <= n {
        collapsed
    } else {
        let mut out: String = collapsed.chars().take(n).collect();
        out.push_str(" …");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_bounds_length_and_collapses_newlines() {
        assert_eq!(preview("abc\ndef", 100), "abc def");
        assert_eq!(preview("abcdefghij", 5), "abcde …");
    }

    #[test]
    fn sink_captures_events() {
        let sink = Arc::new(InMemorySink::new());
        let rid = RunId::new();
        sink.record(
            &rid,
            LoopStage::Transform,
            &AgentEvent::RaceStart {
                specialists: vec!["A".into(), "B".into()],
            },
        );
        let ev = sink.events.lock().unwrap().clone();
        assert_eq!(ev.len(), 1);
    }
}
