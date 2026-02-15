//! # Observability
//!
//! Event tracking and metrics for the unikernel agent.
//! Logs to the serial console and tracks key metrics.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use core::sync::atomic::{AtomicU64, Ordering};

/// Event types tracked by the observer.
#[derive(Debug, Clone)]
pub enum Event {
    AgentStart,
    AgentEnd,
    ToolCall { tool: String, duration_ticks: u64 },
    ChannelMessage { channel: String },
    Heartbeat,
    Error { message: String },
    ProviderRequest { provider: String, tokens: u32 },
}

/// Metrics tracked by the observer.
pub struct Metrics {
    pub total_requests: AtomicU64,
    pub total_tokens: AtomicU64,
    pub total_tool_calls: AtomicU64,
    pub total_messages: AtomicU64,
    pub total_errors: AtomicU64,
}

static METRICS: Metrics = Metrics {
    total_requests: AtomicU64::new(0),
    total_tokens: AtomicU64::new(0),
    total_tool_calls: AtomicU64::new(0),
    total_messages: AtomicU64::new(0),
    total_errors: AtomicU64::new(0),
};

/// Record an event.
pub fn record_event(event: &Event) {
    match event {
        Event::AgentStart => {
            crate::kprintln!("[observe] agent started");
        }
        Event::ToolCall { tool, duration_ticks } => {
            METRICS.total_tool_calls.fetch_add(1, Ordering::Relaxed);
            crate::kprintln!("[observe] tool_call: {} ({} ticks)", tool, duration_ticks);
        }
        Event::ChannelMessage { channel } => {
            METRICS.total_messages.fetch_add(1, Ordering::Relaxed);
            crate::kprintln!("[observe] message from {}", channel);
        }
        Event::ProviderRequest { provider, tokens } => {
            METRICS.total_requests.fetch_add(1, Ordering::Relaxed);
            METRICS.total_tokens.fetch_add(*tokens as u64, Ordering::Relaxed);
        }
        Event::Error { message } => {
            METRICS.total_errors.fetch_add(1, Ordering::Relaxed);
            crate::kprintln!("[observe] ERROR: {}", message);
        }
        Event::Heartbeat => {}
        Event::AgentEnd => {}
    }
}

/// Get a snapshot of current metrics.
pub fn snapshot() -> MetricsSnapshot {
    MetricsSnapshot {
        total_requests: METRICS.total_requests.load(Ordering::Relaxed),
        total_tokens: METRICS.total_tokens.load(Ordering::Relaxed),
        total_tool_calls: METRICS.total_tool_calls.load(Ordering::Relaxed),
        total_messages: METRICS.total_messages.load(Ordering::Relaxed),
        total_errors: METRICS.total_errors.load(Ordering::Relaxed),
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub total_requests: u64,
    pub total_tokens: u64,
    pub total_tool_calls: u64,
    pub total_messages: u64,
    pub total_errors: u64,
}

impl MetricsSnapshot {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"requests\":{},\"tokens\":{},\"tool_calls\":{},\"messages\":{},\"errors\":{}}}",
            self.total_requests,
            self.total_tokens,
            self.total_tool_calls,
            self.total_messages,
            self.total_errors
        )
    }
}
