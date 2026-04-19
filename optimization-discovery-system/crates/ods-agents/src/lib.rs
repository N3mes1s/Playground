//! Agent plane.
//!
//! A [`Planner`] inspects profile evidence and retrieved recipes, then routes
//! work to one or more [`Specialist`]s. Each specialist is a distinct system
//! prompt + tool allowlist running inside the same [`anthropic::ToolUseLoop`].
//! All tools are typed Rust functions; there is no shell-out to an external
//! CLI, keeping the musl single-binary story intact.

pub mod anthropic;
pub mod orchestrator;
pub mod planner;
pub mod specialist;
pub mod tools;

pub use anthropic::{AnthropicClient, Conversation, LoopStats, ToolCall, ToolResult, ToolUseLoop};
pub use orchestrator::{Orchestrator, RunArtifact};
pub use planner::Planner;
pub use specialist::{Specialist, SpecialistKind, SpecialistOutcome};
pub use tools::{SpecialistToolkit, ToolHandlerMap};
