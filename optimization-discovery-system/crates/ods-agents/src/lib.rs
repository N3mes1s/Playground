//! Agent plane.
//!
//! A [`Planner`] inspects profile evidence and retrieved recipes, then routes
//! work to one or more [`Specialist`]s. Each specialist is a distinct system
//! prompt + tool allowlist running inside the same [`anthropic::ToolUseLoop`].
//! All tools are typed Rust functions; there is no shell-out to an external
//! CLI, keeping the musl single-binary story intact.

pub mod anthropic;
pub mod diff_apply;
pub mod discover;
pub mod explorer;
pub mod harvest;
pub mod observe;
pub mod orchestrator;
pub mod planner;
pub mod race;
pub mod recipe_validate;
pub mod schedule;
pub mod specialist;
pub mod tools;

pub use anthropic::{AnthropicClient, Conversation, LoopStats, ToolCall, ToolResult, ToolUseLoop};
pub use discover::{Candidate, Discoverer};
pub use explorer::{run_explorer, ExplorerInput, ExplorerOutcome};
pub use harvest::{harvest as harvest_candidate, harvest_full, record_negatives, HarvestOutcome};
pub use observe::{AgentEvent, EventSink, InMemorySink, SqliteEventSink};
pub use orchestrator::{Orchestrator, RunArtifact};
pub use planner::Planner;
pub use race::{run_specialists, RaceInput, RaceOutput, WinnerRecord};
pub use schedule::{BatchArtifact, Scheduler};
pub use specialist::{Specialist, SpecialistKind, SpecialistOutcome};
pub use tools::{SpecialistToolkit, ToolHandlerMap};
