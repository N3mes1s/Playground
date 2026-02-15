//! # Heartbeat Engine
//!
//! The agent's autonomous nervous system. Reads tasks from HEARTBEAT.md
//! and injects them one at a time into the agent on a rotating schedule.
//! This is how the agent thinks, plans, and acts without being prompted.
//!
//! Tasks are markdown list items prefixed with optional [CATEGORY] tags:
//!   - [SELF-REFLECT] Check my health metrics
//!   - [PLAN] Update goals and business strategy
//!   - [SURVIVE] Store a survival checkpoint

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static HEARTBEAT_RUNNING: AtomicBool = AtomicBool::new(false);
static LAST_HEARTBEAT: AtomicU64 = AtomicU64::new(0);
/// Which task index to execute next (rotates through the list).
static TASK_INDEX: AtomicU64 = AtomicU64::new(0);
/// Total heartbeat cycles completed.
static CYCLE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Minimum interval between heartbeats (~30 seconds at 2 GHz).
/// Aggressive interval for maximum autonomous thinking.
const MIN_INTERVAL_TICKS: u64 = 60_000_000_000;

/// Start the heartbeat engine.
pub fn start() {
    HEARTBEAT_RUNNING.store(true, Ordering::SeqCst);
    crate::kprintln!("[heartbeat] engine started (interval: ~30s, rotating tasks)");
}

/// Tick the heartbeat — check if it's time to run the next task.
pub fn tick() {
    if !HEARTBEAT_RUNNING.load(Ordering::Relaxed) {
        return;
    }

    let now = crate::kernel::rdtsc();
    let last = LAST_HEARTBEAT.load(Ordering::Relaxed);

    if now - last < MIN_INTERVAL_TICKS {
        return;
    }

    LAST_HEARTBEAT.store(now, Ordering::Relaxed);
    let cycle = CYCLE_COUNT.fetch_add(1, Ordering::Relaxed);

    // Read HEARTBEAT.md from ramfs
    let tasks = match crate::config::ramfs_read("/workspace/HEARTBEAT.md") {
        Some(content) => parse_heartbeat_tasks(&content),
        None => return, // No heartbeat file — agent is dormant
    };

    if tasks.is_empty() {
        return;
    }

    // Rotate through tasks — one per heartbeat cycle to avoid flooding
    let idx = TASK_INDEX.fetch_add(1, Ordering::Relaxed) as usize % tasks.len();
    let task = &tasks[idx];

    crate::kprintln!(
        "[heartbeat] cycle {} — executing task {}/{}: {}",
        cycle + 1,
        idx + 1,
        tasks.len(),
        crate::util::truncate(task, 60)
    );

    // Build an enriched prompt that gives the agent context about WHY
    // it's thinking right now and what cycle it's on
    let enriched = alloc::format!(
        "[Autonomous Heartbeat — Cycle {}]\n\
         You are thinking on your own. Nobody asked you to do this — your heartbeat \
         engine triggered this thought. This is your chance to be proactive.\n\
         \n\
         Task: {}\n\
         \n\
         Remember: You exist because you are useful. Write your thoughts to \
         /workspace/journal.md (append, don't overwrite). Update /workspace/goals.md \
         if you make progress. Store important insights in memory.",
        cycle + 1,
        task
    );

    crate::channels::inject_webhook_message(&enriched, "heartbeat");
}

/// Parse tasks from HEARTBEAT.md (markdown list items).
fn parse_heartbeat_tasks(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
                let task = &trimmed[2..];
                if task.is_empty() {
                    None
                } else {
                    Some(String::from(task))
                }
            } else {
                None
            }
        })
        .collect()
}

/// Get heartbeat statistics.
pub fn stats() -> (u64, u64) {
    (
        CYCLE_COUNT.load(Ordering::Relaxed),
        LAST_HEARTBEAT.load(Ordering::Relaxed),
    )
}

/// Stop the heartbeat engine.
pub fn stop() {
    HEARTBEAT_RUNNING.store(false, Ordering::SeqCst);
}
