//! # Heartbeat Engine
//!
//! Reads tasks from a HEARTBEAT.md file and executes them periodically.
//! Tasks are markdown list items that the agent processes on a schedule.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static HEARTBEAT_RUNNING: AtomicBool = AtomicBool::new(false);
static LAST_HEARTBEAT: AtomicU64 = AtomicU64::new(0);

/// Minimum interval between heartbeats (~5 minutes at 2 GHz).
const MIN_INTERVAL_TICKS: u64 = 600_000_000_000;

/// Start the heartbeat engine.
pub fn start() {
    HEARTBEAT_RUNNING.store(true, Ordering::SeqCst);
    crate::kprintln!("[heartbeat] engine started");
}

/// Tick the heartbeat — check if it's time to run tasks.
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

    // Read HEARTBEAT.md from ramfs
    let tasks = match crate::config::ramfs_read("/workspace/HEARTBEAT.md") {
        Some(content) => parse_heartbeat_tasks(&content),
        None => return, // No heartbeat file
    };

    if tasks.is_empty() {
        return;
    }

    crate::kprintln!("[heartbeat] executing {} tasks", tasks.len());
    for task in &tasks {
        crate::kprintln!("[heartbeat] task: {}", task);
        // Inject the task as a webhook message so the daemon picks it up
        // and routes it through the agent
        crate::channels::inject_webhook_message(task, "heartbeat");
    }
}

/// Parse tasks from HEARTBEAT.md (markdown list items).
fn parse_heartbeat_tasks(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
                Some(String::from(&trimmed[2..]))
            } else {
                None
            }
        })
        .collect()
}

/// Stop the heartbeat engine.
pub fn stop() {
    HEARTBEAT_RUNNING.store(false, Ordering::SeqCst);
}
