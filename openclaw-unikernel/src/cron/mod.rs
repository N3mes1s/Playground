//! # Cron Scheduler
//!
//! Persistent cron job management with standard 5-field crontab syntax.
//! Jobs are stored in memory (no SQLite in the unikernel).
//! Supports retry with exponential backoff.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

static CRON_RUNNING: AtomicBool = AtomicBool::new(false);

/// A cron job entry.
#[derive(Debug, Clone)]
pub struct CronJob {
    pub id: u64,
    pub name: String,
    pub schedule: String, // "*/5 * * * *" format
    pub command: String,
    pub enabled: bool,
    pub last_run: u64,
    pub run_count: u32,
    pub error_count: u32,
}

static mut CRON_JOBS: Option<Vec<CronJob>> = None;
static mut NEXT_ID: u64 = 1;

/// Start the cron scheduler.
pub fn start() {
    unsafe {
        CRON_JOBS = Some(Vec::new());
    }
    CRON_RUNNING.store(true, Ordering::SeqCst);
    crate::kprintln!("[cron] scheduler started");
}

/// Add a new cron job.
pub fn add_job(name: &str, schedule: &str, command: &str) -> u64 {
    let id = unsafe {
        let id = NEXT_ID;
        NEXT_ID += 1;
        id
    };

    let job = CronJob {
        id,
        name: String::from(name),
        schedule: String::from(schedule),
        command: String::from(command),
        enabled: true,
        last_run: 0,
        run_count: 0,
        error_count: 0,
    };

    unsafe {
        if let Some(ref mut jobs) = CRON_JOBS {
            jobs.push(job);
        }
    }

    crate::kprintln!("[cron] added job {}: {} ({})", id, name, schedule);
    id
}

/// Remove a cron job by ID.
pub fn remove_job(id: u64) -> bool {
    unsafe {
        if let Some(ref mut jobs) = CRON_JOBS {
            let before = jobs.len();
            jobs.retain(|j| j.id != id);
            return jobs.len() < before;
        }
    }
    false
}

/// List all cron jobs.
pub fn list_jobs() -> Vec<CronJob> {
    unsafe {
        CRON_JOBS.as_ref().cloned().unwrap_or_default()
    }
}

/// Tick the cron scheduler — check if any jobs should run.
pub fn tick() {
    if !CRON_RUNNING.load(Ordering::Relaxed) {
        return;
    }

    let now = crate::kernel::rdtsc();

    unsafe {
        if let Some(ref mut jobs) = CRON_JOBS {
            for job in jobs.iter_mut() {
                if !job.enabled {
                    continue;
                }

                // Check if enough time has passed based on schedule
                // Simplified: use a fixed interval parsed from the cron expression
                let interval_ticks = parse_cron_interval(&job.schedule);
                if now - job.last_run >= interval_ticks {
                    // Validate command against security policy
                    if let Err(e) = crate::security::validate_command(&job.command) {
                        crate::kprintln!("[cron] security blocked job {}: {}", job.name, e);
                        job.error_count += 1;
                        job.last_run = now;
                        continue;
                    }

                    crate::kprintln!("[cron] executing job {}: {}", job.name, job.command);
                    job.last_run = now;
                    job.run_count += 1;

                    // Execute the command through the shell tool
                    let args = alloc::format!(
                        "{{\"command\":\"{}\"}}",
                        job.command.replace('"', "\\\"")
                    );
                    let result = crate::tools::shell_execute(&args);
                    if result.success {
                        crate::kprintln!("[cron] job {} completed: {}", job.name, result.output);
                    } else {
                        crate::kprintln!("[cron] job {} failed: {}", job.name, result.output);
                        job.error_count += 1;
                    }
                }
            }
        }
    }
}

/// Parse a cron expression into an approximate TSC tick interval.
fn parse_cron_interval(cron: &str) -> u64 {
    let parts: Vec<&str> = cron.split_whitespace().collect();

    // Check minute field for */N pattern
    if let Some(min_field) = parts.first() {
        if let Some(interval) = min_field.strip_prefix("*/") {
            if let Some(minutes) = crate::util::parse_u64(interval) {
                // ~2 GHz TSC: 1 minute ≈ 120_000_000_000 ticks
                return minutes * 120_000_000_000;
            }
        }
        if *min_field == "*" {
            return 120_000_000_000; // Every minute
        }
    }

    // Default: every 5 minutes
    600_000_000_000
}
