//! Profiler orchestration. Linux uses `perf_event_open` + eBPF (wired in stage
//! 1 via `perf-event2` and `aya`); macOS falls back to `dtrace`; other
//! platforms expose a sampling-only profiler. Today we ship the trait so the
//! loop compiles.

use anyhow::Result;
use ods_core::TargetSig;
use ods_lang::{Build, ProfileReport};
use serde::{Deserialize, Serialize};

/// Mandatory signals a profiler must attempt to collect. The gate rejects
/// reports that are missing too many of these on platforms where they should
/// be available (Linux in CI is the blessed path).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ProfileGate {
    pub require_cycles: bool,
    pub require_syscalls: bool,
    pub require_allocations: bool,
}

impl Default for ProfileGate {
    fn default() -> Self {
        Self {
            require_cycles: cfg!(target_os = "linux"),
            require_syscalls: cfg!(target_os = "linux"),
            require_allocations: cfg!(target_os = "linux"),
        }
    }
}

impl ProfileGate {
    pub fn validate(&self, report: &ProfileReport) -> Result<()> {
        if self.require_cycles && report.cycles.is_none() {
            anyhow::bail!("profile missing `cycles` counter");
        }
        if self.require_syscalls && report.syscall_counts.is_empty() {
            anyhow::bail!("profile missing syscall counts");
        }
        if self.require_allocations && report.alloc_count.is_none() {
            anyhow::bail!("profile missing allocation counts");
        }
        Ok(())
    }
}

pub trait Profiler: Send + Sync {
    fn name(&self) -> &'static str;
    fn profile(&self, build: &Build, target: &TargetSig) -> Result<ProfileReport>;
}
