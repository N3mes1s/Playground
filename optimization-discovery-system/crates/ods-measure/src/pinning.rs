//! CPU-pinning + determinism helpers. We can't actually *freeze* the CPU
//! governor from a user-space process, but we can:
//!   * wrap a command with `taskset -c <cpu>` to pin it to a specific core,
//!   * assert that the kernel's `perf_event_paranoid` is permissive enough
//!     for the perf-stat path,
//!   * assert the current governor is `performance`.
//!
//! Returning an `AssertVerdict::Locked` means the measurement pipeline is
//! ready for a "green" measurement; `Soft(reason)` lets the run proceed
//! but annotates the report so reviewers understand why CIs might be wide.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssertVerdict {
    Locked,
    Soft(Vec<String>),
}

pub fn assert_determinism() -> AssertVerdict {
    let mut issues = Vec::new();
    if let Some(g) =
        std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
            .ok()
            .map(|s| s.trim().to_string())
    {
        if g != "performance" {
            issues.push(format!("cpu0 governor is `{g}`, not `performance`"));
        }
    } else {
        issues.push("cpufreq governor not readable (container?)".into());
    }
    if let Some(p) = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
    {
        if p > 2 {
            issues.push(format!("perf_event_paranoid={p} blocks perf stat"));
        }
    }
    if issues.is_empty() {
        AssertVerdict::Locked
    } else {
        AssertVerdict::Soft(issues)
    }
}

/// Wrap `cmd args...` with `taskset -c <cpu>` when taskset is available.
/// Returns the composed argv; callers are responsible for executing it.
pub fn taskset_prefix(cpu: u32, cmd: &str, args: &[&str]) -> Vec<String> {
    let have_taskset = Command::new("taskset")
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if have_taskset {
        let mut out = vec![
            "taskset".to_string(),
            "-c".into(),
            cpu.to_string(),
            cmd.into(),
        ];
        out.extend(args.iter().map(|s| s.to_string()));
        out
    } else {
        let mut out = vec![cmd.to_string()];
        out.extend(args.iter().map(|s| s.to_string()));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taskset_prefix_shapes_argv() {
        let v = taskset_prefix(0, "cargo", &["bench"]);
        // First element is either taskset or cargo depending on host.
        assert!(v.contains(&"cargo".to_string()));
        assert!(v.contains(&"bench".to_string()));
    }
}
