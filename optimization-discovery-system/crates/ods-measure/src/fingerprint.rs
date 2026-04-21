//! Environment fingerprint captured alongside every measurement. Runs whose
//! fingerprints disagree are flagged non-deterministic and the PR is
//! withheld.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvFingerprint {
    pub os: String,
    pub arch: String,
    pub kernel: Option<String>,
    pub cpu_model: Option<String>,
    pub cpu_count: Option<u32>,
    pub cpu_governor: Option<String>,
    pub aslr_disabled: bool,
    pub turbo_disabled: bool,
    pub perf_event_paranoid: Option<i32>,
}

impl EnvFingerprint {
    /// Best-effort capture. All reads are file-system only; we never spawn
    /// subprocesses here so this is cheap enough to call on every sample.
    pub fn capture() -> Self {
        Self {
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            kernel: read_trim("/proc/sys/kernel/osrelease"),
            cpu_model: read_cpuinfo_field("model name"),
            cpu_count: std::thread::available_parallelism()
                .ok()
                .map(|n| n.get() as u32),
            cpu_governor: read_first("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
            aslr_disabled: read_trim("/proc/sys/kernel/randomize_va_space")
                .map(|v| v == "0")
                .unwrap_or(false),
            turbo_disabled: read_trim("/sys/devices/system/cpu/intel_pstate/no_turbo")
                .map(|v| v == "1")
                .or_else(|| {
                    // AMD / generic path
                    read_trim("/sys/devices/system/cpu/cpufreq/boost").map(|v| v == "0")
                })
                .unwrap_or(false),
            perf_event_paranoid: read_trim("/proc/sys/kernel/perf_event_paranoid")
                .and_then(|v| v.parse().ok()),
        }
    }

    /// Backwards-compatible name used by earlier crates.
    pub fn capture_minimal() -> Self {
        Self::capture()
    }

    /// Return the list of fields that differ from `other`. An empty list
    /// means the two measurements are environmentally comparable.
    pub fn diff(&self, other: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.os != other.os {
            out.push("os");
        }
        if self.arch != other.arch {
            out.push("arch");
        }
        if self.kernel != other.kernel {
            out.push("kernel");
        }
        if self.cpu_model != other.cpu_model {
            out.push("cpu_model");
        }
        if self.cpu_count != other.cpu_count {
            out.push("cpu_count");
        }
        if self.cpu_governor != other.cpu_governor {
            out.push("cpu_governor");
        }
        if self.aslr_disabled != other.aslr_disabled {
            out.push("aslr_disabled");
        }
        if self.turbo_disabled != other.turbo_disabled {
            out.push("turbo_disabled");
        }
        if self.perf_event_paranoid != other.perf_event_paranoid {
            out.push("perf_event_paranoid");
        }
        out
    }

    /// Returns `true` when the environment looks sufficiently locked-down
    /// for meaningful benchmark comparisons. Used by the zero-diff gate.
    pub fn is_locked(&self) -> bool {
        self.aslr_disabled && self.turbo_disabled
    }
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn read_first(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
}

fn read_cpuinfo_field(field: &str) -> Option<String> {
    let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == field {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_returns_populated_fields() {
        let fp = EnvFingerprint::capture();
        assert!(!fp.os.is_empty());
        assert!(!fp.arch.is_empty());
    }

    #[test]
    fn diff_detects_mismatch() {
        let a = EnvFingerprint::capture();
        let mut b = a.clone();
        b.cpu_governor = Some("foo".into());
        assert!(a.diff(&b).contains(&"cpu_governor"));
    }
}
