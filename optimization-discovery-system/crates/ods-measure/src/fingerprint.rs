//! Environment fingerprint captured alongside every measurement. Runs whose
//! fingerprints disagree are flagged non-deterministic and the PR is
//! withheld.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvFingerprint {
    pub os: String,
    pub arch: String,
    pub kernel: Option<String>,
    pub cpu_model: Option<String>,
    pub cpu_governor: Option<String>,
    pub aslr_disabled: bool,
    pub turbo_disabled: bool,
}

impl EnvFingerprint {
    /// Minimal fingerprint that does not require spawning subprocesses. The
    /// richer fingerprint (reading `/proc/cpuinfo`, `cpufreq` governor, etc.)
    /// lands in stage 1 on the Linux measurement path.
    pub fn capture_minimal() -> Self {
        Self {
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            kernel: None,
            cpu_model: None,
            cpu_governor: None,
            aslr_disabled: false,
            turbo_disabled: false,
        }
    }
}
