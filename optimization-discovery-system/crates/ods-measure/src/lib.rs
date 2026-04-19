//! Measurement plane: profiling, benchmark statistics, environment fingerprint.
//!
//! The core invariant exposed to the rest of the system: a reported speedup
//! is only accepted when `post.ci_lower > pre.ci_upper` at 99% confidence
//! AND the rerun-N gate reports CI overlap across independent runs AND the
//! environment fingerprint is stable across those runs.

pub mod fingerprint;
pub mod pinning;
pub mod profiler;
pub mod rerun;
pub mod stats;

pub use fingerprint::EnvFingerprint;
pub use pinning::{assert_determinism, taskset_prefix, AssertVerdict};
pub use profiler::{ProfileGate, Profiler};
pub use rerun::{rerun, RerunReport};
pub use stats::{compare, ConfidenceInterval, Sample, SpeedupVerdict};
