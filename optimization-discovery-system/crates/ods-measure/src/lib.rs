//! Measurement plane: profiling, benchmark statistics, environment fingerprint.
//!
//! The core invariant exposed to the rest of the system: a reported speedup
//! is only accepted when `post.ci_lower > pre.ci_upper` at 99% confidence.

pub mod fingerprint;
pub mod profiler;
pub mod stats;

pub use fingerprint::EnvFingerprint;
pub use profiler::{ProfileGate, Profiler};
pub use stats::{compare, ConfidenceInterval, Sample, SpeedupVerdict};
