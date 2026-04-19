//! Zero-diff compatibility gate. Combines existing tests, differential/
//! property testing, fuzzing budget, and (for public-API changes or dep
//! bumps) semver checks and downstream-consumer tests.

pub mod downstream;
pub mod gate;
pub mod semver_check;

pub use downstream::{DownstreamConsumer, DownstreamRunner};
pub use gate::{GateDecision, GateInput, GateReport, ZeroDiffGate};
pub use semver_check::{SemverCheck, SemverVerdict};
