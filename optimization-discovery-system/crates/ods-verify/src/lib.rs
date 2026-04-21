//! Zero-diff compatibility gate. Combines existing tests, differential/
//! property testing, fuzzing budget, and (for public-API changes or dep
//! bumps) semver checks and downstream-consumer tests.

pub mod canary;
pub mod downstream;
pub mod gate;
pub mod property;
pub mod semver_check;

pub use canary::{
    CanaryGate, CanaryPlan, CanaryVerdict, ConditionOutcome, Direction, MetricSnapshot,
    MetricValue, StopCondition,
};
pub use downstream::{DownstreamConsumer, DownstreamRunner};
pub use gate::{GateDecision, GateInput, GateReport, ZeroDiffGate};
pub use property::{DifferentialHarness, PropertyFailure, PropertyReport};
pub use semver_check::{SemverCheck, SemverVerdict};
