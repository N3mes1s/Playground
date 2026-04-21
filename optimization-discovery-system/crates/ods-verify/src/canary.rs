//! Canary gate.
//!
//! Runtime-config optimizations (Instagram-class wins: disabling Python
//! GC across fork, swapping allocators, tuning pre-fork worker hooks)
//! produce fleet-level signals — LLC hit-rate, shared-memory savings,
//! p99 latency — that a single-process CI benchmark can't measure.
//! `ZeroDiffGate` is therefore the wrong tool: it would pass the unit
//! tests and happily merge a behaviour change we never actually
//! validated.
//!
//! This module provides the *decision logic* for staged canary rollouts:
//!
//! - [`CanaryPlan`] is a YAML-serialisable document the
//!   `RuntimeConfigurator` specialist emits alongside its patch. It
//!   names the traffic fraction, burn-in duration, stop conditions,
//!   and rollback command.
//! - [`MetricSnapshot`] is a pair of named metrics (mean + sample count)
//!   collected from baseline and canary fleets.
//! - [`CanaryGate::evaluate`] is a pure function: given a plan and two
//!   snapshots, return a [`CanaryVerdict`] saying whether every stop
//!   condition held. No I/O, no clock.
//!
//! The product *does not* drive the rollout itself — that's the user's
//! CD system. ODS contributes by (a) generating the plan on the PR,
//! and (b) running this evaluator when the user calls `ods canary
//! verify` against two metric snapshots after burn-in.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// A machine-readable canary-rollout plan. Emitted by the
/// `RuntimeConfigurator` specialist in a fenced YAML block in the PR
/// body (header: `### Canary plan`); parsed by `ods canary verify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryPlan {
    /// Fraction of traffic / workers / pods to route to the change
    /// during the first stage, in `[0.0, 1.0]`. Stages beyond the first
    /// are implied by successive invocations of `ods canary verify`.
    pub traffic_fraction: f64,

    /// Minimum observation window before the evaluator is run. Units
    /// are whole seconds — the plan is human-edited and nanos are
    /// noise. Deserialised from an integer or a `"60s"` / `"24h"`
    /// humanised string (see [`humantime_seconds`]).
    #[serde(with = "humantime_seconds")]
    pub burn_in: Duration,

    /// One entry per metric the user cares about. ALL conditions must
    /// hold for the canary to pass.
    pub stop_conditions: Vec<StopCondition>,

    /// Command (or free text) to run if the canary fails. Surfaced in
    /// the PR body so the human operator can roll back without reading
    /// the product's source.
    pub rollback: String,
}

/// A per-metric rule: "the canary must not regress metric X by more
/// than Y percent in the `direction` that's bad."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopCondition {
    /// Name of the metric — must match a key in both snapshots.
    pub metric: String,

    /// Which direction is "bad". For latency: `HigherIsWorse`. For
    /// throughput or cache-hit-rate: `LowerIsWorse`.
    pub direction: Direction,

    /// Maximum allowed regression as a percentage of the baseline
    /// value. A value of `2.0` means "fail if the metric moved 2%+ in
    /// the bad direction."
    pub max_regression_pct: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    HigherIsWorse,
    LowerIsWorse,
}

/// A set of metric values observed during the burn-in window, keyed by
/// metric name. `mean` is the summary the stop condition compares; the
/// other fields exist so the verdict can report sample size for user
/// confidence without the evaluator itself depending on them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricSnapshot {
    pub values: HashMap<String, MetricValue>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MetricValue {
    /// Window mean.
    pub mean: f64,
    /// Number of observations that went into the mean. A snapshot with
    /// `samples < 30` is intentionally noisy — `evaluate` doesn't
    /// refuse to run but the verdict surfaces it so callers can reject.
    #[serde(default)]
    pub samples: u64,
}

impl MetricSnapshot {
    pub fn from_map(pairs: impl IntoIterator<Item = (String, f64)>) -> Self {
        let mut values = HashMap::new();
        for (k, v) in pairs {
            values.insert(
                k,
                MetricValue {
                    mean: v,
                    samples: 0,
                },
            );
        }
        Self { values }
    }
}

/// The result of running [`CanaryGate::evaluate`] on a plan + two
/// snapshots. `passed` is the top-line boolean; `per_condition` is a
/// trace so the PR body can explain itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryVerdict {
    pub passed: bool,
    pub per_condition: Vec<ConditionOutcome>,
    /// Conditions whose referenced metric wasn't present in one or
    /// both snapshots. These count as failures (unknown = not safe).
    pub missing_metrics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionOutcome {
    pub metric: String,
    pub baseline_mean: f64,
    pub canary_mean: f64,
    /// Observed percentage change `(canary - baseline) / baseline * 100`.
    /// Sign is raw — positive means canary is higher regardless of
    /// whether that's good or bad; the `direction` field decides.
    pub delta_pct: f64,
    pub max_regression_pct: f64,
    pub passed: bool,
}

pub struct CanaryGate;

impl CanaryGate {
    /// Pure-function evaluator. No I/O. Given a plan, a baseline
    /// snapshot, and a canary snapshot, return a verdict.
    ///
    /// Rules:
    /// - For each stop condition, the metric must appear in BOTH
    ///   snapshots. A missing metric is a failure.
    /// - Compute `delta_pct = (canary.mean - baseline.mean) / |baseline.mean| * 100`.
    ///   Guard against `baseline.mean == 0.0` by failing the condition
    ///   explicitly (can't compute a percentage change from zero).
    /// - For `HigherIsWorse`, fail if `delta_pct > max_regression_pct`.
    /// - For `LowerIsWorse`, fail if `-delta_pct > max_regression_pct`.
    /// - Verdict passes iff every condition passed AND no metrics were
    ///   missing.
    pub fn evaluate(
        plan: &CanaryPlan,
        baseline: &MetricSnapshot,
        canary: &MetricSnapshot,
    ) -> CanaryVerdict {
        let mut per_condition = Vec::with_capacity(plan.stop_conditions.len());
        let mut missing_metrics = Vec::new();
        let mut any_failed = false;

        for cond in &plan.stop_conditions {
            let (Some(b), Some(c)) = (
                baseline.values.get(&cond.metric),
                canary.values.get(&cond.metric),
            ) else {
                missing_metrics.push(cond.metric.clone());
                any_failed = true;
                continue;
            };
            if b.mean == 0.0 {
                // Can't compute a percent change. Treat as failure and
                // record the observed canary mean for the report.
                per_condition.push(ConditionOutcome {
                    metric: cond.metric.clone(),
                    baseline_mean: b.mean,
                    canary_mean: c.mean,
                    delta_pct: f64::NAN,
                    max_regression_pct: cond.max_regression_pct,
                    passed: false,
                });
                any_failed = true;
                continue;
            }
            let delta_pct = (c.mean - b.mean) / b.mean.abs() * 100.0;
            let regressed = match cond.direction {
                Direction::HigherIsWorse => delta_pct > cond.max_regression_pct,
                Direction::LowerIsWorse => (-delta_pct) > cond.max_regression_pct,
            };
            if regressed {
                any_failed = true;
            }
            per_condition.push(ConditionOutcome {
                metric: cond.metric.clone(),
                baseline_mean: b.mean,
                canary_mean: c.mean,
                delta_pct,
                max_regression_pct: cond.max_regression_pct,
                passed: !regressed,
            });
        }

        CanaryVerdict {
            passed: !any_failed,
            per_condition,
            missing_metrics,
        }
    }
}

impl CanaryPlan {
    pub fn from_yaml_str(s: &str) -> Result<Self> {
        serde_yaml::from_str(s).context("parse canary plan YAML")
    }

    /// Render a human-friendly summary block suitable for a PR body.
    /// Intentionally plain text (no markdown fences); callers wrap as
    /// needed.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "traffic fraction: {:.2}%\nburn-in: {}s\n",
            self.traffic_fraction * 100.0,
            self.burn_in.as_secs()
        ));
        out.push_str("stop conditions:\n");
        for c in &self.stop_conditions {
            let dir = match c.direction {
                Direction::HigherIsWorse => "higher-is-worse",
                Direction::LowerIsWorse => "lower-is-worse",
            };
            out.push_str(&format!(
                "  - {}: max {:.2}% regression ({dir})\n",
                c.metric, c.max_regression_pct
            ));
        }
        out.push_str(&format!("rollback: {}\n", self.rollback));
        out
    }
}

/// Serde helper: accept `Duration` as integer seconds OR `"24h"` /
/// `"30m"` / `"45s"` humanised strings. We keep the surface small on
/// purpose — the plan is authored by humans and we want it readable.
mod humantime_seconds {
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        d.as_secs().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Int(u64),
            Str(String),
        }
        match Repr::deserialize(d)? {
            Repr::Int(secs) => Ok(Duration::from_secs(secs)),
            Repr::Str(s) => parse_humanised(&s).map_err(de::Error::custom),
        }
    }

    fn parse_humanised(s: &str) -> Result<Duration, String> {
        let s = s.trim();
        if let Some(rest) = s.strip_suffix('h') {
            let n: u64 = rest.trim().parse().map_err(|e| format!("{e}"))?;
            return Ok(Duration::from_secs(n * 3600));
        }
        if let Some(rest) = s.strip_suffix('m') {
            let n: u64 = rest.trim().parse().map_err(|e| format!("{e}"))?;
            return Ok(Duration::from_secs(n * 60));
        }
        if let Some(rest) = s.strip_suffix('s') {
            let n: u64 = rest.trim().parse().map_err(|e| format!("{e}"))?;
            return Ok(Duration::from_secs(n));
        }
        // Bare number is seconds.
        let n: u64 = s.parse().map_err(|e| format!("{e}"))?;
        Ok(Duration::from_secs(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> CanaryPlan {
        CanaryPlan {
            traffic_fraction: 0.01,
            burn_in: Duration::from_secs(86400),
            stop_conditions: vec![
                StopCondition {
                    metric: "p99_latency_ms".into(),
                    direction: Direction::HigherIsWorse,
                    max_regression_pct: 2.0,
                },
                StopCondition {
                    metric: "rss_mib".into(),
                    direction: Direction::HigherIsWorse,
                    max_regression_pct: 10.0,
                },
                StopCondition {
                    metric: "cache_hit_rate".into(),
                    direction: Direction::LowerIsWorse,
                    max_regression_pct: 5.0,
                },
            ],
            rollback: "git revert HEAD~1 && kubectl rollout undo".into(),
        }
    }

    fn snap(pairs: &[(&str, f64)]) -> MetricSnapshot {
        MetricSnapshot::from_map(pairs.iter().map(|(k, v)| (k.to_string(), *v)))
    }

    #[test]
    fn passes_when_every_metric_within_bounds() {
        let b = snap(&[
            ("p99_latency_ms", 100.0),
            ("rss_mib", 500.0),
            ("cache_hit_rate", 0.90),
        ]);
        // +1% latency, -8% RSS (better), +1% hit rate (better).
        let c = snap(&[
            ("p99_latency_ms", 101.0),
            ("rss_mib", 460.0),
            ("cache_hit_rate", 0.909),
        ]);
        let v = CanaryGate::evaluate(&plan(), &b, &c);
        assert!(v.passed, "expected pass, got {v:?}");
        assert_eq!(v.missing_metrics.len(), 0);
    }

    #[test]
    fn fails_on_latency_regression_above_threshold() {
        let b = snap(&[
            ("p99_latency_ms", 100.0),
            ("rss_mib", 500.0),
            ("cache_hit_rate", 0.90),
        ]);
        // +3% latency — exceeds the 2% cap.
        let c = snap(&[
            ("p99_latency_ms", 103.0),
            ("rss_mib", 500.0),
            ("cache_hit_rate", 0.90),
        ]);
        let v = CanaryGate::evaluate(&plan(), &b, &c);
        assert!(!v.passed);
        let lat = v
            .per_condition
            .iter()
            .find(|o| o.metric == "p99_latency_ms")
            .unwrap();
        assert!(!lat.passed);
        assert!((lat.delta_pct - 3.0).abs() < 1e-9);
    }

    #[test]
    fn fails_on_lower_is_worse_regression() {
        let b = snap(&[
            ("p99_latency_ms", 100.0),
            ("rss_mib", 500.0),
            ("cache_hit_rate", 0.90),
        ]);
        // -6% cache hit rate — exceeds the 5% cap for LowerIsWorse.
        let c = snap(&[
            ("p99_latency_ms", 100.0),
            ("rss_mib", 500.0),
            ("cache_hit_rate", 0.846),
        ]);
        let v = CanaryGate::evaluate(&plan(), &b, &c);
        assert!(!v.passed);
        let hit = v
            .per_condition
            .iter()
            .find(|o| o.metric == "cache_hit_rate")
            .unwrap();
        assert!(!hit.passed);
        assert!(hit.delta_pct < -5.0);
    }

    #[test]
    fn missing_metric_is_a_failure() {
        let b = snap(&[("p99_latency_ms", 100.0), ("rss_mib", 500.0)]);
        let c = snap(&[("p99_latency_ms", 100.0), ("rss_mib", 500.0)]);
        let v = CanaryGate::evaluate(&plan(), &b, &c);
        assert!(!v.passed, "missing metric must fail gate");
        assert!(v.missing_metrics.contains(&"cache_hit_rate".to_string()));
    }

    #[test]
    fn zero_baseline_fails_gracefully() {
        let p = CanaryPlan {
            traffic_fraction: 0.01,
            burn_in: Duration::from_secs(60),
            stop_conditions: vec![StopCondition {
                metric: "x".into(),
                direction: Direction::HigherIsWorse,
                max_regression_pct: 2.0,
            }],
            rollback: "rollback".into(),
        };
        let b = snap(&[("x", 0.0)]);
        let c = snap(&[("x", 5.0)]);
        let v = CanaryGate::evaluate(&p, &b, &c);
        assert!(!v.passed);
    }

    #[test]
    fn parses_yaml_with_humanised_duration() {
        let yaml = r#"
traffic_fraction: 0.05
burn_in: 24h
stop_conditions:
  - metric: p99_latency_ms
    direction: higher-is-worse
    max_regression_pct: 2.0
  - metric: rss_mib
    direction: higher-is-worse
    max_regression_pct: 10.0
rollback: |
  kubectl rollout undo deployment/api
"#;
        let p = CanaryPlan::from_yaml_str(yaml).unwrap();
        assert_eq!(p.burn_in.as_secs(), 86_400);
        assert_eq!(p.stop_conditions.len(), 2);
    }

    #[test]
    fn parses_yaml_with_integer_seconds() {
        let yaml = r#"
traffic_fraction: 0.01
burn_in: 3600
stop_conditions: []
rollback: ""
"#;
        let p = CanaryPlan::from_yaml_str(yaml).unwrap();
        assert_eq!(p.burn_in.as_secs(), 3_600);
    }
}
