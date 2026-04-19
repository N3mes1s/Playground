use crate::semver_check::SemverVerdict;
use anyhow::Result;
use ods_lang::{FuzzReport, TestReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateInput {
    pub tests: TestReport,
    pub property_tests: Option<TestReport>,
    pub fuzz: Option<FuzzReport>,
    pub semver: Option<SemverVerdict>,
    pub downstream_tests: Vec<TestReport>,
    pub touches_public_api: bool,
    pub is_dep_bump: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateDecision {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateReport {
    pub decision: GateDecision,
    pub reasons: Vec<String>,
}

pub struct ZeroDiffGate {
    pub min_fuzz_minutes: u32,
}

impl Default for ZeroDiffGate {
    fn default() -> Self {
        Self {
            min_fuzz_minutes: 5,
        }
    }
}

impl ZeroDiffGate {
    pub fn evaluate(&self, input: &GateInput) -> Result<GateReport> {
        let mut reasons = Vec::new();

        if !input.tests.green() {
            reasons.push(format!("{} project test(s) failed", input.tests.failed));
        }

        if let Some(pt) = &input.property_tests {
            if !pt.green() {
                reasons.push(format!(
                    "{} differential/property-test failure(s)",
                    pt.failed
                ));
            }
        }

        if let Some(f) = &input.fuzz {
            if f.crashes > 0 {
                reasons.push(format!("{} fuzzing crash(es)", f.crashes));
            }
            if f.minutes < self.min_fuzz_minutes {
                reasons.push(format!(
                    "fuzz budget {}m below minimum {}m",
                    f.minutes, self.min_fuzz_minutes
                ));
            }
        } else if input.touches_public_api || input.is_dep_bump {
            reasons.push("fuzz run required for public-API or dep changes".into());
        }

        if input.touches_public_api {
            match &input.semver {
                Some(SemverVerdict::Compatible) => {}
                Some(SemverVerdict::Breaking(items)) => {
                    reasons.push(format!(
                        "cargo-semver-checks reported {} breaking change(s)",
                        items.len()
                    ));
                }
                Some(SemverVerdict::Unchecked(reason)) => {
                    reasons.push(format!("semver check skipped: {reason}"));
                }
                None => reasons.push("semver check missing on public-API change".into()),
            }
        }

        if input.is_dep_bump {
            if input.downstream_tests.is_empty() {
                reasons.push("dep bump requires downstream test runs".into());
            } else {
                let failed: u32 = input.downstream_tests.iter().map(|r| r.failed).sum();
                if failed > 0 {
                    reasons.push(format!("{failed} downstream test failure(s)"));
                }
            }
        }

        let decision = if reasons.is_empty() {
            GateDecision::Pass
        } else {
            GateDecision::Fail
        };
        Ok(GateReport { decision, reasons })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn green_tests() -> TestReport {
        TestReport {
            passed: 42,
            failed: 0,
            skipped: 0,
            log_path: None,
        }
    }

    #[test]
    fn clean_in_repo_change_passes() {
        let gate = ZeroDiffGate::default();
        let input = GateInput {
            tests: green_tests(),
            property_tests: Some(green_tests()),
            fuzz: Some(FuzzReport {
                minutes: 5,
                crashes: 0,
                seed_corpus_size: 0,
            }),
            semver: None,
            downstream_tests: vec![],
            touches_public_api: false,
            is_dep_bump: false,
        };
        let report = gate.evaluate(&input).unwrap();
        assert_eq!(report.decision, GateDecision::Pass, "{:?}", report);
    }

    #[test]
    fn dep_bump_without_downstream_fails() {
        let gate = ZeroDiffGate::default();
        let input = GateInput {
            tests: green_tests(),
            property_tests: None,
            fuzz: Some(FuzzReport {
                minutes: 10,
                crashes: 0,
                seed_corpus_size: 0,
            }),
            semver: Some(SemverVerdict::Compatible),
            downstream_tests: vec![],
            touches_public_api: false,
            is_dep_bump: true,
        };
        let report = gate.evaluate(&input).unwrap();
        assert_eq!(report.decision, GateDecision::Fail);
    }
}
