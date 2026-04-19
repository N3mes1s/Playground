//! Structured ingestion of Criterion's JSON output.
//!
//! Criterion writes per-bench directories under `target/criterion/<name>/new/`
//! containing `estimates.json` (mean/CI) and `raw.csv` (per-iteration times).
//! We prefer these to regexing stdout because they include proper confidence
//! intervals and avoid locale/float-format surprises.

use anyhow::{Context, Result};
use ods_lang::{BenchReport, BenchSample};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct Estimates {
    mean: Estimate,
}

#[derive(Debug, Deserialize)]
struct Estimate {
    point_estimate: f64,
    confidence_interval: ConfidenceInterval,
}

#[derive(Debug, Deserialize)]
struct ConfidenceInterval {
    lower_bound: f64,
    upper_bound: f64,
    confidence_level: f64,
}

#[derive(Debug, Clone)]
pub struct CriterionSample {
    pub name: String,
    pub mean_ns: f64,
    pub ci_lower_ns: f64,
    pub ci_upper_ns: f64,
    pub ci_confidence: f64,
}

/// Walk `<workdir>/target/criterion/` and collect all available estimates.
pub fn collect(workdir: &Path) -> Result<Vec<CriterionSample>> {
    let root = workdir.join("target").join("criterion");
    if !root.exists() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    visit(&root, &mut out)?;
    Ok(out)
}

fn visit(dir: &Path, out: &mut Vec<CriterionSample>) -> Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let p = e.path();
        if p.is_dir() {
            let est = p.join("new").join("estimates.json");
            if est.exists() {
                let text = std::fs::read_to_string(&est)
                    .with_context(|| format!("read {}", est.display()))?;
                let parsed: Estimates = serde_json::from_str(&text)?;
                let name = p
                    .strip_prefix(dir)
                    .map(|r| r.display().to_string())
                    .unwrap_or_else(|_| p.display().to_string());
                out.push(CriterionSample {
                    name,
                    mean_ns: parsed.mean.point_estimate,
                    ci_lower_ns: parsed.mean.confidence_interval.lower_bound,
                    ci_upper_ns: parsed.mean.confidence_interval.upper_bound,
                    ci_confidence: parsed.mean.confidence_interval.confidence_level,
                });
            } else {
                visit(&p, out)?;
            }
        }
    }
    Ok(())
}

pub fn to_bench_report(samples: Vec<CriterionSample>) -> BenchReport {
    BenchReport {
        samples: samples
            .into_iter()
            .map(|s| BenchSample {
                name: s.name,
                ns_per_iter: s.mean_ns,
                iters: 1,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_estimates_json_shape() {
        let dir = tempfile::tempdir().unwrap();
        let crit = dir.path().join("target/criterion/my_bench/new");
        std::fs::create_dir_all(&crit).unwrap();
        let json = r#"{
            "mean": {
                "point_estimate": 1234.5,
                "standard_error": 1.0,
                "confidence_interval": {
                    "confidence_level": 0.95,
                    "lower_bound": 1200.0,
                    "upper_bound": 1260.0
                }
            }
        }"#;
        std::fs::write(crit.join("estimates.json"), json).unwrap();
        let got = collect(dir.path()).unwrap();
        assert_eq!(got.len(), 1);
        assert!((got[0].mean_ns - 1234.5).abs() < 1e-9);
    }
}
