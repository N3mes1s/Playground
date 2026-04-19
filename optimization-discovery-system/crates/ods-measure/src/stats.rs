//! Criterion-style comparison with bootstrap confidence intervals.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub name: String,
    pub values_ns: Vec<f64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub lower: f64,
    pub point: f64,
    pub upper: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedupVerdict {
    pub pre: ConfidenceInterval,
    pub post: ConfidenceInterval,
    pub speedup_point: f64,
    pub speedup_lower: f64,
    pub accepted: bool,
    pub note: String,
}

/// Drop outliers outside Tukey fences (1.5 × IQR).
fn tukey_filter(values: &[f64]) -> Vec<f64> {
    if values.len() < 4 {
        return values.to_vec();
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let q1 = sorted[sorted.len() / 4];
    let q3 = sorted[sorted.len() * 3 / 4];
    let iqr = q3 - q1;
    let lo = q1 - 1.5 * iqr;
    let hi = q3 + 1.5 * iqr;
    sorted.into_iter().filter(|v| *v >= lo && *v <= hi).collect()
}

fn percentile(values: &mut [f64], p: f64) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if values.is_empty() {
        return f64::NAN;
    }
    let idx = ((values.len() - 1) as f64 * p).round() as usize;
    values[idx]
}

/// Deterministic xorshift-based bootstrap. Picking our own RNG keeps the
/// binary free of a rand dep and keeps reruns reproducible when the seed is
/// identical.
struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn index(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
}

fn bootstrap_ci(values: &[f64], confidence: f64, iters: usize, seed: u64) -> ConfidenceInterval {
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let mut rng = XorShift64(seed.max(1));
    let mut means = Vec::with_capacity(iters);
    for _ in 0..iters {
        let mut sum = 0.0;
        for _ in 0..values.len() {
            sum += values[rng.index(values.len())];
        }
        means.push(sum / values.len() as f64);
    }
    let alpha = (1.0 - confidence) / 2.0;
    let lower = percentile(&mut means.clone(), alpha);
    let upper = percentile(&mut means, 1.0 - alpha);
    ConfidenceInterval {
        lower,
        point: mean,
        upper,
        confidence,
    }
}

/// Compare pre and post samples. Returns `accepted = true` only if the
/// post-change CI upper bound is strictly below the pre-change CI lower bound
/// (i.e. the improvement is statistically significant at the given confidence).
pub fn compare(pre: &Sample, post: &Sample) -> SpeedupVerdict {
    const CONFIDENCE: f64 = 0.99;
    const ITERS: usize = 2000;

    let pre_values = tukey_filter(&pre.values_ns);
    let post_values = tukey_filter(&post.values_ns);

    let pre_ci = bootstrap_ci(&pre_values, CONFIDENCE, ITERS, 0xC0FFEE);
    let post_ci = bootstrap_ci(&post_values, CONFIDENCE, ITERS, 0xDEADBEEF);

    let speedup_point = if post_ci.point > 0.0 {
        pre_ci.point / post_ci.point
    } else {
        f64::INFINITY
    };
    let speedup_lower = if post_ci.upper > 0.0 {
        pre_ci.lower / post_ci.upper
    } else {
        f64::INFINITY
    };

    let accepted = post_ci.upper < pre_ci.lower;
    let note = if accepted {
        format!(
            "{:.2}\u{00d7} (lower bound {:.2}\u{00d7}) at {:.0}% CI",
            speedup_point,
            speedup_lower,
            CONFIDENCE * 100.0
        )
    } else {
        "CI overlap: improvement not statistically significant".into()
    };

    SpeedupVerdict {
        pre: pre_ci,
        post: post_ci,
        speedup_point,
        speedup_lower,
        accepted,
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_win_is_accepted() {
        let pre = Sample {
            name: "pre".into(),
            values_ns: (0..50).map(|i| 1000.0 + (i as f64) * 0.1).collect(),
        };
        let post = Sample {
            name: "post".into(),
            values_ns: (0..50).map(|i| 500.0 + (i as f64) * 0.1).collect(),
        };
        let v = compare(&pre, &post);
        assert!(v.accepted, "verdict: {:?}", v);
        assert!(v.speedup_point > 1.5);
    }

    #[test]
    fn no_change_is_rejected() {
        let pre = Sample {
            name: "pre".into(),
            values_ns: (0..50).map(|i| 1000.0 + (i as f64) * 0.5).collect(),
        };
        let post = Sample {
            name: "post".into(),
            values_ns: (0..50).map(|i| 1000.0 + (i as f64) * 0.5).collect(),
        };
        let v = compare(&pre, &post);
        assert!(!v.accepted);
    }
}
