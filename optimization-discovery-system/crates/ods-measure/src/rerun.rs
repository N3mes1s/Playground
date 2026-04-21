//! Deterministic rerun-N gate. Runs the same measurement N times and
//! requires the N independent confidence intervals to pairwise overlap
//! before accepting the speedup claim. Prevents non-deterministic host
//! conditions (thermal throttling, noisy neighbour) from sneaking past the
//! zero-diff gate.

use crate::fingerprint::EnvFingerprint;
use crate::stats::{compare, Sample, SpeedupVerdict};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RerunReport {
    pub n: u32,
    pub verdicts: Vec<SpeedupVerdict>,
    pub fingerprint: EnvFingerprint,
    pub fingerprint_stable: bool,
    pub all_accepted: bool,
    pub cis_overlap: bool,
}

/// Run `measure` `n` times; compare its `pre` and `post` samples each time;
/// return a report that accepts iff every individual run accepted AND the
/// speedup CIs pairwise overlap AND the env fingerprint is stable.
pub fn rerun<F>(n: u32, mut measure: F) -> RerunReport
where
    F: FnMut() -> (Sample, Sample),
{
    let fingerprint = EnvFingerprint::capture();
    let mut verdicts = Vec::with_capacity(n as usize);
    let mut fingerprint_stable = true;
    for _ in 0..n {
        let fp_now = EnvFingerprint::capture();
        if !fp_now.diff(&fingerprint).is_empty() {
            fingerprint_stable = false;
        }
        let (pre, post) = measure();
        verdicts.push(compare(&pre, &post));
    }
    let all_accepted = verdicts.iter().all(|v| v.accepted);
    let cis_overlap = cis_overlap(&verdicts);
    RerunReport {
        n,
        verdicts,
        fingerprint,
        fingerprint_stable,
        all_accepted,
        cis_overlap,
    }
}

/// Accept iff every pair of (post.lower, post.upper) intervals overlaps.
fn cis_overlap(verdicts: &[SpeedupVerdict]) -> bool {
    for i in 0..verdicts.len() {
        for j in (i + 1)..verdicts.len() {
            let a = &verdicts[i].post;
            let b = &verdicts[j].post;
            let lo = a.lower.max(b.lower);
            let hi = a.upper.min(b.upper);
            if lo > hi {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(pre_ns: f64, post_ns: f64) -> (Sample, Sample) {
        (
            Sample {
                name: "pre".into(),
                values_ns: (0..50).map(|i| pre_ns + (i as f64) * 0.01).collect(),
            },
            Sample {
                name: "post".into(),
                values_ns: (0..50).map(|i| post_ns + (i as f64) * 0.01).collect(),
            },
        )
    }

    #[test]
    fn consistent_runs_overlap_and_accept() {
        let r = rerun(3, || pair(1000.0, 500.0));
        assert!(r.all_accepted);
        assert!(r.cis_overlap);
    }

    #[test]
    fn disjoint_post_cis_fail_overlap() {
        let mut i = 0u32;
        let r = rerun(2, || {
            i += 1;
            match i {
                1 => pair(1000.0, 500.0),
                _ => pair(1000.0, 900.0),
            }
        });
        assert!(!r.cis_overlap);
    }
}
