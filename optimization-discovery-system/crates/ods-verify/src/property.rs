//! Tiny property-testing harness for differential testing.
//!
//! We don't depend on `proptest` here because we only need a deterministic,
//! language-agnostic way to generate byte and string inputs that can be
//! piped to a "before" and "after" binary. The caller provides the two
//! oracle closures; the harness walks a seeded corpus and reports any
//! disagreement as a test failure.

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyFailure {
    pub seed: u64,
    pub input_hex: String,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyReport {
    pub samples: u32,
    pub failures: Vec<PropertyFailure>,
}

impl PropertyReport {
    pub fn green(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Deterministic linear-congruential RNG used to keep the seeded corpus
/// reproducible across runs and machines.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next_u64() & 0xFF) as u8).collect()
    }
}

pub struct DifferentialHarness {
    pub seeds: Vec<u64>,
    pub samples_per_seed: u32,
    pub max_len: usize,
}

impl Default for DifferentialHarness {
    fn default() -> Self {
        Self {
            seeds: vec![0xC0FFEE, 0xDEADBEEF, 0xBADC0DE],
            samples_per_seed: 64,
            max_len: 256,
        }
    }
}

impl DifferentialHarness {
    /// Run the differential test. `oracle` returns (before, after) outputs
    /// for the same input, typed as `String`. A mismatch is recorded as a
    /// failure.
    pub fn run<F>(&self, mut oracle: F) -> Result<PropertyReport>
    where
        F: FnMut(&[u8]) -> Result<(String, String)>,
    {
        let mut failures = Vec::new();
        let mut samples = 0u32;
        for &seed in &self.seeds {
            let mut rng = Lcg::new(seed);
            for _ in 0..self.samples_per_seed {
                samples += 1;
                let len = (rng.next_u64() as usize) % self.max_len;
                let input = rng.bytes(len);
                let (before, after) = oracle(&input)?;
                if before != after {
                    failures.push(PropertyFailure {
                        seed,
                        input_hex: to_hex(&input),
                        before,
                        after,
                    });
                    if failures.len() >= 16 {
                        break;
                    }
                }
            }
        }
        Ok(PropertyReport { samples, failures })
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(CHARS[(b >> 4) as usize] as char);
        out.push(CHARS[(b & 0xF) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agreeing_oracles_are_green() {
        let h = DifferentialHarness::default();
        let r = h
            .run(|input| {
                let s = format!("{}", input.len());
                Ok((s.clone(), s))
            })
            .unwrap();
        assert!(r.green());
        assert!(r.samples >= 3 * 64);
    }

    #[test]
    fn disagreeing_oracles_fail() {
        let h = DifferentialHarness::default();
        let r = h
            .run(|input| {
                let a = format!("{}", input.len());
                let b = format!("{}", input.len() + 1);
                Ok((a, b))
            })
            .unwrap();
        assert!(!r.green());
        assert!(!r.failures.is_empty());
    }
}
