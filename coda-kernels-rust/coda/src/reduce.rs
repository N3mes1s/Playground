//! Lightweight **auxiliary reductions** over tile partials.
//!
//! CODA's reparameterizations leave a small amount of genuinely non-tile-local
//! work: a column reduction for the RMSNorm factor `r`, and a max / sum-exp
//! combination for the cross-entropy log-sum-exp. The paper handles these with
//! a "small auxiliary kernel" that reads only a few partial values per tile
//! (paper §3.2.1). These functions are exactly that kernel.

use crate::tensor::{self, Mat};

/// Combine column-block sum-of-squares partials into the row-wise inverse RMS
/// factor `r[m] = 1 / sqrt(mean_n D[m, n]^2 + eps)`.
///
/// `s` has shape `M x n_blocks`; each entry is `Σ_j D[m, j]^2` over one
/// column block ([`crate::epilogue::EvtColBlockReduceStore`]). `n` is the full
/// hidden dimension used to turn the sum of squares into a mean.
pub fn finalize_rms(s: &Mat, n: usize, eps: f32) -> Vec<f32> {
    tensor::account_read(s); // a few partials per row - far less than M x N.
    let mut r = vec![0.0f32; s.rows];
    for m in 0..s.rows {
        let mut sumsq = 0.0f32;
        for b in 0..s.cols {
            sumsq += s.get(m, b);
        }
        let mean_sq = sumsq / n as f32;
        r[m] = 1.0 / (mean_sq + eps).sqrt();
    }
    r
}

/// Combine per-tile `(max, sum-exp)` statistics into the row-wise log-sum-exp.
///
/// Implements the standard online-softmax merge: pick the global max, rescale
/// each tile's sum-exp to that max, sum, and take the log. `zmax` / `zsumexp`
/// both have shape `M x n_tiles`.
pub fn finalize_lse(zmax: &Mat, zsumexp: &Mat) -> Vec<f32> {
    tensor::account_read(zmax);
    tensor::account_read(zsumexp);
    assert_eq!((zmax.rows, zmax.cols), (zsumexp.rows, zsumexp.cols));
    let mut lse = vec![0.0f32; zmax.rows];
    for m in 0..zmax.rows {
        let mut gmax = f32::NEG_INFINITY;
        for t in 0..zmax.cols {
            gmax = gmax.max(zmax.get(m, t));
        }
        let mut sum = 0.0f32;
        for t in 0..zmax.cols {
            sum += zsumexp.get(m, t) * (zmax.get(m, t) - gmax).exp();
        }
        lse[m] = gmax + sum.ln();
    }
    lse
}

/// Per-token cross-entropy loss `ℓ[m] = -z_tgt[m] + lse[m]` (paper §3.2.3).
pub fn cross_entropy_loss(ztgt: &[f32], lse: &[f32]) -> Vec<f32> {
    ztgt.iter().zip(lse).map(|(zt, l)| -zt + l).collect()
}
