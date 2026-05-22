//! The 10 **GEMM-plus-epilogue kernels** of CODA (paper §C.1).
//!
//! Each kernel is one GEMM mainloop ([`crate::gemm::gemm_epilogue`]) followed
//! by an epilogue program assembled from the primitive visitors in
//! [`crate::epilogue`]. Forward kernels are 1-8; backward kernels are 9-10.
//!
//! The naming follows the paper:
//! * Kernel 1 - [`gemm_rope`]
//! * Kernel 2 - [`gemm_swiglu`]
//! * Kernel 3 - [`gemm_partial_ce`]
//! * Kernel 4 - [`gemm_residual_partial_rms`]
//! * Kernel 5 - [`gemm_rmsnorm`]
//! * Kernel 6 - [`gemm_rmsnorm_swiglu`]
//! * Kernel 7 - [`gemm_rmsnorm_rope`]
//! * Kernel 8 - [`gemm_rmsnorm_partial_ce`]
//! * Kernel 9 - [`gemm_residual_rmsnorm_bwd`]
//! * Kernel 10 - [`gemm_swiglu_bwd`]

use crate::epilogue::{
    silu, sigmoid, EpilogueVisitor, EvtColBlockReduceStore, EvtCrossEntropyStore, EvtList,
    EvtResidual, EvtRoPEStore, EvtRowScale, EvtRowVecMulStore, EvtStore, EvtSwiGLUStore,
};
use crate::gemm::{gemm_epilogue, Frag, TileCtx, TILE_N};
use crate::reduce;
use crate::tensor::{self, Mat};

/// Logical `(M, N)` output shape of `op(A) @ op(B)`.
fn out_shape(a: &Mat, ta: bool, b: &Mat, tb: bool) -> (usize, usize) {
    let m = if ta { a.cols } else { a.rows };
    let n = if tb { b.rows } else { b.cols };
    (m, n)
}

/// Fail fast if the cross-entropy `targets` do not match the logits shape.
///
/// A target outside `[0, vocab)` would otherwise never trigger the indexed
/// store in [`EvtCrossEntropyStore`], silently leaving `z_tgt` at zero and
/// corrupting the loss and gradients. This validates at the kernel boundary.
fn validate_ce_targets(targets: &[usize], m: usize, n: usize) {
    assert_eq!(
        targets.len(),
        m,
        "cross-entropy kernel: expected one target per row (got {}, need {m})",
        targets.len()
    );
    if let Some((row, &t)) = targets.iter().enumerate().find(|&(_, &t)| t >= n) {
        panic!("cross-entropy kernel: target {t} at row {row} is outside [0, {n})");
    }
}

/// A plain GEMM `op(A) @ op(B)` with a bare store epilogue. Not one of the
/// paper's fused kernels, but the shared baseline they are all measured
/// against, and the backbone of the backward pass (Theorem 1's GEMMs).
pub fn gemm(a: &Mat, ta: bool, b: &Mat, tb: bool) -> Mat {
    let (m, n) = out_shape(a, ta, b, tb);
    let mut d = Mat::zeros(m, n);
    {
        let mut evt = EvtStore::new(&mut d);
        gemm_epilogue(a, ta, b, tb, &mut evt);
    }
    d
}

/// **Kernel 1** - GEMM with RoPE: `D = A B`, `O = RoPE(D)`.
pub fn gemm_rope(a: &Mat, b: &Mat, cos: &Mat, sin: &Mat) -> Mat {
    let (m, n) = out_shape(a, false, b, false);
    assert!(n % 2 == 0, "RoPE GEMM needs an even output width (got {n})");
    let mut o = Mat::zeros(m, n);
    {
        let mut evt = EvtRoPEStore::new(cos, sin, &mut o);
        gemm_epilogue(a, false, b, false, &mut evt);
    }
    o
}

/// **Kernel 2** - GEMM with SwiGLU: `D = A B`, `[G, U] = split(D)`,
/// `O = silu(G) ⊙ U`. The output feature width is halved.
pub fn gemm_swiglu(a: &Mat, b: &Mat) -> Mat {
    let (m, n) = out_shape(a, false, b, false);
    assert!(n % 2 == 0, "SwiGLU GEMM needs an even output width");
    let mut o = Mat::zeros(m, n / 2);
    {
        let mut evt = EvtSwiGLUStore::new(&mut o);
        gemm_epilogue(a, false, b, false, &mut evt);
    }
    o
}

/// **Kernel 3** - GEMM with partial cross-entropy: `Z = A B`, select the
/// target logit, emit block-wise log-sum-exp statistics.
///
/// Returns `(z_tgt, lse, per_token_loss)`.
pub fn gemm_partial_ce(a: &Mat, b: &Mat, targets: &[usize]) -> (Vec<f32>, Vec<f32>, Vec<f32>) {
    let (m, n) = out_shape(a, false, b, false);
    validate_ce_targets(targets, m, n);
    let n_tiles = n.div_ceil(TILE_N);
    let mut zmax = Mat::zeros(m, n_tiles);
    let mut zsumexp = Mat::zeros(m, n_tiles);
    let mut ztgt = vec![0.0f32; m];
    {
        let mut evt = EvtCrossEntropyStore::new(targets, &mut zmax, &mut zsumexp, &mut ztgt);
        gemm_epilogue(a, false, b, false, &mut evt);
    }
    let lse = reduce::finalize_lse(&zmax, &zsumexp);
    let loss = reduce::cross_entropy_loss(&ztgt, &lse);
    (ztgt, lse, loss)
}

/// **Kernel 4** - GEMM with residual, partial RMSNorm and weight scaling
/// (paper §3.2.1, stage 1 of GEMM-Residual-RMSNorm-GEMM):
///
/// ```text
///   D = A B + C
///   r̂ = reduceTile_cols(D ⊙ D)        (column-block partials)
///   O = D ⊙ γ
/// ```
///
/// Returns `(D, O, r)` where `D` is the updated residual stream, `O = D ⊙ γ`
/// is the normalized-and-weighted activation feeding the next GEMM, and `r` is
/// the row-wise inverse RMS factor obtained from the auxiliary reduction.
pub fn gemm_residual_partial_rms(
    a: &Mat,
    b: &Mat,
    c: &Mat,
    gamma: &[f32],
    eps: f32,
) -> (Mat, Mat, Vec<f32>) {
    let (m, n) = out_shape(a, false, b, false);
    let n_blocks = n.div_ceil(TILE_N);
    let mut d = Mat::zeros(m, n);
    let mut s = Mat::zeros(m, n_blocks);
    let mut o = Mat::zeros(m, n);
    {
        // The visitor tree: residual add -> store D -> square reduce -> γ scale.
        // EvtResidual mutates the fragment first; everything after sees D.
        let mut evt = EvtList::new()
            .with(EvtResidual::new(c))
            .with(EvtStore::new(&mut d))
            .with(EvtColBlockReduceStore::new(&mut s))
            .with(EvtRowVecMulStore::new(gamma, &mut o));
        gemm_epilogue(a, false, b, false, &mut evt);
    }
    let r = reduce::finalize_rms(&s, n, eps);
    (d, o, r)
}

/// **Kernel 5** - GEMM with RMSNorm scaling: `D = A B`, `O = D ⊙ r`.
///
/// Consumes a precomputed row-wise factor `r` and applies it in the epilogue -
/// the delayed-scale step of the GEMM-Residual-RMSNorm-GEMM reparameterization.
pub fn gemm_rmsnorm(a: &Mat, b: &Mat, r: &[f32]) -> Mat {
    let (m, n) = out_shape(a, false, b, false);
    let mut o = Mat::zeros(m, n);
    {
        let mut evt = EvtList::new()
            .with(EvtRowScale::new(r))
            .with(EvtStore::new(&mut o));
        gemm_epilogue(a, false, b, false, &mut evt);
    }
    o
}

/// **Kernel 6** - GEMM with RMSNorm and SwiGLU: `D = A B`, `D' = D ⊙ r`,
/// `[G, U] = split(D')`, `O = silu(G) ⊙ U` (the MLP gate/up projection).
///
/// Returns `(O, D')`. The normalized pre-activation `D'` is emitted as a
/// *saved-activation* side output (paper §3.1, class-3 tile store): the
/// backward pass needs it, and storing it from the on-chip fragment costs one
/// write instead of recomputing the whole gate/up GEMM.
pub fn gemm_rmsnorm_swiglu(a: &Mat, b: &Mat, r: &[f32]) -> (Mat, Mat) {
    let (m, n) = out_shape(a, false, b, false);
    assert!(n % 2 == 0, "SwiGLU GEMM needs an even output width");
    let mut o = Mat::zeros(m, n / 2);
    let mut d_norm = Mat::zeros(m, n);
    {
        let mut evt = EvtList::new()
            .with(EvtRowScale::new(r))
            .with(EvtStore::new(&mut d_norm))
            .with(EvtSwiGLUStore::new(&mut o));
        gemm_epilogue(a, false, b, false, &mut evt);
    }
    (o, d_norm)
}

/// **Kernel 7** - GEMM with RMSNorm and RoPE: `D = A B`, `D' = D ⊙ r`,
/// `O = RoPE(D')` (the QKV projection followed by rotary embedding).
pub fn gemm_rmsnorm_rope(a: &Mat, b: &Mat, r: &[f32], cos: &Mat, sin: &Mat) -> Mat {
    let (m, n) = out_shape(a, false, b, false);
    assert!(n % 2 == 0, "RoPE GEMM needs an even output width (got {n})");
    let mut o = Mat::zeros(m, n);
    {
        let mut evt = EvtList::new()
            .with(EvtRowScale::new(r))
            .with(EvtRoPEStore::new(cos, sin, &mut o));
        gemm_epilogue(a, false, b, false, &mut evt);
    }
    o
}

/// **Kernel 8** - GEMM with RMSNorm and partial cross-entropy:
/// `Z = (A B) ⊙ r`, select target logit, emit log-sum-exp partials
/// (the language-modeling head). Returns `(z_tgt, lse, per_token_loss)`.
pub fn gemm_rmsnorm_partial_ce(
    a: &Mat,
    b: &Mat,
    r: &[f32],
    targets: &[usize],
) -> (Vec<f32>, Vec<f32>, Vec<f32>) {
    let (m, n) = out_shape(a, false, b, false);
    validate_ce_targets(targets, m, n);
    let n_tiles = n.div_ceil(TILE_N);
    let mut zmax = Mat::zeros(m, n_tiles);
    let mut zsumexp = Mat::zeros(m, n_tiles);
    let mut ztgt = vec![0.0f32; m];
    {
        let mut evt = EvtList::new()
            .with(EvtRowScale::new(r))
            .with(EvtCrossEntropyStore::new(targets, &mut zmax, &mut zsumexp, &mut ztgt));
        gemm_epilogue(a, false, b, false, &mut evt);
    }
    let lse = reduce::finalize_lse(&zmax, &zsumexp);
    let loss = reduce::cross_entropy_loss(&ztgt, &lse);
    (ztgt, lse, loss)
}

// ---------------------------------------------------------------------------
// Backward kernels (paper §C.1.3). These mirror the forward structure:
// a GEMM, a tile-local backward rule in the epilogue, plus partial reductions.
// ---------------------------------------------------------------------------

/// Bespoke epilogue for **Kernel 10**, the SwiGLU backward rule.
///
/// The mainloop produces `dO = A Bᵀ`, the gradient of the SwiGLU *output*.
/// Using the saved interleaved pre-activation `Z` (`[G, U] = split(Z)`):
///
/// ```text
///   ∇U = dO ⊙ silu(G)
///   ∇G = dO ⊙ U ⊙ silu'(G)
///   ∇Z = interleavedConcat(∇G, ∇U)
/// ```
///
/// and accumulates `reduceTile_cols(G ⊙ ∇G + U ⊙ ∇U)` into `stat`.
struct EvtSwiGLUBwd<'a> {
    z: &'a Mat,
    dz: &'a mut Mat,
    stat: &'a mut Vec<f32>,
}

impl<'a> EpilogueVisitor for EvtSwiGLUBwd<'a> {
    fn consumer_init(&mut self, _m: usize, _n: usize, _k: usize) {
        tensor::account_read(self.z);
        tensor::account_write(self.dz);
        tensor::account_elems(self.stat.len());
    }
    fn consumer_visit(&mut self, _frag: &mut Frag, _ctx: &TileCtx) {}
    fn consumer_end(&mut self, frag: &Frag, ctx: &TileCtx) {
        for i in 0..ctx.tm {
            let row = ctx.m0 + i;
            let mut acc = 0.0f32;
            for jj in 0..ctx.tn {
                // dO tile column jj -> feature pair (2*(n0+jj), +1) of Z.
                let g = self.z.get(row, 2 * (ctx.n0 + jj));
                let u = self.z.get(row, 2 * (ctx.n0 + jj) + 1);
                let d_o = frag.at(i, jj);
                let sg = silu(g);
                let sig = sigmoid(g);
                let d_silu = sig + sg * (1.0 - sig); // silu'(g)
                let d_u = d_o * sg;
                let d_g = d_o * u * d_silu;
                self.dz.set(row, 2 * (ctx.n0 + jj), d_g);
                self.dz.set(row, 2 * (ctx.n0 + jj) + 1, d_u);
                acc += g * d_g + u * d_u;
            }
            self.stat[row] += acc;
        }
    }
}

/// **Kernel 10** - GEMM with SwiGLU backward.
///
/// `dO = A Bᵀ` is the upstream gradient projected back through the next GEMM;
/// `z` is the saved interleaved pre-activation. Returns `(dZ, stat)` where
/// `dZ` is the gradient w.r.t. the SwiGLU input and `stat` is the row-wise
/// `Σ (G⊙∇G + U⊙∇U)` partial used by the neighboring RMSNorm backward.
pub fn gemm_swiglu_bwd(a: &Mat, b: &Mat, z: &Mat) -> (Mat, Vec<f32>) {
    let (m, half_n) = out_shape(a, false, b, true);
    assert_eq!((m, 2 * half_n), (z.rows, z.cols), "SwiGLU bwd shape mismatch");
    let mut dz = Mat::zeros(z.rows, z.cols);
    let mut stat = vec![0.0f32; m];
    {
        let mut evt = EvtSwiGLUBwd { z, dz: &mut dz, stat: &mut stat };
        gemm_epilogue(a, false, b, true, &mut evt);
    }
    (dz, stat)
}

/// Bespoke epilogue for **Kernel 9**, the residual + RMSNorm backward rule
/// (paper §A.2). The mainloop produces `D = A Bᵀ = ∇h2` (the gradient of the
/// RMSNorm output). With `C` the RMSNorm input, `r` the inverse RMS factor,
/// `γ` the weight and `zddz` the row-wise statistic `s`:
///
/// ```text
///   Cnorm   = C ⊙ r
///   ∇h1     = (∇h2 ⊙ γ - Cnorm ⊙ s) ⊙ r
///   ∇γ̂     += reduceTile_rows(∇h2 ⊙ Cnorm)
/// ```
struct EvtRmsNormBwd<'a> {
    c: &'a Mat,
    r: &'a [f32],
    gamma: &'a [f32],
    zddz: &'a [f32],
    dh1: &'a mut Mat,
    dgamma: &'a mut Vec<f32>,
}

impl<'a> EpilogueVisitor for EvtRmsNormBwd<'a> {
    fn consumer_init(&mut self, _m: usize, n: usize, _k: usize) {
        tensor::account_read(self.c);
        tensor::account_write(self.dh1);
        tensor::account_elems(self.r.len() + self.zddz.len() + 2 * n);
    }
    fn consumer_visit(&mut self, _frag: &mut Frag, _ctx: &TileCtx) {}
    fn consumer_end(&mut self, frag: &Frag, ctx: &TileCtx) {
        for i in 0..ctx.tm {
            let row = ctx.m0 + i;
            let r = self.r[row];
            let s = self.zddz[row];
            for j in 0..ctx.tn {
                let col = ctx.n0 + j;
                let dh2 = frag.at(i, j);
                let c_norm = self.c.get(row, col) * r;
                let dh1 = (dh2 * self.gamma[col] - c_norm * s) * r;
                self.dh1.set(row, col, dh1);
                self.dgamma[col] += dh2 * c_norm;
            }
        }
    }
}

/// **Kernel 9** - GEMM with residual and RMSNorm backward.
///
/// `D = A Bᵀ = ∇h2`. Given the RMSNorm input `c = h1`, the inverse RMS factor
/// `r`, the weight `gamma`, and the row-wise statistic `zddz = s`, returns
/// `(∇h1, ∇γ)`.
pub fn gemm_residual_rmsnorm_bwd(
    a: &Mat,
    b: &Mat,
    c: &Mat,
    r: &[f32],
    gamma: &[f32],
    zddz: &[f32],
) -> (Mat, Vec<f32>) {
    let (m, n) = out_shape(a, false, b, true);
    assert_eq!((m, n), (c.rows, c.cols), "RMSNorm bwd shape mismatch");
    let mut dh1 = Mat::zeros(m, n);
    let mut dgamma = vec![0.0f32; n];
    {
        let mut evt = EvtRmsNormBwd {
            c,
            r,
            gamma,
            zddz,
            dh1: &mut dh1,
            dgamma: &mut dgamma,
        };
        gemm_epilogue(a, false, b, true, &mut evt);
    }
    (dh1, dgamma)
}
