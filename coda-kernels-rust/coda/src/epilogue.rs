//! The **Epilogue Visitor Tree** (EVT): a trait plus a set of composable
//! primitive visitors.
//!
//! This is the heart of CODA. The paper (§3.1) defines five classes of
//! epilogue primitive; each concrete visitor below is tagged with the class
//! it realizes:
//!
//! 1. **Elementwise / pairwise maps** - [`EvtResidual`], [`EvtRowScale`],
//!    [`EvtRowVecMulStore`], [`EvtSwiGLUStore`], [`EvtRoPEStore`].
//! 2. **Vector (rank-1) loads / stores** - the broadcast operands of
//!    [`EvtRowScale`] (per-row factor `r`) and [`EvtRowVecMulStore`]
//!    (per-column weight `γ`).
//! 3. **Tile (rank-2) loads / stores** - [`EvtResidual`] (loads a residual
//!    tile) and [`EvtStore`] (stores the accumulator tile).
//! 4. **Tile reductions** - [`EvtColBlockReduceStore`] (column-block
//!    sum-of-squares for partial RMSNorm) and [`EvtRowReduceStore`]
//!    (cross-row reduction for the RMSNorm weight gradient).
//! 5. **Stateful transforms** - [`EvtCrossEntropyStore`] keeps per-tile
//!    max / sum-exp statistics for the online log-sum-exp.
//!
//! Visitors compose into a tree via [`EvtList`], which simply runs each child
//! at each hook point. Order matters: a visitor that *mutates* the fragment
//! (e.g. [`EvtResidual`]) is placed before visitors that *read* it (e.g.
//! [`EvtColBlockReduceStore`]).

use crate::gemm::{Frag, TileCtx, TILE_N};
use crate::tensor::{self, Mat};

/// `silu(x) = x * sigmoid(x)`, the SwiGLU gate activation.
#[inline]
pub fn silu(x: f32) -> f32 {
    x / (1.0 + (-x).exp())
}

/// `sigmoid(x)`.
#[inline]
pub fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// A node of the Epilogue Visitor Tree.
///
/// The hook points mirror CODA's epilogue template (paper Listing 1),
/// collapsed to the granularity that is meaningful on a CPU:
/// `consumer_init` (once per kernel), `consumer_begin` (once per output tile,
/// for loading per-tile operands), `consumer_visit` (the core transform on the
/// on-chip fragment) and `consumer_end` (per-tile finalization / stores).
pub trait EpilogueVisitor {
    /// Called once, before the tile loop, with the full problem shape.
    /// Visitors use this to account the DRAM traffic of their auxiliary
    /// tensors (read once, streamed tile by tile).
    fn consumer_init(&mut self, _m: usize, _n: usize, _k: usize) {}

    /// Called once per output tile, before [`Self::consumer_visit`].
    fn consumer_begin(&mut self, _ctx: &TileCtx) {}

    /// The core epilogue computation: inspect and/or mutate the on-chip
    /// accumulator fragment. Visitors that only emit side outputs at
    /// [`Self::consumer_end`] can leave this as the default no-op.
    fn consumer_visit(&mut self, _frag: &mut Frag, _ctx: &TileCtx) {}

    /// Called once per output tile, after [`Self::consumer_visit`]; the usual
    /// place for stores and partial-reduction emission.
    fn consumer_end(&mut self, _frag: &Frag, _ctx: &TileCtx) {}
}

/// A composition of epilogue visitors - CODA's `EVTList`.
///
/// Running the list applies each child at every hook point, in insertion
/// order. This is how CODA assembles fused kernels "from reusable building
/// blocks instead of being rewritten from scratch" (paper §3.3.1).
pub struct EvtList<'a> {
    visitors: Vec<Box<dyn EpilogueVisitor + 'a>>,
}

impl<'a> EvtList<'a> {
    /// An empty visitor tree.
    pub fn new() -> EvtList<'a> {
        EvtList { visitors: Vec::new() }
    }

    /// Append a visitor and return the tree (builder style).
    pub fn with(mut self, v: impl EpilogueVisitor + 'a) -> EvtList<'a> {
        self.visitors.push(Box::new(v));
        self
    }
}

impl<'a> Default for EvtList<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> EpilogueVisitor for EvtList<'a> {
    fn consumer_init(&mut self, m: usize, n: usize, k: usize) {
        for v in &mut self.visitors {
            v.consumer_init(m, n, k);
        }
    }
    fn consumer_begin(&mut self, ctx: &TileCtx) {
        for v in &mut self.visitors {
            v.consumer_begin(ctx);
        }
    }
    fn consumer_visit(&mut self, frag: &mut Frag, ctx: &TileCtx) {
        for v in &mut self.visitors {
            v.consumer_visit(frag, ctx);
        }
    }
    fn consumer_end(&mut self, frag: &Frag, ctx: &TileCtx) {
        for v in &mut self.visitors {
            v.consumer_end(frag, ctx);
        }
    }
}

// ---------------------------------------------------------------------------
// Class 3: tile store - write the (possibly mutated) accumulator to DRAM.
// ---------------------------------------------------------------------------

/// Stores the accumulator fragment into a destination matrix.
///
/// Placed *after* mutating visitors, this materializes whatever the GEMM +
/// preceding epilogue produced (e.g. the updated residual stream `D = AB + C`).
pub struct EvtStore<'a> {
    dst: &'a mut Mat,
}

impl<'a> EvtStore<'a> {
    pub fn new(dst: &'a mut Mat) -> EvtStore<'a> {
        EvtStore { dst }
    }
}

impl<'a> EpilogueVisitor for EvtStore<'a> {
    fn consumer_init(&mut self, _m: usize, _n: usize, _k: usize) {
        tensor::account_write(self.dst);
    }
    fn consumer_visit(&mut self, _frag: &mut Frag, _ctx: &TileCtx) {}
    fn consumer_end(&mut self, frag: &Frag, ctx: &TileCtx) {
        for i in 0..ctx.tm {
            for j in 0..ctx.tn {
                self.dst.set(ctx.m0 + i, ctx.n0 + j, frag.at(i, j));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Class 1 + 3: residual update - add a residual tile into the accumulator.
// ---------------------------------------------------------------------------

/// Fuses a residual add `D := acc + C` directly into the fragment.
///
/// `C` is a TMA-style tile load on a GPU; here it is a heap read accounted
/// once. Because the add lands in the on-chip accumulator, no extra DRAM
/// round-trip is needed for the residual-updated tensor.
pub struct EvtResidual<'a> {
    c: &'a Mat,
}

impl<'a> EvtResidual<'a> {
    pub fn new(c: &'a Mat) -> EvtResidual<'a> {
        EvtResidual { c }
    }
}

impl<'a> EpilogueVisitor for EvtResidual<'a> {
    fn consumer_init(&mut self, _m: usize, _n: usize, _k: usize) {
        tensor::account_read(self.c);
    }
    fn consumer_visit(&mut self, frag: &mut Frag, ctx: &TileCtx) {
        for i in 0..ctx.tm {
            for j in 0..ctx.tn {
                let v = frag.at(i, j) + self.c.get(ctx.m0 + i, ctx.n0 + j);
                frag.set(i, j, v);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Class 1 + 2: per-row scaling - multiply the fragment by a per-M factor.
// ---------------------------------------------------------------------------

/// In-place per-row scaling `acc[i, j] := acc[i, j] * r[m0 + i]`.
///
/// This is the delayed RMSNorm factor of paper §3.2.1: because `r` is constant
/// along a row it commutes with the following GEMM, so it can be applied in
/// the *second* GEMM's epilogue rather than before it.
pub struct EvtRowScale<'a> {
    r: &'a [f32],
}

impl<'a> EvtRowScale<'a> {
    pub fn new(r: &'a [f32]) -> EvtRowScale<'a> {
        EvtRowScale { r }
    }
}

impl<'a> EpilogueVisitor for EvtRowScale<'a> {
    fn consumer_init(&mut self, _m: usize, _n: usize, _k: usize) {
        // A rank-1 vector load: tiny, but still global-memory traffic.
        tensor::account_elems(self.r.len());
    }
    fn consumer_visit(&mut self, frag: &mut Frag, ctx: &TileCtx) {
        for i in 0..ctx.tm {
            let s = self.r[ctx.m0 + i];
            for j in 0..ctx.tn {
                let v = frag.at(i, j) * s;
                frag.set(i, j, v);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Class 1 + 2 + 3: per-column weight multiply with a side output.
// ---------------------------------------------------------------------------

/// Computes a side output `O[i, j] = acc[i, j] * gamma[n0 + j]` while leaving
/// the fragment untouched.
///
/// This is CODA's `EVTRowVecMulPostAct` (paper Listing 2): it applies the
/// RMSNorm weight `γ` to produce the normalized-and-weighted activation that
/// feeds the next GEMM, but keeps the *unscaled* `D` available so a downstream
/// RMS reduction still sees the pre-`γ` values.
pub struct EvtRowVecMulStore<'a> {
    gamma: &'a [f32],
    out: &'a mut Mat,
}

impl<'a> EvtRowVecMulStore<'a> {
    pub fn new(gamma: &'a [f32], out: &'a mut Mat) -> EvtRowVecMulStore<'a> {
        EvtRowVecMulStore { gamma, out }
    }
}

impl<'a> EpilogueVisitor for EvtRowVecMulStore<'a> {
    fn consumer_init(&mut self, _m: usize, _n: usize, _k: usize) {
        tensor::account_elems(self.gamma.len());
        tensor::account_write(self.out);
    }
    fn consumer_end(&mut self, frag: &Frag, ctx: &TileCtx) {
        for i in 0..ctx.tm {
            for j in 0..ctx.tn {
                let v = frag.at(i, j) * self.gamma[ctx.n0 + j];
                self.out.set(ctx.m0 + i, ctx.n0 + j, v);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Class 4: column-block tile reduction - partial sum-of-squares for RMSNorm.
// ---------------------------------------------------------------------------

/// Emits `S[m, n_block] = Σ_j acc[m, j]^2` over this tile's columns.
///
/// CODA splits the RMSNorm reduction into two levels (paper §3.2.1): the GEMM
/// epilogue produces per-column-block partials, and a tiny auxiliary kernel
/// ([`crate::reduce::finalize_rms`]) combines them into the row-wise factor
/// `r`. The block size equals `TILE_N`, so each output tile contributes
/// exactly one partial per row.
pub struct EvtColBlockReduceStore<'a> {
    s: &'a mut Mat,
}

impl<'a> EvtColBlockReduceStore<'a> {
    pub fn new(s: &'a mut Mat) -> EvtColBlockReduceStore<'a> {
        EvtColBlockReduceStore { s }
    }
}

impl<'a> EpilogueVisitor for EvtColBlockReduceStore<'a> {
    fn consumer_init(&mut self, _m: usize, _n: usize, _k: usize) {
        tensor::account_write(self.s);
    }
    fn consumer_end(&mut self, frag: &Frag, ctx: &TileCtx) {
        let nb = ctx.n_block();
        for i in 0..ctx.tm {
            let mut sq = 0.0f32;
            for j in 0..ctx.tn {
                let v = frag.at(i, j);
                sq += v * v;
            }
            self.s.add(ctx.m0 + i, nb, sq);
        }
    }
}

// ---------------------------------------------------------------------------
// Class 4: cross-row tile reduction - RMSNorm weight gradient partials.
// ---------------------------------------------------------------------------

/// Accumulates `g[j] += Σ_i acc[i, j]` across rows of every tile.
///
/// `reduceTile_rows` of paper §A.2: the RMSNorm weight gradient `∇γ` is a sum
/// over the row (token) dimension, which spans multiple `TILE_M` tiles, so the
/// epilogue emits per-tile partials that simply accumulate into `g`.
pub struct EvtRowReduceStore<'a> {
    g: &'a mut Vec<f32>,
}

impl<'a> EvtRowReduceStore<'a> {
    pub fn new(g: &'a mut Vec<f32>) -> EvtRowReduceStore<'a> {
        EvtRowReduceStore { g }
    }
}

impl<'a> EpilogueVisitor for EvtRowReduceStore<'a> {
    fn consumer_init(&mut self, _m: usize, n: usize, _k: usize) {
        tensor::account_elems(n);
    }
    fn consumer_visit(&mut self, _frag: &mut Frag, _ctx: &TileCtx) {}
    fn consumer_end(&mut self, frag: &Frag, ctx: &TileCtx) {
        for j in 0..ctx.tn {
            let mut s = 0.0f32;
            for i in 0..ctx.tm {
                s += frag.at(i, j);
            }
            self.g[ctx.n0 + j] += s;
        }
    }
}

// ---------------------------------------------------------------------------
// Class 1: pairwise activation - SwiGLU on interleaved feature pairs.
// ---------------------------------------------------------------------------

/// Fused SwiGLU: `O[i, k] = silu(G) * U` where `[G, U] = interleavedSplit(acc)`
/// takes adjacent feature lanes `(2k, 2k+1)` as gate / value (paper §3.2.2,
/// Kernel 2). The output has half the feature width of the GEMM result.
pub struct EvtSwiGLUStore<'a> {
    out: &'a mut Mat,
}

impl<'a> EvtSwiGLUStore<'a> {
    pub fn new(out: &'a mut Mat) -> EvtSwiGLUStore<'a> {
        EvtSwiGLUStore { out }
    }
}

impl<'a> EpilogueVisitor for EvtSwiGLUStore<'a> {
    fn consumer_init(&mut self, _m: usize, _n: usize, _k: usize) {
        tensor::account_write(self.out);
    }
    fn consumer_end(&mut self, frag: &Frag, ctx: &TileCtx) {
        debug_assert!(ctx.n0 % 2 == 0 && ctx.tn % 2 == 0, "SwiGLU needs even N tiling");
        for i in 0..ctx.tm {
            let mut jj = 0;
            while jj < ctx.tn {
                let g = frag.at(i, jj);
                let u = frag.at(i, jj + 1);
                self.out.set(ctx.m0 + i, (ctx.n0 + jj) / 2, silu(g) * u);
                jj += 2;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Class 1: pairwise activation - RoPE rotation of adjacent feature pairs.
// ---------------------------------------------------------------------------

/// Fused rotary position embedding (paper §3.2.2, Kernel 1).
///
/// Each adjacent feature pair `(2k, 2k+1)` is rotated by the angle stored in
/// the precomputed `cos` / `sin` tables (indexed by row = token position and
/// column = feature). The operation is dimension-preserving.
pub struct EvtRoPEStore<'a> {
    cos: &'a Mat,
    sin: &'a Mat,
    out: &'a mut Mat,
}

impl<'a> EvtRoPEStore<'a> {
    pub fn new(cos: &'a Mat, sin: &'a Mat, out: &'a mut Mat) -> EvtRoPEStore<'a> {
        EvtRoPEStore { cos, sin, out }
    }
}

impl<'a> EpilogueVisitor for EvtRoPEStore<'a> {
    fn consumer_init(&mut self, _m: usize, _n: usize, _k: usize) {
        tensor::account_read(self.cos);
        tensor::account_read(self.sin);
        tensor::account_write(self.out);
    }
    fn consumer_end(&mut self, frag: &Frag, ctx: &TileCtx) {
        debug_assert!(ctx.n0 % 2 == 0 && ctx.tn % 2 == 0, "RoPE needs even N tiling");
        for i in 0..ctx.tm {
            let row = ctx.m0 + i;
            let mut jj = 0;
            while jj < ctx.tn {
                let col = ctx.n0 + jj;
                let x0 = frag.at(i, jj);
                let x1 = frag.at(i, jj + 1);
                let c = self.cos.get(row, col);
                let s = self.sin.get(row, col);
                self.out.set(row, col, x0 * c - x1 * s);
                self.out.set(row, col + 1, x0 * s + x1 * c);
                jj += 2;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Class 5: stateful transform - online log-sum-exp for cross-entropy.
// ---------------------------------------------------------------------------

/// Fused cross-entropy logit handling (paper §3.2.3, Kernel 3 / 8).
///
/// For each output tile this emits, per row, the tile-local maximum and
/// sum-exp of the logits (`zmax`, `zsumexp`) - the "stateful" max / sum-exp
/// statistics of the online log-sum-exp - and, when the target column falls
/// inside the tile, the selected target logit `ztgt`. A small auxiliary
/// reduction ([`crate::reduce::finalize_lse`]) then combines the per-tile
/// statistics, avoiding a standalone softmax over the full vocabulary.
pub struct EvtCrossEntropyStore<'a> {
    targets: &'a [usize],
    zmax: &'a mut Mat,
    zsumexp: &'a mut Mat,
    ztgt: &'a mut [f32],
}

impl<'a> EvtCrossEntropyStore<'a> {
    pub fn new(
        targets: &'a [usize],
        zmax: &'a mut Mat,
        zsumexp: &'a mut Mat,
        ztgt: &'a mut [f32],
    ) -> EvtCrossEntropyStore<'a> {
        EvtCrossEntropyStore { targets, zmax, zsumexp, ztgt }
    }
}

impl<'a> EpilogueVisitor for EvtCrossEntropyStore<'a> {
    fn consumer_init(&mut self, _m: usize, _n: usize, _k: usize) {
        tensor::account_write(self.zmax);
        tensor::account_write(self.zsumexp);
        tensor::account_elems(self.ztgt.len());
    }
    fn consumer_visit(&mut self, _frag: &mut Frag, _ctx: &TileCtx) {}
    fn consumer_end(&mut self, frag: &Frag, ctx: &TileCtx) {
        let nb = ctx.n0 / TILE_N;
        for i in 0..ctx.tm {
            let row = ctx.m0 + i;
            // Stateful statistics: tile-local max, then sum-exp around it.
            let mut mx = f32::NEG_INFINITY;
            for j in 0..ctx.tn {
                mx = mx.max(frag.at(i, j));
            }
            let mut se = 0.0f32;
            for j in 0..ctx.tn {
                se += (frag.at(i, j) - mx).exp();
            }
            self.zmax.set(row, nb, mx);
            self.zsumexp.set(row, nb, se);
            // Indexed-logit selection when the target lands in this tile.
            let tgt = self.targets[row];
            if tgt >= ctx.n0 && tgt < ctx.n0 + ctx.tn {
                self.ztgt[row] = frag.at(i, tgt - ctx.n0);
            }
        }
    }
}
