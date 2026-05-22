//! The fixed, tiled GEMM **mainloop** with epilogue hook points.
//!
//! This mirrors CODA's design principle (paper §3): *the GEMM mainloop is held
//! fixed and highly optimized; only the epilogue is programmable.* The mainloop
//! here computes one `TILE_M x TILE_N` output tile at a time into an
//! accumulator [`Frag`] that conceptually lives "in registers / on-chip", then
//! hands it to an [`EpilogueVisitor`] before anything is written to DRAM.
//!
//! On a GPU the mainloop would be a WGMMA pipeline; here it is a plain triple
//! loop. What matters for the port is the *interface*: the epilogue only ever
//! sees a local output tile (the "locality constraint" of paper §2.2).

use crate::epilogue::EpilogueVisitor;
use crate::tensor::{self, Mat};

/// CTA tile height (rows of the output handled together).
pub const TILE_M: usize = 32;
/// CTA tile width. Also the block size for column-block tile reductions
/// (the partial-RMS reduction in Kernel 4 reduces over exactly one tile).
pub const TILE_N: usize = 32;

/// Geometry of the current output tile, passed to every epilogue hook.
///
/// This is the CPU analogue of CuTeDSL's `tile_coord_mnkl` plus problem shape:
/// an epilogue may use it to index consistently-laid-out auxiliary tensors.
#[derive(Clone, Copy, Debug)]
pub struct TileCtx {
    /// Row origin of this tile in the full `M x N` output.
    pub m0: usize,
    /// Column origin of this tile in the full `M x N` output.
    pub n0: usize,
    /// Actual tile height (`<= TILE_M` at the bottom edge).
    pub tm: usize,
    /// Actual tile width (`<= TILE_N` at the right edge).
    pub tn: usize,
    /// Full problem M.
    pub m: usize,
    /// Full problem N.
    pub n: usize,
    /// Full problem K (contraction dimension).
    pub k: usize,
}

impl TileCtx {
    /// Index of this tile along N, i.e. which column-block it is.
    /// Used by tile-reduction epilogues whose block size equals `TILE_N`.
    #[inline]
    pub fn n_block(&self) -> usize {
        self.n0 / TILE_N
    }

    /// Total number of column-blocks in the full problem.
    #[inline]
    pub fn n_blocks(&self) -> usize {
        self.n.div_ceil(TILE_N)
    }
}

/// The on-chip accumulator tile produced by the mainloop.
///
/// This is the only state the epilogue mutates "for free": transformations
/// applied here never touch DRAM. Side outputs and partial reductions must be
/// explicitly stored by epilogue visitors (which *do* account DRAM traffic).
#[derive(Clone, Debug)]
pub struct Frag {
    /// Tile height.
    pub tm: usize,
    /// Tile width.
    pub tn: usize,
    /// Row-major `tm x tn` accumulator values.
    pub acc: Vec<f32>,
}

impl Frag {
    fn new(tm: usize, tn: usize) -> Frag {
        Frag { tm, tn, acc: vec![0.0; tm * tn] }
    }

    /// Accumulator value at tile-local `(i, j)`.
    #[inline]
    pub fn at(&self, i: usize, j: usize) -> f32 {
        self.acc[i * self.tn + j]
    }

    /// Set accumulator value at tile-local `(i, j)`.
    #[inline]
    pub fn set(&mut self, i: usize, j: usize, v: f32) {
        self.acc[i * self.tn + j] = v;
    }
}

/// The fixed GEMM mainloop: compute `op(A) @ op(B)` tile by tile and run the
/// `epi` epilogue on every output tile before any store.
///
/// * `ta` / `tb` select whether `a` / `b` are used transposed. This is enough
///   to express the three GEMM shapes a Transformer needs: the forward
///   projection `x @ W`, the activation gradient `dh @ Wᵀ`, and the weight
///   gradient `xᵀ @ dh` (paper §3.2.4 / Theorem 1).
///
/// The mainloop accounts the DRAM reads of `A` and `B`; the epilogue accounts
/// every store it performs.
pub fn gemm_epilogue(a: &Mat, ta: bool, b: &Mat, tb: bool, epi: &mut dyn EpilogueVisitor) {
    let (m, ka) = if ta { (a.cols, a.rows) } else { (a.rows, a.cols) };
    let (kb, n) = if tb { (b.cols, b.rows) } else { (b.rows, b.cols) };
    assert_eq!(ka, kb, "gemm_epilogue: inner dimensions disagree");
    let k = ka;

    // Mainloop operands stream in from global memory exactly once.
    tensor::account_read(a);
    tensor::account_read(b);

    let a_get = |i: usize, kk: usize| if ta { a.get(kk, i) } else { a.get(i, kk) };
    let b_get = |kk: usize, j: usize| if tb { b.get(j, kk) } else { b.get(kk, j) };

    epi.consumer_init(m, n, k);

    let mut m0 = 0;
    while m0 < m {
        let tm = TILE_M.min(m - m0);
        let mut n0 = 0;
        while n0 < n {
            let tn = TILE_N.min(n - n0);

            // --- Mainloop: accumulate one output tile in registers. ---
            let mut frag = Frag::new(tm, tn);
            for i in 0..tm {
                for kk in 0..k {
                    let av = a_get(m0 + i, kk);
                    if av == 0.0 {
                        continue;
                    }
                    let base = i * tn;
                    for j in 0..tn {
                        frag.acc[base + j] += av * b_get(kk, n0 + j);
                    }
                }
            }

            // --- Epilogue: visitor-tree hook points (paper Listing 1). ---
            let ctx = TileCtx { m0, n0, tm, tn, m, n, k };
            epi.consumer_begin(&ctx);
            epi.consumer_visit(&mut frag, &ctx);
            epi.consumer_end(&frag, &ctx);

            n0 += tn;
        }
        m0 += tm;
    }
}
