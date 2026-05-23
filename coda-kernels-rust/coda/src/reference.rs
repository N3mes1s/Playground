//! Naive, **unfused** reference operators.
//!
//! These are the "operator sequence" baseline that CODA argues against: every
//! operator reads its inputs from global memory and writes its output back,
//! turning each operator boundary into a materialization boundary (paper §1).
//!
//! They serve two purposes:
//! * **Correctness** - the fused CODA kernels are checked against these.
//! * **Traffic baseline** - run side by side with the fused path, the DRAM
//!   counters quantify how much movement the fusion removed.

use crate::epilogue::silu;
use crate::tensor::{self, Mat};

/// Naive GEMM `op(A) @ op(B)`, materializing the result to global memory.
pub fn gemm(a: &Mat, ta: bool, b: &Mat, tb: bool) -> Mat {
    let (m, ka) = if ta { (a.cols, a.rows) } else { (a.rows, a.cols) };
    let (kb, n) = if tb { (b.cols, b.rows) } else { (b.rows, b.cols) };
    assert_eq!(ka, kb);
    tensor::account_read(a);
    tensor::account_read(b);
    let a_get = |i: usize, k: usize| if ta { a.get(k, i) } else { a.get(i, k) };
    let b_get = |k: usize, j: usize| if tb { b.get(j, k) } else { b.get(k, j) };
    let mut d = Mat::zeros(m, n);
    for i in 0..m {
        for k in 0..ka {
            let av = a_get(i, k);
            if av == 0.0 {
                continue;
            }
            for j in 0..n {
                d.add(i, j, av * b_get(k, j));
            }
        }
    }
    tensor::account_write(&d);
    d
}

/// Naive residual add `out = d + c`.
pub fn residual(d: &Mat, c: &Mat) -> Mat {
    tensor::account_read(d);
    tensor::account_read(c);
    let mut out = d.clone();
    for i in 0..out.data.len() {
        out.data[i] += c.data[i];
    }
    tensor::account_write(&out);
    out
}

/// Naive RMSNorm. Returns `(normalized ⊙ γ, r)` where `r` is the row-wise
/// inverse RMS factor `1 / sqrt(mean(x^2) + eps)`.
pub fn rmsnorm(x: &Mat, gamma: &[f32], eps: f32) -> (Mat, Vec<f32>) {
    tensor::account_read(x);
    tensor::account_elems(gamma.len());
    let mut out = Mat::zeros(x.rows, x.cols);
    let mut r = vec![0.0f32; x.rows];
    for i in 0..x.rows {
        let mut sq = 0.0f32;
        for j in 0..x.cols {
            let v = x.get(i, j);
            sq += v * v;
        }
        let ri = 1.0 / (sq / x.cols as f32 + eps).sqrt();
        r[i] = ri;
        for j in 0..x.cols {
            out.set(i, j, x.get(i, j) * ri * gamma[j]);
        }
    }
    tensor::account_write(&out);
    (out, r)
}

/// Naive per-row scaling `out[i, j] = x[i, j] * r[i]`.
pub fn row_scale(x: &Mat, r: &[f32]) -> Mat {
    tensor::account_read(x);
    tensor::account_elems(r.len());
    let mut out = Mat::zeros(x.rows, x.cols);
    for i in 0..x.rows {
        for j in 0..x.cols {
            out.set(i, j, x.get(i, j) * r[i]);
        }
    }
    tensor::account_write(&out);
    out
}

/// Naive SwiGLU `O = silu(G) ⊙ U`, `[G, U] = interleavedSplit(D)`.
pub fn swiglu(d: &Mat) -> Mat {
    assert!(d.cols % 2 == 0);
    tensor::account_read(d);
    let mut out = Mat::zeros(d.rows, d.cols / 2);
    for i in 0..d.rows {
        for k in 0..d.cols / 2 {
            let g = d.get(i, 2 * k);
            let u = d.get(i, 2 * k + 1);
            out.set(i, k, silu(g) * u);
        }
    }
    tensor::account_write(&out);
    out
}

/// Naive RoPE applied to adjacent feature pairs.
pub fn rope(d: &Mat, cos: &Mat, sin: &Mat) -> Mat {
    tensor::account_read(d);
    tensor::account_read(cos);
    tensor::account_read(sin);
    let mut out = Mat::zeros(d.rows, d.cols);
    for i in 0..d.rows {
        let mut j = 0;
        while j < d.cols {
            let x0 = d.get(i, j);
            let x1 = d.get(i, j + 1);
            let c = cos.get(i, j);
            let s = sin.get(i, j);
            out.set(i, j, x0 * c - x1 * s);
            out.set(i, j + 1, x0 * s + x1 * c);
            j += 2;
        }
    }
    tensor::account_write(&out);
    out
}

/// Naive cross-entropy: full row softmax, returns per-token loss.
pub fn cross_entropy(z: &Mat, targets: &[usize]) -> Vec<f32> {
    tensor::account_read(z);
    let mut loss = vec![0.0f32; z.rows];
    for i in 0..z.rows {
        let mut mx = f32::NEG_INFINITY;
        for j in 0..z.cols {
            mx = mx.max(z.get(i, j));
        }
        let mut se = 0.0f32;
        for j in 0..z.cols {
            se += (z.get(i, j) - mx).exp();
        }
        let lse = mx + se.ln();
        loss[i] = -z.get(i, targets[i]) + lse;
    }
    loss
}
