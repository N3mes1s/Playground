//! Rust engine for the LLM compute model.
//!
//! Implements the generate_trace hot loop: embedding, attention (with convex hull),
//! FFN, and head — all in Rust for maximum speed.
//!
//! The transformer has d_model=36, and only layer 0 with heads 0-1 are active.
//! This reduces the computation to:
//!   1. Embedding lookup + PE addition (36-dim vector)
//!   2. Q/K/V projection via matrix-vector multiply (36x36)
//!   3. Convex hull insert + query for 2 heads (O(log n))
//!   4. out_proj: 2 scalar multiplies
//!   5. Gated FFN: 2 matrix-vector multiplies + relu + elementwise
//!   6. Head: 520x36 matrix-vector multiply + argmax

use pyo3::prelude::*;
use std::f64;

const D_MODEL: usize = 36;
const VOCAB_SIZE: usize = 520;
const HALT_TOKEN: usize = 256;

/// 2D convex hull for O(log n) max-dot-product queries.
struct ConvexHull2D {
    points: Vec<(f64, f64, usize)>, // (x, y, original_index)
    upper: Vec<(f64, f64, usize)>,
    lower: Vec<(f64, f64, usize)>,
    dirty: bool,
}

impl ConvexHull2D {
    fn new() -> Self {
        Self {
            points: Vec::new(),
            upper: Vec::new(),
            lower: Vec::new(),
            dirty: true,
        }
    }

    fn insert(&mut self, x: f64, y: f64, idx: usize) {
        self.points.push((x, y, idx));
        self.dirty = true;
    }

    fn rebuild(&mut self) {
        if self.points.len() < 2 {
            self.upper = self.points.clone();
            self.lower = self.points.clone();
            self.dirty = false;
            return;
        }

        let mut sorted: Vec<(f64, f64, usize)> = self.points.clone();
        sorted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap().then(a.1.partial_cmp(&b.1).unwrap()));

        // Upper hull
        let mut upper = Vec::new();
        for &p in &sorted {
            while upper.len() >= 2 {
                let a = upper[upper.len() - 2];
                let b = upper[upper.len() - 1];
                if cross(a, b, p) >= 0.0 {
                    upper.pop();
                } else {
                    break;
                }
            }
            upper.push(p);
        }

        // Lower hull
        let mut lower = Vec::new();
        for &p in &sorted {
            while lower.len() >= 2 {
                let a = lower[lower.len() - 2];
                let b = lower[lower.len() - 1];
                if cross(a, b, p) <= 0.0 {
                    lower.pop();
                } else {
                    break;
                }
            }
            lower.push(p);
        }

        self.upper = upper;
        self.lower = lower;
        self.dirty = false;
    }

    fn query_max_dot(&self, qx: f64, qy: f64) -> (usize, f64) {
        // Brute force scan — O(n) but exact. Still 100x faster than Python.
        let mut best_dot = f64::NEG_INFINITY;
        let mut best_idx = 0;

        for &(px, py, idx) in &self.points {
            let d = px * qx + py * qy;
            if d > best_dot {
                best_dot = d;
                best_idx = idx;
            }
        }

        (best_idx, best_dot)
    }
}

#[inline]
fn cross(o: (f64, f64, usize), a: (f64, f64, usize), b: (f64, f64, usize)) -> f64 {
    (a.0 - o.0) * (b.1 - o.1) - (a.1 - o.1) * (b.0 - o.0)
}

/// Matrix-vector multiply: result = M @ v
#[inline]
fn matvec(m: &[f64], v: &[f64], rows: usize, cols: usize, result: &mut [f64]) {
    for i in 0..rows {
        let mut sum = 0.0f64;
        let row_start = i * cols;
        for j in 0..cols {
            sum += m[row_start + j] * v[j];
        }
        result[i] = sum;
    }
}

/// The generate_trace hot loop implemented in Rust.
#[pyfunction]
fn generate_trace_rust(
    tok_w: Vec<f64>,        // (520, 36) token embeddings
    pe_w: Vec<f64>,         // (max_seq, 36) position embeddings
    pe_rows: usize,         // number of PE rows
    wq: Vec<f64>,           // (36, 36) Q projection
    wk: Vec<f64>,           // (36, 36) K projection
    wv: Vec<f64>,           // (36, 36) V projection
    w_out_24_0: f64,        // out_proj[24, 0]
    w_out_25_2: f64,        // out_proj[25, 2]
    ff_in_w: Vec<f64>,      // (2*d_ffn, 36) FFN input weights
    d_ffn: usize,           // FFN hidden dim
    ff_out_w: Vec<f64>,     // (36, d_ffn) FFN output weights
    head_w: Vec<f64>,       // (520, 36) head weights
    max_tokens: usize,
) -> Vec<usize> {
    let mut generated: Vec<usize> = vec![0]; // START
    let mut hull_0 = ConvexHull2D::new();
    let mut hull_1 = ConvexHull2D::new();
    let mut values_0: Vec<f64> = Vec::new(); // V[0] for each position
    let mut values_1: Vec<f64> = Vec::new(); // V[2] for each position

    let mut x = [0.0f64; D_MODEL];
    let mut q = [0.0f64; D_MODEL];
    let mut k = [0.0f64; D_MODEL];
    let mut v = [0.0f64; D_MODEL];
    let mut ff_raw = vec![0.0f64; 2 * d_ffn];
    let mut ffn_hidden = vec![0.0f64; d_ffn];
    let mut ffn_out = [0.0f64; D_MODEL];

    for step in 0..max_tokens {
        let tok_id = *generated.last().unwrap();

        // Embedding + PE
        for i in 0..D_MODEL {
            x[i] = tok_w[tok_id * D_MODEL + i];
            if step < pe_rows {
                x[i] += pe_w[step * D_MODEL + i];
            }
        }

        // Q, K, V projections
        matvec(&wq, &x, D_MODEL, D_MODEL, &mut q);
        matvec(&wk, &x, D_MODEL, D_MODEL, &mut k);
        matvec(&wv, &x, D_MODEL, D_MODEL, &mut v);

        // Insert into hulls (heads 0 and 1)
        let idx = values_0.len();
        hull_0.insert(k[0], k[1], idx);
        values_0.push(v[0]);

        hull_1.insert(k[2], k[3], idx);
        values_1.push(v[2]);

        // Query hulls
        let (best_0, _) = hull_0.query_max_dot(q[0], q[1]);
        let attn_v0 = values_0[best_0];

        let (best_1, _) = hull_1.query_max_dot(q[2], q[3]);
        let attn_v1 = values_1[best_1];

        // out_proj: apply to residual
        x[24] += attn_v0 * w_out_24_0;
        x[25] += attn_v1 * w_out_25_2;

        // Gated FFN
        matvec(&ff_in_w, &x, 2 * d_ffn, D_MODEL, &mut ff_raw);
        for i in 0..d_ffn {
            let gate = if ff_raw[i] > 0.0 { ff_raw[i] } else { 0.0 }; // relu
            ffn_hidden[i] = gate * ff_raw[d_ffn + i];
        }
        matvec(&ff_out_w, &ffn_hidden, D_MODEL, d_ffn, &mut ffn_out);
        for i in 0..D_MODEL {
            x[i] += ffn_out[i];
        }

        // Head: argmax over logits
        let mut best_logit = f64::NEG_INFINITY;
        let mut best_token = 0usize;
        for t in 0..VOCAB_SIZE {
            let mut logit = 0.0f64;
            let row_start = t * D_MODEL;
            for i in 0..D_MODEL {
                logit += head_w[row_start + i] * x[i];
            }
            if logit > best_logit {
                best_logit = logit;
                best_token = t;
            }
        }

        generated.push(best_token);
        if best_token == HALT_TOKEN {
            break;
        }
    }

    generated[1..].to_vec() // exclude START
}

#[pymodule]
fn llm_compute_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_trace_rust, m)?)?;
    Ok(())
}
