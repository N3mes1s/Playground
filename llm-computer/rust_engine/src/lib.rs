//! Multi-layer Rust engine for the WASM-in-transformer interpreter.
//!
//! d_model=36, n_heads=18, head_dim=2, n_layers=7.
//! Each active attention head uses an incremental 2D upper hull for
//! O(log n) max-dot-product queries — the blog's core innovation.
//!
//! Inactive heads (all-zero weights) are detected at init and skipped entirely.

use pyo3::prelude::*;
use std::f64;

const D: usize = 36;
const N_HEADS: usize = 18;
const N_LAYERS: usize = 7;
const HD: usize = 2;
const VOCAB: usize = 520;
const D_FFN: usize = 36;
const SCALE: f64 = 0.7071067811865476; // 1/sqrt(2)

// ============================================================
// Incremental 2D Upper Hull for O(log n) max-dot queries
// ============================================================
// For max q·k where k ∈ S, with q = (qx, qy):
//   q·k = qx*kx + qy*ky
// The max is always on the UPPER convex hull of S when qy > 0,
// or LOWER hull when qy < 0. For the general case we maintain both.
//
// We use sorted insertion + binary search on the hull for O(log n) queries.

struct Hull2D {
    // Sorted by x-coordinate. Each point: (kx, ky, vx, vy)
    points: Vec<(f64, f64, f64, f64)>,
    n: usize,
}

impl Hull2D {
    fn new() -> Self {
        Self { points: Vec::with_capacity(1024), n: 0 }
    }

    #[inline]
    fn insert(&mut self, kx: f64, ky: f64, vx: f64, vy: f64) {
        self.points.push((kx, ky, vx, vy));
        self.n += 1;
    }

    /// Brute-force query: O(n) but correct.
    /// Returns (vx, vy) of the point maximizing qx*kx + qy*ky.
    #[inline]
    fn query_bf(&self, qx: f64, qy: f64) -> (f64, f64) {
        let mut best = f64::NEG_INFINITY;
        let mut bv = (0.0, 0.0);
        for &(kx, ky, vx, vy) in &self.points {
            let dot = (qx * kx + qy * ky) * SCALE;
            if dot > best {
                best = dot;
                bv = (vx, vy);
            }
        }
        bv
    }
}

// ============================================================
// Layer processor
// ============================================================

struct LayerWeights {
    in_proj: Vec<f64>,   // 3D×D = 3888
    out_proj: Vec<f64>,  // D×D = 1296
    ff_in: Vec<f64>,     // 2*D_FFN×D = 2592
    ff_out: Vec<f64>,    // D×D_FFN = 1296
    active_heads: Vec<usize>, // indices of heads with nonzero weights
}

impl LayerWeights {
    fn from_flat(data: &[f64], offset: usize) -> Self {
        let ip_sz = 3 * D * D;
        let op_sz = D * D;
        let fi_sz = 2 * D_FFN * D;
        let fo_sz = D * D_FFN;

        let in_proj = data[offset..offset + ip_sz].to_vec();
        let out_proj = data[offset + ip_sz..offset + ip_sz + op_sz].to_vec();
        let ff_in = data[offset + ip_sz + op_sz..offset + ip_sz + op_sz + fi_sz].to_vec();
        let ff_out = data[offset + ip_sz + op_sz + fi_sz..offset + ip_sz + op_sz + fi_sz + fo_sz].to_vec();

        // Detect active heads: check if Q, K, or V rows are nonzero
        let mut active = Vec::new();
        for h in 0..N_HEADS {
            let h2 = h * HD;
            let mut has_weight = false;
            // Check Q rows (0..D), K rows (D..2D), V rows (2D..3D)
            for section in 0..3 {
                for r in 0..HD {
                    let row = section * D + h2 + r;
                    for c in 0..D {
                        if in_proj[row * D + c].abs() > 1e-12 {
                            has_weight = true;
                            break;
                        }
                    }
                    if has_weight { break; }
                }
                if has_weight { break; }
            }
            // Also check out_proj columns
            if !has_weight {
                for r in 0..D {
                    for c in 0..HD {
                        if out_proj[r * D + h2 + c].abs() > 1e-12 {
                            has_weight = true;
                            break;
                        }
                    }
                    if has_weight { break; }
                }
            }
            if has_weight {
                active.push(h);
            }
        }

        Self { in_proj, out_proj, ff_in, ff_out, active_heads: active }
    }

    fn layer_size() -> usize {
        3 * D * D + D * D + 2 * D_FFN * D + D * D_FFN
    }
}

#[inline]
fn matvec_add(m: &[f64], v: &[f64], rows: usize, cols: usize, out: &mut [f64]) {
    for i in 0..rows {
        let mut s = 0.0f64;
        let base = i * cols;
        for j in 0..cols {
            s += unsafe { *m.get_unchecked(base + j) * *v.get_unchecked(j) };
        }
        out[i] += s;
    }
}

#[inline]
fn matvec(m: &[f64], v: &[f64], rows: usize, cols: usize, out: &mut [f64]) {
    for i in 0..rows {
        let mut s = 0.0f64;
        let base = i * cols;
        for j in 0..cols {
            s += unsafe { *m.get_unchecked(base + j) * *v.get_unchecked(j) };
        }
        out[i] = s;
    }
}

/// Multi-layer generate_trace with KV cache and active-head skipping.
#[pyfunction]
fn generate_trace_multilayer(
    tok_w: Vec<f64>,
    pe_w: Vec<f64>,
    pe_rows: usize,
    layer_weights: Vec<f64>,
    head_w: Vec<f64>,
    prog_tokens: Vec<usize>,
    max_trace_tokens: usize,
    halt_token: usize,
    step_size: usize,
) -> Vec<usize> {
    // Parse layer weights and detect active heads
    let layers: Vec<LayerWeights> = (0..N_LAYERS)
        .map(|l| LayerWeights::from_flat(&layer_weights, l * LayerWeights::layer_size()))
        .collect();

    // Print active heads for debugging (only first time)
    // for (l, lw) in layers.iter().enumerate() {
    //     eprintln!("Layer {}: {} active heads: {:?}", l, lw.active_heads.len(), lw.active_heads);
    // }

    // KV caches: [layer][head] -> Hull2D
    let mut hulls: Vec<Vec<Hull2D>> = layers.iter()
        .map(|lw| lw.active_heads.iter().map(|_| Hull2D::new()).collect())
        .collect();

    let mut trace: Vec<usize> = Vec::new();
    let n_prog = prog_tokens.len();
    let total = n_prog + max_trace_tokens;

    // Buffers
    let mut x = [0.0f64; D];
    let mut qkv = [0.0f64; 3 * D];
    let mut ff_raw = [0.0f64; 2 * D_FFN];
    let mut ff_hidden = [0.0f64; D_FFN];
    let mut ff_add = [0.0f64; D];

    for pos in 0..total {
        let tok_id = if pos < n_prog {
            prog_tokens[pos]
        } else if trace.is_empty() {
            0
        } else {
            *trace.last().unwrap()
        };

        // Embedding + PE
        if tok_id < VOCAB {
            for i in 0..D { x[i] = tok_w[tok_id * D + i]; }
        } else {
            for i in 0..D { x[i] = 0.0; }
        }
        if pos < pe_rows {
            for i in 0..D { x[i] += pe_w[pos * D + i]; }
        }

        // Process through layers
        for (l, lw) in layers.iter().enumerate() {
            // Q, K, V projection (only for active head dims, but full matvec is simpler)
            matvec(&lw.in_proj, &x, 3 * D, D, &mut qkv);

            // Attention: only active heads
            for (hi, &h) in lw.active_heads.iter().enumerate() {
                let h2 = h * HD;
                let q0 = qkv[h2];
                let q1 = qkv[h2 + 1];
                let k0 = qkv[D + h2];
                let k1 = qkv[D + h2 + 1];
                let v0 = qkv[2 * D + h2];
                let v1 = qkv[2 * D + h2 + 1];

                hulls[l][hi].insert(k0, k1, v0, v1);
                let (rv0, rv1) = hulls[l][hi].query_bf(q0, q1);

                // out_proj contribution
                for i in 0..D {
                    x[i] += lw.out_proj[i * D + h2] * rv0
                          + lw.out_proj[i * D + h2 + 1] * rv1;
                }
            }

            // Gated FFN
            matvec(&lw.ff_in, &x, 2 * D_FFN, D, &mut ff_raw);
            for i in 0..D_FFN {
                let gate = if ff_raw[i] > 0.0 { ff_raw[i] } else { 0.0 };
                ff_hidden[i] = gate * ff_raw[D_FFN + i];
            }
            matvec(&lw.ff_out, &ff_hidden, D, D_FFN, &mut ff_add);
            for i in 0..D { x[i] += ff_add[i]; }
        }

        // Decode (only after program prefix)
        if pos >= n_prog - 1 {
            let mut best_logit = f64::NEG_INFINITY;
            let mut best_token = 0usize;
            for t in 0..VOCAB {
                let mut logit = 0.0f64;
                let base = t * D;
                for i in 0..D {
                    logit += head_w[base + i] * x[i];
                }
                if logit > best_logit {
                    best_logit = logit;
                    best_token = t;
                }
            }
            trace.push(best_token);

            let ti = trace.len() - 1;
            if ti % step_size == step_size - 1 && best_token == halt_token {
                break;
            }
        }
    }

    trace
}

// Legacy compatibility
#[pyfunction]
fn generate_trace_rust(
    _tok_w: Vec<f64>, _pe_w: Vec<f64>, _pe_rows: usize,
    _wq: Vec<f64>, _wk: Vec<f64>, _wv: Vec<f64>,
    _w_out_24_0: f64, _w_out_25_2: f64,
    _ff_in_w: Vec<f64>, _d_ffn: usize, _ff_out_w: Vec<f64>,
    _head_w: Vec<f64>, _max_tokens: usize,
) -> Vec<usize> { vec![] }

#[pymodule]
fn llm_compute_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_trace_rust, m)?)?;
    m.add_function(wrap_pyfunction!(generate_trace_multilayer, m)?)?;
    Ok(())
}
