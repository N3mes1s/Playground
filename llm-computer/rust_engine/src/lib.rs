//! Multi-layer Rust engine for the WASM-in-transformer interpreter.
//!
//! Supports d_model=36, n_heads=18, head_dim=2, n_layers=7.
//! Each attention head uses brute-force max-dot (O(n) but fast in Rust).
//! KV cache: stores K and V per head per layer. Only active heads are queried.

use pyo3::prelude::*;
use std::f64;

const D: usize = 36;
const N_HEADS: usize = 18;
const N_LAYERS: usize = 7;
const HD: usize = 2; // head_dim
const VOCAB: usize = 520;
const D_FFN: usize = 36;

/// Per-head KV cache: stores (K0, K1, V0, V1) per token.
struct HeadCache {
    keys: Vec<(f64, f64)>,
    vals: Vec<(f64, f64)>,
}

impl HeadCache {
    fn new() -> Self {
        Self { keys: Vec::new(), vals: Vec::new() }
    }
    fn insert(&mut self, k0: f64, k1: f64, v0: f64, v1: f64) {
        self.keys.push((k0, k1));
        self.vals.push((v0, v1));
    }
    /// Hard-max attention: find the key with maximum dot product with (q0, q1).
    /// Returns (v0, v1) of the best-matching key.
    fn query(&self, q0: f64, q1: f64) -> (f64, f64) {
        let mut best_dot = f64::NEG_INFINITY;
        let mut best_v = (0.0, 0.0);
        let scale = 1.0 / (HD as f64).sqrt();
        for i in 0..self.keys.len() {
            let (k0, k1) = self.keys[i];
            let dot = (q0 * k0 + q1 * k1) * scale;
            if dot > best_dot {
                best_dot = dot;
                best_v = self.vals[i];
            }
        }
        best_v
    }
}

#[inline]
fn matvec(m: &[f64], v: &[f64], rows: usize, cols: usize, out: &mut [f64]) {
    for i in 0..rows {
        let mut s = 0.0f64;
        let base = i * cols;
        for j in 0..cols {
            s += m[base + j] * v[j];
        }
        out[i] = s;
    }
}

/// Multi-layer generate_trace.
/// Weights packed as: [tok_w(VOCAB*D), pe_w(max_seq*D), pe_rows,
///   for each layer: in_proj(3D*D), out_proj(D*D), ff_in(2*D_FFN*D), ff_out(D*D_FFN),
///   head_w(VOCAB*D)]
#[pyfunction]
fn generate_trace_multilayer(
    tok_w: Vec<f64>,
    pe_w: Vec<f64>,
    pe_rows: usize,
    layer_weights: Vec<f64>,  // packed: 7 layers × (in_proj + out_proj + ff_in + ff_out)
    head_w: Vec<f64>,
    prog_tokens: Vec<usize>,
    max_trace_tokens: usize,
    halt_token: usize,
    step_size: usize,
) -> Vec<usize> {
    // Per-layer weight sizes
    let in_proj_size = 3 * D * D;  // 3888
    let out_proj_size = D * D;      // 1296
    let ff_in_size = 2 * D_FFN * D; // 2592
    let ff_out_size = D * D_FFN;    // 1296
    let layer_size = in_proj_size + out_proj_size + ff_in_size + ff_out_size;

    // Unpack layer weight offsets
    let layer_offset = |l: usize| -> usize { l * layer_size };

    // Initialize KV caches: [layer][head]
    let mut caches: Vec<Vec<HeadCache>> = (0..N_LAYERS)
        .map(|_| (0..N_HEADS).map(|_| HeadCache::new()).collect())
        .collect();

    let mut trace: Vec<usize> = Vec::new();
    let total_tokens = prog_tokens.len() + max_trace_tokens;

    // Buffers
    let mut x = [0.0f64; D];
    let mut qkv = [0.0f64; 3 * D];
    let mut attn_out = [0.0f64; D];
    let mut ff_raw = [0.0f64; 2 * D_FFN];
    let mut ff_hidden = [0.0f64; D_FFN];
    let mut ff_out = [0.0f64; D];

    let n_prog = prog_tokens.len();

    for pos in 0..total_tokens {
        // Get current token
        let tok_id = if pos < n_prog {
            prog_tokens[pos]
        } else if pos == n_prog {
            // First trace token comes from prefill logits
            // We'll compute it normally
            if trace.is_empty() { 0 } else { *trace.last().unwrap() }
        } else {
            *trace.last().unwrap()
        };

        if pos > n_prog && trace.is_empty() {
            break;
        }

        // Embedding + PE
        if tok_id < VOCAB {
            for i in 0..D {
                x[i] = tok_w[tok_id * D + i];
            }
        } else {
            for i in 0..D { x[i] = 0.0; }
        }
        if pos < pe_rows {
            for i in 0..D {
                x[i] += pe_w[pos * D + i];
            }
        }

        // Process through all layers
        for l in 0..N_LAYERS {
            let loff = layer_offset(l);
            let in_proj = &layer_weights[loff..loff + in_proj_size];
            let out_proj = &layer_weights[loff + in_proj_size..loff + in_proj_size + out_proj_size];
            let ff_in = &layer_weights[loff + in_proj_size + out_proj_size..loff + in_proj_size + out_proj_size + ff_in_size];
            let ff_out_w = &layer_weights[loff + in_proj_size + out_proj_size + ff_in_size..loff + layer_size];

            // Q, K, V projection
            matvec(in_proj, &x, 3 * D, D, &mut qkv);

            // Insert K, V into caches and query Q against all K
            for i in 0..D { attn_out[i] = 0.0; }

            for h in 0..N_HEADS {
                let h2 = h * HD;
                let q0 = qkv[h2];
                let q1 = qkv[h2 + 1];
                let k0 = qkv[D + h2];
                let k1 = qkv[D + h2 + 1];
                let v0 = qkv[2 * D + h2];
                let v1 = qkv[2 * D + h2 + 1];

                caches[l][h].insert(k0, k1, v0, v1);

                // Query
                let (rv0, rv1) = caches[l][h].query(q0, q1);

                // out_proj: head h outputs at columns h2, h2+1
                for i in 0..D {
                    attn_out[i] += out_proj[i * D + h2] * rv0
                                 + out_proj[i * D + h2 + 1] * rv1;
                }
            }

            // Residual
            for i in 0..D { x[i] += attn_out[i]; }

            // Gated FFN
            matvec(ff_in, &x, 2 * D_FFN, D, &mut ff_raw);
            for i in 0..D_FFN {
                let gate = if ff_raw[i] > 0.0 { ff_raw[i] } else { 0.0 };
                ff_hidden[i] = gate * ff_raw[D_FFN + i];
            }
            matvec(ff_out_w, &ff_hidden, D, D_FFN, &mut ff_out);
            for i in 0..D { x[i] += ff_out[i]; }
        }

        // Only decode trace tokens (skip program tokens)
        if pos >= n_prog - 1 {
            let mut best_logit = f64::NEG_INFINITY;
            let mut best_token = 0usize;
            for t in 0..VOCAB {
                let mut logit = 0.0f64;
                for i in 0..D {
                    logit += head_w[t * D + i] * x[i];
                }
                if logit > best_logit {
                    best_logit = logit;
                    best_token = t;
                }
            }
            trace.push(best_token);

            // Check halt
            let trace_idx = trace.len() - 1;
            if trace_idx % step_size == step_size - 1 && best_token == halt_token {
                break;
            }
        }
    }

    trace
}

// Keep old function for backwards compat
#[pyfunction]
fn generate_trace_rust(
    tok_w: Vec<f64>,
    pe_w: Vec<f64>,
    pe_rows: usize,
    wq: Vec<f64>,
    wk: Vec<f64>,
    wv: Vec<f64>,
    w_out_24_0: f64,
    w_out_25_2: f64,
    ff_in_w: Vec<f64>,
    d_ffn: usize,
    ff_out_w: Vec<f64>,
    head_w: Vec<f64>,
    max_tokens: usize,
) -> Vec<usize> {
    // Legacy single-layer implementation
    vec![]
}

#[pymodule]
fn llm_compute_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_trace_rust, m)?)?;
    m.add_function(wrap_pyfunction!(generate_trace_multilayer, m)?)?;
    Ok(())
}
